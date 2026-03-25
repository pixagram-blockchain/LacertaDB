/**
 * LacertaDB V0.13.0 - Production Library
 * @module LacertaDB
 * @version 0.13.0
 * @license MIT
 * @author Pixagram SA
 */

'use strict';

// ========================
// Polyfills
// ========================

if (typeof window !== 'undefined' && !window.requestIdleCallback) {
    window.requestIdleCallback = function(callback) {
        return setTimeout(callback, 0);
    };
    window.cancelIdleCallback = clearTimeout;
}

// ========================
// Dependencies
// ========================

import TurboSerial from "@pixagram/turboserial";
import TurboBase64 from "@pixagram/turbobase64";

// Default TurboSerial configuration (overridable via LacertaDB constructor)
//
// IMPORTANT: compression, preservePropertyDescriptors, and shareArrayBuffers
// affect the BINARY WIRE FORMAT of serialized data. Changing them breaks
// deserialization of all existing documents. Only change these if you also
// migrate all stored data.
//
// Safe to change without migration:
//   detectCircular  — only affects serialization behavior (throws vs infinite loop)
//   memoryPoolSize  — only affects memory allocation
const TURBO_SERIAL_DEFAULTS = {
    compression: false,
    preservePropertyDescriptors: false,
    deduplication: false,
    simdOptimization: true,
    detectCircular: false,
    shareArrayBuffers: false,
    allowFunction: false,
    serializeFunctions: false,
    memoryPoolSize: 65536 * 4
};

// ========================
// Quick Store (Optimized)
// ========================

/**
 * Optimized QuickStore.
 * All documents live in an in-memory Map for O(1) reads (no serialization overhead).
 * IndexedDB is the persistence backend (non-blocking, no 5MB limit).
 * Persistence triggers:
 *   - Async hydration from IDB on startup (via hydrateFromIDB)
 *   - Debounced writes (add/update/delete schedule an async persist to IDB)
 */
class QuickStore {
    constructor(dbName, serializer, base64, idb = null) {
        this._dbName = dbName;
        this._serializer = serializer;
        this._base64 = base64;
        this._idb = idb; // IDB connection for async persistence
        this._metaKey = `quickstore_${dbName}`;

        // In-memory cache: docId → deserialized data
        this._docs = new Map();
        this._hydrated = false;

        // Dirty tracking: set of docIds that need IDB persistence
        this._dirtyDocs = new Set();
        this._dirtyIndex = false;
        this._saveTimer = null;
    }

    destroy() {
        if (this._saveTimer) {
            if (typeof window !== 'undefined' && window.cancelIdleCallback) {
                window.cancelIdleCallback(this._saveTimer);
            } else {
                clearTimeout(this._saveTimer);
            }
            this._saveTimer = null;
        }
    }

    /** Hydrate all quickstore docs from IDB on startup */
    async hydrateFromIDB() {
        if (this._hydrated) return;

        if (this._idb && this._idb.objectStoreNames.contains('__meta')) {
            try {
                const stored = await Database._readMeta(this._idb, this._metaKey);
                if (stored && stored.docs) {
                    const decoded = this._base64.decode(stored.docs);
                    const entries = this._serializer.deserialize(decoded);
                    if (Array.isArray(entries)) {
                        for (const [docId, data] of entries) {
                            this._docs.set(docId, data);
                        }
                    }
                }
            } catch (e) {
                console.warn('QuickStore IDB hydration failed, trying localStorage fallback.', e);
                this._hydrateFromLocalStorage();
            }
        } else {
            this._hydrateFromLocalStorage();
        }
        this._hydrated = true;
    }

    /** Legacy localStorage hydration (migration fallback) */
    _hydrateFromLocalStorage() {
        const keyPrefix = `lacertadb_${this._dbName}_quickstore_`;
        const indexKey = `${keyPrefix}index`;
        const indexStr = localStorage.getItem(indexKey);
        if (indexStr) {
            try {
                const decoded = this._base64.decode(indexStr);
                const list = this._serializer.deserialize(decoded);
                for (const docId of list) {
                    const key = `${keyPrefix}data_${docId}`;
                    const stored = localStorage.getItem(key);
                    if (stored) {
                        try {
                            const decodedDoc = this._base64.decode(stored);
                            this._docs.set(docId, this._serializer.deserialize(decodedDoc));
                        } catch (e) { /* skip corrupted */ }
                    }
                }
                // Clean up localStorage after successful migration
                this._dirtyIndex = true;
                for (const docId of this._docs.keys()) this._dirtyDocs.add(docId);
                this._persistDirty();
                // Remove old localStorage keys
                localStorage.removeItem(indexKey);
                for (const docId of this._docs.keys()) {
                    localStorage.removeItem(`${keyPrefix}data_${docId}`);
                }
            } catch (e) {
                console.warn('QuickStore localStorage hydration failed.', e);
            }
        }
    }

    _ensureHydrated() {
        // In the new architecture, hydration is async via hydrateFromIDB()
        // This is kept for backward compat with sync callers
        if (!this._hydrated) {
            this._hydrated = true; // prevent infinite recursion
        }
    }

    /** Schedule debounced persistence of dirty entries */
    _scheduleSave() {
        if (this._saveTimer) return;

        const save = () => {
            this._saveTimer = null;
            this._persistDirty();
        };

        if (typeof window !== 'undefined' && window.requestIdleCallback) {
            this._saveTimer = window.requestIdleCallback(save);
        } else {
            this._saveTimer = setTimeout(save, 200);
        }
    }

    /** Persist all quickstore data to IDB as a single blob */
    _persistDirty() {
        if (this._dirtyDocs.size === 0 && !this._dirtyIndex) return;

        this._dirtyDocs.clear();
        this._dirtyIndex = false;

        if (!this._idb || !this._idb.objectStoreNames.contains('__meta')) return;

        try {
            const entries = Array.from(this._docs.entries());
            const serialized = this._serializer.serialize(entries);
            const encoded = this._base64.encode(serialized);

            Database._writeMeta(this._idb, this._metaKey, { docs: encoded }).catch(e => {
                console.error('QuickStore IDB save failed:', e);
            });
        } catch (e) {
            console.error('QuickStore serialization failed:', e);
        }
    }

    add(docId, data) {
        this._ensureHydrated();
        const isNew = !this._docs.has(docId);
        this._docs.set(docId, data);
        this._dirtyDocs.add(docId);
        if (isNew) this._dirtyIndex = true;
        this._scheduleSave();
        return true;
    }

    get(docId) {
        this._ensureHydrated();
        const data = this._docs.get(docId);
        return data !== undefined ? data : null;
    }

    update(docId, data) {
        return this.add(docId, data);
    }

    delete(docId) {
        this._ensureHydrated();
        if (this._docs.has(docId)) {
            this._docs.delete(docId);
            this._dirtyDocs.add(docId);
            this._dirtyIndex = true;
            this._scheduleSave();
        }
    }

    getAll() {
        this._ensureHydrated();
        const results = [];
        for (const [docId, data] of this._docs) {
            results.push({ _id: docId, ...data });
        }
        return results;
    }

    query(filter = {}) {
        if (Object.keys(filter).length === 0) return this.getAll();
        const allDocs = this.getAll();
        return allDocs.filter(doc => queryEngine.evaluate(doc, filter));
    }

    clear() {
        this._ensureHydrated();
        this._docs.clear();
        this._dirtyDocs.clear();
        this._dirtyIndex = false;
        if (this._saveTimer) {
            if (typeof window !== 'undefined' && window.cancelIdleCallback) {
                window.cancelIdleCallback(this._saveTimer);
            } else {
                clearTimeout(this._saveTimer);
            }
            this._saveTimer = null;
        }
        // Clear from IDB
        if (this._idb && this._idb.objectStoreNames.contains('__meta')) {
            Database._writeMeta(this._idb, this._metaKey, { docs: null }).catch(() => {});
        }
        // Clean up any legacy localStorage keys
        const keyPrefix = `lacertadb_${this._dbName}_quickstore_`;
        const indexKey = `${keyPrefix}index`;
        try { localStorage.removeItem(indexKey); } catch(e) {}
    }

    get size() {
        this._ensureHydrated();
        return this._docs.size;
    }
}

// ========================
// Global IndexedDB Connection Pool
// ========================

class IndexedDBConnectionPool {
    constructor() {
        this._connections = new Map();
        this._refCounts = new Map();
    }

    async getConnection(dbName, version = 1, upgradeCallback) {
        const key = `${dbName}_v${version}`;

        if (this._connections.has(key)) {
            this._refCounts.set(key, (this._refCounts.get(key) || 0) + 1);
            return this._connections.get(key);
        }

        const db = await new Promise((resolve, reject) => {
            const request = indexedDB.open(dbName, version);
            request.onerror = () => reject(new LacertaDBError(
                'Failed to open database', 'DATABASE_OPEN_FAILED', request.error
            ));
            request.onsuccess = () => resolve(request.result);
            request.onupgradeneeded = event => {
                if (upgradeCallback) {
                    upgradeCallback(event.target.result, event.oldVersion, event.newVersion);
                }
            };
        });

        // Ensure we handle unexpected closures
        db.onclose = () => {
            this._connections.delete(key);
            this._refCounts.delete(key);
        };

        this._connections.set(key, db);
        this._refCounts.set(key, 1);
        return db;
    }

    releaseConnection(dbName, version = 1) {
        const key = `${dbName}_v${version}`;
        const refCount = this._refCounts.get(key) || 0;

        if (refCount <= 1) {
            const db = this._connections.get(key);
            if (db) {
                db.close();
                this._connections.delete(key);
                this._refCounts.delete(key);
            }
        } else {
            this._refCounts.set(key, refCount - 1);
        }
    }

    closeAll() {
        for (const db of this._connections.values()) {
            db.close();
        }
        this._connections.clear();
        this._refCounts.clear();
    }
}

const connectionPool = new IndexedDBConnectionPool();

// ========================
// Async Mutex
// ========================

class AsyncMutex {
    constructor() {
        this._queue = [];
        this._headIndex = 0;
        this._locked = false;
    }

    acquire() {
        return new Promise(resolve => {
            this._queue.push(resolve);
            this._dispatch();
        });
    }

    release() {
        this._locked = false;
        this._dispatch();
    }

    async runExclusive(callback) {
        const release = await this.acquire();
        try {
            return await callback();
        } finally {
            release();
        }
    }

    _dispatch() {
        if (this._locked || this._headIndex >= this._queue.length) {
            return;
        }
        this._locked = true;
        const resolve = this._queue[this._headIndex++];
        resolve(() => this.release());

        // Compact when the consumed portion exceeds half the array
        if (this._headIndex > 1000 && this._headIndex > (this._queue.length >>> 1)) {
            this._queue = this._queue.slice(this._headIndex);
            this._headIndex = 0;
        }
    }
}

// ========================
// Custom Errors
// ========================

class LacertaDBError extends Error {
    constructor(message, code, originalError) {
        super(message);
        this.name = 'LacertaDBError';
        this.code = code;
        this.originalError = originalError || null;
        this._ts = Date.now();
    }
    get timestamp() { return new Date(this._ts).toISOString(); }
}

// ========================
// LRU Cache Implementation
// ========================

class LRUCache {
    constructor(maxSize = 100, ttl = null) {
        this._maxSize = maxSize;
        this._ttl = ttl;
        this._cache = new Map();
        // Map maintains insertion order, so we don't need a separate array
    }

    get(key) {
        const item = this._cache.get(key);
        if (!item) return null;

        if (this._ttl && (Date.now() - item.ts > this._ttl)) {
            this._cache.delete(key);
            return null;
        }

        // Refresh access order (delete and re-set moves it to the end)
        this._cache.delete(key);
        this._cache.set(key, item);
        return item.value;
    }

    set(key, value) {
        if (this._cache.has(key)) this._cache.delete(key);
        else if (this._cache.size >= this._maxSize) {
            // Remove the first (oldest) item
            this._cache.delete(this._cache.keys().next().value);
        }
        this._cache.set(key, { value, ts: Date.now() });
    }

    delete(key) { return this._cache.delete(key); }
    clear() { this._cache.clear(); }
    has(key) { return this.get(key) !== null; }
    get size() { return this._cache.size; }
}

// ========================
// LFU Cache Implementation
// ========================

class LFUCache {
    constructor(maxSize = 100, ttl = null) {
        this._maxSize = maxSize;
        this._ttl = ttl;
        this._cache = new Map();          // key → value
        this._frequencies = new Map();    // key → frequency
        this._timestamps = new Map();     // key → insertion timestamp
        this._buckets = new Map();        // frequency → Set<key>
        this._minFreq = 0;
    }

    get(key) {
        if (!this._cache.has(key)) {
            return null;
        }

        if (this._ttl) {
            const timestamp = this._timestamps.get(key);
            if (Date.now() - timestamp > this._ttl) {
                this.delete(key);
                return null;
            }
        }

        // Promote: remove from old bucket, add to new bucket
        const oldFreq = this._frequencies.get(key) || 1;
        const newFreq = oldFreq + 1;
        this._frequencies.set(key, newFreq);

        const oldBucket = this._buckets.get(oldFreq);
        if (oldBucket) {
            oldBucket.delete(key);
            if (oldBucket.size === 0) {
                this._buckets.delete(oldFreq);
                if (this._minFreq === oldFreq) this._minFreq = newFreq;
            }
        }

        if (!this._buckets.has(newFreq)) this._buckets.set(newFreq, new Set());
        this._buckets.get(newFreq).add(key);

        return this._cache.get(key);
    }

    set(key, value) {
        if (this._maxSize <= 0) return;

        if (this._cache.has(key)) {
            this._cache.set(key, value);
            this.get(key); // triggers frequency promotion
            return;
        }

        if (this._cache.size >= this._maxSize) {
            // O(1) eviction: grab any key from the lowest-frequency bucket
            const minBucket = this._buckets.get(this._minFreq);
            if (minBucket && minBucket.size > 0) {
                const evictKey = minBucket.values().next().value;
                this.delete(evictKey);
            }
        }

        this._cache.set(key, value);
        this._frequencies.set(key, 1);
        this._timestamps.set(key, Date.now());

        if (!this._buckets.has(1)) this._buckets.set(1, new Set());
        this._buckets.get(1).add(key);
        this._minFreq = 1;
    }

    delete(key) {
        if (!this._cache.has(key)) return false;

        const freq = this._frequencies.get(key) || 1;
        const bucket = this._buckets.get(freq);
        if (bucket) {
            bucket.delete(key);
            if (bucket.size === 0) this._buckets.delete(freq);
        }

        this._frequencies.delete(key);
        this._timestamps.delete(key);
        return this._cache.delete(key);
    }

    clear() {
        this._cache.clear();
        this._frequencies.clear();
        this._timestamps.clear();
        this._buckets.clear();
        this._minFreq = 0;
    }

    has(key) {
        return this.get(key) !== null;
    }

    get size() {
        return this._cache.size;
    }
}

// ========================
// TTL Cache Implementation
// ========================

class TTLCache {
    constructor(ttl = 60000) {
        this._ttl = ttl;
        this._cache = new Map();       // key → { value, ts }
        this._sweepTimer = null;

        // Use requestIdleCallback for background sweeps (non-blocking)
        this._scheduleSweep();
    }

    get(key) {
        const entry = this._cache.get(key);
        if (!entry) return null;

        // Lazy eviction: check TTL on read
        if (Date.now() - entry.ts > this._ttl) {
            this._cache.delete(key);
            return null;
        }
        return entry.value;
    }

    set(key, value) {
        this._cache.set(key, { value, ts: Date.now() });
    }

    delete(key) {
        return this._cache.delete(key);
    }

    clear() {
        this._cache.clear();
    }

    has(key) {
        return this.get(key) !== null;
    }

    get size() {
        return this._cache.size;
    }

    /** Chunked sweep via requestIdleCallback: process entries until idle deadline expires */
    _scheduleSweep() {
        if (typeof globalThis === 'undefined') return;

        const sweepChunk = (deadline) => {
            if (this._cache.size === 0) {
                this._sweepTimer = requestIdleCallback(sweepChunk, { timeout: this._ttl });
                return;
            }

            const now = Date.now();
            const iter = this._cache.entries();
            let item = iter.next();

            while (!item.done && deadline.timeRemaining() > 0) {
                const [key, entry] = item.value;
                if (now - entry.ts > this._ttl) {
                    this._cache.delete(key);
                }
                item = iter.next();
            }

            this._sweepTimer = requestIdleCallback(sweepChunk, { timeout: this._ttl });
        };

        this._sweepTimer = requestIdleCallback(sweepChunk, { timeout: this._ttl });
    }

    destroy() {
        if (this._sweepTimer) {
            if (typeof cancelIdleCallback !== 'undefined') {
                cancelIdleCallback(this._sweepTimer);
            } else {
                clearTimeout(this._sweepTimer);
            }
            this._sweepTimer = null;
        }
        this._cache.clear();
    }
}

// ========================
// Cache Strategy System
// ========================

class CacheStrategy {
    constructor(config = {}) {
        this._config = config;
        this._cache = this._createCache();
    }

    get cache() {
        if (!this._cache) {
            this._cache = this._createCache();
        }
        return this._cache;
    }

    _createCache() {
        const type = this._config.type || 'lru';
        const max = this._config.maxSize || 100;
        const ttl = this._config.ttl;

        if (type === 'none' || this._config.enabled === false) return null;
        if (type === 'ttl') return new TTLCache(ttl);
        if (type === 'lfu') return new LFUCache(max, ttl);
        return new LRUCache(max, ttl);
    }

    get(key) {
        if (!this.cache) return null;
        return this.cache.get(key);
    }

    set(key, value) {
        if (!this.cache) return;
        this.cache.set(key, value);
    }

    delete(key) {
        if (!this.cache) return;
        this.cache.delete(key);
    }

    clear() {
        if (!this.cache) return;
        this.cache.clear();
    }

    updateStrategy(newConfig) {
        this._config = {...this._config, ...newConfig};
        this._cache = null;
    }

    destroy() {
        if (this._cache && this._cache.destroy) {
            this._cache.destroy();
        } else if (this._cache && this._cache.clear) {
            this._cache.clear();
        }
        this._cache = null;
    }
}

// ========================
// Compression Utility (Fixed)
// ========================

class BrowserCompressionUtility {
    // Magic header to distinguish compressed data.
    // 0x01 = Compressed (Deflate), 0x00 = Raw

    async compress(input) {
        if (!(input instanceof Uint8Array)) {
            throw new TypeError('Input must be Uint8Array');
        }
        try {
            const stream = new Response(input).body.pipeThrough(new CompressionStream('deflate'));
            const compressed = await new Response(stream).arrayBuffer();
            const result = new Uint8Array(compressed.byteLength + 1);
            result[0] = 0x01; // Compressed marker
            result.set(new Uint8Array(compressed), 1);
            return result;
        } catch (error) {
            // Fallback to raw if compression not supported
            const result = new Uint8Array(input.byteLength + 1);
            result[0] = 0x00; // Raw marker
            result.set(input, 1);
            return result;
        }
    }

    async decompress(input) {
        if (!(input instanceof Uint8Array)) {
            throw new TypeError('Input must be Uint8Array');
        }
        if (input.length === 0) return input;

        const marker = input[0];
        const data = input.slice(1);

        if (marker === 0x00) {
            return data; // Raw data
        } else if (marker === 0x01) {
            try {
                const stream = new Response(data).body.pipeThrough(new DecompressionStream('deflate'));
                const buf = await new Response(stream).arrayBuffer();
                return new Uint8Array(buf);
            } catch (e) {
                console.error('Decompression failed', e);
                // Return original on failure as a failsafe
                return input;
            }
        } else {
            // Legacy support (no marker)
            return input;
        }
    }

    compressSync(input) {
        if (!(input instanceof Uint8Array)) {
            throw new TypeError('Input must be Uint8Array');
        }
        return input;
    }

    decompressSync(input) {
        if (!(input instanceof Uint8Array)) {
            throw new TypeError('Input must be Uint8Array');
        }
        return input;
    }
}

// Shared singleton — BrowserCompressionUtility is stateless
const _sharedCompression = new BrowserCompressionUtility();

// ========================
// Browser Encryption Utility
// ========================

class BrowserEncryptionUtility {
    async encrypt(data, password) {
        const encoder = new TextEncoder();
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const passwordBuffer = encoder.encode(password);
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 600000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );

        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            data
        );

        const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
        result.set(salt, 0);
        result.set(iv, salt.length);
        result.set(new Uint8Array(encrypted), salt.length + iv.length);

        return result;
    }

    async decrypt(encryptedData, password) {
        const encoder = new TextEncoder();
        const salt = encryptedData.slice(0, 16);
        const iv = encryptedData.slice(16, 28);
        const data = encryptedData.slice(28);

        const passwordBuffer = encoder.encode(password);
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 600000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            data
        );

        return new Uint8Array(decrypted);
    }
}

// ========================
// Secure Database Encryption (Master Key Wrapping)
// ========================

class SecureDatabaseEncryption {
    constructor(config = {}, serializer, base64) {
        this._iterations = config.iterations || 600000; // Increased to OWASP recommendation
        this._hashAlgorithm = config.hashAlgorithm || 'SHA-256';
        this._keyLength = config.keyLength || 256;
        this._saltLength = config.saltLength || 32;
        this._initialized = false;
        this._serializer = serializer;
        this._base64 = base64;

        this._masterKey = null; // The actual key used for data encryption
        this._hmacKey = null;   // Key for HMAC operations
        this._salt = null;      // Salt for KEK derivation
        this._wrappedKeyBlob = null; // Encrypted master key
    }

    get initialized() { return this._initialized; }

    async initialize(pin, existingMetadata = null) {
        if (this._initialized) {
            throw new Error('Database encryption already initialized');
        }

        const enc = new TextEncoder();
        const pinBytes = enc.encode(pin);

        if (existingMetadata) {
            // Load existing
            this._salt = this._base64.decode(existingMetadata.salt);
            const kek = await this._deriveKEK(pinBytes, this._salt);

            // Unwrap Master Key
            const wrappedBytes = this._base64.decode(existingMetadata.wrappedKey);
            const iv = wrappedBytes.slice(0, 12);
            const encryptedMK = wrappedBytes.slice(12);

            try {
                const rawKeysBuffer = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv }, kek, encryptedMK
                );
                await this._importMasterKeys(rawKeysBuffer);
            } catch (e) {
                throw new Error('Invalid PIN or corrupted key data');
            }
        } else {
            // New Database
            this._salt = crypto.getRandomValues(new Uint8Array(this._saltLength));
            const kek = await this._deriveKEK(pinBytes, this._salt);

            // Generate Master Keys (64 bytes: 32 enc + 32 hmac)
            const rawKeys = crypto.getRandomValues(new Uint8Array(64));
            await this._importMasterKeys(rawKeys.buffer);

            // Wrap Master Key
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encryptedMK = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv }, kek, rawKeys
            );

            const wrappedKey = new Uint8Array(12 + encryptedMK.byteLength);
            wrappedKey.set(iv, 0);
            wrappedKey.set(new Uint8Array(encryptedMK), 12);

            this._wrappedKeyBlob = this._base64.encode(wrappedKey);
        }

        this._initialized = true;
        return this.exportMetadata();
    }

    async _deriveKEK(pinBytes, salt) {
        const keyMaterial = await crypto.subtle.importKey(
            'raw', pinBytes, 'PBKDF2', false, ['deriveBits', 'deriveKey']
        );
        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: this._iterations,
                hash: this._hashAlgorithm
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async _importMasterKeys(rawBuffer) {
        const rawBytes = new Uint8Array(rawBuffer);
        const encBytes = rawBytes.slice(0, 32);
        const hmacBytes = rawBytes.slice(32, 64);

        this._masterKey = await crypto.subtle.importKey(
            'raw', encBytes, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
        );
        this._hmacKey = await crypto.subtle.importKey(
            'raw', hmacBytes, { name: 'HMAC', hash: 'SHA-256' }, true, ['sign', 'verify']
        );
    }

    async _exportMasterKeys() {
        const encBytes = await crypto.subtle.exportKey('raw', this._masterKey);
        const hmacBytes = await crypto.subtle.exportKey('raw', this._hmacKey);
        const raw = new Uint8Array(64);
        raw.set(new Uint8Array(encBytes), 0);
        raw.set(new Uint8Array(hmacBytes), 32);
        return raw;
    }

    async changePin(oldPin, newPin) {
        if (!this._initialized) {
            throw new Error('Database encryption not initialized');
        }

        // Verify old PIN by attempting to unwrap current master key
        const oldKek = await this._deriveKEK(new TextEncoder().encode(oldPin), this._salt);
        const currentWrappedBytes = this._base64.decode(this._wrappedKeyBlob);
        const currentIv = currentWrappedBytes.slice(0, 12);
        const currentEncMK = currentWrappedBytes.slice(12);
        try {
            await crypto.subtle.decrypt({ name: 'AES-GCM', iv: currentIv }, oldKek, currentEncMK);
        } catch (e) {
            throw new Error('Invalid old PIN');
        }

        // Derive new KEK
        const newSalt = crypto.getRandomValues(new Uint8Array(this._saltLength));
        const newKek = await this._deriveKEK(new TextEncoder().encode(newPin), newSalt);

        // Export current Master Keys (Cleartext in RAM only briefly)
        const rawKeys = await this._exportMasterKeys();

        // Encrypt Master Keys with NEW KEK
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedMK = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv }, newKek, rawKeys
        );

        const wrappedKey = new Uint8Array(12 + encryptedMK.byteLength);
        wrappedKey.set(iv, 0);
        wrappedKey.set(new Uint8Array(encryptedMK), 12);

        // Update State
        this._salt = newSalt;
        this._wrappedKeyBlob = this._base64.encode(wrappedKey);

        return this.exportMetadata();
    }

    async encrypt(data) {
        if (!this._initialized) {
            throw new Error('Database encryption not initialized');
        }

        let dataBytes;
        if (typeof data === 'string') {
            dataBytes = new TextEncoder().encode(data);
        } else if (data instanceof Uint8Array) {
            dataBytes = data;
        } else {
            dataBytes = this._serializer.serialize(data);
        }

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedData = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            this._masterKey,
            dataBytes
        );

        const hmacData = new Uint8Array(iv.length + encryptedData.byteLength);
        hmacData.set(iv, 0);
        hmacData.set(new Uint8Array(encryptedData), iv.length);

        const hmac = await crypto.subtle.sign(
            'HMAC',
            this._hmacKey,
            hmacData
        );

        const result = new Uint8Array(
            iv.length + encryptedData.byteLength + 32
        );
        result.set(iv, 0);
        result.set(new Uint8Array(encryptedData), iv.length);
        result.set(new Uint8Array(hmac), iv.length + encryptedData.byteLength);

        return result;
    }

    async decrypt(encryptedPackage) {
        if (!this._initialized) {
            throw new Error('Database encryption not initialized');
        }

        if (!(encryptedPackage instanceof Uint8Array)) {
            throw new TypeError('Encrypted data must be Uint8Array');
        }

        const iv = encryptedPackage.slice(0, 12);
        const hmac = encryptedPackage.slice(-32);
        const encryptedData = encryptedPackage.slice(12, -32);

        const hmacData = new Uint8Array(iv.length + encryptedData.length);
        hmacData.set(iv, 0);
        hmacData.set(encryptedData, iv.length);

        const isValid = await crypto.subtle.verify(
            'HMAC',
            this._hmacKey,
            hmac,
            hmacData
        );

        if (!isValid) {
            throw new Error('HMAC verification failed - data may be tampered');
        }

        const decryptedData = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            this._masterKey,
            encryptedData
        );

        return new Uint8Array(decryptedData);
    }

    async encryptPrivateKey(privateKey, additionalAuth = '') {
        if (!this._initialized) {
            throw new Error('Database encryption not initialized');
        }

        const encoder = new TextEncoder();
        const authData = encoder.encode(additionalAuth);

        let keyData;
        if (typeof privateKey === 'string') {
            keyData = encoder.encode(privateKey);
        } else if (privateKey instanceof Uint8Array) {
            keyData = privateKey;
        } else {
            keyData = this._serializer.serialize(privateKey);
        }

        const iv = crypto.getRandomValues(new Uint8Array(12));

        const encryptedKey = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv,
                additionalData: authData,
                tagLength: 128
            },
            this._masterKey,
            keyData
        );

        const authLength = new Uint32Array([authData.length]);
        const result = new Uint8Array(
            12 + 4 + authData.length + encryptedKey.byteLength
        );

        result.set(iv, 0);
        result.set(new Uint8Array(authLength.buffer), 12);
        result.set(authData, 16);
        result.set(new Uint8Array(encryptedKey), 16 + authData.length);

        return this._base64.encode(result);
    }

    async decryptPrivateKey(encryptedKeyString, additionalAuth = '') {
        if (!this._initialized) {
            throw new Error('Database encryption not initialized');
        }

        const encryptedPackage = this._base64.decode(encryptedKeyString);

        const iv = encryptedPackage.slice(0, 12);
        const authLengthBytes = encryptedPackage.slice(12, 16);
        const authLength = new Uint32Array(authLengthBytes.buffer)[0];
        const authData = encryptedPackage.slice(16, 16 + authLength);
        const encryptedKey = encryptedPackage.slice(16 + authLength);

        const encoder = new TextEncoder();
        const expectedAuth = encoder.encode(additionalAuth);

        if (!this._arrayEquals(authData, expectedAuth)) {
            throw new Error('Additional authentication data mismatch');
        }

        const decryptedKey = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv,
                additionalData: authData,
                tagLength: 128
            },
            this._masterKey,
            encryptedKey
        );

        return new TextDecoder().decode(decryptedKey);
    }

    static generateSecurePIN(length = 6) {
        const digits = [];
        const buf = new Uint8Array(1);
        while (digits.length < length) {
            crypto.getRandomValues(buf);
            // Rejection sampling: only accept values 0-249 to avoid modulo bias
            if (buf[0] < 250) {
                digits.push((buf[0] % 10).toString());
            }
        }
        return digits.join('');
    }

    destroy() {
        this._masterKey = null;
        this._hmacKey = null;
        this._initialized = false;
    }

    _arrayEquals(a, b) {
        if (a.length !== b.length) return false;
        // Constant-time comparison to prevent timing attacks
        let diff = 0;
        for (let i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff === 0;
    }

    exportMetadata() {
        return {
            salt: this._base64.encode(this._salt),
            wrappedKey: this._wrappedKeyBlob,
            iterations: this._iterations,
            algorithm: 'AES-GCM-256',
            kdf: 'PBKDF2',
            hashAlgorithm: this._hashAlgorithm,
            keyLength: this._keyLength,
            saltLength: this._saltLength
        };
    }

    importMetadata(metadata) { /* Managed via initialize */ }
}

// ========================
// QuadTree (O(log N) Geo Index)
// ========================

class QuadTree {
    constructor(boundary, capacity = 4) {
        this.boundary = boundary; // {x, y, w, h}
        this.capacity = capacity;
        this.points = [];
        this.divided = false;
    }

    insert(point) { // {x, y, data}
        if (!this._contains(this.boundary, point)) return false;

        if (this.points.length < this.capacity) {
            this.points.push(point);
            return true;
        }

        if (!this.divided) this._subdivide();

        return (this.northeast.insert(point) || this.northwest.insert(point) ||
            this.southeast.insert(point) || this.southwest.insert(point));
    }

    query(range, found = []) { // range: {x, y, w, h}
        if (!this._intersects(this.boundary, range)) return found;

        for (let p of this.points) {
            if (this._contains(range, p)) found.push(p);
        }

        if (this.divided) {
            this.northwest.query(range, found);
            this.northeast.query(range, found);
            this.southwest.query(range, found);
            this.southeast.query(range, found);
        }
        return found;
    }

    remove(id) {
        this.points = this.points.filter(p => p.data !== id);
        if (this.divided) {
            this.northwest.remove(id);
            this.northeast.remove(id);
            this.southwest.remove(id);
            this.southeast.remove(id);
        }
    }

    _subdivide() {
        const {x, y, w, h} = this.boundary;
        const mw = w/2;
        const mh = h/2;
        this.northeast = new QuadTree({x: x + mw, y: y - mh, w: mw, h: mh}, this.capacity);
        this.northwest = new QuadTree({x: x - mw, y: y - mh, w: mw, h: mh}, this.capacity);
        this.southeast = new QuadTree({x: x + mw, y: y + mh, w: mw, h: mh}, this.capacity);
        this.southwest = new QuadTree({x: x - mw, y: y + mh, w: mw, h: mh}, this.capacity);
        this.divided = true;
    }

    _contains(b, p) {
        return (p.x >= b.x - b.w && p.x <= b.x + b.w &&
            p.y >= b.y - b.h && p.y <= b.y + b.h);
    }

    _intersects(a, b) {
        return !(b.x - b.w > a.x + a.w || b.x + b.w < a.x - a.w ||
            b.y - b.h > a.y + a.h || b.y + b.h < a.y - a.h);
    }
}

// ========================
// B-Tree Index Implementation (Hardened)
// ========================

/**
 * Safe total-order comparison for B-Tree keys.
 * JavaScript's >, <, === do NOT provide a total order when
 * types are mixed or special values (undefined, null, NaN) appear.
 * This function guarantees a consistent -1/0/+1 for ANY input.
 *
 * Ordering: numbers < strings (within same type, natural order)
 * @param {*} a
 * @param {*} b
 * @returns {number} -1 if a<b, 0 if a===b, 1 if a>b
 */
function _btreeCmp(a, b) {
    // Identical references (covers same-value primitives and same object)
    if (a === b) return 0;

    const ta = typeof a;
    const tb = typeof b;

    // Same type — fast path (99% of real usage)
    if (ta === tb) {
        if (ta === 'number') return a < b ? -1 : 1;
        if (ta === 'string') return a < b ? -1 : (a > b ? 1 : 0);
        // Fallback: coerce to string for other types
        const sa = String(a), sb = String(b);
        return sa < sb ? -1 : (sa > sb ? 1 : 0);
    }

    // Different types — sort by type name for a stable total order
    return ta < tb ? -1 : 1;
}

class BTreeNode {
    constructor(order, leaf) {
        this.keys = new Array(2 * order - 1);
        this.values = new Array(2 * order - 1);
        this.children = new Array(2 * order);
        this.n = 0;
        this.leaf = leaf;
        this.order = order;
    }

    search(key) {
        let i = 0;
        while (i < this.n && _btreeCmp(key, this.keys[i]) > 0) {
            i++;
        }

        if (i < this.n && _btreeCmp(key, this.keys[i]) === 0) {
            return this.values[i];
        }

        if (this.leaf) {
            return null;
        }

        return this.children[i] ? this.children[i].search(key) : null;
    }

    rangeSearch(min, max, results, excludeMin = false, excludeMax = false) {
        let i = 0;
        if (min !== null) {
            while (i < this.n && _btreeCmp(this.keys[i], min) < 0) {
                i++;
            }
        }

        for (; i < this.n; i++) {
            if (max !== null) {
                const cmpMax = _btreeCmp(this.keys[i], max);
                const pastMax = excludeMax ? cmpMax >= 0 : cmpMax > 0;
                if (pastMax) {
                    if (!this.leaf && this.children[i]) {
                        this.children[i].rangeSearch(min, max, results, excludeMin, excludeMax);
                    }
                    return;
                }
            }

            if (!this.leaf && this.children[i]) {
                this.children[i].rangeSearch(min, max, results, excludeMin, excludeMax);
            }

            const cmpMin = min === null ? 1 : _btreeCmp(this.keys[i], min);
            const cmpMaxCheck = max === null ? -1 : _btreeCmp(this.keys[i], max);
            const meetsMin = min === null || (excludeMin ? cmpMin > 0 : cmpMin >= 0);
            const meetsMax = max === null || (excludeMax ? cmpMaxCheck < 0 : cmpMaxCheck <= 0);

            if (meetsMin && meetsMax && this.values[i]) {
                this.values[i].forEach(v => results.push(v));
            }
        }

        if (!this.leaf && this.children[i]) {
            this.children[i].rangeSearch(min, max, results, excludeMin, excludeMax);
        }
    }

    insertNonFull(key, value) {
        let i = this.n - 1;

        if (this.leaf) {
            while (i >= 0 && _btreeCmp(this.keys[i], key) > 0) {
                this.keys[i + 1] = this.keys[i];
                this.values[i + 1] = this.values[i];
                i--;
            }

            if (i >= 0 && _btreeCmp(this.keys[i], key) === 0) {
                if (!this.values[i]) {
                    this.values[i] = new Set();
                }
                this.values[i].add(value);
            } else {
                this.keys[i + 1] = key;
                this.values[i + 1] = new Set([value]);
                this.n++;
            }
        } else {
            while (i >= 0 && _btreeCmp(this.keys[i], key) > 0) {
                i--;
            }

            if (i >= 0 && _btreeCmp(this.keys[i], key) === 0) {
                if (!this.values[i]) {
                    this.values[i] = new Set();
                }
                this.values[i].add(value);
                return;
            }

            i++;
            if (this.children[i] && this.children[i].n === 2 * this.order - 1) {
                this.splitChild(i, this.children[i]);

                const cmp = _btreeCmp(this.keys[i], key);
                if (cmp === 0) {
                    if (!this.values[i]) this.values[i] = new Set();
                    this.values[i].add(value);
                    return;
                }
                if (cmp < 0) {
                    i++;
                }
            }
            if (this.children[i]) {
                this.children[i].insertNonFull(key, value);
            }
        }
    }

    splitChild(i, y) {
        const z = new BTreeNode(this.order, y.leaf);
        z.n = this.order - 1;

        for (let j = 0; j < this.order - 1; j++) {
            z.keys[j] = y.keys[j + this.order];
            z.values[j] = y.values[j + this.order];
        }

        if (!y.leaf) {
            for (let j = 0; j < this.order; j++) {
                z.children[j] = y.children[j + this.order];
            }
        }

        // CRITICAL: Save the median BEFORE cleaning stale slots.
        // The clean loop covers index (order-1) which IS the median position.
        const medianKey = y.keys[this.order - 1];
        const medianValue = y.values[this.order - 1];

        y.n = this.order - 1;

        // Clean all stale slots in y (median + right half)
        for (let j = this.order - 1; j < 2 * this.order - 1; j++) {
            y.keys[j] = undefined;
            y.values[j] = undefined;
        }
        if (!y.leaf) {
            for (let j = this.order; j < 2 * this.order; j++) {
                y.children[j] = undefined;
            }
        }

        // Shift parent's children right to make room
        for (let j = this.n; j >= i + 1; j--) {
            this.children[j + 1] = this.children[j];
        }
        this.children[i + 1] = z;

        // Shift parent's keys/values right to make room
        for (let j = this.n - 1; j >= i; j--) {
            this.keys[j + 1] = this.keys[j];
            this.values[j + 1] = this.values[j];
        }

        // Promote the saved median
        this.keys[i] = medianKey;
        this.values[i] = medianValue;
        this.n++;
    }

    // ---- Deletion helpers ----

    _getPredecessor(idx) {
        let node = this.children[idx];
        while (!node.leaf) {
            node = node.children[node.n];
        }
        return { key: node.keys[node.n - 1], value: node.values[node.n - 1] };
    }

    _getSuccessor(idx) {
        let node = this.children[idx + 1];
        while (!node.leaf) {
            node = node.children[0];
        }
        return { key: node.keys[0], value: node.values[0] };
    }

    _merge(idx) {
        const child = this.children[idx];
        const sibling = this.children[idx + 1];
        const t = this.order;

        child.keys[t - 1] = this.keys[idx];
        child.values[t - 1] = this.values[idx];

        for (let j = 0; j < sibling.n; j++) {
            child.keys[t + j] = sibling.keys[j];
            child.values[t + j] = sibling.values[j];
        }

        if (!child.leaf) {
            for (let j = 0; j <= sibling.n; j++) {
                child.children[t + j] = sibling.children[j];
            }
        }

        child.n += sibling.n + 1;

        for (let j = idx; j < this.n - 1; j++) {
            this.keys[j] = this.keys[j + 1];
            this.values[j] = this.values[j + 1];
        }

        for (let j = idx + 1; j < this.n; j++) {
            this.children[j] = this.children[j + 1];
        }

        this.keys[this.n - 1] = undefined;
        this.values[this.n - 1] = undefined;
        this.children[this.n] = undefined;

        this.n--;
    }

    _borrowFromPrev(idx) {
        const child = this.children[idx];
        const sibling = this.children[idx - 1];

        for (let j = child.n - 1; j >= 0; j--) {
            child.keys[j + 1] = child.keys[j];
            child.values[j + 1] = child.values[j];
        }
        if (!child.leaf) {
            for (let j = child.n; j >= 0; j--) {
                child.children[j + 1] = child.children[j];
            }
        }

        child.keys[0] = this.keys[idx - 1];
        child.values[0] = this.values[idx - 1];

        if (!child.leaf) {
            child.children[0] = sibling.children[sibling.n];
            sibling.children[sibling.n] = undefined;
        }

        this.keys[idx - 1] = sibling.keys[sibling.n - 1];
        this.values[idx - 1] = sibling.values[sibling.n - 1];

        sibling.keys[sibling.n - 1] = undefined;
        sibling.values[sibling.n - 1] = undefined;

        child.n++;
        sibling.n--;
    }

    _borrowFromNext(idx) {
        const child = this.children[idx];
        const sibling = this.children[idx + 1];

        child.keys[child.n] = this.keys[idx];
        child.values[child.n] = this.values[idx];

        if (!child.leaf) {
            child.children[child.n + 1] = sibling.children[0];
        }

        this.keys[idx] = sibling.keys[0];
        this.values[idx] = sibling.values[0];

        for (let j = 0; j < sibling.n - 1; j++) {
            sibling.keys[j] = sibling.keys[j + 1];
            sibling.values[j] = sibling.values[j + 1];
        }
        if (!sibling.leaf) {
            for (let j = 0; j < sibling.n; j++) {
                sibling.children[j] = sibling.children[j + 1];
            }
            sibling.children[sibling.n] = undefined;
        }

        sibling.keys[sibling.n - 1] = undefined;
        sibling.values[sibling.n - 1] = undefined;

        child.n++;
        sibling.n--;
    }

    _fill(idx) {
        const t = this.order;
        if (idx > 0 && this.children[idx - 1] && this.children[idx - 1].n >= t) {
            this._borrowFromPrev(idx);
        } else if (idx < this.n && this.children[idx + 1] && this.children[idx + 1].n >= t) {
            this._borrowFromNext(idx);
        } else {
            if (idx < this.n) {
                this._merge(idx);
            } else {
                this._merge(idx - 1);
            }
        }
    }

    _removeFromLeaf(idx) {
        for (let j = idx; j < this.n - 1; j++) {
            this.keys[j] = this.keys[j + 1];
            this.values[j] = this.values[j + 1];
        }
        this.keys[this.n - 1] = undefined;
        this.values[this.n - 1] = undefined;
        this.n--;
    }

    _removeFromInternal(idx) {
        const t = this.order;
        const key = this.keys[idx];

        if (this.children[idx] && this.children[idx].n >= t) {
            const pred = this._getPredecessor(idx);
            this.keys[idx] = pred.key;
            this.values[idx] = pred.value;
            this.children[idx]._remove(pred.key, null, true);
        } else if (this.children[idx + 1] && this.children[idx + 1].n >= t) {
            const succ = this._getSuccessor(idx);
            this.keys[idx] = succ.key;
            this.values[idx] = succ.value;
            this.children[idx + 1]._remove(succ.key, null, true);
        } else {
            this._merge(idx);
            this.children[idx]._remove(key, null, true);
        }
    }

    _remove(key, value, removeEntire) {
        let i = 0;
        while (i < this.n && _btreeCmp(key, this.keys[i]) > 0) {
            i++;
        }

        if (i < this.n && _btreeCmp(key, this.keys[i]) === 0) {
            let shouldRemoveEntry = removeEntire;

            if (!shouldRemoveEntry && this.values[i]) {
                this.values[i].delete(value);
                shouldRemoveEntry = this.values[i].size === 0;
            }

            if (shouldRemoveEntry) {
                if (this.leaf) {
                    this._removeFromLeaf(i);
                } else {
                    this._removeFromInternal(i);
                }
                return true;
            }
            return false;
        } else {
            if (this.leaf) return false;

            const isLastChild = (i === this.n);

            if (this.children[i] && this.children[i].n < this.order) {
                this._fill(i);
            }

            if (isLastChild && i > this.n) {
                return this.children[i - 1]
                    ? this.children[i - 1]._remove(key, value, removeEntire)
                    : false;
            } else {
                return this.children[i]
                    ? this.children[i]._remove(key, value, removeEntire)
                    : false;
            }
        }
    }

    remove(key, value) {
        return this._remove(key, value, false);
    }

    removeKey(key) {
        return this._remove(key, null, true);
    }

    verify() {
        const issues = [];
        for (let i = 0; i < this.n; i++) {
            if (this.keys[i] === undefined || this.keys[i] === null) {
                issues.push(`Invalid key (${this.keys[i]}) at index ${i}`);
            }
        }
        for (let i = 1; i < this.n; i++) {
            if (_btreeCmp(this.keys[i], this.keys[i - 1]) <= 0) {
                issues.push(`Key order violation at index ${i}`);
            }
        }
        if (!this.leaf) {
            for (let i = 0; i <= this.n; i++) {
                if (this.children[i]) {
                    const childIssues = this.children[i].verify();
                    issues.push(...childIssues);
                }
            }
        }
        return issues;
    }
}

class BTreeIndex {
    constructor(order = 4) {
        this._root = null;
        this._order = order;
        this._size = 0;
    }

    insert(key, value) {
        // Reject keys that break comparison semantics
        if (key === undefined || key === null || (typeof key === 'number' && isNaN(key))) return;

        // Check for exact duplicate (key, value) to keep _size accurate
        if (this._root) {
            const existing = this._root.search(key);
            if (existing && existing.has(value)) {
                return; // Already present, no-op
            }
        }

        if (!this._root) {
            this._root = new BTreeNode(this._order, true);
            this._root.keys[0] = key;
            this._root.values[0] = new Set([value]);
            this._root.n = 1;
        } else {
            if (this._root.n === 2 * this._order - 1) {
                const s = new BTreeNode(this._order, false);
                s.children[0] = this._root;
                s.splitChild(0, this._root);

                let i = 0;
                const cmp = _btreeCmp(s.keys[0], key);
                if (cmp === 0) {
                    if (!s.values[0]) s.values[0] = new Set();
                    s.values[0].add(value);
                } else {
                    if (cmp < 0) i++;
                    s.children[i].insertNonFull(key, value);
                }

                this._root = s;
            } else {
                this._root.insertNonFull(key, value);
            }
        }
        this._size++;
    }

    find(key) {
        if (!this._root) return [];
        const values = this._root.search(key);
        return values ? Array.from(values) : [];
    }

    contains(key) {
        if (!this._root) return false;
        return this._root.search(key) !== null;
    }

    range(min, max, excludeMin = false, excludeMax = false) {
        if (!this._root) return [];
        const results = [];
        this._root.rangeSearch(min, max, results, excludeMin, excludeMax);
        return results;
    }

    rangeFrom(min, excludeMin = false) {
        if (!this._root) return [];
        const results = [];
        this._root.rangeSearch(min, null, results, excludeMin, false);
        return results;
    }

    rangeTo(max, excludeMax = false) {
        if (!this._root) return [];
        const results = [];
        this._root.rangeSearch(null, max, results, false, excludeMax);
        return results;
    }

    remove(key, value) {
        if (!this._root) return;
        const existing = this._root.search(key);
        if (existing && existing.has(value)) {
            this._root.remove(key, value);
            if (this._root.n === 0 && !this._root.leaf && this._root.children[0]) {
                this._root = this._root.children[0];
            }
            this._size--;
        }
    }

    verify() {
        if (!this._root) return { healthy: true, issues: [] };
        const issues = this._root.verify();
        if (issues.length > 0) {
            console.warn('BTree index issues detected (rebuild required):', issues);
        }
        return {
            healthy: issues.length === 0,
            issues,
            requiresRebuild: issues.length > 0
        };
    }

    clear() {
        this._root = null;
        this._size = 0;
    }

    get size() {
        return this._size;
    }

    /**
     * Export all entries as a flat sorted array for persistence.
     * Format: [[key, [docId1, docId2, ...]], ...]
     * @returns {Array}
     */
    toSortedEntries() {
        if (!this._root) return [];
        const entries = [];
        this._collectInOrder(this._root, entries);
        return entries;
    }

    /** @private In-order traversal to collect all key-value pairs */
    _collectInOrder(node, entries) {
        for (let i = 0; i < node.n; i++) {
            if (!node.leaf && node.children[i]) {
                this._collectInOrder(node.children[i], entries);
            }
            if (node.values[i] && node.values[i].size > 0) {
                entries.push([node.keys[i], Array.from(node.values[i])]);
            }
        }
        if (!node.leaf && node.children[node.n]) {
            this._collectInOrder(node.children[node.n], entries);
        }
    }

    /**
     * Restore a BTreeIndex from persisted sorted entries.
     * Much faster than full document scan + unpack.
     * @param {Array} entries - [[key, [docId1, ...]], ...]
     * @param {number} [order=4]
     * @returns {BTreeIndex}
     */
    static fromSortedEntries(entries, order = 4) {
        const tree = new BTreeIndex(order);
        for (let i = 0; i < entries.length; i++) {
            const [key, values] = entries[i];
            if (key === undefined || key === null) continue;
            for (let j = 0; j < values.length; j++) {
                tree.insert(key, values[j]);
            }
        }
        return tree;
    }
}

// ========================
// Text Index (Fixed CJK)
// ========================

class TextIndex {
    constructor() {
        this._invertedIndex = new Map();
        this._docTokens = new Map();
        this._segmenter = typeof Intl !== 'undefined' && Intl.Segmenter ?
            new Intl.Segmenter(undefined, { granularity: 'word' }) : null;
    }

    addDocument(text, docId) {
        if (typeof text !== 'string') return;
        const tokens = this._tokenize(text);
        this._docTokens.set(docId, new Set(tokens));

        for (const token of tokens) {
            if (!this._invertedIndex.has(token)) {
                this._invertedIndex.set(token, new Set());
            }
            this._invertedIndex.get(token).add(docId);
        }
    }

    removeDocument(docId) {
        const tokens = this._docTokens.get(docId);
        if (!tokens) return;

        for (const token of tokens) {
            const docs = this._invertedIndex.get(token);
            if (docs) {
                docs.delete(docId);
                if (docs.size === 0) {
                    this._invertedIndex.delete(token);
                }
            }
        }
        this._docTokens.delete(docId);
    }

    updateDocument(docId, newText) {
        this.removeDocument(docId);
        this.addDocument(newText, docId);
    }

    search(query) {
        const tokens = this._tokenize(query);
        if (tokens.length === 0) return [];

        let results = null;
        for (const token of tokens) {
            const docs = this._invertedIndex.get(token);
            if (!docs || docs.size === 0) {
                return [];
            }

            if (results === null) {
                results = new Set(docs);
            } else {
                // Direct Set intersection: always iterate the smaller set
                if (results.size <= docs.size) {
                    const intersection = new Set();
                    for (const id of results) {
                        if (docs.has(id)) intersection.add(id);
                    }
                    results = intersection;
                } else {
                    const intersection = new Set();
                    for (const id of docs) {
                        if (results.has(id)) intersection.add(id);
                    }
                    results = intersection;
                }
                if (results.size === 0) return [];
            }
        }

        return results ? Array.from(results) : [];
    }

    _tokenize(text) {
        if (this._segmenter) {
            const segments = this._segmenter.segment(text.toLowerCase());
            const tokens = [];
            for (const seg of segments) {
                if (seg.isWordLike) tokens.push(seg.segment);
            }
            return tokens.filter(t => t.length > 1);
        } else {
            return text.toLowerCase()
                .replace(/[^\w\s]/g, ' ')
                .split(/\s+/)
                .filter(token => token.length > 1);
        }
    }

    get size() {
        return this._docTokens.size;
    }
}

// ========================
// Geo Index (QuadTree)
// ========================

class GeoIndex {
    constructor() {
        this._tree = new QuadTree({x: 0, y: 0, w: 180, h: 90});
        this._size = 0;
    }

    addPoint(coords, docId) {
        if (!coords || typeof coords.lat !== 'number' || typeof coords.lng !== 'number') {
            return;
        }
        this._tree.insert({x: coords.lng, y: coords.lat, data: docId});
        this._size++;
    }

    removePoint(docId) {
        this._tree.remove(docId);
        if (this._size > 0) this._size--;
    }

    updatePoint(docId, newCoords) {
        this.removePoint(docId);
        this.addPoint(newCoords, docId);
    }

    findNear(center, maxDistance) {
        const rangeDeg = maxDistance / 111;
        const range = {
            x: center.lng, y: center.lat,
            w: rangeDeg, h: rangeDeg
        };

        const candidates = this._tree.query(range);
        const results = [];

        // Pre-filter: squared Euclidean distance in degrees (cheap rejection)
        // 1 degree ≈ 111 km, so maxDistance/111 gives approx degree threshold
        const threshDeg = rangeDeg;
        const threshSq = threshDeg * threshDeg;

        for (const p of candidates) {
            const dx = p.x - center.lng;
            const dy = p.y - center.lat;
            // Fast reject: if squared distance in degrees exceeds threshold, skip Haversine
            if (dx * dx + dy * dy > threshSq) continue;

            const distance = this._haversine(center, {lat: p.y, lng: p.x});
            if (distance <= maxDistance) {
                results.push({ docId: p.data, distance });
            }
        }

        return results.sort((a, b) => a.distance - b.distance)
            .map(r => r.docId);
    }

    findWithin(bounds) {
        // QuadTree query usually takes center/width/height, need conversion if strict bounding box
        // Approximate for now using query
        const w = (bounds.maxLng - bounds.minLng) / 2;
        const h = (bounds.maxLat - bounds.minLat) / 2;
        const x = bounds.minLng + w;
        const y = bounds.minLat + h;

        const candidates = this._tree.query({x, y, w, h});
        return candidates.map(p => p.data);
    }

    _haversine(coord1, coord2) {
        const R = 6371; // Earth's radius in km
        const dLat = this._toRad(coord2.lat - coord1.lat);
        const dLng = this._toRad(coord2.lng - coord1.lng);

        const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
            Math.cos(this._toRad(coord1.lat)) * Math.cos(this._toRad(coord2.lat)) *
            Math.sin(dLng/2) * Math.sin(dLng/2);

        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
        return R * c;
    }

    _toRad(deg) {
        return deg * (Math.PI / 180);
    }

    get size() {
        return this._size;
    }
}

// ========================
// Index Manager (Cursor Optimized)
// ========================

class IndexManager {
    constructor(collection) {
        this._collection = collection;
        this._serializer = collection.database._serializer;
        this._base64 = collection.database._base64;
        this._indexes = new Map();
        this._indexData = new Map();
        this._indexQueue = [];
        this._processing = false;

        // Debounced persistence — coalesce many writes into one IDB save
        this._dirtyIndexes = new Set();
        this._persistTimer = null;
        this._persistDelay = 2000; // ms — save at most every 2s
    }

    get indexes() {
        return this._indexes;
    }

    /** Reserved _id prefix for persisted index entries in the documents store */
    static get IDX_PREFIX() { return '__lacerta_idx_'; }

    async createIndex(fieldPath, options = {}) {
        const indexName = options.name || fieldPath;

        if (this._indexes.has(indexName)) {
            throw new Error(`Index '${indexName}' already exists`);
        }

        const index = {
            fieldPath,
            unique: options.unique || false,
            sparse: options.sparse || false,
            type: options.type || 'btree',
            hashed: options.hashed || false,
            collation: options.collation || null,
            createdAt: Date.now()
        };

        this._indexes.set(indexName, index);

        await this.rebuildIndex(indexName);

        this._saveIndexMetadata();

        return indexName;
    }

    /**
     * Full rebuild: scan all documents from IDB, extract field values, build index.
     * This is the SLOW path — only used on first-ever index creation or when
     * persisted index data is missing/corrupt.
     */
    async rebuildIndex(indexName) {
        const index = this._indexes.get(indexName);
        if (!index) {
            throw new Error(`Index '${indexName}' not found`);
        }

        const indexData = this._createIndexStructure(index.type);
        this._indexData.set(indexName, indexData);

        let lastKey = null;
        const batchSize = 200;

        while (true) {
            const batch = await this._collection._indexedDB.getBatch(
                this._collection._db,
                this._collection._storeName,
                lastKey,
                batchSize
            );

            if (batch.length === 0) break;

            for (const docData of batch) {
                // Skip persisted index entries
                if (typeof docData._id === 'string' && docData._id.startsWith(IndexManager.IDX_PREFIX)) {
                    lastKey = docData._id;
                    continue;
                }
                lastKey = docData._id;
                let doc = docData;

                if (docData.packedData) {
                    const d = new Document(docData, {
                        compressed: docData._compressed,
                        encrypted: docData._encrypted
                    }, this._serializer);
                    await d.unpack(this._collection.database.encryption);
                    doc = d.objectOutput();
                }

                let value = this._getFieldValue(doc, index.fieldPath);

                if (index.sparse && (value === null || value === undefined)) {
                    continue;
                }

                if (index.unique && indexData.has && indexData.has(value)) {
                    continue;
                }

                if (index.hashed && index.type === 'btree') {
                    value = await this._hashVal(value);
                }

                this._addToIndex(indexData, value, doc._id, index.type);
            }
        }

        // Persist immediately after a full rebuild so next load is fast
        await this._persistIndex(indexName);
    }

    /**
     * FAST PATH: Restore a BTree index from persisted entries stored in IDB.
     * Returns true if successful, false if persisted data is missing/corrupt.
     * @param {string} indexName
     * @returns {Promise<boolean>}
     */
    async _restoreIndex(indexName) {
        const index = this._indexes.get(indexName);
        if (!index || index.type !== 'btree') return false;

        try {
            const docId = `${IndexManager.IDX_PREFIX}${indexName}`;
            const stored = await this._collection._indexedDB.get(
                this._collection._db, this._collection._storeName, docId
            );

            if (!stored || !stored._entries || !Array.isArray(stored._entries)) {
                return false;
            }

            // Restore B-Tree from sorted entries — no document scanning needed
            const btree = BTreeIndex.fromSortedEntries(stored._entries, 4);

            // Quick sanity check
            const v = btree.verify();
            if (!v.healthy) {
                console.warn(`[IndexManager] Persisted index '${indexName}' is corrupt, will rebuild`);
                return false;
            }

            this._indexData.set(indexName, btree);
            return true;
        } catch (e) {
            return false;
        }
    }

    /**
     * Persist a single BTree index's entries to IDB.
     * Stored as a document with reserved _id in the existing 'documents' store.
     * @param {string} indexName
     */
    async _persistIndex(indexName) {
        const indexData = this._indexData.get(indexName);
        if (!indexData || !(indexData instanceof BTreeIndex)) return;

        try {
            const docId = `${IndexManager.IDX_PREFIX}${indexName}`;
            const payload = {
                _id: docId,
                _entries: indexData.toSortedEntries(),
                _persisted_at: Date.now(),
                _size: indexData.size
            };

            await this._collection._indexedDB.put(
                this._collection._db, this._collection._storeName, payload
            );
        } catch (e) {
            console.warn(`[IndexManager] Failed to persist index '${indexName}':`, e.message);
        }
    }

    /**
     * Schedule a debounced persist for modified indexes.
     * Coalesces rapid writes into a single IDB save.
     * @param {string} indexName
     */
    _schedulePersist(indexName) {
        this._dirtyIndexes.add(indexName);

        if (this._persistTimer) return;

        this._persistTimer = setTimeout(async () => {
            this._persistTimer = null;
            const dirty = Array.from(this._dirtyIndexes);
            this._dirtyIndexes.clear();

            for (const name of dirty) {
                await this._persistIndex(name);
            }
        }, this._persistDelay);
    }

    /** Flush any pending index persistence immediately (e.g., before page unload) */
    async flushPersistence() {
        if (this._persistTimer) {
            clearTimeout(this._persistTimer);
            this._persistTimer = null;
        }
        const dirty = Array.from(this._dirtyIndexes);
        this._dirtyIndexes.clear();
        for (const name of dirty) {
            await this._persistIndex(name);
        }
    }

    _createIndexStructure(type) {
        switch (type) {
            case 'btree':
                return new BTreeIndex();
            case 'hash':
                return new Map();
            case 'text':
                return new TextIndex();
            case 'geo':
                return new GeoIndex();
            default:
                return new Map();
        }
    }

    _addToIndex(indexData, value, docId, type) {
        switch (type) {
            case 'btree':
                indexData.insert(value, docId);
                break;
            case 'hash':
                if (!indexData.has(value)) {
                    indexData.set(value, new Set());
                }
                indexData.get(value).add(docId);
                break;
            case 'text':
                indexData.addDocument(value, docId);
                break;
            case 'geo':
                indexData.addPoint(value, docId);
                break;
        }
    }

    async _hashVal(val) {
        const msg = new TextEncoder().encode(String(val));
        const hash = await crypto.subtle.digest('SHA-256', msg);
        return this._base64.encode(new Uint8Array(hash));
    }

    async updateIndexForDocument(docId, oldDoc, newDoc) {
        for (const [indexName, index] of this._indexes) {
            const indexData = this._indexData.get(indexName);
            if (!indexData) continue;

            let oldValue = oldDoc ? this._getFieldValue(oldDoc, index.fieldPath) : undefined;
            let newValue = newDoc ? this._getFieldValue(newDoc, index.fieldPath) : undefined;

            if (index.hashed) {
                if (oldValue) oldValue = await this._hashVal(oldValue);
                if (newValue) newValue = await this._hashVal(newValue);
            }

            if (oldValue === newValue) continue;

            switch (index.type) {
                case 'btree':
                    if (oldValue !== undefined) indexData.remove(oldValue, docId);
                    if (newValue !== undefined) indexData.insert(newValue, docId);
                    break;
                case 'hash':
                    if (oldValue !== undefined) {
                        const oldSet = indexData.get(oldValue);
                        if (oldSet) {
                            oldSet.delete(docId);
                            if (oldSet.size === 0) indexData.delete(oldValue);
                        }
                    }
                    if (newValue !== undefined) {
                        if (!indexData.has(newValue)) indexData.set(newValue, new Set());
                        indexData.get(newValue).add(docId);
                    }
                    break;
                case 'text':
                    if (oldValue || newValue) {
                        indexData.updateDocument(docId, newValue || '');
                    }
                    break;
                case 'geo':
                    if (oldValue) indexData.removePoint(docId);
                    if (newValue) indexData.addPoint(newValue, docId);
                    break;
            }

            // Schedule async persistence for modified btree indexes
            if (index.type === 'btree') {
                this._schedulePersist(indexName);
            }
        }
    }

    async query(indexName, queryOptions) {
        const index = this._indexes.get(indexName);
        const indexData = this._indexData.get(indexName);

        if (!index || !indexData) {
            throw new Error(`Index '${indexName}' not found`);
        }

        if (index.hashed && typeof queryOptions !== 'object') {
            queryOptions = await this._hashVal(queryOptions);
        }

        return this._queryIndex(indexData, queryOptions, index.type);
    }

    _queryIndex(indexData, options, type) {
        switch (type) {
            case 'btree':
                return this._queryBTree(indexData, options);
            case 'hash':
                return this._queryHash(indexData, options);
            case 'text':
                return this._queryText(indexData, options);
            case 'geo':
                return this._queryGeo(indexData, options);
            default:
                return [];
        }
    }

    _queryBTree(indexData, options) {
        if (typeof options !== 'object' || options === null) {
            return indexData.find(options);
        }

        const results = new Set();

        if (options.$eq !== undefined) {
            const docs = indexData.find(options.$eq);
            docs.forEach(doc => results.add(doc));
        }

        const hasGte = options.$gte !== undefined;
        const hasGt  = options.$gt  !== undefined;
        const hasLte = options.$lte !== undefined;
        const hasLt  = options.$lt  !== undefined;

        if (hasGte || hasGt || hasLte || hasLt) {
            const min        = hasGte ? options.$gte : (hasGt ? options.$gt : null);
            const max        = hasLte ? options.$lte : (hasLt ? options.$lt : null);
            const excludeMin = !hasGte && hasGt;
            const excludeMax = !hasLte && hasLt;

            const docs = indexData.range(min, max, excludeMin, excludeMax);
            docs.forEach(doc => results.add(doc));
        }

        return Array.from(results);
    }

    _queryHash(indexData, options) {
        if (options.$eq !== undefined) {
            const docs = indexData.get(options.$eq);
            return docs ? Array.from(docs) : [];
        }

        if (options.$in !== undefined) {
            const results = new Set();
            for (const value of options.$in) {
                const docs = indexData.get(value);
                if (docs) {
                    docs.forEach(doc => results.add(doc));
                }
            }
            return Array.from(results);
        }

        return [];
    }

    _queryText(indexData, options) {
        if (options.$search) {
            return indexData.search(options.$search);
        }
        return [];
    }

    _queryGeo(indexData, options) {
        if (options.$near) {
            return indexData.findNear(
                options.$near.coordinates,
                options.$near.maxDistance || 1000
            );
        }
        if (options.$within) {
            return indexData.findWithin(options.$within);
        }
        return [];
    }

    dropIndex(indexName) {
        this._indexes.delete(indexName);
        this._indexData.delete(indexName);
        this._dirtyIndexes.delete(indexName);
        this._saveIndexMetadata();

        // Remove persisted index from IDB (fire-and-forget)
        const docId = `${IndexManager.IDX_PREFIX}${indexName}`;
        this._collection._indexedDB.delete(this._collection._db, this._collection._storeName, docId).catch(() => {});
    }

    _getFieldValue(doc, path) {
        return queryEngine.getFieldValue(doc, path);
    }

    async _saveIndexMetadata() {
        const metaKey = `idxmeta_${this._collection.database.name}_${this._collection.name}`;

        const metadata = {
            indexes: Array.from(this._indexes.entries()).map(([name, index]) => ({
                name,
                ...index
            }))
        };
        const serialized = this._serializer.serialize(metadata);
        const encoded = this._base64.encode(serialized);

        const idb = this._collection._db;
        if (idb && idb.objectStoreNames.contains('__meta')) {
            Database._writeMeta(idb, metaKey, { data: encoded }).catch(e => {
                console.warn('IndexManager metadata IDB save failed:', e);
            });
        } else {
            // Fallback: localStorage
            const key = `lacertadb_${this._collection.database.name}_${this._collection.name}_indexes`;
            localStorage.setItem(key, encoded);
        }
    }

    /**
     * Load index definitions and restore persisted index data.
     * FAST PATH: Restore BTree from persisted entries (no document scanning).
     * SLOW PATH: Full rebuild only if persisted data is missing/corrupt.
     */
    async loadIndexMetadata() {
        const metaKey = `idxmeta_${this._collection.database.name}_${this._collection.name}`;
        let encoded = null;

        // Try IDB first
        const idb = this._collection._db;
        if (idb && idb.objectStoreNames.contains('__meta')) {
            try {
                const stored = await Database._readMeta(idb, metaKey);
                if (stored && stored.data) {
                    encoded = stored.data;
                }
            } catch (e) { /* fallback to localStorage */ }
        }

        // Fallback: localStorage (for migration)
        if (!encoded) {
            const lsKey = `lacertadb_${this._collection.database.name}_${this._collection.name}_indexes`;
            const lsStored = localStorage.getItem(lsKey);
            if (lsStored) {
                encoded = lsStored;
                // Migrate to IDB on next save
                localStorage.removeItem(lsKey);
            }
        }

        if (!encoded) return;

        try {
            const decoded = this._base64.decode(encoded);
            const metadata = this._serializer.deserialize(decoded);

            if (!metadata || !Array.isArray(metadata.indexes)) return;

            for (const indexDef of metadata.indexes) {
                const { name, ...index } = indexDef;
                this._indexes.set(name, index);
            }

            // Try to restore each index from persisted IDB data (fast path).
            // Only fall back to full rebuild for indexes that can't be restored.
            const needsRebuild = [];

            for (const [indexName, index] of this._indexes) {
                if (index.type === 'btree') {
                    const restored = await this._restoreIndex(indexName);
                    if (!restored) {
                        needsRebuild.push(indexName);
                    }
                } else {
                    // Non-btree indexes (text, geo, hash) always need rebuild
                    needsRebuild.push(indexName);
                }
            }

            if (needsRebuild.length > 0) {
                // Rebuild only the indexes that couldn't be restored
                for (const indexName of needsRebuild) {
                    await this.rebuildIndex(indexName);
                }
            }
        } catch (error) {
            console.error('Failed to load index metadata:', error);
        }
    }

    getIndexStats() {
        const stats = {};
        for (const [name, index] of this._indexes) {
            const indexData = this._indexData.get(name);
            stats[name] = {
                ...index,
                size: indexData ? indexData.size || indexData.length || 0 : 0,
                memoryUsage: this._estimateMemoryUsage(indexData)
            };
        }
        return stats;
    }

    _estimateMemoryUsage(indexData) {
        if (!indexData) return 0;
        if (indexData instanceof Map) return indexData.size * 100;
        if (indexData instanceof BTreeIndex) return indexData.size * 120;
        return 0;
    }

    async verifyIndexes() {
        const report = {};
        for (const [name, index] of this._indexes) {
            const indexData = this._indexData.get(name);
            if (!indexData) {
                report[name] = { status: 'missing', rebuilt: true };
                await this.rebuildIndex(name);
            } else if (indexData.verify) {
                const result = indexData.verify();
                if (result.requiresRebuild) {
                    await this.rebuildIndex(name);
                    result.rebuilt = true;
                }
                report[name] = result;
            } else {
                report[name] = { status: 'ok' };
            }
        }
        return report;
    }

    destroy() {
        if (this._persistTimer) {
            clearTimeout(this._persistTimer);
            this._persistTimer = null;
        }
        for (const [name, indexData] of this._indexData) {
            if (indexData && indexData.clear) {
                indexData.clear();
            }
        }
        this._indexData.clear();
        this._indexes.clear();
        this._dirtyIndexes.clear();
        this._indexQueue = [];
        this._processing = false;
    }
}


class OPFSUtility {
    async saveAttachments(dbName, collectionName, documentId, attachments) {
        try {
            const attachmentPaths = [];
            const root = await navigator.storage.getDirectory();
            const dbDir = await root.getDirectoryHandle(dbName, { create: true });
            const collDir = await dbDir.getDirectoryHandle(collectionName, { create: true });
            const docDir = await collDir.getDirectoryHandle(documentId, { create: true });

            for (const [index, attachment] of attachments.entries()) {
                const filename = `${index}_${attachment.name || 'file'}`;
                const fileHandle = await docDir.getFileHandle(filename, { create: true });
                const writable = await fileHandle.createWritable();

                let dataToWrite;
                if (attachment.data instanceof Uint8Array) {
                    dataToWrite = attachment.data;
                } else if (attachment.data instanceof ArrayBuffer) {
                    dataToWrite = new Uint8Array(attachment.data);
                } else if (attachment.data instanceof Blob) {
                    dataToWrite = new Uint8Array(await attachment.data.arrayBuffer());
                } else {
                    throw new TypeError('Unsupported attachment data type');
                }

                const blob = new Blob([dataToWrite], { type: attachment.type || 'application/octet-stream' });
                await writable.write(blob);
                await writable.close();

                const path = `/${dbName}/${collectionName}/${documentId}/${filename}`;
                attachmentPaths.push({
                    path,
                    name: attachment.name,
                    type: attachment.type,
                    size: dataToWrite.byteLength,
                    originalName: attachment.originalName || attachment.name
                });
            }
            return attachmentPaths;
        } catch (error) {
            throw new LacertaDBError('Failed to save attachments', 'ATTACHMENT_SAVE_FAILED', error);
        }
    }

    async getAttachments(attachmentPaths) {
        const attachments = [];
        const root = await navigator.storage.getDirectory();

        for (const attachmentInfo of attachmentPaths) {
            try {
                const pathParts = attachmentInfo.path.split('/').filter(p => p);
                let currentDir = root;

                for (let i = 0; i < pathParts.length - 1; i++) {
                    currentDir = await currentDir.getDirectoryHandle(pathParts[i]);
                }

                const fileHandle = await currentDir.getFileHandle(pathParts[pathParts.length - 1]);
                const file = await fileHandle.getFile();
                const data = await file.arrayBuffer();

                attachments.push({
                    name: attachmentInfo.originalName || attachmentInfo.name,
                    type: attachmentInfo.type,
                    data: new Uint8Array(data),
                    size: attachmentInfo.size
                });
            } catch (error) {
                console.error(`Failed to get attachment: ${attachmentInfo.path}`, error);
            }
        }
        return attachments;
    }

    async deleteAttachments(dbName, collectionName, documentId) {
        try {
            const root = await navigator.storage.getDirectory();
            const dbDir = await root.getDirectoryHandle(dbName);
            const collDir = await dbDir.getDirectoryHandle(collectionName);
            await collDir.removeEntry(documentId, { recursive: true });
        } catch (error) {
            if (error.name !== 'NotFoundError') {
                console.error(`Failed to delete attachments for ${documentId}:`, error);
            }
        }
    }

    static async prepareAttachment(file, name) {
        let data;
        if (file instanceof File || file instanceof Blob) {
            const buffer = await file.arrayBuffer();
            data = new Uint8Array(buffer);
        } else if (file instanceof ArrayBuffer) {
            data = new Uint8Array(file);
        } else if (file instanceof Uint8Array) {
            data = file;
        } else {
            throw new TypeError('Unsupported file type for attachment');
        }

        return {
            name: name || file.name || 'unnamed',
            type: file.type || 'application/octet-stream',
            data,
            originalName: file.name || name
        };
    }
}

// ========================
// IndexedDB Utility (Optimized with Batches)
// ========================

class IndexedDBUtility {
    constructor() {
        this._mutex = new AsyncMutex();
    }

    async performTransaction(db, storeNames, mode, callback, retries = 3) {
        // Optimization: Only use exclusive mutex for readwrite transactions
        if (mode === 'readonly') {
            return this._runTx(db, storeNames, mode, callback, retries);
        } else {
            return this._mutex.runExclusive(() => this._runTx(db, storeNames, mode, callback, retries));
        }
    }

    async _runTx(db, storeNames, mode, callback, retries) {
        let lastError;
        for (let i = 0; i < retries; i++) {
            try {
                return await new Promise((resolve, reject) => {
                    const transaction = db.transaction(storeNames, mode);
                    let result;

                    transaction.oncomplete = () => resolve(result);
                    transaction.onerror = () => reject(transaction.error);
                    transaction.onabort = () => reject(new Error('Transaction aborted'));

                    try {
                        const cbResult = callback(transaction);
                        if (cbResult instanceof Promise) {
                            cbResult.then(res => { result = res; }).catch(reject);
                        } else {
                            result = cbResult;
                        }
                    } catch (error) {
                        reject(error);
                    }
                });
            } catch (error) {
                lastError = error;
                if (i < retries - 1) {
                    await new Promise(resolve => setTimeout(resolve, (2 ** i) * 100));
                }
            }
        }
        throw new LacertaDBError('Transaction failed after retries', 'TRANSACTION_FAILED', lastError);
    }

    _promisifyRequest(requestFactory) {
        return new Promise((resolve, reject) => {
            const request = requestFactory();
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
            request.onabort = () => reject(new DOMException('Request aborted', 'AbortError'));
        });
    }

    // New: Batched Retrieval for processing large datasets efficiently
    async getBatch(db, storeName, lastKey, limit) {
        return this.performTransaction(db, [storeName], 'readonly', tx => {
            const store = tx.objectStore(storeName);
            let range;
            if (lastKey !== null && lastKey !== undefined) {
                range = IDBKeyRange.lowerBound(lastKey, true); // true = open range (skip lastKey)
            }
            // Use getAll which is faster than cursor for batches
            return this._promisifyRequest(() => store.getAll(range, limit));
        });
    }

    add(db, storeName, value, key) {
        return this.performTransaction(db, [storeName], 'readwrite', tx => {
            const store = tx.objectStore(storeName);
            return this._promisifyRequest(() => key !== undefined ? store.add(value, key) : store.add(value));
        });
    }

    put(db, storeName, value, key) {
        return this.performTransaction(db, [storeName], 'readwrite', tx => {
            const store = tx.objectStore(storeName);
            return this._promisifyRequest(() => key !== undefined ? store.put(value, key) : store.put(value));
        });
    }

    get(db, storeName, key) {
        return this.performTransaction(db, [storeName], 'readonly', tx => {
            return this._promisifyRequest(() => tx.objectStore(storeName).get(key));
        });
    }

    getAll(db, storeName, query, count) {
        return this.performTransaction(db, [storeName], 'readonly', tx => {
            return this._promisifyRequest(() => tx.objectStore(storeName).getAll(query, count));
        });
    }

    delete(db, storeName, key) {
        return this.performTransaction(db, [storeName], 'readwrite', tx => {
            return this._promisifyRequest(() => tx.objectStore(storeName).delete(key));
        });
    }

    clear(db, storeName) {
        return this.performTransaction(db, [storeName], 'readwrite', tx => {
            return this._promisifyRequest(() => tx.objectStore(storeName).clear());
        });
    }

    count(db, storeName, query) {
        return this.performTransaction(db, [storeName], 'readonly', tx => {
            return this._promisifyRequest(() => tx.objectStore(storeName).count(query));
        });
    }

    async batchOperation(db, operations, storeName = 'documents') {
        return new Promise((resolve, reject) => {
            const results = new Array(operations.length);
            let hasError = false;

            const transaction = db.transaction([storeName], 'readwrite');
            const store = transaction.objectStore(storeName);

            transaction.oncomplete = () => resolve(results);
            transaction.onerror = () => {
                // Fill remaining results with error
                for (let i = 0; i < results.length; i++) {
                    if (!results[i]) results[i] = { success: false, error: transaction.error?.message || 'Transaction failed' };
                }
                reject(new LacertaDBError('Batch transaction failed', 'TRANSACTION_FAILED', transaction.error));
            };
            transaction.onabort = () => {
                for (let i = 0; i < results.length; i++) {
                    if (!results[i]) results[i] = { success: false, error: 'Transaction aborted' };
                }
                reject(new LacertaDBError('Batch transaction aborted', 'TRANSACTION_ABORTED'));
            };

            // Fire all IDB requests synchronously in a tight loop — no Promises per request
            for (let i = 0; i < operations.length; i++) {
                const op = operations[i];
                let request;
                try {
                    switch (op.type) {
                        case 'add':
                            request = store.add(op.data);
                            break;
                        case 'put':
                            request = store.put(op.data);
                            break;
                        case 'delete':
                            request = store.delete(op.key);
                            break;
                        default:
                            results[i] = { success: false, error: `Unknown operation type: ${op.type}` };
                            continue;
                    }

                    // Capture index in closure for async callbacks
                    const idx = i;
                    request.onsuccess = () => {
                        results[idx] = { success: true, result: request.result };
                    };
                    request.onerror = (e) => {
                        results[idx] = { success: false, error: request.error?.message || 'Request failed' };
                        // Prevent the error from aborting the entire transaction
                        e.preventDefault();
                        e.stopPropagation();
                    };
                } catch (error) {
                    results[i] = { success: false, error: error.message };
                }
            }
        });
    }
}

// ========================
// ULID Generator (Lexicographically Sortable IDs)
// ========================

const _ULID_ENCODING = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford's Base32
let _ulid_lastTime = 0;
let _ulid_lastRandom = new Uint8Array(10);

function _generateULID() {
    let now = Date.now();

    // Timestamp component: 10 chars of Crockford Base32 (48 bits = ~8900 years from epoch)
    let ts = '';
    let t = now;
    for (let i = 9; i >= 0; i--) {
        ts = _ULID_ENCODING[t & 31] + ts;
        t = Math.floor(t / 32);
    }

    // Randomness component: 16 chars (80 bits)
    // If same millisecond, increment the random component for monotonicity
    if (now === _ulid_lastTime) {
        // Increment the random bytes (big-endian)
        let carry = 1;
        for (let i = 9; i >= 0 && carry; i--) {
            const sum = _ulid_lastRandom[i] + carry;
            _ulid_lastRandom[i] = sum & 0xFF;
            carry = sum >>> 8;
        }
    } else {
        crypto.getRandomValues(_ulid_lastRandom);
        _ulid_lastTime = now;
    }

    let rand = '';
    // Encode 10 random bytes as 16 Base32 chars
    const r = _ulid_lastRandom;
    rand += _ULID_ENCODING[(r[0] & 248) >>> 3];
    rand += _ULID_ENCODING[((r[0] & 7) << 2) | ((r[1] & 192) >>> 6)];
    rand += _ULID_ENCODING[(r[1] & 62) >>> 1];
    rand += _ULID_ENCODING[((r[1] & 1) << 4) | ((r[2] & 240) >>> 4)];
    rand += _ULID_ENCODING[((r[2] & 15) << 1) | ((r[3] & 128) >>> 7)];
    rand += _ULID_ENCODING[(r[3] & 124) >>> 2];
    rand += _ULID_ENCODING[((r[3] & 3) << 3) | ((r[4] & 224) >>> 5)];
    rand += _ULID_ENCODING[r[4] & 31];
    rand += _ULID_ENCODING[(r[5] & 248) >>> 3];
    rand += _ULID_ENCODING[((r[5] & 7) << 2) | ((r[6] & 192) >>> 6)];
    rand += _ULID_ENCODING[(r[6] & 62) >>> 1];
    rand += _ULID_ENCODING[((r[6] & 1) << 4) | ((r[7] & 240) >>> 4)];
    rand += _ULID_ENCODING[((r[7] & 15) << 1) | ((r[8] & 128) >>> 7)];
    rand += _ULID_ENCODING[(r[8] & 124) >>> 2];
    rand += _ULID_ENCODING[((r[8] & 3) << 3) | ((r[9] & 224) >>> 5)];
    rand += _ULID_ENCODING[r[9] & 31];

    return ts + rand;
}

// ========================
// Document Class
// ========================

class Document {
    constructor(data = {}, options = {}, serializer) {
        this._id = data._id || this._generateId();
        this._created = data._created || Date.now();
        this._modified = data._modified || Date.now();
        this._permanent = data._permanent || options.permanent || false;
        this._encrypted = false;
        this._compressed = data._compressed || options.compressed || false;
        this._attachments = data._attachments || [];
        this._data = null;
        this._packedData = data.packedData || null;
        this._compression = _sharedCompression;
        this._serializer = serializer;

        if (data.data) {
            this.data = data.data;
        }
    }

    get data() {
        return this._data || {};
    }

    set data(value) {
        this._data = value;
    }

    _generateId() {
        return _generateULID();
    }

    async pack(encryptionUtil = null) {
        try {
            let packed = this._serializer.serialize(this.data);
            if (this._compressed) {
                packed = await this._compression.compress(packed);
            }
            if (encryptionUtil) {
                packed = await encryptionUtil.encrypt(packed);
                this._encrypted = true;
            }
            this._packedData = packed;
            return packed;
        } catch (error) {
            throw new LacertaDBError('Failed to pack document', 'PACK_FAILED', error);
        }
    }

    async unpack(encryptionUtil = null) {
        try {
            let unpacked = this._packedData;
            if (this._encrypted && encryptionUtil) {
                unpacked = await encryptionUtil.decrypt(unpacked);
            }
            if (this._compressed) {
                unpacked = await this._compression.decompress(unpacked);
            }

            if (!unpacked || unpacked.length === 0) {
                throw new Error('Empty unpacked data');
            }

            this.data = this._serializer.deserialize(unpacked);

            if (typeof this.data !== 'object' || this.data === null) {
                throw new Error('Invalid deserialized data');
            }

            return this.data;
        } catch (error) {
            console.error('Document unpack failed:', error);
            this.data = {};
            return this.data;
        }
    }

    packSync() {
        let packed = this._serializer.serialize(this.data);
        if (this._compressed) {
            packed = this._compression.compressSync(packed);
        }
        this._packedData = packed;
        return packed;
    }

    unpackSync() {
        if (this._encrypted) {
            throw new LacertaDBError('Synchronous decryption not supported', 'SYNC_DECRYPT_NOT_SUPPORTED');
        }
        let unpacked = this._packedData;
        if (this._compressed) {
            unpacked = this._compression.decompressSync(unpacked);
        }
        this.data = this._serializer.deserialize(unpacked);
        return this.data;
    }

    objectOutput(includeAttachments = false) {
        const output = {
            _id: this._id,
            _created: this._created,
            _modified: this._modified,
            _permanent: this._permanent,
            ...this.data
        };
        if (includeAttachments && this._attachments.length > 0) {
            output._attachments = this._attachments;
        }
        return output;
    }

    databaseOutput() {
        return {
            _id: this._id,
            _created: this._created,
            _modified: this._modified,
            _permanent: this._permanent,
            _encrypted: this._encrypted,
            _compressed: this._compressed,
            _attachments: this._attachments,
            packedData: this._packedData
        };
    }
}

// ========================
// Metadata Classes
// ========================

class CollectionMetadata {
    constructor(name, data = {}, serializer, base64, dbName, idb = null) {
        this.name = name;
        this._serializer = serializer;
        this._base64 = base64;
        this._dbName = dbName;
        this._idb = idb; // IDB connection for async persistence
        this._metaKey = dbName ? `collmeta_${dbName}_${name}` : null;

        // Aggregate stats
        this.sizeKB = data.sizeKB || 0;
        this.length = data.length || 0;
        this.createdAt = data.createdAt || Date.now();
        this.modifiedAt = data.modifiedAt || Date.now();

        // Per-document tracking (in-memory Maps for O(1) ops)
        this._docSizes = new Map(data._docSizes || []);        // docId -> sizeKB
        this._docModified = new Map(data._docModified || []);   // docId -> timestamp
        this._docPermanent = new Map(data._docPermanent || []); // docId -> boolean
        this._docAttachments = new Map(data._docAttachments || []); // docId -> count

        // Debounced persistence
        this._dirty = false;
        this._saveTimer = null;
    }

    /** Set the IDB connection for persistence (called after Database.init()) */
    setIDB(idb) {
        this._idb = idb;
    }

    // ---- Mutations (in-memory only, schedule async save) ----

    addDocument(docId, sizeKB, isPermanent = false, attachmentCount = 0) {
        this._docSizes.set(docId, sizeKB);
        this._docModified.set(docId, Date.now());
        this._docPermanent.set(docId, isPermanent);
        this._docAttachments.set(docId, attachmentCount);

        this.sizeKB += sizeKB;
        this.length++;
        this.modifiedAt = Date.now();
        this._scheduleSave();
    }

    updateDocument(docId, newSizeKB, isPermanent = false, attachmentCount = 0) {
        const oldSize = this._docSizes.get(docId) || 0;
        this.sizeKB = this.sizeKB - oldSize + newSizeKB;

        this._docSizes.set(docId, newSizeKB);
        this._docModified.set(docId, Date.now());
        this._docPermanent.set(docId, isPermanent);
        this._docAttachments.set(docId, attachmentCount);

        this.modifiedAt = Date.now();
        this._scheduleSave();
    }

    removeDocument(docId) {
        const sizeKB = this._docSizes.get(docId) || 0;
        this.sizeKB -= sizeKB;
        this.length--;

        this._docSizes.delete(docId);
        this._docModified.delete(docId);
        this._docPermanent.delete(docId);
        this._docAttachments.delete(docId);

        this.modifiedAt = Date.now();
        this._scheduleSave();
    }

    // ---- Queries (instant from memory) ----

    getOldestNonPermanentDocuments(count) {
        const candidates = [];
        for (const [docId, modified] of this._docModified) {
            if (!this._docPermanent.get(docId)) {
                candidates.push({ id: docId, modified });
            }
        }
        candidates.sort((a, b) => a.modified - b.modified);
        return candidates.slice(0, count).map(c => c.id);
    }

    getDocumentSize(docId) {
        return this._docSizes.get(docId) || 0;
    }

    isDocumentPermanent(docId) {
        return this._docPermanent.get(docId) || false;
    }

    hasDocument(docId) {
        return this._docSizes.has(docId);
    }

    // ---- Aggregate snapshot (for DatabaseMetadata) ----

    getAggregateSnapshot() {
        return {
            sizeKB: this.sizeKB,
            length: this.length,
            createdAt: this.createdAt,
            modifiedAt: this.modifiedAt
        };
    }

    // ---- Persistence ----

    _scheduleSave() {
        this._dirty = true;
        if (this._saveTimer) return;

        const save = () => {
            this._saveTimer = null;
            if (!this._dirty) return;
            this._persistToStorage();
        };

        if (typeof window !== 'undefined' && window.requestIdleCallback) {
            this._saveTimer = window.requestIdleCallback(save);
        } else {
            this._saveTimer = setTimeout(save, 300);
        }
    }

    _flushSync() {
        if (!this._dirty) return;
        // Can't do sync IDB writes — trigger async persist and hope it completes
        this._persistToStorage();
    }

    _persistToStorage() {
        if (!this._metaKey || !this._serializer || !this._base64) return;

        const dataToStore = {
            sizeKB: this.sizeKB,
            length: this.length,
            createdAt: this.createdAt,
            modifiedAt: this.modifiedAt,
            _docSizes: Array.from(this._docSizes.entries()),
            _docModified: Array.from(this._docModified.entries()),
            _docPermanent: Array.from(this._docPermanent.entries()),
            _docAttachments: Array.from(this._docAttachments.entries())
        };

        try {
            const serialized = this._serializer.serialize(dataToStore);
            const encoded = this._base64.encode(serialized);

            if (this._idb && this._idb.objectStoreNames.contains('__meta')) {
                // Primary: async IDB write (non-blocking)
                Database._writeMeta(this._idb, this._metaKey, { data: encoded }).catch(e => {
                    console.warn('CollectionMetadata IDB save failed:', e);
                });
                this._dirty = false;
            } else {
                // Fallback: localStorage (only if IDB not available)
                const lsKey = `lacertadb_${this._dbName}_${this.name}_collmeta`;
                localStorage.setItem(lsKey, encoded);
                this._dirty = false;
            }
        } catch (e) {
            if (e.name === 'QuotaExceededError') {
                // Fallback: persist only aggregate stats
                console.warn('CollectionMetadata: quota exceeded, saving aggregates only');
                try {
                    const fallback = {
                        sizeKB: this.sizeKB, length: this.length,
                        createdAt: this.createdAt, modifiedAt: this.modifiedAt
                    };
                    const serialized = this._serializer.serialize(fallback);
                    const encoded = this._base64.encode(serialized);
                    if (this._idb && this._idb.objectStoreNames.contains('__meta')) {
                        Database._writeMeta(this._idb, this._metaKey, { data: encoded }).catch(() => {});
                    }
                    this._dirty = false;
                } catch (e2) {
                    console.error('CollectionMetadata: fallback save also failed:', e2);
                }
            } else {
                console.error('CollectionMetadata save failed:', e);
            }
        }
    }

    /** Load from IDB with localStorage migration fallback */
    static async loadAsync(dbName, collName, serializer, base64, idb) {
        const metaKey = `collmeta_${dbName}_${collName}`;

        // Try IDB first
        if (idb && idb.objectStoreNames.contains('__meta')) {
            try {
                const stored = await Database._readMeta(idb, metaKey);
                if (stored && stored.data) {
                    const decoded = base64.decode(stored.data);
                    const data = serializer.deserialize(decoded);
                    return new CollectionMetadata(collName, data, serializer, base64, dbName, idb);
                }
            } catch (e) {
                console.warn('CollectionMetadata IDB load failed, trying localStorage:', e);
            }
        }

        // Fallback: localStorage (for migration)
        const lsKey = `lacertadb_${dbName}_${collName}_collmeta`;
        const lsStored = localStorage.getItem(lsKey);
        if (lsStored) {
            try {
                const decoded = base64.decode(lsStored);
                const data = serializer.deserialize(decoded);
                const meta = new CollectionMetadata(collName, data, serializer, base64, dbName, idb);
                // Migrate to IDB and remove localStorage key
                meta._dirty = true;
                meta._persistToStorage();
                localStorage.removeItem(lsKey);
                return meta;
            } catch (e) {
                console.warn('CollectionMetadata localStorage corrupted, resetting:', e);
            }
        }

        return new CollectionMetadata(collName, {}, serializer, base64, dbName, idb);
    }

    static load(dbName, collName, serializer, base64) {
        // Synchronous fallback for backward compat
        const key = `lacertadb_${dbName}_${collName}_collmeta`;
        const stored = localStorage.getItem(key);
        if (stored) {
            try {
                const decoded = base64.decode(stored);
                const data = serializer.deserialize(decoded);
                return new CollectionMetadata(collName, data, serializer, base64, dbName);
            } catch (e) {
                console.warn('CollectionMetadata corrupted, resetting:', e);
            }
        }
        return new CollectionMetadata(collName, {}, serializer, base64, dbName);
    }

    // ---- Lifecycle ----

    destroy() {
        this._flushSync();
        if (this._saveTimer) {
            if (typeof window !== 'undefined' && window.cancelIdleCallback) {
                window.cancelIdleCallback(this._saveTimer);
            } else {
                clearTimeout(this._saveTimer);
            }
            this._saveTimer = null;
        }
    }

    clear() {
        this.sizeKB = 0;
        this.length = 0;
        this.modifiedAt = Date.now();
        this._docSizes.clear();
        this._docModified.clear();
        this._docPermanent.clear();
        this._docAttachments.clear();
        this._dirty = true;
        this._flushSync();
    }
}

class DatabaseMetadata {
    constructor(name, data = {}, serializer, base64, idb = null) {
        this.name = name;
        this._serializer = serializer;
        this._base64 = base64;
        this._idb = idb;
        this._metaKey = `dbmeta_${name}`;
        if (!data || typeof data !== 'object') data = {};
        this.collections = data.collections || {};
        this.totalSizeKB = data.totalSizeKB || 0;
        this.totalLength = data.totalLength || 0;
        this.modifiedAt = data.modifiedAt || Date.now();

        // Debounced persistence
        this._dirty = false;
        this._saveTimer = null;
    }

    /** Set the IDB connection for persistence */
    setIDB(idb) {
        this._idb = idb;
    }

    /** Async load: IDB first, localStorage migration fallback */
    static async loadAsync(dbName, serializer, base64, idb) {
        const metaKey = `dbmeta_${dbName}`;

        // Try IDB first
        if (idb && idb.objectStoreNames.contains('__meta')) {
            try {
                const stored = await Database._readMeta(idb, metaKey);
                if (stored && stored.data) {
                    const decoded = base64.decode(stored.data);
                    const data = serializer.deserialize(decoded);
                    if (data && typeof data === 'object') {
                        return new DatabaseMetadata(dbName, data, serializer, base64, idb);
                    }
                }
            } catch (e) {
                console.warn('DatabaseMetadata IDB load failed, trying localStorage:', e);
            }
        }

        // Fallback: localStorage (for migration)
        const lsKey = `lacertadb_${dbName}_metadata`;
        const lsStored = localStorage.getItem(lsKey);
        if (lsStored) {
            try {
                const decoded = base64.decode(lsStored);
                const data = serializer.deserialize(decoded);
                if (data && typeof data === 'object') {
                    const meta = new DatabaseMetadata(dbName, data, serializer, base64, idb);
                    // Migrate to IDB
                    meta._dirty = true;
                    meta._persistToStorage();
                    localStorage.removeItem(lsKey);
                    return meta;
                }
            } catch (e) {
                console.error('Failed to load metadata from localStorage:', e);
            }
        }

        return new DatabaseMetadata(dbName, {}, serializer, base64, idb);
    }

    static load(dbName, serializer, base64) {
        // Synchronous fallback for backward compat
        const key = `lacertadb_${dbName}_metadata`;
        const stored = localStorage.getItem(key);
        if (stored) {
            try {
                const decoded = base64.decode(stored);
                const data = serializer.deserialize(decoded);
                if (data && typeof data === 'object') {
                    return new DatabaseMetadata(dbName, data, serializer, base64);
                }
            } catch (e) {
                console.error('Failed to load metadata:', e);
            }
        }
        return new DatabaseMetadata(dbName, {}, serializer, base64);
    }

    setCollection(collectionMetadata) {
        this.collections[collectionMetadata.name] = collectionMetadata.getAggregateSnapshot();
        this._recalculate();
        this._scheduleSave();
    }

    removeCollection(collectionName) {
        delete this.collections[collectionName];
        this._recalculate();
        this._scheduleSave();
    }

    _recalculate() {
        this.totalSizeKB = 0;
        this.totalLength = 0;
        for (const collName in this.collections) {
            const coll = this.collections[collName];
            this.totalSizeKB += coll.sizeKB;
            this.totalLength += coll.length;
        }
        this.modifiedAt = Date.now();
    }

    // ---- Debounced persistence ----

    _scheduleSave() {
        this._dirty = true;
        if (this._saveTimer) return;

        const save = () => {
            this._saveTimer = null;
            if (!this._dirty) return;
            this._persistToStorage();
        };

        if (typeof window !== 'undefined' && window.requestIdleCallback) {
            this._saveTimer = window.requestIdleCallback(save);
        } else {
            this._saveTimer = setTimeout(save, 300);
        }
    }

    _flushSync() {
        if (!this._dirty) return;
        this._persistToStorage();
    }

    _persistToStorage() {
        try {
            const dataToStore = {
                collections: this.collections,
                totalSizeKB: this.totalSizeKB,
                totalLength: this.totalLength,
                modifiedAt: this.modifiedAt
            };
            const serializedData = this._serializer.serialize(dataToStore);
            const encodedData = this._base64.encode(serializedData);

            if (this._idb && this._idb.objectStoreNames.contains('__meta')) {
                // Primary: async IDB write (non-blocking)
                Database._writeMeta(this._idb, this._metaKey, { data: encodedData }).catch(e => {
                    console.warn('DatabaseMetadata IDB save failed:', e);
                });
                this._dirty = false;
            } else {
                // Fallback: localStorage
                const key = `lacertadb_${this.name}_metadata`;
                localStorage.setItem(key, encodedData);
                this._dirty = false;
            }
        } catch (e) {
            if (e.name === 'QuotaExceededError') {
                console.error('CRITICAL: Metadata save failed — quota exceeded for db:', this.name);
                if (typeof window !== 'undefined') {
                    window.dispatchEvent(new CustomEvent('lacertadb:quotaexceeded', { detail: { db: this.name } }));
                }
            } else {
                console.error('Failed to save metadata:', e);
            }
        }
    }

    // Force immediate save (for critical operations like clearAll)
    save() {
        this._dirty = true;
        this._flushSync();
    }

    // ---- Lifecycle ----

    destroy() {
        this._flushSync();
        if (this._saveTimer) {
            if (typeof window !== 'undefined' && window.cancelIdleCallback) {
                window.cancelIdleCallback(this._saveTimer);
            } else {
                clearTimeout(this._saveTimer);
            }
            this._saveTimer = null;
        }
    }
}

class Settings {
    constructor(dbName, data = {}, serializer, base64, idb = null) {
        this.dbName = dbName;
        this._serializer = serializer;
        this._base64 = base64;
        this._idb = idb;
        this._metaKey = `settings_${dbName}`;
        this.sizeLimitKB = data.sizeLimitKB != null ? data.sizeLimitKB : Infinity;
        const defaultBuffer = this.sizeLimitKB === Infinity ? Infinity : this.sizeLimitKB * 0.8;
        this.bufferLimitKB = data.bufferLimitKB != null ? data.bufferLimitKB : defaultBuffer;
        this.freeSpaceEvery = this.sizeLimitKB === Infinity ? 0 : (data.freeSpaceEvery || 10000);
    }

    /** Set the IDB connection for persistence */
    setIDB(idb) {
        this._idb = idb;
    }

    /** Async load: IDB first, localStorage migration fallback */
    static async loadAsync(dbName, serializer, base64, idb) {
        const metaKey = `settings_${dbName}`;

        // Try IDB first
        if (idb && idb.objectStoreNames.contains('__meta')) {
            try {
                const stored = await Database._readMeta(idb, metaKey);
                if (stored && stored.data) {
                    const decoded = base64.decode(stored.data);
                    const data = serializer.deserialize(decoded);
                    return new Settings(dbName, data, serializer, base64, idb);
                }
            } catch (e) {
                console.warn('Settings IDB load failed, trying localStorage:', e);
            }
        }

        // Fallback: localStorage (for migration)
        const lsKey = `lacertadb_${dbName}_settings`;
        const lsStored = localStorage.getItem(lsKey);
        if (lsStored) {
            try {
                const decoded = base64.decode(lsStored);
                const data = serializer.deserialize(decoded);
                const settings = new Settings(dbName, data, serializer, base64, idb);
                // Migrate to IDB
                settings.save();
                localStorage.removeItem(lsKey);
                return settings;
            } catch (e) {
                console.error('Failed to load settings from localStorage:', e);
            }
        }

        return new Settings(dbName, {}, serializer, base64, idb);
    }

    static load(dbName, serializer, base64) {
        // Synchronous fallback for backward compat
        const key = `lacertadb_${dbName}_settings`;
        const stored = localStorage.getItem(key);
        if (stored) {
            try {
                const decoded = base64.decode(stored);
                const data = serializer.deserialize(decoded);
                return new Settings(dbName, data, serializer, base64);
            } catch (e) {
                console.error('Failed to load settings:', e);
            }
        }
        return new Settings(dbName, {}, serializer, base64);
    }

    save() {
        try {
            const dataToStore = {
                sizeLimitKB: this.sizeLimitKB,
                bufferLimitKB: this.bufferLimitKB,
                freeSpaceEvery: this.freeSpaceEvery
            };
            const serializedData = this._serializer.serialize(dataToStore);
            const encodedData = this._base64.encode(serializedData);

            if (this._idb && this._idb.objectStoreNames.contains('__meta')) {
                Database._writeMeta(this._idb, this._metaKey, { data: encodedData }).catch(e => {
                    console.warn('Settings IDB save failed:', e);
                });
            } else {
                const key = `lacertadb_${this.dbName}_settings`;
                localStorage.setItem(key, encodedData);
            }
        } catch (e) {
            if (e.name === 'QuotaExceededError') {
                console.error('CRITICAL: Settings save failed — quota exceeded');
                if (typeof window !== 'undefined') {
                    window.dispatchEvent(new CustomEvent('lacertadb:quotaexceeded', { detail: { source: 'settings', db: this.dbName } }));
                }
            } else {
                console.error('Settings save failed:', e);
            }
        }
    }

    updateSettings(newSettings) {
        Object.assign(this, newSettings);
        if (newSettings.sizeLimitKB !== undefined && newSettings.bufferLimitKB === undefined) {
            this.bufferLimitKB = this.sizeLimitKB === Infinity ? Infinity : this.sizeLimitKB * 0.8;
        }
        if (this.sizeLimitKB === Infinity) {
            this.freeSpaceEvery = 0;
        }
        this.save();
    }
}

// ========================
// Query Engine
// ========================

class QueryEngine {
    constructor() {
        // Path cache: avoids repeated path.split('.') allocations during scans
        this._pathCache = new Map();

        this.operators = {
            '$eq': (a, b) => a === b,
            '$ne': (a, b) => a !== b,
            '$gt': (a, b) => a > b,
            '$gte': (a, b) => a >= b,
            '$lt': (a, b) => a < b,
            '$lte': (a, b) => a <= b,
            '$in': (a, b) => Array.isArray(b) && b.includes(a),
            '$nin': (a, b) => Array.isArray(b) && !b.includes(a),

            '$and': (doc, conditions) => conditions.every(cond => this.evaluate(doc, cond)),
            '$or': (doc, conditions) => conditions.some(cond => this.evaluate(doc, cond)),
            '$not': (doc, condition) => !this.evaluate(doc, condition),
            '$nor': (doc, conditions) => !conditions.some(cond => this.evaluate(doc, cond)),

            '$exists': (value, exists) => (value !== undefined) === exists,
            '$type': (value, type) => typeof value === type,

            '$all': (arr, values) => Array.isArray(arr) && values.every(v => arr.includes(v)),
            '$elemMatch': (arr, condition) => Array.isArray(arr) && arr.some(elem => this.evaluate({ value: elem }, { value: condition })),
            '$size': (arr, size) => Array.isArray(arr) && arr.length === size,

            '$regex': (str, pattern) => {
                if (typeof str !== 'string') return false;
                try {
                    const regex = new RegExp(pattern);
                    return regex.test(str);
                } catch {
                    return false;
                }
            },
            '$text': (str, search) => typeof str === 'string' && str.toLowerCase().includes(search.toLowerCase())
        };
    }

    evaluate(doc, query) {
        for (const key in query) {
            const value = query[key];
            if (key.startsWith('$')) {
                const operator = this.operators[key];
                if (!operator || !operator(doc, value)) return false;
            } else {
                const fieldValue = this.getFieldValue(doc, key);
                if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
                    for (const op in value) {
                        if (op.startsWith('$')) {
                            const operatorFn = this.operators[op];
                            if (!operatorFn || !operatorFn(fieldValue, value[op])) {
                                return false;
                            }
                        }
                    }
                } else {
                    if (fieldValue !== value) return false;
                }
            }
        }
        return true;
    }

    /** Pre-parse and cache a dot-path into an array of segments */
    _getParsedPath(path) {
        let parts = this._pathCache.get(path);
        if (parts === undefined) {
            parts = path.indexOf('.') === -1 ? null : path.split('.');
            this._pathCache.set(path, parts);
            // Cap cache size to prevent unbounded growth
            if (this._pathCache.size > 2000) {
                // Delete oldest entries (first 500)
                const iter = this._pathCache.keys();
                for (let i = 0; i < 500; i++) iter.next();
                // Rebuild with remaining
                const newCache = new Map();
                for (const [k, v] of this._pathCache) newCache.set(k, v);
                this._pathCache = newCache;
            }
        }
        return parts;
    }

    getFieldValue(doc, path) {
        // Fast path: no dot in path (single-level field access)
        const parts = this._getParsedPath(path);
        if (parts === null) {
            return doc == null ? undefined : doc[path];
        }

        let current = doc;
        for (let i = 0; i < parts.length; i++) {
            if (current === null || current === undefined) {
                return undefined;
            }
            current = current[parts[i]];
        }
        return current;
    }
}
const queryEngine = new QueryEngine();

// ========================
// Aggregation Pipeline
// ========================

class AggregationPipeline {
    constructor() {
        this.stages = {
            '$match': (docs, condition) => docs.filter(doc => queryEngine.evaluate(doc, condition)),

            '$project': (docs, projection) => docs.map(doc => {
                const projected = {};
                for (const key in projection) {
                    const value = projection[key];
                    if (value === 1 || value === true) {
                        projected[key] = queryEngine.getFieldValue(doc, key);
                    } else if (typeof value === 'string' && value.startsWith('$')) {
                        projected[key] = queryEngine.getFieldValue(doc, value.substring(1));
                    }
                }
                if (Object.values(projection).some(v => v === 0 || v === false)) {
                    const exclusions = Object.keys(projection).filter(k => projection[k] === 0 || projection[k] === false);
                    const included = { ...doc };
                    exclusions.forEach(key => delete included[key]);
                    return included;
                }
                return projected;
            }),

            '$sort': (docs, sortSpec) => [...docs].sort((a, b) => {
                for (const key in sortSpec) {
                    const order = sortSpec[key];
                    const aVal = queryEngine.getFieldValue(a, key);
                    const bVal = queryEngine.getFieldValue(b, key);
                    if (aVal < bVal) return -order;
                    if (aVal > bVal) return order;
                }
                return 0;
            }),

            '$limit': (docs, limit) => docs.slice(0, limit),

            '$skip': (docs, skip) => docs.slice(skip),

            '$group': (docs, groupSpec) => {
                const groups = new Map();
                const idField = groupSpec._id;

                // Fast key generation: avoid recursive stableStringify for primitives/flat arrays
                const fastKey = (val) => {
                    if (val === null || val === undefined) return '\x00null';
                    const t = typeof val;
                    if (t === 'string') return '\x01' + val;
                    if (t === 'number' || t === 'boolean') return '\x02' + val;
                    if (Array.isArray(val)) return '\x03[' + val.join(',') + ']';
                    // Object key: sorted JSON (last resort)
                    const sorted = Object.keys(val).sort();
                    return '\x04{' + sorted.map(k => k + ':' + fastKey(val[k])).join(',') + '}';
                };

                // Helper: resolve $field references in an _id expression object
                const resolveIdValue = (doc, idExpr) => {
                    if (typeof idExpr === 'string' && idExpr.startsWith('$')) {
                        return queryEngine.getFieldValue(doc, idExpr.substring(1));
                    }
                    if (idExpr !== null && typeof idExpr === 'object' && !Array.isArray(idExpr)) {
                        const resolved = {};
                        for (const key in idExpr) {
                            resolved[key] = resolveIdValue(doc, idExpr[key]);
                        }
                        return resolved;
                    }
                    return idExpr;
                };

                for (const doc of docs) {
                    let groupKey;
                    if (typeof idField === 'string') {
                        groupKey = idField.startsWith('$')
                            ? queryEngine.getFieldValue(doc, idField.substring(1))
                            : idField;
                    } else if (idField !== null && typeof idField === 'object') {
                        groupKey = fastKey(resolveIdValue(doc, idField));
                    } else {
                        groupKey = idField; // null or literal
                    }

                    if (!groups.has(groupKey)) {
                        groups.set(groupKey, { _id: groupKey, docs: [] });
                    }
                    groups.get(groupKey).docs.push(doc);
                }

                const results = [];
                for (const group of groups.values()) {
                    const result = { _id: group._id };
                    for (const fieldKey in groupSpec) {
                        if (fieldKey === '_id') continue;
                        const accumulator = groupSpec[fieldKey];
                        const op = Object.keys(accumulator)[0];
                        const field = accumulator[op].toString().replace('$', '');

                        switch(op) {
                            case '$sum':
                                result[fieldKey] = group.docs.reduce((sum, d) => sum + (queryEngine.getFieldValue(d, field) || 0), 0);
                                break;
                            case '$avg': {
                                const sum = group.docs.reduce((s, d) => s + (queryEngine.getFieldValue(d, field) || 0), 0);
                                result[fieldKey] = sum / group.docs.length;
                                break;
                            }
                            case '$count':
                                result[fieldKey] = group.docs.length;
                                break;
                            case '$max':
                                result[fieldKey] = Math.max(...group.docs.map(d => queryEngine.getFieldValue(d, field)));
                                break;
                            case '$min':
                                result[fieldKey] = Math.min(...group.docs.map(d => queryEngine.getFieldValue(d, field)));
                                break;
                        }
                    }
                    results.push(result);
                }
                return results;
            },

            '$lookup': async (docs, lookupSpec, db) => {
                // Collect unique localField values to avoid loading the entire foreign collection
                const localValues = new Set();
                for (const doc of docs) {
                    const val = queryEngine.getFieldValue(doc, lookupSpec.localField);
                    if (val !== undefined && val !== null) localValues.add(val);
                }

                const foreignCollection = await db.getCollection(lookupSpec.from);
                const foreignMap = new Map();

                if (localValues.size > 0) {
                    // Try to use an index on the foreign field for selective fetch
                    const foreignIndexes = foreignCollection._indexManager.indexes;
                    let usedIndex = false;

                    for (const [indexName, index] of foreignIndexes) {
                        if (index.fieldPath === lookupSpec.foreignField) {
                            // Use $in query via the index
                            const docIds = await foreignCollection._indexManager.query(
                                indexName, { $in: Array.from(localValues) }
                            );
                            const fetchedDocs = await Promise.all(
                                docIds.map(id => foreignCollection.get(id).catch(() => null))
                            );
                            for (const doc of fetchedDocs) {
                                if (!doc) continue;
                                const key = queryEngine.getFieldValue(doc, lookupSpec.foreignField);
                                if (!foreignMap.has(key)) foreignMap.set(key, []);
                                foreignMap.get(key).push(doc);
                            }
                            usedIndex = true;
                            break;
                        }
                    }

                    if (!usedIndex) {
                        // Fallback: query with filter (still avoids loading ALL docs into memory)
                        const foreignDocs = await foreignCollection.query({
                            [lookupSpec.foreignField]: { $in: Array.from(localValues) }
                        });
                        for (const doc of foreignDocs) {
                            const key = queryEngine.getFieldValue(doc, lookupSpec.foreignField);
                            if (!foreignMap.has(key)) foreignMap.set(key, []);
                            foreignMap.get(key).push(doc);
                        }
                    }
                }

                return docs.map(doc => {
                    const localValue = queryEngine.getFieldValue(doc, lookupSpec.localField);
                    return {
                        ...doc,
                        [lookupSpec.as]: foreignMap.get(localValue) || []
                    };
                });
            }
        };
    }

    async execute(docs, pipeline, db) {
        let result = docs;
        for (const stage of pipeline) {
            const stageName = Object.keys(stage)[0];
            const stageSpec = stage[stageName];
            const stageFunction = this.stages[stageName];

            if (!stageFunction) {
                throw new Error(`Unknown aggregation stage: ${stageName}`);
            }

            if (stageName === '$lookup') {
                result = await stageFunction(result, stageSpec, db);
            } else {
                result = stageFunction(result, stageSpec);
            }
        }
        return result;
    }
}
const aggregationPipeline = new AggregationPipeline();

// ========================
// Migration Manager
// ========================

class MigrationManager {
    constructor(database) {
        this.database = database;
        this.migrations = [];
        this.currentVersion = this._loadVersion();
    }

    _loadVersion() {
        return localStorage.getItem(`lacertadb_${this.database.name}_version`) || '1.0.0';
    }

    _saveVersion(version) {
        localStorage.setItem(`lacertadb_${this.database.name}_version`, version);
        this.currentVersion = version;
    }

    addMigration(migration) {
        this.migrations.push(migration);
    }

    _compareVersions(a, b) {
        const partsA = a.split('.').map(Number);
        const partsB = b.split('.').map(Number);
        const len = Math.max(partsA.length, partsB.length);

        for (let i = 0; i < len; i++) {
            const partA = partsA[i] || 0;
            const partB = partsB[i] || 0;
            if (partA > partB) return 1;
            if (partA < partB) return -1;
        }
        return 0;
    }

    async runMigrations(targetVersion) {
        const applicableMigrations = this.migrations
            .filter(m => this._compareVersions(m.version, this.currentVersion) > 0 &&
                this._compareVersions(m.version, targetVersion) <= 0)
            .sort((a, b) => this._compareVersions(a.version, b.version));

        for (const migration of applicableMigrations) {
            await this._applyMigration(migration, 'up');
            this._saveVersion(migration.version);
        }
    }

    async rollback(targetVersion) {
        const applicableMigrations = this.migrations
            .filter(m => m.down &&
                this._compareVersions(m.version, targetVersion) > 0 &&
                this._compareVersions(m.version, this.currentVersion) <= 0)
            .sort((a, b) => this._compareVersions(b.version, a.version));

        for (const migration of applicableMigrations) {
            await this._applyMigration(migration, 'down');
        }
        this._saveVersion(targetVersion);
    }

    async _applyMigration(migration, direction) {
        console.log(`${direction === 'up' ? 'Running' : 'Rolling back'} migration: ${migration.name} (v${migration.version})`);
        const collections = await this.database.listCollections();
        for (const collectionName of collections) {
            const coll = await this.database.getCollection(collectionName);
            const docs = await coll.getAll();
            for (const doc of docs) {
                const updated = await migration[direction](doc);
                if (updated) {
                    await coll.update(doc._id, updated);
                }
            }
        }
    }
}

// ========================
// Performance Monitor
// ========================

class PerformanceMonitor {
    constructor() {
        this._metrics = {
            operations: [],
            latencies: [],
            cacheHits: 0,
            cacheMisses: 0,
            memoryUsage: []
        };
        this._monitoring = false;
        this._monitoringInterval = null;
    }

    startMonitoring() {
        if (this._monitoring) return;
        this._monitoring = true;
        this._monitoringInterval = setInterval(() => this._collectMetrics(), 1000);
    }

    stopMonitoring() {
        if (!this._monitoring) return;
        this._monitoring = false;
        clearInterval(this._monitoringInterval);
        this._monitoringInterval = null;
    }

    recordOperation(type, duration) {
        if (!this._monitoring) return;
        this._metrics.operations.push({ type, duration, timestamp: Date.now() });
        this._metrics.latencies.push(duration);
        if (this._metrics.operations.length > 100) this._metrics.operations.shift();
        if (this._metrics.latencies.length > 100) this._metrics.latencies.shift();
    }

    recordCacheHit() { this._metrics.cacheHits++; }
    recordCacheMiss() { this._metrics.cacheMisses++; }

    _collectMetrics() {
        if (performance && performance.memory) {
            this._metrics.memoryUsage.push({
                used: performance.memory.usedJSHeapSize,
                total: performance.memory.totalJSHeapSize,
                limit: performance.memory.jsHeapSizeLimit,
                timestamp: Date.now()
            });
            if (this._metrics.memoryUsage.length > 60) this._metrics.memoryUsage.shift();
        }
    }

    getStats() {
        const opsPerSec = this._metrics.operations.filter(op => Date.now() - op.timestamp < 1000).length;
        const totalLatency = this._metrics.latencies.reduce((a, b) => a + b, 0);
        const avgLatency = this._metrics.latencies.length > 0 ? totalLatency / this._metrics.latencies.length : 0;
        const totalCacheOps = this._metrics.cacheHits + this._metrics.cacheMisses;
        const cacheHitRate = totalCacheOps > 0 ? (this._metrics.cacheHits / totalCacheOps) * 100 : 0;

        const latestMemory = this._metrics.memoryUsage.length > 0 ? this._metrics.memoryUsage[this._metrics.memoryUsage.length - 1] : null;
        const memoryUsageMB = latestMemory ? latestMemory.used / (1024 * 1024) : 0;

        return {
            opsPerSec,
            avgLatency: avgLatency.toFixed(2),
            cacheHitRate: cacheHitRate.toFixed(1),
            memoryUsageMB: memoryUsageMB.toFixed(2)
        };
    }

    getOptimizationTips() {
        const tips = [];
        const stats = this.getStats();

        if (stats.avgLatency > 100) {
            tips.push('High average latency detected. Consider enabling compression and indexing frequently queried fields.');
        }
        if (stats.cacheHitRate < 50 && (this._metrics.cacheHits + this._metrics.cacheMisses) > 20) {
            tips.push('Low cache hit rate. Consider increasing cache size or optimizing query patterns.');
        }
        if (this._metrics.memoryUsage.length > 10) {
            const recent = this._metrics.memoryUsage.slice(-10);
            const trend = recent[recent.length - 1].used - recent[0].used;
            if (trend > 10 * 1024 * 1024) {
                tips.push('Memory usage is increasing rapidly. Check for memory leaks or consider batch processing.');
            }
        }
        return tips.length > 0 ? tips : ['Performance is optimal. No issues detected.'];
    }
}

// ========================
// Stable Cache Key Utility
// ========================

/**
 * MurmurHash3 (32-bit) for fast, deterministic cache key generation.
 * Produces a numeric hash from a string — avoids JSON.stringify + sort overhead.
 * @param {string} str
 * @param {number} [seed=0]
 * @returns {number}
 */
function _murmurHash3(str, seed = 0) {
    let h = seed | 0;
    const len = str.length;
    const nblocks = len >>> 2;

    for (let i = 0; i < nblocks; i++) {
        const i4 = i << 2;
        let k = (str.charCodeAt(i4) & 0xffff) |
            ((str.charCodeAt(i4 + 1) & 0xffff) << 8) |
            ((str.charCodeAt(i4 + 2) & 0xffff) << 16) |
            ((str.charCodeAt(i4 + 3) & 0xffff) << 24);

        k = Math.imul(k, 0xcc9e2d51);
        k = (k << 15) | (k >>> 17);
        k = Math.imul(k, 0x1b873593);

        h ^= k;
        h = (h << 13) | (h >>> 19);
        h = Math.imul(h, 5) + 0xe6546b64 | 0;
    }

    let k = 0;
    const tail = nblocks << 2;
    switch (len & 3) {
        case 3: k ^= (str.charCodeAt(tail + 2) & 0xffff) << 16;
        case 2: k ^= (str.charCodeAt(tail + 1) & 0xffff) << 8;
        case 1:
            k ^= str.charCodeAt(tail) & 0xffff;
            k = Math.imul(k, 0xcc9e2d51);
            k = (k << 15) | (k >>> 17);
            k = Math.imul(k, 0x1b873593);
            h ^= k;
    }

    h ^= len;
    h ^= h >>> 16;
    h = Math.imul(h, 0x85ebca6b);
    h ^= h >>> 13;
    h = Math.imul(h, 0xc2b2ae35);
    h ^= h >>> 16;
    return h >>> 0;
}

/**
 * Generate a deterministic cache key from query filter + options.
 * Uses sorted-keys JSON serialization hashed via MurmurHash3 for speed.
 * @param {object} filter
 * @param {object} options
 * @returns {number}
 */
function _stableCacheKey(filter, options) {
    const replacer = (_, v) => {
        if (v && typeof v === 'object' && !Array.isArray(v)) {
            const sorted = {};
            for (const k of Object.keys(v).sort()) sorted[k] = v[k];
            return sorted;
        }
        return v;
    };
    const str = JSON.stringify({ f: filter, o: options }, replacer);
    return _murmurHash3(str);
}

// ========================
// Collection Class (Optimized)
// ========================

class Collection {
    constructor(name, database) {
        this.name = name;
        this.database = database;
        this._serializer = database._serializer;
        this._base64 = database._base64;
        this._db = null;           // Reference to parent's consolidated IDB connection
        this._storeName = name;    // Object store name within the consolidated database
        this._metadata = null;
        this._settings = database.settings;
        this._indexedDB = new IndexedDBUtility();
        this._opfs = new OPFSUtility();
        this._cleanupInterval = null;
        this._events = new Map();

        this._indexManager = new IndexManager(this);
        this._cacheStrategy = new CacheStrategy({
            type: 'lru',
            maxSize: 100,
            ttl: 60000,
            enabled: true
        });

        // Document-level cache: avoids IDB reads + deserialization for repeated get() calls
        this._docCache = new LRUCache(200);

        // Pending indexes: definitions registered before init() — applied during init
        this._pendingIndexes = [];

        this._performanceMonitor = database.performanceMonitor;
        this._initialized = false;
    }

    get settings() {
        return this._settings;
    }

    get metadata() {
        return this._metadata;
    }

    get initialized() {
        return this._initialized;
    }

    async init() {
        if (this._initialized) return this;

        // Use the parent Database's consolidated IDB connection
        await this.database._ensureStore(this._storeName);
        this._db = this.database._db;

        // Load per-collection metadata from IDB (with localStorage migration fallback)
        this._metadata = await CollectionMetadata.loadAsync(
            this.database.name, this.name, this._serializer, this._base64, this._db
        );

        await this._indexManager.loadIndexMetadata();

        // Apply any indexes that were registered before init()
        if (this._pendingIndexes.length > 0) {
            for (const { fieldPath, options } of this._pendingIndexes) {
                if (!this._indexManager.indexes.has(options.name || fieldPath)) {
                    await this._indexManager.createIndex(fieldPath, options).catch(() => {});
                }
            }
            this._pendingIndexes = [];
        }

        if (this._settings.freeSpaceEvery > 0 && this._settings.sizeLimitKB !== Infinity) {
            this._cleanupInterval = setInterval(() => this._freeSpace(), this._settings.freeSpaceEvery);
        }

        this._initialized = true;
        return this;
    }

    // Index methods
    async createIndex(fieldPath, options = {}) {
        // If not yet initialized, queue the definition — will be applied during init()
        if (!this._initialized) {
            this._pendingIndexes.push({ fieldPath, options });
            return options.name || fieldPath;
        }
        return await this._indexManager.createIndex(fieldPath, options);
    }

    async dropIndex(indexName) {
        return this._indexManager.dropIndex(indexName);
    }

    async getIndexes() {
        return this._indexManager.getIndexStats();
    }

    async verifyIndexes() {
        return await this._indexManager.verifyIndexes();
    }

    configureCacheStrategy(config) {
        this._cacheStrategy.updateStrategy(config);
    }

    async add(documentData, options = {}) {
        if (!this._initialized) await this.init();

        if (options.encrypted && !this.database.isEncrypted) {
            throw new LacertaDBError(
                'Document-level encryption requires database-level encryption. Use getSecureDatabase() to create an encrypted database.',
                'ENCRYPTION_NOT_INITIALIZED'
            );
        }

        await this._trigger('beforeAdd', documentData);

        const doc = new Document({data: documentData, _id: options.id}, {
            compressed: options.compressed || false,
            permanent: options.permanent || false
        }, this._serializer);

        const attachments = options.attachments;
        if (attachments && attachments.length > 0) {
            const preparedAttachments = await Promise.all(
                attachments.map(att => (att instanceof File || att instanceof Blob) ?
                    OPFSUtility.prepareAttachment(att, att.name) :
                    Promise.resolve(att))
            );
            doc._attachments = await this._opfs.saveAttachments(this.database.name, this.name, doc._id, preparedAttachments);
        }

        await doc.pack(this.database.encryption);
        const dbOutput = doc.databaseOutput();
        await this._indexedDB.add(this._db, this._storeName, dbOutput);

        const fullDoc = doc.objectOutput();
        await this._indexManager.updateIndexForDocument(doc._id, null, fullDoc);

        const sizeKB = dbOutput.packedData.byteLength / 1024;
        this._metadata.addDocument(doc._id, sizeKB, doc._permanent, doc._attachments.length);
        this.database.metadata.setCollection(this._metadata);

        await this._checkSpaceLimit();
        await this._trigger('afterAdd', doc);
        this._cacheStrategy.clear();
        this._docCache.set(doc._id, fullDoc);
        return doc._id;
    }

    async get(docId, options = {}) {
        if (!this._initialized) await this.init();

        // Document-level cache: return immediately if cached (skips IDB + deserialize)
        if (!options.includeAttachments) {
            const cached = this._docCache.get(docId);
            if (cached) return cached;
        }

        const stored = await this._indexedDB.get(this._db, this._storeName, docId);
        if (!stored) {
            throw new LacertaDBError(`Document with id '${docId}' not found.`, 'DOCUMENT_NOT_FOUND');
        }

        const doc = new Document(stored, {
            encrypted: stored._encrypted,
            compressed: stored._compressed
        }, this._serializer);

        if (stored.packedData) {
            await doc.unpack(this.database.encryption);
        }

        if (options.includeAttachments && doc._attachments.length > 0) {
            doc.data._attachments = await this._opfs.getAttachments(doc._attachments);
        }

        await this._trigger('afterGet', doc);
        const output = doc.objectOutput(options.includeAttachments);
        // Populate document cache (skip if attachments were included — those are transient)
        if (!options.includeAttachments) {
            this._docCache.set(docId, output);
        }
        return output;
    }

    async getAll(options = {}) {
        if (!this._initialized) await this.init();

        const stored = await this._indexedDB.getAll(this._db, this._storeName, undefined, options.limit);
        // Filter out persisted index entries (reserved _id prefix)
        const userDocs = stored.filter(d => !(typeof d._id === 'string' && d._id.startsWith(IndexManager.IDX_PREFIX)));
        return Promise.all(userDocs.map(async docData => {
            try {
                const doc = new Document(docData, {
                    encrypted: docData._encrypted,
                    compressed: docData._compressed
                }, this._serializer);
                if (docData.packedData) {
                    await doc.unpack(this.database.encryption);
                }
                return doc.objectOutput();
            } catch (error) {
                console.error(`Failed to unpack document ${docData._id}:`, error);
                return null;
            }
        })).then(docs => docs.filter(Boolean));
    }

    async update(docId, updates, options = {}) {
        if (!this._initialized) await this.init();

        await this._trigger('beforeUpdate', {docId, updates});

        const stored = await this._indexedDB.get(this._db, this._storeName, docId);
        if (!stored) {
            throw new LacertaDBError(`Document with id '${docId}' not found for update.`, 'DOCUMENT_NOT_FOUND');
        }

        const existingDoc = new Document(stored, {}, this._serializer);
        if (stored.packedData) await existingDoc.unpack(this.database.encryption);

        const oldDocOutput = existingDoc.objectOutput();
        const updatedData = {...existingDoc.data, ...updates};

        const doc = new Document({
            _id: docId,
            _created: stored._created,
            data: updatedData
        }, {
            compressed: options.compressed !== undefined ? options.compressed : stored._compressed,
            permanent: options.permanent !== undefined ? options.permanent : stored._permanent
        }, this._serializer);
        doc._modified = Date.now();

        const attachments = options.attachments;
        if (attachments && attachments.length > 0) {
            await this._opfs.deleteAttachments(this.database.name, this.name, docId);
            const preparedAttachments = await Promise.all(
                attachments.map(att => (att instanceof File || att instanceof Blob) ?
                    OPFSUtility.prepareAttachment(att, att.name) :
                    Promise.resolve(att))
            );
            doc._attachments = await this._opfs.saveAttachments(this.database.name, this.name, doc._id, preparedAttachments);
        } else {
            doc._attachments = stored._attachments;
        }

        await doc.pack(this.database.encryption);
        const dbOutput = doc.databaseOutput();
        await this._indexedDB.put(this._db, this._storeName, dbOutput);

        const newDocOutput = doc.objectOutput();
        await this._indexManager.updateIndexForDocument(doc._id, oldDocOutput, newDocOutput);

        const sizeKB = dbOutput.packedData.byteLength / 1024;
        this._metadata.updateDocument(doc._id, sizeKB, doc._permanent, doc._attachments.length);
        this.database.metadata.setCollection(this._metadata);

        await this._trigger('afterUpdate', doc);
        this._cacheStrategy.clear();
        this._docCache.set(doc._id, newDocOutput);
        return doc._id;
    }

    async delete(docId, options = {}) {
        if (!this._initialized) await this.init();

        await this._trigger('beforeDelete', docId);

        const doc = await this._indexedDB.get(this._db, this._storeName, docId);
        if (!doc) {
            throw new LacertaDBError('Document not found for deletion', 'DOCUMENT_NOT_FOUND');
        }

        if (doc._permanent && !options.force) {
            throw new LacertaDBError(
                'Cannot delete a permanent document. Use options.force = true to force deletion.',
                'PERMANENT_DOCUMENT_PROTECTION'
            );
        }

        if (doc._permanent && options.force) {
            console.warn(`Force deleting permanent document: ${docId}`);
        }

        const fullDoc = await this.get(docId);

        await this._indexManager.updateIndexForDocument(docId, fullDoc, null);

        await this._indexedDB.delete(this._db, this._storeName, docId);
        const attachments = doc._attachments;
        if (attachments && attachments.length > 0) {
            await this._opfs.deleteAttachments(this.database.name, this.name, docId);
        }

        this._metadata.removeDocument(docId);
        this.database.metadata.setCollection(this._metadata);

        await this._trigger('afterDelete', docId);
        this._cacheStrategy.clear();
        this._docCache.delete(docId);
    }    async query(filter = {}, options = {}) {
        if (!this._initialized) await this.init();

        const startTime = performance.now();

        const cacheKey = _stableCacheKey(filter, options);
        const cached = this._cacheStrategy.get(cacheKey);

        if (cached) {
            if (this._performanceMonitor) this._performanceMonitor.recordCacheHit();
            return cached;
        }
        if (this._performanceMonitor) this._performanceMonitor.recordCacheMiss();

        let results;
        let usedIndex = false;

        for (const [indexName, index] of this._indexManager.indexes) {
            const fieldValue = filter[index.fieldPath];
            if (fieldValue !== undefined) {
                const docIds = await this._indexManager.query(indexName, fieldValue);
                results = await Promise.all(
                    docIds.map(id => this.get(id).catch(() => null))
                );
                results = results.filter(Boolean);
                usedIndex = true;
                break;
            }
        }

        if (!usedIndex) {
            results = await this.getAll(options);
            if (Object.keys(filter).length > 0) {
                results = results.filter(doc => queryEngine.evaluate(doc, filter));
            }
        }

        if (options.sort) results = aggregationPipeline.stages.$sort(results, options.sort);
        if (options.skip) results = aggregationPipeline.stages.$skip(results, options.skip);
        if (options.limit) results = aggregationPipeline.stages.$limit(results, options.limit);
        if (options.projection) results = aggregationPipeline.stages.$project(results, options.projection);

        if (this._performanceMonitor) {
            this._performanceMonitor.recordOperation(
                usedIndex ? 'indexed-query' : 'full-scan-query',
                performance.now() - startTime
            );
        }

        this._cacheStrategy.set(cacheKey, results);

        return results;
    }

    async aggregate(pipeline) {
        if (!this._initialized) await this.init();

        const startTime = performance.now();

        // Optimization: push leading $match down to query() which can use indexes
        let docs;
        let remainingPipeline = pipeline;
        if (pipeline.length > 0 && pipeline[0].$match) {
            docs = await this.query(pipeline[0].$match);
            remainingPipeline = pipeline.slice(1);
        } else {
            docs = await this.getAll();
        }

        const result = await aggregationPipeline.execute(docs, remainingPipeline, this.database);
        if (this._performanceMonitor) this._performanceMonitor.recordOperation('aggregate', performance.now() - startTime);
        return result;
    }

    async batchAdd(documents, options = {}) {
        if (!this._initialized) await this.init();

        const startTime = performance.now();
        const operations = [];
        const results = [];
        const useSync = !this.database.encryption && !(options.compressed);

        for (const documentData of documents) {
            const doc = new Document({data: documentData}, {
                compressed: options.compressed || false,
                permanent: options.permanent || false
            }, this._serializer);

            if (useSync) {
                doc.packSync();
            } else {
                await doc.pack(this.database.encryption);
            }
            operations.push({
                type: 'add',
                data: doc.databaseOutput()
            });
            results.push(doc);
        }

        const dbResults = await this._indexedDB.batchOperation(this._db, operations, this._storeName);

        for (let i = 0; i < results.length; i++) {
            if (dbResults[i].success) {
                const doc = results[i];
                const fullDoc = doc.objectOutput();
                await this._indexManager.updateIndexForDocument(doc._id, null, fullDoc);

                const sizeKB = doc._packedData.byteLength / 1024;
                this._metadata.addDocument(doc._id, sizeKB, doc._permanent, 0);
                this._docCache.set(doc._id, fullDoc);
            }
        }

        this.database.metadata.setCollection(this._metadata);
        if (this._performanceMonitor) {
            this._performanceMonitor.recordOperation('batchAdd', performance.now() - startTime);
        }

        return dbResults.map((r, i) => ({
            ...r,
            id: results[i]._id
        }));
    }

    async batchUpdate(updates, options = {}) {
        if (!this._initialized) await this.init();

        const startTime = performance.now();
        const operations = [];
        const oldDocs = [];
        const newDocs = [];
        const skipped = [];
        const useSync = !this.database.encryption && !(options.compressed);

        // Phase 1: Bulk-fetch all existing docs in a single IDB read transaction
        const updateIds = updates.map(u => u.id);
        const storedMap = new Map();

        // Fetch all at once via getAll, then build a Map for O(1) lookup
        const allStored = await this._indexedDB.getAll(this._db, this._storeName);
        for (const doc of allStored) {
            if (doc._id && updateIds.includes(doc._id)) {
                storedMap.set(doc._id, doc);
            }
        }

        for (const update of updates) {
            const stored = storedMap.get(update.id);
            if (!stored) {
                skipped.push({ success: false, id: update.id, error: 'Document not found' });
                continue;
            }

            const existingDoc = new Document(stored, {}, this._serializer);
            if (stored.packedData) await existingDoc.unpack(this.database.encryption);

            oldDocs.push(existingDoc.objectOutput());

            const updatedData = { ...existingDoc.data, ...update.data };
            const doc = new Document({
                _id: update.id,
                _created: stored._created,
                data: updatedData
            }, {
                compressed: options.compressed !== undefined ? options.compressed : stored._compressed,
                permanent: options.permanent !== undefined ? options.permanent : stored._permanent
            }, this._serializer);
            doc._modified = Date.now();
            doc._attachments = stored._attachments;

            if (useSync) {
                doc.packSync();
            } else {
                await doc.pack(this.database.encryption);
            }
            newDocs.push(doc);

            operations.push({
                type: 'put',
                data: doc.databaseOutput()
            });
        }

        if (operations.length === 0) return skipped;

        // Phase 2: Single-transaction write
        const dbResults = await this._indexedDB.batchOperation(this._db, operations, this._storeName);

        // Phase 3: Update indexes, metadata, and doc cache post-transaction
        for (let i = 0; i < newDocs.length; i++) {
            if (dbResults[i].success) {
                const doc = newDocs[i];
                const newOutput = doc.objectOutput();
                await this._indexManager.updateIndexForDocument(doc._id, oldDocs[i], newOutput);

                const sizeKB = doc._packedData.byteLength / 1024;
                this._metadata.updateDocument(doc._id, sizeKB, doc._permanent, doc._attachments.length);
                this._docCache.set(doc._id, newOutput);
            }
        }

        this.database.metadata.setCollection(this._metadata);
        this._cacheStrategy.clear();

        if (this._performanceMonitor) {
            this._performanceMonitor.recordOperation('batchUpdate', performance.now() - startTime);
        }

        return [
            ...dbResults.map((r, i) => ({ ...r, id: newDocs[i]._id })),
            ...skipped
        ];
    }

    async batchDelete(items) {
        if (!this._initialized) await this.init();

        const startTime = performance.now();
        const normalizedItems = items.map(item => {
            if (typeof item === 'string') {
                return { id: item, options: {} };
            }
            return { id: item.id, options: item.options || {} };
        });

        const operations = [];
        const docsToRemove = [];
        const skipped = [];

        // Phase 1: Validate all documents and prepare delete operations
        for (const { id, options } of normalizedItems) {
            const doc = await this._indexedDB.get(this._db, this._storeName, id);
            if (!doc) {
                skipped.push({ success: false, id, error: 'Document not found' });
                continue;
            }

            if (doc._permanent && !options.force) {
                skipped.push({ success: false, id, error: 'Cannot delete permanent document without force flag' });
                continue;
            }

            const fullDoc = await this.get(id);
            docsToRemove.push({ id, fullDoc, stored: doc });

            operations.push({
                type: 'delete',
                key: id
            });
        }

        if (operations.length === 0) return skipped;

        // Phase 2: Single-transaction delete
        const dbResults = await this._indexedDB.batchOperation(this._db, operations, this._storeName);

        // Phase 3: Update indexes, OPFS cleanup, and metadata post-transaction
        for (let i = 0; i < docsToRemove.length; i++) {
            if (dbResults[i].success) {
                const { id, fullDoc, stored } = docsToRemove[i];
                await this._indexManager.updateIndexForDocument(id, fullDoc, null);

                if (stored._attachments && stored._attachments.length > 0) {
                    await this._opfs.deleteAttachments(this.database.name, this.name, id);
                }

                this._metadata.removeDocument(id);
                this._docCache.delete(id);
            }
        }

        this.database.metadata.setCollection(this._metadata);
        this._cacheStrategy.clear();

        if (this._performanceMonitor) {
            this._performanceMonitor.recordOperation('batchDelete', performance.now() - startTime);
        }

        return [
            ...dbResults.map((r, i) => ({ ...r, id: docsToRemove[i].id })),
            ...skipped
        ];
    }

    async _checkSpaceLimit() {
        if (this._settings.sizeLimitKB !== Infinity && this._metadata.sizeKB > this._settings.bufferLimitKB) {
            await this._freeSpace();
        }
    }

    async _freeSpace() {
        const targetSize = this._settings.bufferLimitKB * 0.8;
        while (this._metadata.sizeKB > targetSize) {
            const oldestDocs = this._metadata.getOldestNonPermanentDocuments(10);
            if (oldestDocs.length === 0) break;
            await this.batchDelete(oldestDocs);
        }
    }

    on(event, callback) {
        if (!this._events.has(event)) this._events.set(event, []);
        this._events.get(event).push(callback);
    }

    off(event, callback) {
        if (!this._events.has(event)) return;
        const listeners = this._events.get(event).filter(cb => cb !== callback);
        this._events.set(event, listeners);
    }

    async _trigger(event, data) {
        const listeners = this._events.get(event);
        if (!listeners || listeners.length === 0) return;
        for (const callback of listeners) {
            await callback(data);
        }
    }

    clearCache() {
        this._cacheStrategy.clear();
        this._docCache.clear();
    }

    async clear(options = {}) {
        if (!this._initialized) await this.init();

        if (options.force) {
            // Clear documents first
            await this._indexedDB.clear(this._db, this._storeName);

            // Reset metadata
            if (this._metadata) this._metadata.destroy();
            this._metadata = new CollectionMetadata(
                this.name, {}, this._serializer, this._base64, this.database.name, this._db
            );
            this._metadata._flushSync();
            this.database.metadata.setCollection(this._metadata);

            // Clear cache
            this._cacheStrategy.clear();
            this._docCache.clear();

            // Rebuild indexes after clearing
            for (const indexName of this._indexManager.indexes.keys()) {
                await this._indexManager.rebuildIndex(indexName);
            }
        } else {
            const allDocs = await this.getAll();
            const nonPermanentDocs = allDocs.filter(doc => !doc._permanent);
            await this.batchDelete(nonPermanentDocs.map(doc => doc._id));
        }

        // Reset cleanup interval if needed
        if (this._cleanupInterval) {
            clearInterval(this._cleanupInterval);
            this._cleanupInterval = null;

            if (this._settings.freeSpaceEvery > 0 && this._settings.sizeLimitKB !== Infinity) {
                this._cleanupInterval = setInterval(() => this._freeSpace(), this._settings.freeSpaceEvery);
            }
        }
    }

    destroy() {
        // Flush and destroy collection metadata
        if (this._metadata) {
            this._metadata.destroy();
        }

        // Flush dirty index data to IDB before teardown
        if (this._indexManager) {
            this._indexManager.flushPersistence().catch(() => {});
            this._indexManager.destroy();
        }

        // Clear the cleanup interval
        if (this._cleanupInterval) {
            clearInterval(this._cleanupInterval);
            this._cleanupInterval = null;
        }

        // Destroy cache strategy
        if (this._cacheStrategy) {
            this._cacheStrategy.destroy();
        }

        // Clear document cache
        if (this._docCache) {
            this._docCache.clear();
        }

        // Release the connection reference (owned by parent Database)
        this._db = null;

        // Clear event listeners
        this._events.clear();
    }
}

// ========================
// Database Class (Optimized with QuickStore)
// ========================

class Database {
    constructor(name, performanceMonitor, serializer, base64) {
        this.name = name;
        this._collections = new Map();
        this._metadata = null;
        this._settings = null;
        this._quickStore = null;
        this._performanceMonitor = performanceMonitor;
        this._serializer = serializer;
        this._base64 = base64;

        // Consolidated IDB connection (one per Database, not per Collection)
        this._db = null;
        this._idbVersion = 0;
        this._knownStores = new Set();
        this._ensureStorePromise = null;
        this._idbVersionKey = `lacertadb_${name}_idb_version`;
        this._idbStoresKey = `lacertadb_${name}_idb_stores`;

        // Database-level encryption
        this._encryption = null;
    }

    get collections() {
        return this._collections;
    }

    get metadata() {
        return this._metadata;
    }

    get settings() {
        return this._settings;
    }

    get quickStore() {
        return this._quickStore;
    }

    get performanceMonitor() {
        return this._performanceMonitor;
    }

    get encryption() {
        return this._encryption;
    }

    get isEncrypted() {
        return !!this._encryption;
    }

    /**
     * Open or reuse the consolidated IDB connection.
     * All collections share this single connection.
     * @returns {Promise<IDBDatabase>}
     */
    async _getConnection() {
        if (this._db) return this._db;

        // Load known version and stores from localStorage
        try {
            this._idbVersion = parseInt(localStorage.getItem(this._idbVersionKey), 10) || 1;
            const storedStores = localStorage.getItem(this._idbStoresKey);
            if (storedStores) {
                const decoded = this._base64.decode(storedStores);
                const list = this._serializer.deserialize(decoded);
                this._knownStores = new Set(list);
            }
        } catch (_) {
            this._idbVersion = 1;
        }

        this._db = await this._openIDB(this._idbVersion);
        return this._db;
    }

    /** @private Open IDB at a specific version */
    async _openIDB(version) {
        const knownStores = this._knownStores;
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(`lacertadb_${this.name}`, version);
            request.onerror = () => reject(new LacertaDBError(
                'Failed to open database', 'DATABASE_OPEN_FAILED', request.error
            ));
            request.onsuccess = () => resolve(request.result);
            request.onupgradeneeded = event => {
                const db = event.target.result;
                // Always ensure __meta store exists for metadata persistence
                if (!db.objectStoreNames.contains('__meta')) {
                    db.createObjectStore('__meta', { keyPath: '_id' });
                }
                for (const storeName of knownStores) {
                    if (!db.objectStoreNames.contains(storeName)) {
                        const store = db.createObjectStore(storeName, { keyPath: '_id' });
                        store.createIndex('modified', '_modified', { unique: false });
                    }
                }
            };
        });
    }

    /**
     * Ensure an object store exists for a collection.
     * If the store doesn't exist, bumps the IDB version to create it.
     * @param {string} storeName
     * @returns {Promise<void>}
     */
    /**
     * Ensure an object store exists for a collection.
     * Batches multiple new stores into a single IDB version bump.
     * Dedup-guarded so concurrent init() calls don't race.
     * @param {string} storeName
     * @returns {Promise<void>}
     */
    async _ensureStore(storeName) {
        // Already exists in current IDB — nothing to do
        if (this._db && this._db.objectStoreNames.contains(storeName)) {
            this._knownStores.add(storeName);
            return;
        }

        this._knownStores.add(storeName);

        // Dedup: if a version bump is already in flight, piggyback on it
        if (this._ensureStorePromise) {
            await this._ensureStorePromise;
            // After the in-flight bump, our store should now exist
            if (this._db && this._db.objectStoreNames.contains(storeName)) return;
        }

        // Collect ALL known stores that are missing from current IDB
        const missingStores = [];
        for (const name of this._knownStores) {
            if (!this._db || !this._db.objectStoreNames.contains(name)) {
                missingStores.push(name);
            }
        }

        if (missingStores.length === 0) return;

        this._ensureStorePromise = (async () => {
            this._idbVersion++;

            // Persist the new version and store list
            localStorage.setItem(this._idbVersionKey, String(this._idbVersion));
            const serialized = this._serializer.serialize(Array.from(this._knownStores));
            const encoded = this._base64.encode(serialized);
            localStorage.setItem(this._idbStoresKey, encoded);

            // Close current connection and reopen with new version (creates all missing stores)
            if (this._db) {
                this._db.close();
                this._db = null;
            }

            this._db = await this._openIDB(this._idbVersion);
        })();

        try {
            await this._ensureStorePromise;
        } finally {
            this._ensureStorePromise = null;
        }
    }

    async init(options = {}) {
        // Open the consolidated IDB connection first (needed for metadata IDB persistence)
        await this._getConnection();

        // Ensure __meta store exists
        if (!this._db.objectStoreNames.contains('__meta')) {
            await this._ensureStore('__meta');
        }

        // Load metadata from IDB (with localStorage migration/fallback)
        this._metadata = await DatabaseMetadata.loadAsync(this.name, this._serializer, this._base64, this._db);
        this._settings = await Settings.loadAsync(this.name, this._serializer, this._base64, this._db);
        this._quickStore = new QuickStore(this.name, this._serializer, this._base64, this._db);
        await this._quickStore.hydrateFromIDB();

        // Migrate old per-collection databases if they exist
        await this._migrateOldDatabases();

        if (options.pin) {
            await this._initializeEncryption(options.pin, options.salt, options.encryptionConfig);
        }

        return this;
    }

    /**
     * Read a metadata entry from the __meta IDB store.
     * @param {IDBDatabase} db
     * @param {string} key
     * @returns {Promise<*>}
     */
    static async _readMeta(db, key) {
        if (!db || !db.objectStoreNames.contains('__meta')) return null;
        return new Promise((resolve) => {
            try {
                const tx = db.transaction('__meta', 'readonly');
                const store = tx.objectStore('__meta');
                const request = store.get(key);
                request.onsuccess = () => resolve(request.result || null);
                request.onerror = () => resolve(null);
            } catch (e) {
                resolve(null);
            }
        });
    }

    /**
     * Write a metadata entry to the __meta IDB store.
     * @param {IDBDatabase} db
     * @param {string} key
     * @param {*} data - Must include _id property matching key
     * @returns {Promise<void>}
     */
    static async _writeMeta(db, key, data) {
        if (!db || !db.objectStoreNames.contains('__meta')) return;
        return new Promise((resolve) => {
            try {
                const tx = db.transaction('__meta', 'readwrite');
                const store = tx.objectStore('__meta');
                const record = { _id: key, ...data };
                const request = store.put(record);
                request.onsuccess = () => resolve();
                request.onerror = () => resolve();
                tx.oncomplete = () => resolve();
            } catch (e) {
                resolve();
            }
        });
    }

    async _initializeEncryption(pin, salt = null, config = {}) {
        const encMetaKey = `lacertadb_${this.name}_encryption`;
        let existingMetadata = null;
        const stored = localStorage.getItem(encMetaKey);

        if (stored) {
            const decoded = this._base64.decode(stored);
            existingMetadata = this._serializer.deserialize(decoded);
        }

        this._encryption = new SecureDatabaseEncryption(config, this._serializer, this._base64);
        const newMeta = await this._encryption.initialize(pin, existingMetadata);

        if (!existingMetadata) {
            const serialized = this._serializer.serialize(newMeta);
            const encoded = this._base64.encode(serialized);
            localStorage.setItem(encMetaKey, encoded);
        }
    }

    async changePin(oldPin, newPin) {
        if (!this._encryption) {
            throw new Error('Database is not encrypted');
        }

        const newMeta = await this._encryption.changePin(oldPin, newPin);

        const encMetaKey = `lacertadb_${this.name}_encryption`;
        const serialized = this._serializer.serialize(newMeta);
        const encoded = this._base64.encode(serialized);
        localStorage.setItem(encMetaKey, encoded);

        return true;
    }

    async storePrivateKey(keyName, privateKey, additionalAuth = '') {
        if (!this._encryption) {
            throw new Error('Database must be encrypted to store private keys');
        }

        const encryptedKey = await this._encryption.encryptPrivateKey(
            privateKey,
            additionalAuth
        );

        let keyStore = await this.getCollection('__private_keys__').catch(() => null);
        if (!keyStore) {
            keyStore = await this.createCollection('__private_keys__');
        }

        await keyStore.add({
            name: keyName,
            key: encryptedKey,
            createdAt: Date.now()
        }, {
            id: keyName,
            permanent: true
        });

        return true;
    }

    async getPrivateKey(keyName, additionalAuth = '') {
        if (!this._encryption) {
            throw new Error('Database must be encrypted to retrieve private keys');
        }

        const keyStore = await this.getCollection('__private_keys__');
        const doc = await keyStore.get(keyName);

        if (!doc) {
            throw new Error(`Private key '${keyName}' not found`);
        }

        return await this._encryption.decryptPrivateKey(doc.key, additionalAuth);
    }

    async createCollection(name, options) {
        if (this._collections.has(name)) {
            throw new LacertaDBError(`Collection '${name}' already exists.`, 'COLLECTION_EXISTS');
        }

        // Ensure the object store exists in the consolidated IDB
        await this._ensureStore(name);

        const collection = new Collection(name, this);
        this._collections.set(name, collection);

        if (!this._metadata.collections[name]) {
            this._metadata.setCollection(new CollectionMetadata(
                name, {}, this._serializer, this._base64, this.name, this._db
            ));
        }
        return collection;
    }

    async getCollection(name) {
        if (this._collections.has(name)) {
            const collection = this._collections.get(name);
            if (!collection.initialized) {
                await collection.init();
            }
            return collection;
        }
        if (this._metadata.collections[name]) {
            // Ensure store exists before initializing
            await this._ensureStore(name);
            const collection = new Collection(name, this);
            this._collections.set(name, collection);
            await collection.init();
            return collection;
        }
        throw new LacertaDBError(`Collection '${name}' not found.`, 'COLLECTION_NOT_FOUND');
    }

    /**
     * Ensure a collection handle exists in memory without triggering init().
     * Creates the IDB object store if needed.
     * The collection will lazy-init on first actual operation.
     * @param {string} name
     * @returns {Collection}
     */
    ensureCollection(name) {
        if (this._collections.has(name)) {
            return this._collections.get(name);
        }
        // Mark store as known — will be created on next _ensureStore or IDB open
        if (!this._knownStores.has(name)) {
            this._knownStores.add(name);
            // Persist so warm start creates all stores in one shot
            try {
                const serialized = this._serializer.serialize(Array.from(this._knownStores));
                const encoded = this._base64.encode(serialized);
                localStorage.setItem(this._idbStoresKey, encoded);
            } catch (_) {}
        }
        const collection = new Collection(name, this);
        this._collections.set(name, collection);
        if (!this._metadata.collections[name]) {
            this._metadata.setCollection(new CollectionMetadata(
                name, {}, this._serializer, this._base64, this.name, this._db
            ));
        }
        return collection;
    }

    async dropCollection(name) {
        if (this._collections.has(name)) {
            const collection = this._collections.get(name);
            if (collection.initialized) {
                await collection.clear({ force: true });
                collection.destroy();
            }
            this._collections.delete(name);
        }

        this._metadata.removeCollection(name);

        // Clean up collection-level metadata and index localStorage keys
        localStorage.removeItem(`lacertadb_${this.name}_${name}_collmeta`);
        localStorage.removeItem(`lacertadb_${this.name}_${name}_indexes`);

        // Clear the store contents (can't delete an object store without version bump,
        // but clearing it is equivalent for our purposes — the empty store costs nothing)
        if (this._db && this._knownStores.has(name)) {
            try {
                const idbUtil = new IndexedDBUtility();
                await idbUtil.clear(this._db, name);
            } catch (e) {
                // Store may not exist yet if collection was never initialized
            }
        }

        // Also clean up old per-collection database if it exists (migration residue)
        const legacyDbName = `${this.name}_${name}`;
        try {
            await new Promise((resolve, reject) => {
                const deleteReq = indexedDB.deleteDatabase(legacyDbName);
                deleteReq.onsuccess = resolve;
                deleteReq.onerror = resolve; // don't fail if it doesn't exist
                deleteReq.onblocked = resolve;
            });
        } catch (e) {}
    }

    /**
     * Migrate data from old per-collection databases to the consolidated database.
     * Runs once on first load with the new schema. Safe to call multiple times.
     * @private
     */
    async _migrateOldDatabases() {
        const migrationKey = `lacertadb_${this.name}_consolidated`;
        if (localStorage.getItem(migrationKey)) return; // already migrated

        const collectionNames = Object.keys(this._metadata.collections || {});
        if (collectionNames.length === 0) {
            localStorage.setItem(migrationKey, '1');
            return;
        }

        let migrated = 0;
        for (const collName of collectionNames) {
            const legacyDbName = `${this.name}_${collName}`;

            try {
                // Try to open the old per-collection database
                const oldDb = await new Promise((resolve, reject) => {
                    const request = indexedDB.open(legacyDbName, 1);
                    request.onerror = () => resolve(null);
                    request.onsuccess = () => resolve(request.result);
                    request.onupgradeneeded = (event) => {
                        // If version was 0, it's a brand new DB — nothing to migrate
                        if (event.oldVersion === 0) {
                            event.target.transaction.abort();
                            resolve(null);
                        }
                    };
                });

                if (!oldDb) {
                    // Clean up ghost database created by the probe
                    indexedDB.deleteDatabase(legacyDbName);
                    continue;
                }

                // Check if the old DB has a 'documents' store
                if (!oldDb.objectStoreNames.contains('documents')) {
                    oldDb.close();
                    continue;
                }

                // Read all documents from the old database
                const oldDocs = await new Promise((resolve, reject) => {
                    const tx = oldDb.transaction('documents', 'readonly');
                    const store = tx.objectStore('documents');
                    const request = store.getAll();
                    request.onsuccess = () => resolve(request.result || []);
                    request.onerror = () => resolve([]);
                });

                oldDb.close();

                if (oldDocs.length === 0) continue;

                // Ensure the new consolidated store exists
                await this._ensureStore(collName);

                // Write all documents to the new consolidated store
                const idbUtil = new IndexedDBUtility();
                const ops = oldDocs.map(doc => ({ type: 'put', data: doc }));
                // Use performTransaction directly since batchOperation hardcodes 'documents'
                await idbUtil.performTransaction(this._db, [collName], 'readwrite', tx => {
                    const store = tx.objectStore(collName);
                    const promises = ops.map(op => {
                        return new Promise((resolve, reject) => {
                            const req = store.put(op.data);
                            req.onsuccess = () => resolve();
                            req.onerror = () => resolve(); // skip individual failures
                        });
                    });
                    return Promise.all(promises);
                });

                // Delete the old database
                await new Promise((resolve) => {
                    const deleteReq = indexedDB.deleteDatabase(legacyDbName);
                    deleteReq.onsuccess = resolve;
                    deleteReq.onerror = resolve;
                    deleteReq.onblocked = resolve;
                });

                migrated++;
            } catch (e) {
                console.warn(`[LacertaDB] Migration of '${collName}' failed:`, e.message);
            }
        }

        if (migrated > 0) {
            console.log(`[LacertaDB] Migrated ${migrated} collections to consolidated database`);
        }

        localStorage.setItem(migrationKey, '1');
    }

    listCollections() {
        return Object.keys(this._metadata.collections);
    }

    getStats() {
        return {
            name: this.name,
            totalSizeKB: this._metadata.totalSizeKB,
            totalDocuments: this._metadata.totalLength,
            collections: Object.entries(this._metadata.collections).map(([name, data]) => ({
                name,
                sizeKB: data.sizeKB,
                documents: data.length,
                createdAt: new Date(data.createdAt).toISOString(),
                modifiedAt: new Date(data.modifiedAt).toISOString()
            }))
        };
    }

    updateSettings(newSettings) {
        this._settings.updateSettings(newSettings);
    }

    async export(format = 'json', password = null) {
        const data = {
            version: '0.12.0',
            database: this.name,
            timestamp: Date.now(),
            collections: {}
        };

        for (const collName of this.listCollections()) {
            const collection = await this.getCollection(collName);
            data.collections[collName] = await collection.getAll();
        }

        if (format === 'json') {
            const serialized = this._serializer.serialize(data);
            return this._base64.encode(serialized);
        }
        if (format === 'encrypted' && password) {
            const encryption = new BrowserEncryptionUtility();
            const serializedData = this._serializer.serialize(data);
            const encrypted = await encryption.encrypt(serializedData, password);
            return this._base64.encode(encrypted);
        }
        throw new LacertaDBError(`Unsupported export format: ${format}`, 'INVALID_FORMAT');
    }

    async import(data, format = 'json', password = null) {
        let parsed;
        try {
            const decoded = this._base64.decode(data);
            if (format === 'encrypted' && password) {
                const encryption = new BrowserEncryptionUtility();
                const decrypted = await encryption.decrypt(decoded, password);
                parsed = this._serializer.deserialize(decrypted);
            } else {
                parsed = this._serializer.deserialize(decoded);
            }
        } catch (e) {
            throw new LacertaDBError('Failed to parse import data', 'IMPORT_PARSE_FAILED', e);
        }

        for (const collName in parsed.collections) {
            const docs = parsed.collections[collName];
            let collection;
            try {
                collection = await this.createCollection(collName);
            } catch (e) {
                if (e.code === 'COLLECTION_EXISTS') {
                    collection = await this.getCollection(collName);
                } else {
                    throw e;
                }
            }
            await collection.batchAdd(docs);
        }

        const docCount = Object.values(parsed.collections).reduce((sum, docs) => sum + docs.length, 0);
        return {
            collections: Object.keys(parsed.collections).length,
            documents: docCount
        };
    }

    async clearAll() {
        await Promise.all([...this._collections.keys()].map(name => this.dropCollection(name)));
        this._collections.clear();
        if (this._metadata) this._metadata.destroy();
        this._metadata = new DatabaseMetadata(this.name, {}, this._serializer, this._base64, this._db);
        this._metadata.save();
        this._quickStore.clear();
    }

    async destroy() {
        // Destroy all collections first
        for (const collection of this._collections.values()) {
            if (collection.initialized) {
                await collection.clear({ force: true });
                collection.destroy();
            }
        }
        this._collections.clear();

        // Close consolidated IDB connection
        if (this._db) {
            this._db.close();
            this._db = null;
        }

        // Clear quickstore
        if (this._quickStore) {
            this._quickStore.destroy();
        }

        // Destroy database metadata
        if (this._metadata) {
            this._metadata.destroy();
        }

        // Destroy encryption
        if (this._encryption) {
            this._encryption.destroy();
        }

        // Clear references
        this._metadata = null;
        this._settings = null;
        this._quickStore = null;
        this._performanceMonitor = null;
    }
}

// ========================
// Main LacertaDB Class
// ========================

class LacertaDB {
    constructor(config = {}) {
        this._databases = new Map();
        this._performanceMonitor = new PerformanceMonitor();

        // Instantiate serializer with user-overridable config merged over defaults
        const serialConfig = { ...TURBO_SERIAL_DEFAULTS, ...(config.turboSerial || {}) };
        this._serializer = new TurboSerial(serialConfig);
        this._base64 = new TurboBase64();
    }

    get performanceMonitor() {
        return this._performanceMonitor;
    }

    get serializer() {
        return this._serializer;
    }

    get base64() {
        return this._base64;
    }

    async getDatabase(name, options = {}) {
        if (!this._databases.has(name)) {
            const db = new Database(name, this._performanceMonitor, this._serializer, this._base64);
            await db.init(options);
            this._databases.set(name, db);
        }
        return this._databases.get(name);
    }

    async getSecureDatabase(name, pin, salt = null, encryptionConfig = {}) {
        return this.getDatabase(name, { pin, salt, encryptionConfig });
    }

    async dropDatabase(name) {
        if (this._databases.has(name)) {
            const db = this._databases.get(name);
            await db.clearAll();
            db.destroy();
            this._databases.delete(name);
        }

        ['metadata', 'settings', 'version', 'encryption', 'idb_version', 'idb_stores', 'consolidated'].forEach(suffix => {
            localStorage.removeItem(`lacertadb_${name}_${suffix}`);
        });

        // Clean up quickstore
        const quickStore = new QuickStore(name, this._serializer, this._base64);
        quickStore.clear();

        // Clean up all collection-level localStorage keys
        const keysToRemove = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(`lacertadb_${name}_`)) {
                keysToRemove.push(key);
            }
        }
        keysToRemove.forEach(key => localStorage.removeItem(key));

        // Delete the consolidated IDB database
        await new Promise((resolve) => {
            const deleteReq = indexedDB.deleteDatabase(`lacertadb_${name}`);
            deleteReq.onsuccess = resolve;
            deleteReq.onerror = resolve;
            deleteReq.onblocked = resolve;
        });
    }

    listDatabases() {
        const dbNames = new Set();
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith('lacertadb_')) {
                const match = key.match(/^lacertadb_([^_]+)_(metadata|settings|version|encryption|quickstore)$/);
                if (match) {
                    dbNames.add(match[1]);
                }
            }
        }
        return [...dbNames];
    }

    async createBackup(password = null) {
        const backup = {
            version: '0.12.0',
            timestamp: Date.now(),
            databases: {}
        };

        for (const dbName of this.listDatabases()) {
            const db = await this.getDatabase(dbName);
            const exported = await db.export('json');
            const decoded = this._base64.decode(exported);
            backup.databases[dbName] = this._serializer.deserialize(decoded);
        }

        const serializedBackup = this._serializer.serialize(backup);
        if (password) {
            const encryption = new BrowserEncryptionUtility();
            const encrypted = await encryption.encrypt(serializedBackup, password);
            return this._base64.encode(encrypted);
        }
        return this._base64.encode(serializedBackup);
    }

    async restoreBackup(backupData, password = null) {
        let backup;
        try {
            let decodedData = this._base64.decode(backupData);
            if (password) {
                const encryption = new BrowserEncryptionUtility();
                const decrypted = await encryption.decrypt(decodedData, password);
                backup = this._serializer.deserialize(decrypted);
            } else {
                backup = this._serializer.deserialize(decodedData);
            }
        } catch (e) {
            throw new LacertaDBError('Failed to parse backup data', 'BACKUP_PARSE_FAILED', e);
        }

        const results = { databases: 0, collections: 0, documents: 0 };
        for (const [dbName, dbData] of Object.entries(backup.databases)) {
            const db = await this.getDatabase(dbName);
            const encodedDbData = this._base64.encode(this._serializer.serialize(dbData));
            const importResult = await db.import(encodedDbData);

            results.databases++;
            results.collections += importResult.collections;
            results.documents += importResult.documents;
        }
        return results;
    }

    close() {
        for (const db of this._databases.values()) {
            if (db._db) {
                db._db.close();
                db._db = null;
            }
        }
    }

    destroy() {
        for (const db of this._databases.values()) {
            db.destroy();
        }
        this._databases.clear();
    }
}

// ========================
// Export all components
// ========================

export {
    LacertaDB,
    Database,
    Collection,
    Document,
    MigrationManager,
    PerformanceMonitor,
    LacertaDBError,
    OPFSUtility,
    IndexManager,
    CacheStrategy,
    LRUCache,
    LFUCache,
    TTLCache,
    BTreeIndex,
    TextIndex,
    GeoIndex,
    SecureDatabaseEncryption,
    QuickStore,
    AsyncMutex,
    IndexedDBConnectionPool,
    BrowserCompressionUtility,
    BrowserEncryptionUtility
};
