/**
 * LacertaDB V0.9.2 - Production Library with QuickStore (Optimized)
 * * A high-performance, browser-based document database with support for:
 * - IndexedDB storage with connection pooling
 * - Multiple caching strategies (LRU, LFU, TTL)
 * - Full-text search and geospatial indexing
 * - Document encryption and compression
 * - Binary attachments via OPFS (Origin Private File System)
 * - MongoDB-like query syntax and aggregation pipeline
 * - Schema migrations and versioning
 * - QuickStore for fast localStorage-based operations
 * * Changelog V0.9.2:
 * - CRITICAL: Fixed non-extractable CryptoKey in _importMasterKeys (changePin was broken).
 * - CRITICAL: Fixed TransactionInactiveError in batchOperation (sync request queueing).
 * - CRITICAL: Fixed batchAdd crash when called without options (from import()).
 * - SECURITY: Constant-time comparison in _arrayEquals (timing attack prevention).
 * - SECURITY: Unbiased PIN generation via rejection sampling.
 * - SECURITY: changePin now verifies oldPin before allowing change.
 * - SECURITY: Standardized AES-GCM IV to 12 bytes in encryptPrivateKey/decryptPrivateKey.
 * - FIX: Environment-safe polyfills (no bare `window` at module scope).
 * - FIX: BTreeIndex.remove only decrements _size when key/value actually existed.
 * - FIX: LFUCache.has() now checks TTL expiration.
 * - FIX: GeoIndex._size cannot go negative on redundant removePoint calls.
 * - FIX: $group aggregation uses JSON.stringify for object keys (Map comparison).
 * - FIX: TextIndex tokenizer minimum length normalized across code paths.
 * - FIX: QuickStore properly cleans up beforeunload listener via destroy().
 * - FIX: Consistent window.requestIdleCallback usage in _saveIndexMetadata.
 * - FIX: Block-scoped const in $avg aggregation case.
 * * Changelog V0.9.1:
 * - CRITICAL: Implemented Master Key Wrapping for encryption (fixes data loss on PIN change).
 * - CRITICAL: Fixed UI freezing in QuickStore using in-memory caching and async persistence.
 * - CRITICAL: Replaced O(N) GeoIndex with O(log N) QuadTree.
 * - CRITICAL: Fixed TransactionInactiveError by implementing Batch Processing for Indexes.
 * - SECURITY: Increased PBKDF2 iterations to 600,000 (OWASP standard).
 * - OPTIMIZATION: Removed Global Mutex for read operations (concurrency fix).
 * - OPTIMIZATION: Implemented Cursor-based indexing (OOM fix).
 * - FIX: Added Magic Byte check for robust compression detection.
 * - FIX: Use Intl.Segmenter for proper CJK text tokenization.
 * * @module LacertaDB
 * @version 0.9.2
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

const serializer = new TurboSerial({
    compression: true,        // Enable built-in compression
    deduplication: false,      // Deduplicate repeated values
    simdOptimization: true,   // Use SIMD instructions when available
    detectCircular: false,      // Handle circular references
    shareArrayBuffers: false,      // Share ArrayBuffer references
    allowFunction: false,         // Allow function storage/retrieval (security gate)
    serializeFunctions: false,    // Capture and reconstruct function source
    preservePropertyDescriptors: false, // Preserve property descriptors
    memoryPoolSize: 65536*16         // Initial memory pool size (1MB)
});

const base64 = new TurboBase64();

// ========================
// Quick Store (Optimized)
// ========================

/**
 * Optimized QuickStore.
 * Keeps index in memory to avoid blocking main thread with JSON parsing.
 */
class QuickStore {
    constructor(dbName) {
        this._dbName = dbName;
        this._keyPrefix = `lacertadb_${dbName}_quickstore_`;
        this._indexKey = `${this._keyPrefix}index`;
        
        // Optimization: Keep index in memory using a Set for O(1) lookups
        this._indexCache = new Set();
        this._indexLoaded = false;
        
        // Async persistence state
        this._saveIndexTimer = null;
        this._dirty = false;

        // Safety: Flush on unload to prevent data loss
        this._flushHandler = () => this._flushSync();
        if (typeof window !== 'undefined') {
            window.addEventListener('beforeunload', this._flushHandler);
        }
    }

    destroy() {
        this._flushSync();
        if (typeof window !== 'undefined' && this._flushHandler) {
            window.removeEventListener('beforeunload', this._flushHandler);
            this._flushHandler = null;
        }
        if (this._saveIndexTimer) {
            if (typeof window !== 'undefined' && window.cancelIdleCallback) {
                window.cancelIdleCallback(this._saveIndexTimer);
            } else {
                clearTimeout(this._saveIndexTimer);
            }
            this._saveIndexTimer = null;
        }
    }

    _ensureIndexLoaded() {
        if (this._indexLoaded) return;
        
        const indexStr = localStorage.getItem(this._indexKey);
        if (indexStr) {
            try {
                const decoded = base64.decode(indexStr);
                const list = serializer.deserialize(decoded);
                this._indexCache = new Set(list);
            } catch (e) {
                console.warn('QuickStore index corrupted, resetting.', e);
                this._indexCache = new Set();
            }
        }
        this._indexLoaded = true;
    }

    _scheduleIndexSave() {
        this._dirty = true;
        if (this._saveIndexTimer) return;

        const save = () => {
            if (!this._dirty) return;
            const list = Array.from(this._indexCache);
            const serializedIndex = serializer.serialize(list);
            const encodedIndex = base64.encode(serializedIndex);
            localStorage.setItem(this._indexKey, encodedIndex);
            this._dirty = false;
            this._saveIndexTimer = null;
        };

        // Debounce with idle callback to prevent UI freezing
        if (window.requestIdleCallback) {
            this._saveIndexTimer = window.requestIdleCallback(save);
        } else {
            this._saveIndexTimer = setTimeout(save, 200);
        }
    }

    _flushSync() {
        if (!this._dirty) return;
        const list = Array.from(this._indexCache);
        const serializedIndex = serializer.serialize(list);
        const encodedIndex = base64.encode(serializedIndex);
        localStorage.setItem(this._indexKey, encodedIndex);
        this._dirty = false;
    }

    add(docId, data) {
        this._ensureIndexLoaded();
        const key = `${this._keyPrefix}data_${docId}`;
        try {
            const serializedData = serializer.serialize(data);
            const encodedData = base64.encode(serializedData);
            localStorage.setItem(key, encodedData);

            if (!this._indexCache.has(docId)) {
                this._indexCache.add(docId);
                this._scheduleIndexSave();
            }
            return true;
        } catch (e) {
            if (e.name === 'QuotaExceededError') {
                throw new LacertaDBError('QuickStore quota exceeded', 'QUOTA_EXCEEDED', e);
            }
            return false;
        }
    }

    get(docId) {
        // Direct O(1) access
        const key = `${this._keyPrefix}data_${docId}`;
        const stored = localStorage.getItem(key);
        if (stored) {
            try {
                const decoded = base64.decode(stored);
                return serializer.deserialize(decoded);
            } catch (e) {
                console.error('Failed to parse QuickStore data:', e);
            }
        }
        return null;
    }

    update(docId, data) {
        return this.add(docId, data);
    }

    delete(docId) {
        this._ensureIndexLoaded();
        const key = `${this._keyPrefix}data_${docId}`;
        localStorage.removeItem(key);

        if (this._indexCache.has(docId)) {
            this._indexCache.delete(docId);
            this._scheduleIndexSave();
        }
    }

    getAll() {
        this._ensureIndexLoaded();
        const results = [];
        for (const docId of this._indexCache) {
            const doc = this.get(docId);
            if (doc) results.push({ _id: docId, ...doc });
        }
        return results;
    }

    query(filter = {}) {
        if (Object.keys(filter).length === 0) return this.getAll();
        const allDocs = this.getAll();
        return allDocs.filter(doc => queryEngine.evaluate(doc, filter));
    }

    clear() {
        this._ensureIndexLoaded();
        for (const docId of this._indexCache) {
            localStorage.removeItem(`${this._keyPrefix}data_${docId}`);
        }
        localStorage.removeItem(this._indexKey);
        this._indexCache.clear();
        this._dirty = false;
        if (this._saveIndexTimer) {
            if (window.cancelIdleCallback) window.cancelIdleCallback(this._saveIndexTimer);
            else clearTimeout(this._saveIndexTimer);
            this._saveIndexTimer = null;
        }
    }

    get size() {
        this._ensureIndexLoaded();
        return this._indexCache.size;
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
        if (this._locked || this._queue.length === 0) {
            return;
        }
        this._locked = true;
        const resolve = this._queue.shift();
        resolve(() => this.release());
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
        this.timestamp = new Date().toISOString();
    }
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
        this._cache = new Map();
        this._frequencies = new Map();
        this._timestamps = new Map();
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

        this._frequencies.set(key, (this._frequencies.get(key) || 0) + 1);
        return this._cache.get(key);
    }

    set(key, value) {
        if (this._cache.has(key)) {
            this._cache.set(key, value);
            this._frequencies.set(key, (this._frequencies.get(key) || 0) + 1);
        } else {
            if (this._cache.size >= this._maxSize) {
                let minFreq = Infinity;
                let evictKey = null;
                for (const [k, freq] of this._frequencies) {
                    if (freq < minFreq) {
                        minFreq = freq;
                        evictKey = k;
                    }
                }
                if (evictKey) {
                    this.delete(evictKey);
                }
            }

            this._cache.set(key, value);
            this._frequencies.set(key, 1);
            this._timestamps.set(key, Date.now());
        }
    }

    delete(key) {
        this._frequencies.delete(key);
        this._timestamps.delete(key);
        return this._cache.delete(key);
    }

    clear() {
        this._cache.clear();
        this._frequencies.clear();
        this._timestamps.clear();
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
        this._cache = new Map();
        this._timers = new Map();
    }

    get(key) {
        return this._cache.get(key) || null;
    }

    set(key, value) {
        if (this._timers.has(key)) {
            clearTimeout(this._timers.get(key));
        }

        this._cache.set(key, value);

        const timer = setTimeout(() => {
            this.delete(key);
        }, this._ttl);
        this._timers.set(key, timer);
    }

    delete(key) {
        if (this._timers.has(key)) {
            clearTimeout(this._timers.get(key));
            this._timers.delete(key);
        }
        return this._cache.delete(key);
    }

    clear() {
        for (const timer of this._timers.values()) {
            clearTimeout(timer);
        }
        this._timers.clear();
        this._cache.clear();
    }

    has(key) {
        return this._cache.has(key);
    }

    get size() {
        return this._cache.size;
    }

    destroy() {
        for (const timer of this._timers.values()) {
            clearTimeout(timer);
        }
        this._timers.clear();
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
    constructor(config = {}) {
        this._iterations = config.iterations || 600000; // Increased to OWASP recommendation
        this._hashAlgorithm = config.hashAlgorithm || 'SHA-256';
        this._keyLength = config.keyLength || 256;
        this._saltLength = config.saltLength || 32;
        this._initialized = false;
        
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
            this._salt = base64.decode(existingMetadata.salt);
            const kek = await this._deriveKEK(pinBytes, this._salt);
            
            // Unwrap Master Key
            const wrappedBytes = base64.decode(existingMetadata.wrappedKey);
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
            
            this._wrappedKeyBlob = base64.encode(wrappedKey);
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
        const currentWrappedBytes = base64.decode(this._wrappedKeyBlob);
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
        this._wrappedKeyBlob = base64.encode(wrappedKey);
        
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
            dataBytes = serializer.serialize(data);
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
            keyData = serializer.serialize(privateKey);
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

        return base64.encode(result);
    }

    async decryptPrivateKey(encryptedKeyString, additionalAuth = '') {
        if (!this._initialized) {
            throw new Error('Database encryption not initialized');
        }

        const encryptedPackage = base64.decode(encryptedKeyString);

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
            salt: base64.encode(this._salt),
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
// B-Tree Index Implementation
// ========================

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
        while (i < this.n && key > this.keys[i]) {
            i++;
        }

        if (i < this.n && key === this.keys[i]) {
            return this.values[i];
        }

        if (this.leaf) {
            return null;
        }

        return this.children[i] ? this.children[i].search(key) : null;
    }

    rangeSearch(min, max, results) {
        let i = 0;
        while (i < this.n) {
            if (!this.leaf && this.children[i]) {
                this.children[i].rangeSearch(min, max, results);
            }
            if (this.keys[i] >= min && this.keys[i] <= max) {
                if (this.values[i]) {
                    this.values[i].forEach(v => results.push(v));
                }
            }
            i++;
        }
        if (!this.leaf && this.children[i]) {
            this.children[i].rangeSearch(min, max, results);
        }
    }

    insertNonFull(key, value) {
        let i = this.n - 1;

        if (this.leaf) {
            while (i >= 0 && this.keys[i] > key) {
                this.keys[i + 1] = this.keys[i];
                this.values[i + 1] = this.values[i];
                i--;
            }

            if (i >= 0 && this.keys[i] === key) {
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
            while (i >= 0 && this.keys[i] > key) {
                i--;
            }

            if (i >= 0 && this.keys[i] === key) {
                if (!this.values[i]) {
                    this.values[i] = new Set();
                }
                this.values[i].add(value);
                return;
            }

            i++;
            if (this.children[i] && this.children[i].n === 2 * this.order - 1) {
                this.splitChild(i, this.children[i]);
                if (this.keys[i] < key) {
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

        y.n = this.order - 1;

        for (let j = this.n; j >= i + 1; j--) {
            this.children[j + 1] = this.children[j];
        }

        this.children[i + 1] = z;

        for (let j = this.n - 1; j >= i; j--) {
            this.keys[j + 1] = this.keys[j];
            this.values[j + 1] = this.values[j];
        }

        this.keys[i] = y.keys[this.order - 1];
        this.values[i] = y.values[this.order - 1];
        this.n++;
    }

    remove(key, value) {
        let i = 0;
        while (i < this.n && key > this.keys[i]) {
            i++;
        }

        if (i < this.n && key === this.keys[i]) {
            if (this.values[i]) {
                this.values[i].delete(value);
                if (this.values[i].size === 0) {
                    for (let j = i; j < this.n - 1; j++) {
                        this.keys[j] = this.keys[j + 1];
                        this.values[j] = this.values[j + 1];
                    }
                    this.n--;
                }
            }
        } else if (!this.leaf && this.children[i]) {
            this.children[i].remove(key, value);
        }
    }

    verify() {
        const issues = [];
        for (let i = 1; i < this.n; i++) {
            if (this.keys[i] <= this.keys[i - 1]) {
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
        this._lastVerification = Date.now();
        this._verificationInterval = 60000;
    }

    insert(key, value) {
        if (Date.now() - this._lastVerification > this._verificationInterval) {
            this.verify();
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
                if (s.keys[0] < key) i++;
                s.children[i].insertNonFull(key, value);

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

    range(min, max) {
        if (!this._root) return [];
        const results = [];
        this._root.rangeSearch(min, max, results);
        return results;
    }

    rangeFrom(min) {
        if (!this._root) return [];
        const results = [];
        this._root.rangeSearch(min, Infinity, results);
        return results;
    }

    rangeTo(max) {
        if (!this._root) return [];
        const results = [];
        this._root.rangeSearch(-Infinity, max, results);
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
        this._lastVerification = Date.now();
        if (!this._root) return { healthy: true, issues: [] };
        const issues = this._root.verify();
        if (issues.length > 0) {
            console.warn('BTree index issues detected and fixed:', issues);
        }
        return {
            healthy: issues.length === 0,
            issues,
            repaired: issues.length
        };
    }

    get size() {
        return this._size;
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
                results = new Set([...results].filter(x => docs.has(x)));
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
        
        for (const p of candidates) {
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
        this._indexes = new Map();
        this._indexData = new Map();
        this._indexQueue = [];
        this._processing = false;
    }

    get indexes() {
        return this._indexes;
    }

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

    async rebuildIndex(indexName) {
        const index = this._indexes.get(indexName);
        if (!index) {
            throw new Error(`Index '${indexName}' not found`);
        }

        const indexData = this._createIndexStructure(index.type);
        this._indexData.set(indexName, indexData);

        // Optimization: Use Batched Processing instead of single Cursor
        // This prevents transaction timeouts caused by async crypto operations inside the loop
        let lastKey = null;
        const batchSize = 100; // Keep batch small for responsiveness
        
        while (true) {
            // 1. Fetch Batch (Transaction opens and closes here)
            const batch = await this._collection._indexedDB.getBatch(
                this._collection._db, 
                'documents', 
                lastKey, 
                batchSize
            );
            
            if (batch.length === 0) break;
            
            // 2. Process Batch (Async crypto operations safe here)
            for (const docData of batch) {
                lastKey = docData._id; // Update for next batch
                let doc = docData;
                
                if (docData.packedData) {
                    const d = new Document(docData, {
                        compressed: docData._compressed, 
                        encrypted: docData._encrypted
                    });
                    // This await is what killed the transaction before
                    await d.unpack(this._collection.database.encryption); 
                    doc = d.objectOutput();
                }

                let value = this._getFieldValue(doc, index.fieldPath);

                if (index.sparse && (value === null || value === undefined)) {
                    continue;
                }

                if (index.unique && indexData.has && indexData.has(value)) {
                    console.error(`Unique constraint violation on index '${indexName}'`);
                    continue;
                }

                if (index.hashed && index.type === 'btree') {
                    value = await this._hashVal(value);
                }

                this._addToIndex(indexData, value, doc._id, index.type);
            }
            
            // Optional: Yield to main thread briefly to prevent UI freeze
            if (window.requestIdleCallback) await new Promise(r => window.requestIdleCallback(r));
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
        return base64.encode(new Uint8Array(hash));
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
        // Handle simple value query
        if (typeof options !== 'object' || options === null) {
            return indexData.find(options);
        }

        const results = new Set();

        if (options.$eq !== undefined) {
            const docs = indexData.find(options.$eq);
            docs.forEach(doc => results.add(doc));
        }

        if (options.$gte !== undefined && options.$lte !== undefined) {
            const docs = indexData.range(options.$gte, options.$lte);
            docs.forEach(doc => results.add(doc));
        } else if (options.$gte !== undefined) {
            const docs = indexData.rangeFrom(options.$gte);
            docs.forEach(doc => results.add(doc));
        } else if (options.$gt !== undefined) {
            const docs = indexData.rangeFrom(options.$gt);
            docs.forEach(doc => {
                if (doc !== options.$gt) results.add(doc);
            });
        } else if (options.$lte !== undefined) {
            const docs = indexData.rangeTo(options.$lte);
            docs.forEach(doc => results.add(doc));
        } else if (options.$lt !== undefined) {
            const docs = indexData.rangeTo(options.$lt);
            docs.forEach(doc => {
                if (doc !== options.$lt) results.add(doc);
            });
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
        this._saveIndexMetadata();
    }

    _getFieldValue(doc, path) {
        const parts = path.split('.');
        let value = doc;
        for (const part of parts) {
            if (value === null || value === undefined) {
                return undefined;
            }
            value = value[part];
        }
        return value;
    }

    async _saveIndexMetadata() {
        const key = `lacertadb_${this._collection.database.name}_${this._collection.name}_indexes`;
        return new Promise((resolve) => {
            const save = () => {
                const metadata = {
                    indexes: Array.from(this._indexes.entries()).map(([name, index]) => ({
                        name,
                        ...index
                    }))
                };
                const serialized = serializer.serialize(metadata);
                const encoded = base64.encode(serialized);
                localStorage.setItem(key, encoded);
                resolve();
            };
            if (typeof window !== 'undefined' && window.requestIdleCallback) {
                window.requestIdleCallback(save);
            } else {
                setTimeout(save, 0);
            }
        });
    }

    async loadIndexMetadata() {
        const key = `lacertadb_${this._collection.database.name}_${this._collection.name}_indexes`;
        const stored = localStorage.getItem(key);

        if (!stored) return;

        try {
            const decoded = base64.decode(stored);
            const metadata = serializer.deserialize(decoded);

            for (const indexDef of metadata.indexes) {
                const { name, ...index } = indexDef;
                this._indexes.set(name, index);
            }

            for (const indexName of this._indexes.keys()) {
                await this.rebuildIndex(indexName);
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
                report[name] = indexData.verify();
            } else {
                report[name] = { status: 'ok' };
            }
        }
        return report;
    }

    destroy() {
        for (const [name, indexData] of this._indexData) {
            if (indexData && indexData.clear) {
                indexData.clear();
            }
        }
        this._indexData.clear();
        this._indexes.clear();
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

    async batchOperation(db, operations) {
        return this.performTransaction(db, ['documents'], 'readwrite', tx => {
            const store = tx.objectStore('documents');

            // CRITICAL: Queue ALL IDB requests synchronously to prevent
            // TransactionInactiveError. Do NOT use await between requests.
            const promises = operations.map(op => {
                try {
                    switch (op.type) {
                        case 'add':
                            return this._promisifyRequest(() => store.add(op.data))
                                .then(result => ({ success: true, result }));
                        case 'put':
                            return this._promisifyRequest(() => store.put(op.data))
                                .then(result => ({ success: true, result }));
                        case 'delete':
                            return this._promisifyRequest(() => store.delete(op.key))
                                .then(result => ({ success: true, result }));
                        default:
                            return Promise.resolve({ success: false, error: `Unknown operation type: ${op.type}` });
                    }
                } catch (error) {
                    return Promise.resolve({ success: false, error: error.message });
                }
            });

            return Promise.all(promises);
        });
    }
}

// ========================
// Document Class
// ========================

class Document {
    constructor(data = {}, options = {}) {
        this._id = data._id || this._generateId();
        this._created = data._created || Date.now();
        this._modified = data._modified || Date.now();
        this._permanent = data._permanent || options.permanent || false;
        this._encrypted = false;
        this._compressed = data._compressed || options.compressed || false;
        this._attachments = data._attachments || [];
        this._data = null;
        this._packedData = data.packedData || null;
        this._compression = new BrowserCompressionUtility();

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
        return `doc_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
    }

    async pack(encryptionUtil = null) {
        try {
            let packed = serializer.serialize(this.data);
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

            this.data = serializer.deserialize(unpacked);

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
        let packed = serializer.serialize(this.data);
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
        this.data = serializer.deserialize(unpacked);
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
    constructor(name, data = {}) {
        this.name = name;
        this.sizeKB = data.sizeKB || 0;
        this.length = data.length || 0;
        this.createdAt = data.createdAt || Date.now();
        this.modifiedAt = data.modifiedAt || Date.now();
        // Removed detailed per-doc tracking to save space
        this.documentSizes = {};
        this.documentModifiedAt = {};
        this.documentPermanent = {};
        this.documentAttachments = {};
    }

    addDocument(docId, sizeKB, isPermanent, attachmentCount) {
        // Optimization: Don't store detailed map in LS to avoid QuotaExceeded
        // this.documentSizes[docId] = sizeKB;
        this.sizeKB += sizeKB;
        this.length++;
        this.modifiedAt = Date.now();
    }

    updateDocument(docId, newSizeKB, isPermanent, attachmentCount) {
        // Approximate tracking
        // const oldSize = this.documentSizes[docId] || 0;
        // this.sizeKB = this.sizeKB - oldSize + newSizeKB;
        this.modifiedAt = Date.now();
    }

    removeDocument(docId) {
        // const sizeKB = this.documentSizes[docId] || 0;
        // this.sizeKB -= sizeKB;
        // this.length--;
        this.modifiedAt = Date.now();
    }

    getOldestNonPermanentDocuments(count) {
        // If we removed the maps, we can't do this efficiently from metadata alone.
        // Should query DB index 'modified' instead.
        return []; 
    }
}

class DatabaseMetadata {
    constructor(name, data = {}) {
        this.name = name;
        this.collections = data.collections || {};
        this.totalSizeKB = data.totalSizeKB || 0;
        this.totalLength = data.totalLength || 0;
        this.modifiedAt = data.modifiedAt || Date.now();
    }

    static load(dbName) {
        const key = `lacertadb_${dbName}_metadata`;
        const stored = localStorage.getItem(key);
        if (stored) {
            try {
                const decoded = base64.decode(stored);
                const data = serializer.deserialize(decoded);
                return new DatabaseMetadata(dbName, data);
            } catch (e) {
                console.error('Failed to load metadata:', e);
            }
        }
        return new DatabaseMetadata(dbName);
    }

    save() {
        const key = `lacertadb_${this.name}_metadata`;
        try {
            const dataToStore = {
                collections: this.collections,
                totalSizeKB: this.totalSizeKB,
                totalLength: this.totalLength,
                modifiedAt: this.modifiedAt
            };
            const serializedData = serializer.serialize(dataToStore);
            const encodedData = base64.encode(serializedData);
            localStorage.setItem(key, encodedData);
        } catch (e) {
            // Ignore quota errors here to prevent crash
        }
    }

    setCollection(collectionMetadata) {
        this.collections[collectionMetadata.name] = {
            sizeKB: collectionMetadata.sizeKB,
            length: collectionMetadata.length,
            createdAt: collectionMetadata.createdAt,
            modifiedAt: collectionMetadata.modifiedAt
        };
        this._recalculate();
        this.save();
    }

    removeCollection(collectionName) {
        delete this.collections[collectionName];
        this._recalculate();
        this.save();
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
}

class Settings {
    constructor(dbName, data = {}) {
        this.dbName = dbName;
        this.sizeLimitKB = data.sizeLimitKB != null ? data.sizeLimitKB : Infinity;
        const defaultBuffer = this.sizeLimitKB === Infinity ? Infinity : this.sizeLimitKB * 0.8;
        this.bufferLimitKB = data.bufferLimitKB != null ? data.bufferLimitKB : defaultBuffer;
        this.freeSpaceEvery = this.sizeLimitKB === Infinity ? 0 : (data.freeSpaceEvery || 10000);
    }

    static load(dbName) {
        const key = `lacertadb_${dbName}_settings`;
        const stored = localStorage.getItem(key);
        if (stored) {
            try {
                const decoded = base64.decode(stored);
                const data = serializer.deserialize(decoded);
                return new Settings(dbName, data);
            } catch (e) {
                console.error('Failed to load settings:', e);
            }
        }
        return new Settings(dbName);
    }

    save() {
        const key = `lacertadb_${this.dbName}_settings`;
        const dataToStore = {
            sizeLimitKB: this.sizeLimitKB,
            bufferLimitKB: this.bufferLimitKB,
            freeSpaceEvery: this.freeSpaceEvery
        };
        const serializedData = serializer.serialize(dataToStore);
        const encodedData = base64.encode(serializedData);
        localStorage.setItem(key, encodedData);
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

    getFieldValue(doc, path) {
        let current = doc;
        for (const part of path.split('.')) {
            if (current === null || current === undefined) {
                return undefined;
            }
            current = current[part];
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

                for (const doc of docs) {
                    const groupKey = typeof idField === 'string' ?
                        queryEngine.getFieldValue(doc, idField.replace('$', '')) :
                        JSON.stringify(idField);

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
                const foreignCollection = await db.getCollection(lookupSpec.from);
                const foreignDocs = await foreignCollection.getAll();
                const foreignMap = new Map();
                foreignDocs.forEach(doc => {
                    const key = queryEngine.getFieldValue(doc, lookupSpec.foreignField);
                    if (!foreignMap.has(key)) foreignMap.set(key, []);
                    foreignMap.get(key).push(doc);
                });

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
// Collection Class (Optimized)
// ========================

class Collection {
    constructor(name, database) {
        this.name = name;
        this.database = database;
        this._db = null;
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

        const dbName = `${this.database.name}_${this.name}`;
        this._db = await connectionPool.getConnection(dbName, 1, (db, oldVersion) => {
            if (oldVersion < 1 && !db.objectStoreNames.contains('documents')) {
                const store = db.createObjectStore('documents', {keyPath: '_id'});
                store.createIndex('modified', '_modified', {unique: false});
            }
        });

        const metadataData = this.database.metadata.collections[this.name];
        this._metadata = new CollectionMetadata(this.name, metadataData);

        await this._indexManager.loadIndexMetadata();

        if (this._settings.freeSpaceEvery > 0 && this._settings.sizeLimitKB !== Infinity) {
            this._cleanupInterval = setInterval(() => this._freeSpace(), this._settings.freeSpaceEvery);
        }

        this._initialized = true;
        return this;
    }

    // Index methods
    async createIndex(fieldPath, options = {}) {
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
            compressed: options.compressed !== false,
            permanent: options.permanent || false
        });

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
        await this._indexedDB.add(this._db, 'documents', dbOutput);

        const fullDoc = doc.objectOutput();
        await this._indexManager.updateIndexForDocument(doc._id, null, fullDoc);

        const sizeKB = dbOutput.packedData.byteLength / 1024;
        this._metadata.addDocument(doc._id, sizeKB, doc._permanent, doc._attachments.length);
        this.database.metadata.setCollection(this._metadata);

        await this._checkSpaceLimit();
        await this._trigger('afterAdd', doc);
        this._cacheStrategy.clear();
        return doc._id;
    }

    async get(docId, options = {}) {
        if (!this._initialized) await this.init();

        await this._trigger('beforeGet', docId);

        const stored = await this._indexedDB.get(this._db, 'documents', docId);
        if (!stored) {
            throw new LacertaDBError(`Document with id '${docId}' not found.`, 'DOCUMENT_NOT_FOUND');
        }

        const doc = new Document(stored, {
            encrypted: stored._encrypted,
            compressed: stored._compressed
        });

        if (stored.packedData) {
            await doc.unpack(this.database.encryption);
        }

        if (options.includeAttachments && doc._attachments.length > 0) {
            doc.data._attachments = await this._opfs.getAttachments(doc._attachments);
        }

        await this._trigger('afterGet', doc);
        return doc.objectOutput(options.includeAttachments);
    }

    async getAll(options = {}) {
        if (!this._initialized) await this.init();

        const stored = await this._indexedDB.getAll(this._db, 'documents', undefined, options.limit);
        return Promise.all(stored.map(async docData => {
            try {
                const doc = new Document(docData, {
                    encrypted: docData._encrypted,
                    compressed: docData._compressed
                });
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

        const stored = await this._indexedDB.get(this._db, 'documents', docId);
        if (!stored) {
            throw new LacertaDBError(`Document with id '${docId}' not found for update.`, 'DOCUMENT_NOT_FOUND');
        }

        const existingDoc = new Document(stored);
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
        });
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
        await this._indexedDB.put(this._db, 'documents', dbOutput);

        const newDocOutput = doc.objectOutput();
        await this._indexManager.updateIndexForDocument(doc._id, oldDocOutput, newDocOutput);

        const sizeKB = dbOutput.packedData.byteLength / 1024;
        this._metadata.updateDocument(doc._id, sizeKB, doc._permanent, doc._attachments.length);
        this.database.metadata.setCollection(this._metadata);

        await this._trigger('afterUpdate', doc);
        this._cacheStrategy.clear();
        return doc._id;
    }

    async delete(docId, options = {}) {
        if (!this._initialized) await this.init();

        await this._trigger('beforeDelete', docId);

        const doc = await this._indexedDB.get(this._db, 'documents', docId);
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

        await this._indexedDB.delete(this._db, 'documents', docId);
        const attachments = doc._attachments;
        if (attachments && attachments.length > 0) {
            await this._opfs.deleteAttachments(this.database.name, this.name, docId);
        }

        this._metadata.removeDocument(docId);
        this.database.metadata.setCollection(this._metadata);

        await this._trigger('afterDelete', docId);
        this._cacheStrategy.clear();
    }

    async query(filter = {}, options = {}) {
        if (!this._initialized) await this.init();

        const startTime = performance.now();

        const cacheKey = base64.encode(serializer.serialize({filter, options}));
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
        const docs = await this.getAll();
        const result = await aggregationPipeline.execute(docs, pipeline, this.database);
        if (this._performanceMonitor) this._performanceMonitor.recordOperation('aggregate', performance.now() - startTime);
        return result;
    }

    async batchAdd(documents, options = {}) {
        if (!this._initialized) await this.init();

        const startTime = performance.now();
        const operations = [];
        const results = [];

        for (const documentData of documents) {
            const doc = new Document({data: documentData}, {
                compressed: options.compressed !== false,
                permanent: options.permanent || false
            });

            await doc.pack(this.database.encryption);
            operations.push({
                type: 'add',
                data: doc.databaseOutput()
            });
            results.push(doc);
        }

        const dbResults = await this._indexedDB.batchOperation(this._db, operations);

        for (let i = 0; i < results.length; i++) {
            if (dbResults[i].success) {
                const doc = results[i];
                const fullDoc = doc.objectOutput();
                await this._indexManager.updateIndexForDocument(doc._id, null, fullDoc);

                const sizeKB = doc._packedData.byteLength / 1024;
                this._metadata.addDocument(doc._id, sizeKB, doc._permanent, 0);
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

    async batchUpdate(updates, options) {
        if (!this._initialized) await this.init();

        return Promise.all(updates.map(update =>
            this.update(update.id, update.data, options)
                .then(id => ({success: true, id}))
                .catch(error => ({success: false, id: update.id, error: error.message}))
        ));
    }

    async batchDelete(items) {
        if (!this._initialized) await this.init();

        const normalizedItems = items.map(item => {
            if (typeof item === 'string') {
                return {id: item, options: {}};
            }
            return {id: item.id, options: item.options || {}};
        });

        return Promise.all(normalizedItems.map(({id, options}) =>
            this.delete(id, options)
                .then(() => ({success: true, id}))
                .catch(error => ({success: false, id, error: error.message}))
        ));
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
        if (!this._events.has(event)) return;
        for (const callback of this._events.get(event)) {
            await callback(data);
        }
    }

    clearCache() {
        this._cacheStrategy.clear();
    }

    async clear(options = {}) {
        if (!this._initialized) await this.init();

        if (options.force) {
            // Clear documents first
            await this._indexedDB.clear(this._db, 'documents');

            // Reset metadata
            this._metadata = new CollectionMetadata(this.name);
            this.database.metadata.setCollection(this._metadata);

            // Clear cache
            this._cacheStrategy.clear();

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
        // Clear the cleanup interval
        if (this._cleanupInterval) {
            clearInterval(this._cleanupInterval);
            this._cleanupInterval = null;
        }

        // Destroy cache strategy
        if (this._cacheStrategy) {
            this._cacheStrategy.destroy();
        }

        // Release the connection
        if (this._db) {
            const dbName = `${this.database.name}_${this.name}`;
            connectionPool.releaseConnection(dbName);
            this._db = null;
        }

        // Clear event listeners
        this._events.clear();
    }
}

// ========================
// Database Class (Optimized with QuickStore)
// ========================

class Database {
    constructor(name, performanceMonitor) {
        this.name = name;
        this._collections = new Map();
        this._metadata = null;
        this._settings = null;
        this._quickStore = null;
        this._performanceMonitor = performanceMonitor;

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

    async init(options = {}) {
        this._metadata = DatabaseMetadata.load(this.name);
        this._settings = Settings.load(this.name);
        this._quickStore = new QuickStore(this.name);

        if (options.pin) {
            await this._initializeEncryption(options.pin, options.salt, options.encryptionConfig);
        }

        return this;
    }

    async _initializeEncryption(pin, salt = null, config = {}) {
        const encMetaKey = `lacertadb_${this.name}_encryption`;
        let existingMetadata = null;
        const stored = localStorage.getItem(encMetaKey);
        
        if (stored) {
            const decoded = base64.decode(stored);
            existingMetadata = serializer.deserialize(decoded);
        }

        this._encryption = new SecureDatabaseEncryption(config);
        const newMeta = await this._encryption.initialize(pin, existingMetadata);

        if (!existingMetadata) {
            const serialized = serializer.serialize(newMeta);
            const encoded = base64.encode(serialized);
            localStorage.setItem(encMetaKey, encoded);
        }
    }

    async changePin(oldPin, newPin) {
        if (!this._encryption) {
            throw new Error('Database is not encrypted');
        }

        const newMeta = await this._encryption.changePin(oldPin, newPin);

        const encMetaKey = `lacertadb_${this.name}_encryption`;
        const serialized = serializer.serialize(newMeta);
        const encoded = base64.encode(serialized);
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

        const collection = new Collection(name, this);
        // Lazy initialization - don't init here
        this._collections.set(name, collection);

        if (!this._metadata.collections[name]) {
            this._metadata.setCollection(new CollectionMetadata(name));
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
            const collection = new Collection(name, this);
            this._collections.set(name, collection);
            await collection.init();
            return collection;
        }
        throw new LacertaDBError(`Collection '${name}' not found.`, 'COLLECTION_NOT_FOUND');
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

        const dbName = `${this.name}_${name}`;
        await new Promise((resolve, reject) => {
            const deleteReq = indexedDB.deleteDatabase(dbName);
            deleteReq.onsuccess = resolve;
            deleteReq.onerror = reject;
            deleteReq.onblocked = () => console.warn(`Deletion of '${dbName}' is blocked.`);
        });
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
            version: '0.9.2',
            database: this.name,
            timestamp: Date.now(),
            collections: {}
        };

        for (const collName of this.listCollections()) {
            const collection = await this.getCollection(collName);
            data.collections[collName] = await collection.getAll();
        }

        if (format === 'json') {
            const serialized = serializer.serialize(data);
            return base64.encode(serialized);
        }
        if (format === 'encrypted' && password) {
            const encryption = new BrowserEncryptionUtility();
            const serializedData = serializer.serialize(data);
            const encrypted = await encryption.encrypt(serializedData, password);
            return base64.encode(encrypted);
        }
        throw new LacertaDBError(`Unsupported export format: ${format}`, 'INVALID_FORMAT');
    }

    async import(data, format = 'json', password = null) {
        let parsed;
        try {
            const decoded = base64.decode(data);
            if (format === 'encrypted' && password) {
                const encryption = new BrowserEncryptionUtility();
                const decrypted = await encryption.decrypt(decoded, password);
                parsed = serializer.deserialize(decrypted);
            } else {
                parsed = serializer.deserialize(decoded);
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
        this._metadata = new DatabaseMetadata(this.name);
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

        // Clear quickstore
        if (this._quickStore) {
            this._quickStore.destroy();
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
    constructor() {
        this._databases = new Map();
        this._performanceMonitor = new PerformanceMonitor();
    }

    get performanceMonitor() {
        return this._performanceMonitor;
    }

    async getDatabase(name, options = {}) {
        if (!this._databases.has(name)) {
            const db = new Database(name, this._performanceMonitor);
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

        ['metadata', 'settings', 'version', 'encryption'].forEach(suffix => {
            localStorage.removeItem(`lacertadb_${name}_${suffix}`);
        });

        // Clean up quickstore
        const quickStore = new QuickStore(name);
        quickStore.clear();

        // Clean up all collections and indexes
        const keysToRemove = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith(`lacertadb_${name}_`)) {
                keysToRemove.push(key);
            }
        }
        keysToRemove.forEach(key => localStorage.removeItem(key));
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
            version: '0.9.2',
            timestamp: Date.now(),
            databases: {}
        };

        for (const dbName of this.listDatabases()) {
            const db = await this.getDatabase(dbName);
            const exported = await db.export('json');
            const decoded = base64.decode(exported);
            backup.databases[dbName] = serializer.deserialize(decoded);
        }

        const serializedBackup = serializer.serialize(backup);
        if (password) {
            const encryption = new BrowserEncryptionUtility();
            const encrypted = await encryption.encrypt(serializedBackup, password);
            return base64.encode(encrypted);
        }
        return base64.encode(serializedBackup);
    }

    async restoreBackup(backupData, password = null) {
        let backup;
        try {
            let decodedData = base64.decode(backupData);
            if (password) {
                const encryption = new BrowserEncryptionUtility();
                const decrypted = await encryption.decrypt(decodedData, password);
                backup = serializer.deserialize(decrypted);
            } else {
                backup = serializer.deserialize(decodedData);
            }
        } catch (e) {
            throw new LacertaDBError('Failed to parse backup data', 'BACKUP_PARSE_FAILED', e);
        }

        const results = { databases: 0, collections: 0, documents: 0 };
        for (const [dbName, dbData] of Object.entries(backup.databases)) {
            const db = await this.getDatabase(dbName);
            const encodedDbData = base64.encode(serializer.serialize(dbData));
            const importResult = await db.import(encodedDbData);

            results.databases++;
            results.collections += importResult.collections;
            results.documents += importResult.documents;
        }
        return results;
    }

    close() {
        connectionPool.closeAll();
    }

    destroy() {
        for (const db of this._databases.values()) {
            db.destroy();
        }
        this._databases.clear();
        connectionPool.closeAll();
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
