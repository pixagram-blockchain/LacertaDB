/**
 * LacertaDB V4 - Complete Core Library (Repaired and Enhanced)
 * A powerful browser-based document database with encryption, compression, and OPFS support
 * @version 4.0.3 (Max Compatibility)
 * @license MIT
 */

'use strict';
// Note: These imports are for browser environments using a bundler (e.g., Webpack, Vite).
// For direct browser usage, you would use an ES module import from a URL or local path.
import TurboSerial from "@pixagram/turboserial";
import TurboBase64 from "@pixagram/turbobase64";

const serializer = new TurboSerial({
    compression: true,
    deduplication: true,
    shareArrayBuffers: true,
    simdOptimization: true,
    detectCircular: true
});
const base64 = new TurboBase64();

/**
 * Async Mutex for managing concurrent operations
 */
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

/**
 * Custom error class for LacertaDB
 */
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
// Compression Utility
// ========================

class BrowserCompressionUtility {
    async compress(input) {
        if (!(input instanceof Uint8Array)) {
            throw new TypeError('Input must be Uint8Array');
        }
        try {
            const stream = new Response(input).body
                .pipeThrough(new CompressionStream('deflate'));
            const compressed = await new Response(stream).arrayBuffer();
            return new Uint8Array(compressed);
        } catch (error) {
            throw new LacertaDBError('Compression failed', 'COMPRESSION_FAILED', error);
        }
    }

    async decompress(compressedData) {
        if (!(compressedData instanceof Uint8Array)) {
            throw new TypeError('Input must be Uint8Array');
        }
        try {
            const stream = new Response(compressedData).body
                .pipeThrough(new DecompressionStream('deflate'));
            const decompressed = await new Response(stream).arrayBuffer();
            return new Uint8Array(decompressed);
        } catch (error) {
            throw new LacertaDBError('Decompression failed', 'DECOMPRESSION_FAILED', error);
        }
    }

    // Fallback sync methods are simple pass-throughs
    compressSync(input) {
        if (!(input instanceof Uint8Array)) {
            throw new TypeError('Input must be Uint8Array');
        }
        return input;
    }

    decompressSync(compressedData) {
        if (!(compressedData instanceof Uint8Array)) {
            throw new TypeError('Input must be Uint8Array');
        }
        return compressedData;
    }
}

// ========================
// Encryption Utility (FIXED & IMPROVED)
// ========================

class BrowserEncryptionUtility {
    async encrypt(data, password) {
        if (!(data instanceof Uint8Array)) {
            throw new TypeError('Data must be Uint8Array');
        }
        try {
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));

            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(password),
                'PBKDF2',
                false,
                ['deriveKey']
            );

            const key = await crypto.subtle.deriveKey({
                    name: 'PBKDF2',
                    salt,
                    iterations: 600000,
                    hash: 'SHA-512'
                },
                keyMaterial, {
                    name: 'AES-GCM',
                    length: 256
                },
                false,
                ['encrypt']
            );

            const encrypted = await crypto.subtle.encrypt({
                    name: 'AES-GCM',
                    iv
                },
                key,
                data
            );

            // The checksum was removed as AES-GCM provides this via an authentication tag.
            const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
            result.set(salt, 0);
            result.set(iv, salt.length);
            result.set(new Uint8Array(encrypted), salt.length + iv.length);

            return result;
        } catch (error) {
            throw new LacertaDBError('Encryption failed', 'ENCRYPTION_FAILED', error);
        }
    }

    async decrypt(wrappedData, password) {
        if (!(wrappedData instanceof Uint8Array)) {
            throw new TypeError('Data must be Uint8Array');
        }
        try {
            const salt = wrappedData.slice(0, 16);
            const iv = wrappedData.slice(16, 28);
            const encryptedData = wrappedData.slice(28);

            const keyMaterial = await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(password),
                'PBKDF2',
                false,
                ['deriveKey']
            );

            const key = await crypto.subtle.deriveKey({
                    name: 'PBKDF2',
                    salt,
                    iterations: 600000,
                    hash: 'SHA-512'
                },
                keyMaterial, {
                    name: 'AES-GCM',
                    length: 256
                },
                false,
                ['decrypt']
            );

            const decrypted = await crypto.subtle.decrypt({
                    name: 'AES-GCM',
                    iv
                },
                key,
                encryptedData
            );

            // Checksum verification removed. crypto.subtle.decrypt will throw on failure.
            return new Uint8Array(decrypted);
        } catch (error) {
            // Provide a more specific error for failed decryption, which often indicates a wrong password.
            throw new LacertaDBError('Decryption failed. This may be due to an incorrect password or corrupted data.', 'DECRYPTION_FAILED', error);
        }
    }
}

// ========================
// OPFS (Origin Private File System) Utility
// ========================

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
                // Optionally, collect errors and return them
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
            // Ignore "NotFoundError" as the directory might already be gone
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
// IndexedDB Utility
// ========================

class IndexedDBUtility {
    constructor() {
        this.mutex = new AsyncMutex();
    }

    openDatabase(dbName, version = 1, upgradeCallback) {
        return new Promise((resolve, reject) => {
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
    }

    async performTransaction(db, storeNames, mode, callback, retries = 3) {
        return this.mutex.runExclusive(async () => {
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
        });
    }

    _promisifyRequest(requestFactory) {
        return new Promise((resolve, reject) => {
            const request = requestFactory();
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
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

    iterateCursorSafe(db, storeName, callback, direction = 'next', query) {
        return this.performTransaction(db, [storeName], 'readonly', tx => {
            return new Promise((resolve, reject) => {
                const results = [];
                const request = tx.objectStore(storeName).openCursor(query, direction);

                request.onsuccess = event => {
                    const cursor = event.target.result;
                    if (cursor) {
                        try {
                            const result = callback(cursor.value, cursor.key);
                            if (result !== false) {
                                results.push(result);
                                cursor.continue();
                            } else {
                                resolve(results);
                            }
                        } catch (error) {
                            reject(error);
                        }
                    } else {
                        resolve(results);
                    }
                };
                request.onerror = () => reject(request.error);
            });
        });
    }
}

// ========================
// Document Class
// ========================

class Document {
    constructor(data = {}, options = {}) {
        this._id = data._id || this.generateId();
        this._created = data._created || Date.now();
        this._modified = data._modified || Date.now();
        this._permanent = data._permanent || options.permanent || false;
        this._encrypted = data._encrypted || options.encrypted || false;
        this._compressed = data._compressed || options.compressed || false;
        this._attachments = data._attachments || [];
        this.data = data.data || {};
        this.packedData = data.packedData || null;

        // Utilities can be passed in or instantiated. For simplicity, we keep instantiation here.
        this.compression = new BrowserCompressionUtility();
        this.encryption = new BrowserEncryptionUtility();
        this.password = options.password || null;
    }

    generateId() {
        return `doc_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
    }

    async pack() {
        try {
            let packed = serializer.serialize(this.data);
            if (this._compressed) {
                packed = await this.compression.compress(packed);
            }
            if (this._encrypted && this.password) {
                packed = await this.encryption.encrypt(packed, this.password);
            }
            this.packedData = packed;
            return packed;
        } catch (error) {
            throw new LacertaDBError('Failed to pack document', 'PACK_FAILED', error);
        }
    }

    async unpack() {
        try {
            let unpacked = this.packedData;
            if (this._encrypted && this.password) {
                unpacked = await this.encryption.decrypt(unpacked, this.password);
            }
            if (this._compressed) {
                unpacked = await this.compression.decompress(unpacked);
            }
            this.data = serializer.deserialize(unpacked);
            return this.data;
        } catch (error) {
            throw new LacertaDBError('Failed to unpack document', 'UNPACK_FAILED', error);
        }
    }

    packSync() {
        let packed = serializer.serialize(this.data);
        if (this._compressed) {
            packed = this.compression.compressSync(packed);
        }
        if (this._encrypted) {
            throw new LacertaDBError('Synchronous encryption not supported', 'SYNC_ENCRYPT_NOT_SUPPORTED');
        }
        this.packedData = packed;
        return packed;
    }

    unpackSync() {
        let unpacked = this.packedData;
        if (this._encrypted) {
            throw new LacertaDBError('Synchronous decryption not supported', 'SYNC_DECRYPT_NOT_SUPPORTED');
        }
        if (this._compressed) {
            unpacked = this.compression.decompressSync(unpacked);
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
            packedData: this.packedData
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
        this.documentSizes = data.documentSizes || {};
        this.documentModifiedAt = data.documentModifiedAt || {};
        this.documentPermanent = data.documentPermanent || {};
        this.documentAttachments = data.documentAttachments || {};
    }

    addDocument(docId, sizeKB, isPermanent, attachmentCount) {
        this.documentSizes[docId] = sizeKB;
        this.documentModifiedAt[docId] = Date.now();
        if (isPermanent) this.documentPermanent[docId] = true;
        if (attachmentCount > 0) this.documentAttachments[docId] = attachmentCount;

        this.sizeKB += sizeKB;
        this.length++;
        this.modifiedAt = Date.now();
    }

    updateDocument(docId, newSizeKB, isPermanent, attachmentCount) {
        const oldSize = this.documentSizes[docId] || 0;
        this.sizeKB = this.sizeKB - oldSize + newSizeKB;
        this.documentSizes[docId] = newSizeKB;
        this.documentModifiedAt[docId] = Date.now();

        if (isPermanent) {
            this.documentPermanent[docId] = true;
        } else {
            delete this.documentPermanent[docId];
        }

        if (attachmentCount > 0) {
            this.documentAttachments[docId] = attachmentCount;
        } else {
            delete this.documentAttachments[docId];
        }

        this.modifiedAt = Date.now();
    }

    removeDocument(docId) {
        const sizeKB = this.documentSizes[docId] || 0;
        if (this.documentSizes[docId]) {
            this.sizeKB -= sizeKB;
            this.length--;
        }
        delete this.documentSizes[docId];
        delete this.documentModifiedAt[docId];
        delete this.documentPermanent[docId];
        delete this.documentAttachments[docId];
        this.modifiedAt = Date.now();
    }

    getOldestNonPermanentDocuments(count) {
        return Object.entries(this.documentModifiedAt)
            .filter(([docId]) => !this.documentPermanent[docId])
            .sort(([, timeA], [, timeB]) => timeA - timeB)
            .slice(0, count)
            .map(([docId]) => docId);
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
            if (e.name === 'QuotaExceededError') {
                throw new LacertaDBError('Storage quota exceeded for metadata', 'QUOTA_EXCEEDED', e);
            }
            throw new LacertaDBError('Failed to save metadata', 'METADATA_SAVE_FAILED', e);
        }
    }

    setCollection(collectionMetadata) {
        this.collections[collectionMetadata.name] = {
            sizeKB: collectionMetadata.sizeKB,
            length: collectionMetadata.length,
            createdAt: collectionMetadata.createdAt,
            modifiedAt: collectionMetadata.modifiedAt,
            documentSizes: collectionMetadata.documentSizes,
            documentModifiedAt: collectionMetadata.documentModifiedAt,
            documentPermanent: collectionMetadata.documentPermanent,
            documentAttachments: collectionMetadata.documentAttachments
        };
        this.recalculate();
        this.save();
    }

    removeCollection(collectionName) {
        delete this.collections[collectionName];
        this.recalculate();
        this.save();
    }

    recalculate() {
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
        // Replaced `??` with ternary operator for compatibility
        this.sizeLimitKB = data.sizeLimitKB != null ? data.sizeLimitKB : Infinity;
        const defaultBuffer = this.sizeLimitKB === Infinity ? 0 : this.sizeLimitKB * 0.8;
        this.bufferLimitKB = data.bufferLimitKB != null ? data.bufferLimitKB : defaultBuffer;
        this.freeSpaceEvery = data.freeSpaceEvery || 10000;
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
        this.save();
    }
}

// ========================
// Quick Store (localStorage based)
// ========================

class QuickStore {
    constructor(dbName) {
        this.dbName = dbName;
        this.keyPrefix = `lacertadb_${dbName}_quickstore_`;
        this.indexKey = `${this.keyPrefix}index`;
    }

    _readIndex() {
        const indexStr = localStorage.getItem(this.indexKey);
        if (!indexStr) return [];
        try {
            const decoded = base64.decode(indexStr);
            return serializer.deserialize(decoded);
        } catch {
            return [];
        }
    }

    _writeIndex(index) {
        const serializedIndex = serializer.serialize(index);
        const encodedIndex = base64.encode(serializedIndex);
        localStorage.setItem(this.indexKey, encodedIndex);
    }

    add(docId, data) {
        const key = `${this.keyPrefix}data_${docId}`;
        try {
            const serializedData = serializer.serialize(data);
            const encodedData = base64.encode(serializedData);
            localStorage.setItem(key, encodedData);

            const index = this._readIndex();
            if (!index.includes(docId)) {
                index.push(docId);
                this._writeIndex(index);
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
        const key = `${this.keyPrefix}data_${docId}`;
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
        const key = `${this.keyPrefix}data_${docId}`;
        localStorage.removeItem(key);

        let index = this._readIndex();
        const initialLength = index.length;
        index = index.filter(id => id !== docId);
        if (index.length < initialLength) {
            this._writeIndex(index);
        }
    }

    getAll() {
        const index = this._readIndex();
        return index.map(docId => {
            const doc = this.get(docId);
            return doc ? { _id: docId, ...doc } : null;
        }).filter(Boolean);
    }

    clear() {
        const index = this._readIndex();
        for (const docId of index) {
            localStorage.removeItem(`${this.keyPrefix}data_${docId}`);
        }
        localStorage.removeItem(this.indexKey);
    }
}

// ========================
// Query Engine
// ========================

class QueryEngine {
    constructor() {
        this.operators = {
            // Comparison
            '$eq': (a, b) => a === b,
            '$ne': (a, b) => a !== b,
            '$gt': (a, b) => a > b,
            '$gte': (a, b) => a >= b,
            '$lt': (a, b) => a < b,
            '$lte': (a, b) => a <= b,
            '$in': (a, b) => Array.isArray(b) && b.includes(a),
            '$nin': (a, b) => Array.isArray(b) && !b.includes(a),

            // Logical
            '$and': (doc, conditions) => conditions.every(cond => this.evaluate(doc, cond)),
            '$or': (doc, conditions) => conditions.some(cond => this.evaluate(doc, cond)),
            '$not': (doc, condition) => !this.evaluate(doc, condition),
            '$nor': (doc, conditions) => !conditions.some(cond => this.evaluate(doc, cond)),

            // Element
            '$exists': (value, exists) => (value !== undefined) === exists,
            '$type': (value, type) => typeof value === type,

            // Array
            '$all': (arr, values) => Array.isArray(arr) && values.every(v => arr.includes(v)),
            '$elemMatch': (arr, condition) => Array.isArray(arr) && arr.some(elem => this.evaluate({ value: elem }, { value: condition })),
            '$size': (arr, size) => Array.isArray(arr) && arr.length === size,

            // String
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
                // Logical operator at root level
                const operator = this.operators[key];
                if (!operator || !operator(doc, value)) return false;
            } else {
                // Field-level query
                const fieldValue = this.getFieldValue(doc, key);
                if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
                    // Operator-based comparison
                    for (const op in value) {
                        if (op.startsWith('$')) {
                            const operatorFn = this.operators[op];
                            if (!operatorFn || !operatorFn(fieldValue, value[op])) {
                                return false;
                            }
                        }
                    }
                } else {
                    // Direct equality comparison
                    if (fieldValue !== value) return false;
                }
            }
        }
        return true;
    }

    getFieldValue(doc, path) {
        // Replaced optional chaining with a loop for compatibility
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
                    } else if (typeof value === 'object') {
                        // Handle computed fields if necessary
                    } else if (typeof value === 'string' && value.startsWith('$')) {
                        projected[key] = queryEngine.getFieldValue(doc, value.substring(1));
                    }
                }
                // Handle exclusion projection
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
                    const order = sortSpec[key]; // 1 for asc, -1 for desc
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
                        JSON.stringify(idField); // Fallback for complex IDs

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
                            case '$avg':
                                const sum = group.docs.reduce((s, d) => s + (queryEngine.getFieldValue(d, field) || 0), 0);
                                result[fieldKey] = sum / group.docs.length;
                                break;
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
        this.currentVersion = this.loadVersion();
    }

    loadVersion() {
        return localStorage.getItem(`lacertadb_${this.database.name}_version`) || '1.0.0';
    }

    saveVersion(version) {
        localStorage.setItem(`lacertadb_${this.database.name}_version`, version);
        this.currentVersion = version;
    }

    addMigration(migration) {
        this.migrations.push(migration);
    }

    compareVersions(a, b) {
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
            .filter(m => this.compareVersions(m.version, this.currentVersion) > 0 &&
                this.compareVersions(m.version, targetVersion) <= 0)
            .sort((a, b) => this.compareVersions(a.version, b.version));

        for (const migration of applicableMigrations) {
            await this._applyMigration(migration, 'up');
            this.saveVersion(migration.version);
        }
    }

    async rollback(targetVersion) {
        const applicableMigrations = this.migrations
            .filter(m => m.down &&
                this.compareVersions(m.version, targetVersion) > 0 &&
                this.compareVersions(m.version, this.currentVersion) <= 0)
            .sort((a, b) => this.compareVersions(b.version, a.version));

        for (const migration of applicableMigrations) {
            await this._applyMigration(migration, 'down');
        }
        this.saveVersion(targetVersion);
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
        this.metrics = {
            operations: [],
            latencies: [],
            cacheHits: 0,
            cacheMisses: 0,
            memoryUsage: []
        };
        this.monitoring = false;
        this.monitoringInterval = null;
    }

    startMonitoring() {
        if (this.monitoring) return;
        this.monitoring = true;
        this.monitoringInterval = setInterval(() => this.collectMetrics(), 1000);
    }

    stopMonitoring() {
        if (!this.monitoring) return;
        this.monitoring = false;
        clearInterval(this.monitoringInterval);
        this.monitoringInterval = null;
    }

    recordOperation(type, duration) {
        if (!this.monitoring) return;
        this.metrics.operations.push({ type, duration, timestamp: Date.now() });
        this.metrics.latencies.push(duration);
        if (this.metrics.operations.length > 100) this.metrics.operations.shift();
        if (this.metrics.latencies.length > 100) this.metrics.latencies.shift();
    }

    recordCacheHit() { this.metrics.cacheHits++; }
    recordCacheMiss() { this.metrics.cacheMisses++; }

    collectMetrics() {
        // Replaced optional chaining with `&&` for compatibility
        if (performance && performance.memory) {
            this.metrics.memoryUsage.push({
                used: performance.memory.usedJSHeapSize,
                total: performance.memory.totalJSHeapSize,
                limit: performance.memory.jsHeapSizeLimit,
                timestamp: Date.now()
            });
            if (this.metrics.memoryUsage.length > 60) this.metrics.memoryUsage.shift();
        }
    }

    getStats() {
        const opsPerSec = this.metrics.operations.filter(op => Date.now() - op.timestamp < 1000).length;
        const totalLatency = this.metrics.latencies.reduce((a, b) => a + b, 0);
        const avgLatency = this.metrics.latencies.length > 0 ? totalLatency / this.metrics.latencies.length : 0;
        const totalCacheOps = this.metrics.cacheHits + this.metrics.cacheMisses;
        const cacheHitRate = totalCacheOps > 0 ? (this.metrics.cacheHits / totalCacheOps) * 100 : 0;

        // Replaced `.at(-1)` with classic index access for compatibility
        const latestMemory = this.metrics.memoryUsage.length > 0 ? this.metrics.memoryUsage[this.metrics.memoryUsage.length - 1] : null;
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
        if (stats.cacheHitRate < 50 && (this.metrics.cacheHits + this.metrics.cacheMisses) > 20) {
            tips.push('Low cache hit rate. Consider increasing cache size or optimizing query patterns.');
        }
        if (this.metrics.memoryUsage.length > 10) {
            const recent = this.metrics.memoryUsage.slice(-10);
            const trend = recent[recent.length - 1].used - recent[0].used;
            if (trend > 10 * 1024 * 1024) { // > 10MB increase
                tips.push('Memory usage is increasing rapidly. Check for memory leaks or consider batch processing.');
            }
        }
        return tips.length > 0 ? tips : ['Performance is optimal. No issues detected.'];
    }
}

// ========================
// Collection Class
// ========================

class Collection {
    constructor(name, database) {
        this.name = name;
        this.database = database;
        this.db = null;
        this.metadata = null;
        this.settings = database.settings;
        this.indexedDB = new IndexedDBUtility();
        this.opfs = new OPFSUtility();
        this.cleanupInterval = null;
        this.events = new Map();
        this.queryCache = new Map();
        this.cacheTimeout = 60000;
        this.performanceMonitor = database.performanceMonitor;
    }

    async init() {
        const dbName = `${this.database.name}_${this.name}`;
        this.db = await this.indexedDB.openDatabase(dbName, 1, (db, oldVersion) => {
            if (oldVersion < 1 && !db.objectStoreNames.contains('documents')) {
                const store = db.createObjectStore('documents', { keyPath: '_id' });
                store.createIndex('modified', '_modified', { unique: false });
            }
            // Future index creation logic would go here during version bumps
        });

        const metadataData = this.database.metadata.collections[this.name];
        this.metadata = new CollectionMetadata(this.name, metadataData);

        if (this.settings.freeSpaceEvery > 0) {
            this.cleanupInterval = setInterval(() => this.freeSpace(), this.settings.freeSpaceEvery);
        }
        return this;
    }

    async add(documentData, options = {}) {
        await this.trigger('beforeAdd', documentData);

        const doc = new Document({ data: documentData, _id: options.id }, {
            encrypted: options.encrypted || false,
            compressed: options.compressed !== false,
            permanent: options.permanent || false,
            password: options.password
        });

        const attachments = options.attachments;
        if (attachments && attachments.length > 0) {
            const preparedAttachments = await Promise.all(
                attachments.map(att => (att instanceof File || att instanceof Blob) ?
                    OPFSUtility.prepareAttachment(att, att.name) :
                    Promise.resolve(att))
            );
            doc._attachments = await this.opfs.saveAttachments(this.database.name, this.name, doc._id, preparedAttachments);
        }

        await doc.pack();
        const dbOutput = doc.databaseOutput();
        await this.indexedDB.add(this.db, 'documents', dbOutput);

        const sizeKB = dbOutput.packedData.byteLength / 1024;
        this.metadata.addDocument(doc._id, sizeKB, doc._permanent, doc._attachments.length);
        this.database.metadata.setCollection(this.metadata);

        await this.checkSpaceLimit();
        await this.trigger('afterAdd', doc);
        this.queryCache.clear();
        return doc._id;
    }

    async get(docId, options = {}) {
        await this.trigger('beforeGet', docId);

        const stored = await this.indexedDB.get(this.db, 'documents', docId);
        if (!stored) {
            throw new LacertaDBError(`Document with id '${docId}' not found.`, 'DOCUMENT_NOT_FOUND');
        }

        const doc = new Document(stored, {
            password: options.password,
            encrypted: stored._encrypted,
            compressed: stored._compressed
        });

        if (stored.packedData) {
            await doc.unpack();
        }

        if (options.includeAttachments && doc._attachments.length > 0) {
            doc.data._attachments = await this.opfs.getAttachments(doc._attachments);
        }

        await this.trigger('afterGet', doc);
        return doc.objectOutput(options.includeAttachments);
    }

    async getAll(options = {}) {
        const stored = await this.indexedDB.getAll(this.db, 'documents', undefined, options.limit);
        return Promise.all(stored.map(async docData => {
            try {
                const doc = new Document(docData, {
                    password: options.password,
                    encrypted: docData._encrypted,
                    compressed: docData._compressed
                });
                if (docData.packedData) {
                    await doc.unpack();
                }
                return doc.objectOutput();
            } catch (error) {
                console.error(`Failed to unpack document ${docData._id}:`, error);
                return null;
            }
        })).then(docs => docs.filter(Boolean));
    }

    async update(docId, updates, options = {}) {
        await this.trigger('beforeUpdate', { docId, updates });

        const stored = await this.indexedDB.get(this.db, 'documents', docId);
        if (!stored) {
            throw new LacertaDBError(`Document with id '${docId}' not found for update.`, 'DOCUMENT_NOT_FOUND');
        }

        const existingDoc = new Document(stored, { password: options.password });
        if (stored.packedData) await existingDoc.unpack();

        const updatedData = { ...existingDoc.data, ...updates };

        // Replaced `??` with ternary operator for compatibility
        const doc = new Document({
            _id: docId,
            _created: stored._created,
            data: updatedData
        }, {
            encrypted: options.encrypted !== undefined ? options.encrypted : stored._encrypted,
            compressed: options.compressed !== undefined ? options.compressed : stored._compressed,
            permanent: options.permanent !== undefined ? options.permanent : stored._permanent,
            password: options.password
        });
        doc._modified = Date.now();

        const attachments = options.attachments;
        if (attachments && attachments.length > 0) {
            await this.opfs.deleteAttachments(this.database.name, this.name, docId);
            const preparedAttachments = await Promise.all(
                attachments.map(att => (att instanceof File || att instanceof Blob) ?
                    OPFSUtility.prepareAttachment(att, att.name) :
                    Promise.resolve(att))
            );
            doc._attachments = await this.opfs.saveAttachments(this.database.name, this.name, doc._id, preparedAttachments);
        } else {
            doc._attachments = stored._attachments;
        }

        await doc.pack();
        const dbOutput = doc.databaseOutput();
        await this.indexedDB.put(this.db, 'documents', dbOutput);

        const sizeKB = dbOutput.packedData.byteLength / 1024;
        this.metadata.updateDocument(doc._id, sizeKB, doc._permanent, doc._attachments.length);
        this.database.metadata.setCollection(this.metadata);

        await this.trigger('afterUpdate', doc);
        this.queryCache.clear();
        return doc._id;
    }

    async delete(docId) {
        await this.trigger('beforeDelete', docId);

        const doc = await this.indexedDB.get(this.db, 'documents', docId);
        if (!doc) throw new LacertaDBError('Document not found for deletion', 'DOCUMENT_NOT_FOUND');
        if (doc._permanent) throw new LacertaDBError('Cannot delete a permanent document', 'INVALID_OPERATION');

        await this.indexedDB.delete(this.db, 'documents', docId);
        const attachments = doc._attachments;
        if (attachments && attachments.length > 0) {
            await this.opfs.deleteAttachments(this.database.name, this.name, docId);
        }

        this.metadata.removeDocument(docId);
        this.database.metadata.setCollection(this.metadata);

        await this.trigger('afterDelete', docId);
        this.queryCache.clear();
    }

    async query(filter = {}, options = {}) {
        const startTime = performance.now();
        const cacheKey = base64.encode(serializer.serialize({ filter, options }));
        const cached = this.queryCache.get(cacheKey);

        if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
            if (this.performanceMonitor) this.performanceMonitor.recordCacheHit();
            return cached.data;
        }
        if (this.performanceMonitor) this.performanceMonitor.recordCacheMiss();

        let results = await this.getAll(options);
        if (Object.keys(filter).length > 0) {
            results = results.filter(doc => queryEngine.evaluate(doc, filter));
        }

        if (options.sort) results = aggregationPipeline.stages.$sort(results, options.sort);
        if (options.skip) results = aggregationPipeline.stages.$skip(results, options.skip);
        if (options.limit) results = aggregationPipeline.stages.$limit(results, options.limit);
        if (options.projection) results = aggregationPipeline.stages.$project(results, options.projection);

        if (this.performanceMonitor) this.performanceMonitor.recordOperation('query', performance.now() - startTime);

        this.queryCache.set(cacheKey, { data: results, timestamp: Date.now() });
        if (this.queryCache.size > 100) {
            this.queryCache.delete(this.queryCache.keys().next().value);
        }
        return results;
    }

    async aggregate(pipeline) {
        const startTime = performance.now();
        const docs = await this.getAll();
        const result = await aggregationPipeline.execute(docs, pipeline, this.database);
        if (this.performanceMonitor) this.performanceMonitor.recordOperation('aggregate', performance.now() - startTime);
        return result;
    }

    async batchAdd(documents, options) {
        const startTime = performance.now();
        const results = await Promise.all(documents.map(doc =>
            this.add(doc, options)
                .then(id => ({ success: true, id }))
                .catch(error => ({ success: false, error: error.message }))
        ));
        if (this.performanceMonitor) this.performanceMonitor.recordOperation('batchAdd', performance.now() - startTime);
        return results;
    }

    batchUpdate(updates, options) {
        return Promise.all(updates.map(update =>
            this.update(update.id, update.data, options)
                .then(id => ({ success: true, id }))
                .catch(error => ({ success: false, id: update.id, error: error.message }))
        ));
    }

    batchDelete(ids) {
        return Promise.all(ids.map(id =>
            this.delete(id)
                .then(() => ({ success: true, id }))
                .catch(error => ({ success: false, id, error: error.message }))
        ));
    }

    async clear() {
        await this.indexedDB.clear(this.db, 'documents');
        this.metadata = new CollectionMetadata(this.name);
        this.database.metadata.setCollection(this.metadata);
        this.queryCache.clear();
    }

    async checkSpaceLimit() {
        if (this.settings.sizeLimitKB !== Infinity && this.metadata.sizeKB > this.settings.bufferLimitKB) {
            await this.freeSpace();
        }
    }

    async freeSpace() {
        const targetSize = this.settings.bufferLimitKB * 0.8;
        while (this.metadata.sizeKB > targetSize) {
            const oldestDocs = this.metadata.getOldestNonPermanentDocuments(10);
            if (oldestDocs.length === 0) break;
            await this.batchDelete(oldestDocs);
        }
    }

    on(event, callback) {
        if (!this.events.has(event)) this.events.set(event, []);
        this.events.get(event).push(callback);
    }

    off(event, callback) {
        if (!this.events.has(event)) return;
        const listeners = this.events.get(event).filter(cb => cb !== callback);
        this.events.set(event, listeners);
    }

    async trigger(event, data) {
        if (!this.events.has(event)) return;
        for (const callback of this.events.get(event)) {
            await callback(data);
        }
    }

    clearCache() { this.queryCache.clear(); }

    destroy() {
        clearInterval(this.cleanupInterval);
        if (this.db) {
            this.db.close();
        }
    }
}

// ========================
// Database Class
// ========================

class Database {
    constructor(name, performanceMonitor) {
        this.name = name;
        this.collections = new Map();
        this.metadata = null;
        this.settings = null;
        this.quickStore = null;
        this.performanceMonitor = performanceMonitor;
    }

    async init() {
        this.metadata = DatabaseMetadata.load(this.name);
        this.settings = Settings.load(this.name);
        this.quickStore = new QuickStore(this.name);
        return this;
    }

    async createCollection(name, options) {
        if (this.collections.has(name)) {
            throw new LacertaDBError(`Collection '${name}' already exists.`, 'COLLECTION_EXISTS');
        }

        const collection = new Collection(name, this);
        await collection.init();
        this.collections.set(name, collection);

        if (!this.metadata.collections[name]) {
            this.metadata.setCollection(new CollectionMetadata(name));
        }
        return collection;
    }

    async getCollection(name) {
        if (this.collections.has(name)) {
            return this.collections.get(name);
        }
        if (this.metadata.collections[name]) {
            const collection = new Collection(name, this);
            await collection.init();
            this.collections.set(name, collection);
            return collection;
        }
        throw new LacertaDBError(`Collection '${name}' not found.`, 'COLLECTION_NOT_FOUND');
    }

    async dropCollection(name) {
        if (this.collections.has(name)) {
            const collection = this.collections.get(name);
            await collection.clear();
            collection.destroy();
            this.collections.delete(name);
        }

        this.metadata.removeCollection(name);

        const dbName = `${this.name}_${name}`;
        await new Promise((resolve, reject) => {
            const deleteReq = indexedDB.deleteDatabase(dbName);
            deleteReq.onsuccess = resolve;
            deleteReq.onerror = reject;
            deleteReq.onblocked = () => console.warn(`Deletion of '${dbName}' is blocked.`);
        });
    }

    listCollections() {
        return Object.keys(this.metadata.collections);
    }

    getStats() {
        return {
            name: this.name,
            totalSizeKB: this.metadata.totalSizeKB,
            totalDocuments: this.metadata.totalLength,
            collections: Object.entries(this.metadata.collections).map(([name, data]) => ({
                name,
                sizeKB: data.sizeKB,
                documents: data.length,
                createdAt: new Date(data.createdAt).toISOString(),
                modifiedAt: new Date(data.modifiedAt).toISOString()
            }))
        };
    }

    updateSettings(newSettings) { this.settings.updateSettings(newSettings); }

    async export(format = 'json', password = null) {
        const data = {
            version: '4.0.3',
            database: this.name,
            timestamp: Date.now(),
            collections: {}
        };

        for (const collName of this.listCollections()) {
            const collection = await this.getCollection(collName);
            data.collections[collName] = await collection.getAll({ password });
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
            const collection = await this.createCollection(collName).catch(() => this.getCollection(collName));
            await collection.batchAdd(docs);
        }

        const docCount = Object.values(parsed.collections).reduce((sum, docs) => sum + docs.length, 0);
        return {
            collections: Object.keys(parsed.collections).length,
            documents: docCount
        };
    }

    async clearAll() {
        await Promise.all([...this.collections.keys()].map(name => this.dropCollection(name)));
        this.collections.clear();
        this.metadata = new DatabaseMetadata(this.name);
        this.metadata.save();
        this.quickStore.clear();
    }

    destroy() {
        this.collections.forEach(collection => collection.destroy());
        this.collections.clear();
    }
}

// ========================
// Main LacertaDB Class
// ========================

export class LacertaDB {
    constructor() {
        this.databases = new Map();
        this.performanceMonitor = new PerformanceMonitor();
    }

    async getDatabase(name) {
        if (!this.databases.has(name)) {
            const db = new Database(name, this.performanceMonitor);
            await db.init();
            this.databases.set(name, db);
        }
        return this.databases.get(name);
    }

    async dropDatabase(name) {
        if (this.databases.has(name)) {
            const db = this.databases.get(name);
            await db.clearAll();
            db.destroy();
            this.databases.delete(name);
        }

        ['metadata', 'settings', 'version'].forEach(suffix => {
            localStorage.removeItem(`lacertadb_${name}_${suffix}`);
        });
        const quickStore = new QuickStore(name);
        quickStore.clear();
    }

    listDatabases() {
        const dbNames = new Set();
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            // Replaced optional chaining with `&&` for compatibility
            if (key && key.startsWith('lacertadb_')) {
                const dbName = key.split('_')[1];
                dbNames.add(dbName);
            }
        }
        return [...dbNames];
    }

    async createBackup(password = null) {
        const backup = {
            version: '4.0.3',
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
}

// Export all major components for advanced usage
export {
    Database,
    Collection,
    Document,
    MigrationManager,
    PerformanceMonitor,
    LacertaDBError,
    OPFSUtility
};