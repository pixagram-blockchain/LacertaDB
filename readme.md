<p align="center">
  <img src="https://raw.githubusercontent.com/pixagram-blockchain/LacertaDB/main/logo.webp?raw=true" alt="LacertaDB Logo" width="800"/>
</p>

<h1 align="center">LacertaDB 0.11.4</h1>

<p align="center">
  <strong>A high-performance, browser-native document database with encryption, indexing, and MongoDB-like queries.</strong>
</p>

<p align="center">
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#api-reference">API Reference</a> •
  <a href="#examples">Examples</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.9.2-blue.svg" alt="Version"/>
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"/>
  <img src="https://img.shields.io/badge/platform-browser-orange.svg" alt="Browser Only"/>
  <img src="https://img.shields.io/badge/encryption-AES--GCM--256-red.svg" alt="Encryption"/>
</p>

---

> *"Store your data like a lizard stores heat — efficiently, locally, and securely."*

LacertaDB is a **browser-native** document database built for Web3 applications, offline-first PWAs, and any browser application requiring robust local storage with encryption. It combines IndexedDB, OPFS, and localStorage into a unified API with MongoDB-style queries, four index types, and military-grade encryption via the Web Crypto API.

**Dependencies:** [@pixagram/turboserial](https://www.npmjs.com/package/@pixagram/turboserial) (binary serialization) and [@pixagram/turbobase64](https://www.npmjs.com/package/@pixagram/turbobase64) (base64 encoding) — both installed automatically.

> +"NEW! NO LONGER USE: `deduplication`, `shareArrayBuffers`, `detectCircular`, `allowFunction`, `serializeFunctions`, `preservePropertyDescriptors`. It's safer and faster but you can no longer store sharedArrayBuffers, CircularReferences, Functions and PropertyDescriptors (except if you modify the TurboSerial 0.1.9 configuration on purpose not to be safe.)

---

## Table of Contents

| Section | Description |
|---------|-------------|
| [Features](#features) | What LacertaDB offers |
| [Installation](#installation) | How to install and bundle |
| [Quick Start](#quick-start) | Get running in 2 minutes |
| [Architecture](#architecture) | System design overview |
| [API Reference](#api-reference) | Complete method documentation |
| [Query Operators](#query-operators) | MongoDB-style query syntax |
| [Aggregation Pipeline](#aggregation-pipeline) | Data transformation stages |
| [Indexing](#indexing) | B-Tree, Hash, Text, Geo indexes |
| [Encryption](#encryption) | AES-GCM-256 + Master Key Wrapping |
| [Caching](#caching) | LRU, LFU, TTL strategies |
| [QuickStore](#quickstore) | Fast localStorage key-value access |
| [Binary Attachments](#binary-attachments) | File storage via OPFS |
| [Migrations](#migrations) | Schema version management |
| [Performance](#performance-monitoring) | Metrics and optimization |
| [Error Handling](#error-handling) | Error codes and patterns |
| [Examples](#examples) | Real-world usage patterns |
| [Exports](#exports) | All exported classes |
| [Browser Compatibility](#browser-compatibility) | Supported browsers |

---

## Features

<table>
<tr>
<td width="50%">

### Storage
- **IndexedDB** backend with connection pooling and retry logic
- **OPFS** (Origin Private File System) for binary attachments
- **localStorage** QuickStore for synchronous fast-access data
- Automatic space management with configurable limits
- Batch operations with atomic transactions

</td>
<td width="50%">

### Security
- **AES-GCM-256** encryption via Web Crypto API
- **PBKDF2** key derivation (600,000 iterations, OWASP standard)
- **Master Key Wrapping** — PIN changes don't re-encrypt data
- **HMAC-SHA-256** integrity verification on every document
- Dedicated private key vault with additional authentication data
- Constant-time comparison to prevent timing attacks

</td>
</tr>
<tr>
<td>

### Querying
- **MongoDB-style** query syntax with 20+ operators
- **Aggregation pipeline** with 7 stages including `$lookup` joins
- **B-Tree** indexes for range queries and sorting
- **Hash** indexes for O(1) exact-match lookups
- **Full-text search** with CJK support via `Intl.Segmenter`
- **Geospatial queries** with QuadTree-backed `$near` and `$within`

</td>
<td>

### Performance
- **LRU / LFU / TTL** caching strategies per collection
- **Compression** via CompressionStream (deflate) with magic-byte detection
- **Cursor-free batch indexing** to prevent `TransactionInactiveError`
- **Read-optimized mutex** — no global lock on read transactions
- Built-in performance monitor with optimization tips
- Idle callback scheduling to keep UI responsive

</td>
</tr>
</table>

---

## Installation

```bash
npm install @pixagram/lacerta-db
```

Both required dependencies are installed automatically:

```
@pixagram/lacerta-db
├── @pixagram/turboserial   # Binary serialization with compression
└── @pixagram/turbobase64   # High-performance base64 encoding
```

### Bundler Setup

LacertaDB is an ES module. It works out of the box with Webpack, Vite, Rollup, or any modern bundler.

```javascript
// ES module import (recommended)
import { LacertaDB } from '@pixagram/lacerta-db';

// Named imports for specific components
import { LacertaDB, Database, Collection, LacertaDBError } from '@pixagram/lacerta-db';
```

### Build from Source

```bash
git clone https://github.com/pixagram-blockchain/LacertaDB.git
cd LacertaDB
npm install
npm run build
```

> **Note:** The build script uses `NODE_OPTIONS=--openssl-legacy-provider` for compatibility with Webpack 4. Node.js >= 0.8.0 is required for building, but the output runs exclusively in browsers.

---

## Quick Start

```javascript
import { LacertaDB } from '@pixagram/lacerta-db';

// 1. Initialize LacertaDB
const lacerta = new LacertaDB();

// 2. Get or create a database
const db = await lacerta.getDatabase('myapp');

// 3. Create a collection
const users = await db.createCollection('users');

// 4. Add a document
const userId = await users.add({
  name: 'Alice',
  email: 'alice@example.com',
  age: 28
});

// 5. Query with MongoDB-style operators
const results = await users.query({ age: { $gte: 18 } });

// 6. Update
await users.update(userId, { age: 29 });

// 7. Delete
await users.delete(userId);
```

<details>
<summary><strong>With Encryption</strong></summary>

```javascript
// Create an encrypted database — all documents are encrypted at rest
const secureDb = await lacerta.getSecureDatabase('vault', '123456');

const secrets = await secureDb.createCollection('secrets');
await secrets.add({ apiKey: 'sk-xxx-secret', privateData: 'sensitive' });

// Change PIN without re-encrypting documents (Master Key Wrapping)
await secureDb.changePin('123456', 'newSecurePin!');

// Store blockchain private keys with additional authentication
await secureDb.storePrivateKey('wallet-main', privateKeyString, 'optionalAuthData');
const key = await secureDb.getPrivateKey('wallet-main', 'optionalAuthData');
```

</details>

<details>
<summary><strong>With Indexes and Aggregation</strong></summary>

```javascript
const orders = await db.createCollection('orders');

// Create indexes for performance
await orders.createIndex('customerId', { type: 'hash' });
await orders.createIndex('amount', { type: 'btree' });
await orders.createIndex('description', { type: 'text' });

// Indexed queries run in O(log N) instead of full scans
const bigOrders = await orders.query({ amount: { $gte: 1000 } });

// Aggregation pipeline
const report = await orders.aggregate([
  { $match: { status: 'completed' } },
  { $group: {
      _id: '$customerId',
      totalSpent: { $sum: '$amount' },
      orderCount: { $count: 1 }
  }},
  { $sort: { totalSpent: -1 } },
  { $limit: 10 }
]);
```

</details>

---

## Architecture

LacertaDB follows a **layered architecture** where each component encapsulates complexity while exposing a simple interface.

```
┌──────────────────────────────────────────────────────────────────────┐
│                            LacertaDB                                 │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │                          Database                              │  │
│  │  ┌──────────────────────────────────────────────────────────┐  │  │
│  │  │                     Collection                            │  │  │
│  │  │  ┌────────────────────────────────────────────────────┐  │  │  │
│  │  │  │                    Document                        │  │  │  │
│  │  │  │  • Data (serialized via TurboSerial)               │  │  │  │
│  │  │  │  • Metadata (_id, _created, _modified, _permanent) │  │  │  │
│  │  │  │  • Attachments (OPFS file references)              │  │  │  │
│  │  │  └────────────────────────────────────────────────────┘  │  │  │
│  │  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐     │  │  │
│  │  │  │ IndexManager │ │CacheStrategy │ │  Event Bus   │     │  │  │
│  │  │  │  B-Tree      │ │  LRU / LFU   │ │  before/after│     │  │  │
│  │  │  │  Hash        │ │  TTL / None  │ │  CRUD hooks  │     │  │  │
│  │  │  │  Text        │ │              │ │              │     │  │  │
│  │  │  │  Geo(Quad)   │ │              │ │              │     │  │  │
│  │  │  └──────────────┘ └──────────────┘ └──────────────┘     │  │  │
│  │  └──────────────────────────────────────────────────────────┘  │  │
│  │  ┌──────────────┐ ┌────────────────────┐ ┌─────────────────┐  │  │
│  │  │  QuickStore   │ │SecureDatabaseEncr. │ │MigrationManager │  │  │
│  │  │  (localStorage)│ │ (Master Key Wrap) │ │ (versioned)     │  │  │
│  │  └──────────────┘ └────────────────────┘ └─────────────────┘  │  │
│  └────────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────────┐│
│  │                    Shared Infrastructure                          ││
│  │  ConnectionPool │ AsyncMutex │ QueryEngine │ AggregationPipeline ││
│  │  Compression    │ Serializer │ Base64      │ OPFS Utility        ││
│  └──────────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Storage Backend |
|-----------|---------------|-----------------|
| `LacertaDB` | Top-level manager, backup/restore, database lifecycle | Memory |
| `Database` | Collection manager, encryption, settings, QuickStore | localStorage |
| `Collection` | CRUD, queries, indexes, caching, events | IndexedDB |
| `Document` | Data container, serialize/compress/encrypt pipeline | IndexedDB |
| `QuickStore` | Synchronous fast key-value access | localStorage |
| `OPFSUtility` | Binary file attachments | OPFS |
| `SecureDatabaseEncryption` | Master key wrapping, PBKDF2, AES-GCM, HMAC | localStorage (metadata) |

### Data Flow

When a document is stored, it passes through a multi-stage pipeline. Each stage is optional and configurable:

```
Write Path:
  User Data → TurboSerial.serialize() → CompressionStream (deflate) → AES-GCM-256 encrypt → IndexedDB

Read Path:
  IndexedDB → AES-GCM-256 decrypt → DecompressionStream (inflate) → TurboSerial.deserialize() → User Data
```

| Stage | Technology | Optional | Default |
|-------|------------|----------|---------|
| Serialize | TurboSerial (CBOR-like binary) | No | Always |
| Compress | CompressionStream (deflate) with magic byte | Yes | On |
| Encrypt | AES-GCM-256 + HMAC-SHA-256 | Yes | Off |
| Store | IndexedDB (documents) / OPFS (attachments) | No | Always |

---

## API Reference

### LacertaDB (Entry Point)

The top-level class manages databases and provides global operations.

```javascript
const lacerta = new LacertaDB();
```

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `getDatabase` | `name`, `options?` | `Promise<Database>` | Get or create a database |
| `getSecureDatabase` | `name`, `pin`, `salt?`, `config?` | `Promise<Database>` | Get or create an encrypted database |
| `dropDatabase` | `name` | `Promise<void>` | Permanently delete a database and all its data |
| `listDatabases` | — | `string[]` | List all database names found in localStorage |
| `createBackup` | `password?` | `Promise<string>` | Export all databases as a base64 string |
| `restoreBackup` | `data`, `password?` | `Promise<Object>` | Import backup data, returns `{ databases, collections, documents }` |
| `close` | — | `void` | Close all IndexedDB connections |
| `destroy` | — | `void` | Destroy all database instances and close connections |

| Property | Type | Description |
|----------|------|-------------|
| `performanceMonitor` | `PerformanceMonitor` | Global performance metrics collector |

---

### Database

Each database manages its own collections, encryption, settings, and QuickStore.

<details>
<summary><strong>Collection Management</strong></summary>

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `createCollection` | `name` | `Promise<Collection>` | Create a new collection (throws if exists) |
| `getCollection` | `name` | `Promise<Collection>` | Get existing collection (auto-initializes) |
| `dropCollection` | `name` | `Promise<void>` | Delete collection and its IndexedDB store |
| `listCollections` | — | `string[]` | List collection names |

```javascript
const users = await db.createCollection('users');
const posts = await db.createCollection('posts');

console.log(db.listCollections()); // ['users', 'posts']

await db.dropCollection('posts');
```

</details>

<details>
<summary><strong>Encryption & Key Management</strong></summary>

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `changePin` | `oldPin`, `newPin` | `Promise<boolean>` | Change encryption PIN (verifies old PIN first) |
| `storePrivateKey` | `keyName`, `privateKey`, `additionalAuth?` | `Promise<boolean>` | Store an encrypted private key |
| `getPrivateKey` | `keyName`, `additionalAuth?` | `Promise<string>` | Retrieve and decrypt a private key |

```javascript
// PIN change — re-wraps master key, does NOT re-encrypt documents
await db.changePin('oldPin', 'newPin');

// Private key vault with optional additional authentication data
await db.storePrivateKey('eth-wallet', '0xabc...', 'user@example.com');
const key = await db.getPrivateKey('eth-wallet', 'user@example.com');
```

> **How it works:** LacertaDB uses a Master Key Wrapping architecture. Your PIN derives a Key Encryption Key (KEK) via PBKDF2 which wraps/unwraps a random master key. Changing the PIN only re-wraps the master key — existing encrypted documents remain untouched.

</details>

<details>
<summary><strong>Data Management</strong></summary>

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `getStats` | — | `Object` | Returns `{ name, totalSizeKB, totalDocuments, collections[] }` |
| `updateSettings` | `settings` | `void` | Update `{ sizeLimitKB, bufferLimitKB, freeSpaceEvery }` |
| `export` | `format?`, `password?` | `Promise<string>` | Export as `'json'` or `'encrypted'` (base64 string) |
| `import` | `data`, `format?`, `password?` | `Promise<Object>` | Import data, returns `{ collections, documents }` |
| `clearAll` | — | `Promise<void>` | Clear all collections and reset metadata |
| `destroy` | — | `void` | Destroy database instance and release resources |

</details>

<details>
<summary><strong>Properties</strong></summary>

| Property | Type | Description |
|----------|------|-------------|
| `name` | `string` | Database name |
| `isEncrypted` | `boolean` | Whether encryption is active |
| `encryption` | `SecureDatabaseEncryption \| null` | Encryption utility (null if unencrypted) |
| `metadata` | `DatabaseMetadata` | Size and document counts |
| `settings` | `Settings` | Configuration (size limits, cleanup interval) |
| `quickStore` | `QuickStore` | Fast localStorage access |
| `performanceMonitor` | `PerformanceMonitor` | Metrics collector |
| `collections` | `Map<string, Collection>` | Loaded collections |

</details>

---

### Collection

Collections are the primary interface for storing, querying, and managing documents.

<details>
<summary><strong>CRUD Operations</strong></summary>

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `add` | `data`, `options?` | `Promise<string>` | Add a document, returns its ID |
| `get` | `docId`, `options?` | `Promise<Object>` | Get document by ID |
| `getAll` | `options?` | `Promise<Array>` | Get all documents |
| `update` | `docId`, `updates`, `options?` | `Promise<string>` | Merge updates into document |
| `delete` | `docId`, `options?` | `Promise<void>` | Delete a document |

**`add` Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | `string` | auto-generated | Custom document ID |
| `compressed` | `boolean` | `true` | Enable deflate compression |
| `permanent` | `boolean` | `false` | Protect from automatic cleanup |
| `encrypted` | `boolean` | `false` | Requires database-level encryption |
| `attachments` | `Array<File\|Blob\|Object>` | `[]` | Binary attachments stored via OPFS |

**`get` Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `includeAttachments` | `boolean` | `false` | Load binary attachments from OPFS |

**`delete` Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `force` | `boolean` | `false` | Required to delete permanent documents |

```javascript
// Add with options
const id = await users.add(
  { name: 'Alice', email: 'alice@example.com' },
  { compressed: true, permanent: true, id: 'user_alice' }
);

// Get with attachments
const doc = await users.get('user_alice', { includeAttachments: true });
// → { _id: 'user_alice', _created: 1702..., _modified: 1702..., name: 'Alice', ... }

// Update (shallow merge)
await users.update('user_alice', { age: 29, status: 'active' });

// Delete permanent document
await users.delete('user_alice', { force: true });
```

</details>

<details>
<summary><strong>Batch Operations</strong></summary>

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `batchAdd` | `documents[]`, `options?` | `Promise<Array>` | Add multiple documents atomically |
| `batchUpdate` | `updates[]`, `options?` | `Promise<Array>` | Update multiple documents |
| `batchDelete` | `items[]` | `Promise<Array>` | Delete multiple documents |

Each method returns an array of `{ success: boolean, id: string, error?: string }`.

```javascript
// Batch add — all documents in a single IndexedDB transaction
const results = await collection.batchAdd([
  { name: 'Alice', role: 'admin' },
  { name: 'Bob', role: 'user' },
  { name: 'Charlie', role: 'user' }
]);

// Batch update
await collection.batchUpdate([
  { id: 'doc_1', data: { status: 'active' } },
  { id: 'doc_2', data: { status: 'suspended' } }
]);

// Batch delete — strings or objects with options
await collection.batchDelete(['doc_1', 'doc_2']);
await collection.batchDelete([
  { id: 'permanent_doc', options: { force: true } }
]);
```

</details>

<details>
<summary><strong>Querying</strong></summary>

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `query` | `filter`, `options?` | `Promise<Array>` | Query documents with filter and options |
| `aggregate` | `pipeline[]` | `Promise<Array>` | Run an aggregation pipeline |

**Query Options:**

| Option | Type | Description |
|--------|------|-------------|
| `sort` | `Object` | Sort specification: `{ field: 1 }` (asc) or `{ field: -1 }` (desc) |
| `skip` | `number` | Skip N documents |
| `limit` | `number` | Limit result count |
| `projection` | `Object` | Field selection: `{ name: 1 }` (include) or `{ password: 0 }` (exclude) |

```javascript
const results = await collection.query(
  { status: 'active', age: { $gte: 18 } },
  {
    sort: { createdAt: -1 },
    skip: 10,
    limit: 20,
    projection: { name: 1, email: 1 }
  }
);
```

> **Index hint:** If a filter field matches an existing index, LacertaDB automatically uses it instead of scanning all documents.

</details>

<details>
<summary><strong>Index Management</strong></summary>

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `createIndex` | `fieldPath`, `options?` | `Promise<string>` | Create an index, returns its name |
| `dropIndex` | `indexName` | `void` | Remove an index |
| `getIndexes` | — | `Promise<Object>` | Get index stats (size, memory, type) |
| `verifyIndexes` | — | `Promise<Object>` | Check index integrity, auto-rebuild if needed |

See the [Indexing](#indexing) section for full details and options.

</details>

<details>
<summary><strong>Cache Configuration</strong></summary>

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `configureCacheStrategy` | `config` | `void` | Update cache type/size/TTL |
| `clearCache` | — | `void` | Manually invalidate all cached queries |

See the [Caching](#caching) section for strategies and configuration.

</details>

<details>
<summary><strong>Lifecycle Events</strong></summary>

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `on` | `event`, `callback` | `void` | Subscribe to a collection event |
| `off` | `event`, `callback` | `void` | Unsubscribe from an event |

**Available Events:**

| Event | Callback Argument | Description |
|-------|-------------------|-------------|
| `beforeAdd` | `documentData` | Before a document is inserted |
| `afterAdd` | `Document` | After successful insert |
| `beforeUpdate` | `{ docId, updates }` | Before a document is updated |
| `afterUpdate` | `Document` | After successful update |
| `beforeDelete` | `docId` | Before a document is deleted |
| `afterDelete` | `docId` | After successful deletion |
| `beforeGet` | `docId` | Before a document is retrieved |
| `afterGet` | `Document` | After successful retrieval |

```javascript
// Audit logging
collection.on('afterAdd', async (doc) => {
  console.log(`Created: ${doc._id} at ${new Date(doc._created).toISOString()}`);
});

// Validation hook
collection.on('beforeAdd', async (data) => {
  if (!data.email) throw new Error('Email is required');
});
```

> **Note:** Throwing an error in a `before*` hook aborts the operation.

</details>

<details>
<summary><strong>Other Methods</strong></summary>

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `clear` | `options?` | `Promise<void>` | Clear documents (`{ force: true }` to include permanent) |
| `destroy` | — | `void` | Release IndexedDB connection, clear timers and cache |

</details>

---

## Query Operators

LacertaDB supports **MongoDB-compatible** query operators. They can be used in `collection.query()`, `quickStore.query()`, event hooks, and aggregation `$match` stages.

### Comparison

| Operator | Description | Example |
|----------|-------------|---------|
| `$eq` | Equal to | `{ status: { $eq: 'active' } }` |
| `$ne` | Not equal to | `{ status: { $ne: 'deleted' } }` |
| `$gt` | Greater than | `{ age: { $gt: 18 } }` |
| `$gte` | Greater than or equal | `{ score: { $gte: 90 } }` |
| `$lt` | Less than | `{ price: { $lt: 100 } }` |
| `$lte` | Less than or equal | `{ qty: { $lte: 10 } }` |
| `$in` | Value in array | `{ status: { $in: ['active', 'pending'] } }` |
| `$nin` | Value not in array | `{ role: { $nin: ['guest'] } }` |

> **Shorthand:** `{ status: 'active' }` is equivalent to `{ status: { $eq: 'active' } }`.

### Logical

| Operator | Description | Example |
|----------|-------------|---------|
| `$and` | All conditions must match | `{ $and: [{ a: 1 }, { b: 2 }] }` |
| `$or` | At least one condition must match | `{ $or: [{ a: 1 }, { b: 2 }] }` |
| `$not` | Inverts a condition | `{ $not: { status: 'deleted' } }` |
| `$nor` | None of the conditions must match | `{ $nor: [{ a: 1 }, { b: 2 }] }` |

### Element

| Operator | Description | Example |
|----------|-------------|---------|
| `$exists` | Field exists (or not) | `{ email: { $exists: true } }` |
| `$type` | JavaScript `typeof` check | `{ age: { $type: 'number' } }` |

### Array

| Operator | Description | Example |
|----------|-------------|---------|
| `$all` | Array contains all values | `{ tags: { $all: ['js', 'db'] } }` |
| `$elemMatch` | At least one element matches | `{ items: { $elemMatch: { qty: { $gt: 5 } } } }` |
| `$size` | Array has exact length | `{ tags: { $size: 3 } }` |

### String

| Operator | Description | Example |
|----------|-------------|---------|
| `$regex` | Regular expression match | `{ name: { $regex: '^Alice' } }` |
| `$text` | Case-insensitive substring search | `{ bio: { $text: 'developer' } }` |

### Geospatial

| Operator | Description | Example |
|----------|-------------|---------|
| `$near` | Find points near coordinates | `{ location: { $near: { coordinates: { lat, lng }, maxDistance: 10 } } }` |
| `$within` | Find points within bounds | `{ location: { $within: { minLat, maxLat, minLng, maxLng } } }` |

> **Geo queries require** a geo index on the field. See [Indexing](#indexing).

<details>
<summary><strong>Complex Query Examples</strong></summary>

```javascript
// Active users over 18 with verified email
const users = await collection.query({
  $and: [
    { status: 'active' },
    { age: { $gte: 18 } },
    { emailVerified: { $exists: true } }
  ]
});

// Products in price range with specific tags
const products = await collection.query({
  $and: [
    { price: { $gte: 10, $lte: 100 } },
    { tags: { $all: ['sale', 'featured'] } },
    { category: { $in: ['electronics', 'accessories'] } }
  ]
});

// Dot notation for nested fields
const docs = await collection.query({
  'address.city': 'Zurich',
  'metadata.version': { $gte: 2 }
});

// Combined text and regex search
const articles = await collection.query({
  $or: [
    { title: { $regex: 'blockchain' } },
    { content: { $text: 'cryptocurrency' } }
  ]
});
```

</details>

---

## Aggregation Pipeline

Transform and analyze data using a sequence of pipeline stages. Each stage receives the output of the previous stage.

```javascript
const results = await collection.aggregate([
  { $match: { ... } },     // Filter
  { $group: { ... } },     // Group & accumulate
  { $sort: { ... } },      // Order
  { $limit: 10 }           // Trim
]);
```

### Stages

| Stage | Description | Example |
|-------|-------------|---------|
| `$match` | Filter documents (same syntax as `query`) | `{ $match: { status: 'active' } }` |
| `$project` | Include/exclude fields | `{ $project: { name: 1, email: 1 } }` |
| `$sort` | Order results (1 = asc, -1 = desc) | `{ $sort: { date: -1 } }` |
| `$limit` | Take first N results | `{ $limit: 10 }` |
| `$skip` | Skip first N results | `{ $skip: 20 }` |
| `$group` | Group by field and accumulate | See below |
| `$lookup` | Join with another collection | See below |

### Group Accumulators

| Accumulator | Description | Example |
|-------------|-------------|---------|
| `$sum` | Sum of field values | `{ total: { $sum: '$amount' } }` |
| `$avg` | Average of field values | `{ avgPrice: { $avg: '$price' } }` |
| `$min` | Minimum value | `{ cheapest: { $min: '$price' } }` |
| `$max` | Maximum value | `{ mostExpensive: { $max: '$price' } }` |
| `$count` | Count of documents in group | `{ orderCount: { $count: 1 } }` |

<details>
<summary><strong>Aggregation Examples</strong></summary>

```javascript
// Sales report by category
const report = await orders.aggregate([
  { $match: { status: 'completed' } },
  { $group: {
      _id: '$category',
      totalSales: { $sum: '$amount' },
      avgOrder: { $avg: '$amount' },
      orderCount: { $count: 1 }
  }},
  { $sort: { totalSales: -1 } },
  { $limit: 10 }
]);

// Join users with their orders ($lookup)
const usersWithOrders = await users.aggregate([
  { $lookup: {
      from: 'orders',          // Foreign collection name
      localField: '_id',        // Field in current collection
      foreignField: 'userId',   // Field in foreign collection
      as: 'orders'             // Output array field name
  }},
  { $project: { name: 1, email: 1, orders: 1 } }
]);

// Top customers this month
const topCustomers = await orders.aggregate([
  { $match: { date: { $gte: startOfMonth } } },
  { $group: {
      _id: '$customerId',
      total: { $sum: '$amount' },
      orders: { $count: 1 }
  }},
  { $sort: { total: -1 } },
  { $limit: 5 }
]);
```

</details>

---

## Indexing

Indexes dramatically improve query performance by avoiding full collection scans. LacertaDB supports four index types, each optimized for different query patterns.

### Index Types

| Type | Complexity | Best For | Query Operators |
|------|-----------|----------|-----------------|
| `btree` | O(log N) | Range queries, sorting, equality | `$eq`, `$gt`, `$gte`, `$lt`, `$lte` |
| `hash` | O(1) | Exact match, `$in` lookups | `$eq`, `$in` |
| `text` | O(tokens) | Full-text search (CJK-aware) | `$search` |
| `geo` | O(log N) | Location queries (QuadTree) | `$near`, `$within` |

### Creating Indexes

```javascript
// B-Tree index (default) — best for range queries
await collection.createIndex('email', { unique: true });
await collection.createIndex('createdAt');

// Hash index — fastest for exact-match lookups
await collection.createIndex('userId', { type: 'hash' });

// Text index — full-text search with Intl.Segmenter for CJK support
await collection.createIndex('content', { type: 'text' });

// Geo index — QuadTree-backed spatial queries
await collection.createIndex('location', { type: 'geo' });

// Sparse index — skip documents where field is null/undefined
await collection.createIndex('optionalField', { sparse: true });

// Hashed B-Tree — hash values before inserting into B-Tree
await collection.createIndex('sensitiveField', { hashed: true });
```

### Index Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `name` | `string` | `fieldPath` | Custom index name |
| `type` | `'btree' \| 'hash' \| 'text' \| 'geo'` | `'btree'` | Index structure |
| `unique` | `boolean` | `false` | Reject duplicate values |
| `sparse` | `boolean` | `false` | Skip null/undefined fields |
| `hashed` | `boolean` | `false` | SHA-256 hash values before indexing |
| `collation` | `Object \| null` | `null` | Reserved for future locale-aware sorting |

### Index Management

```javascript
// Get index statistics
const stats = await collection.getIndexes();
// { email: { fieldPath: 'email', type: 'btree', unique: true, size: 1500, memoryUsage: 180000 } }

// Verify integrity (auto-rebuilds if corrupted)
const report = await collection.verifyIndexes();
// { email: { healthy: true, issues: [], repaired: 0 } }

// Drop an index
await collection.dropIndex('email');
```

<details>
<summary><strong>Geospatial Queries</strong></summary>

```javascript
await places.createIndex('coordinates', { type: 'geo' });

// Find places within 10km of Zurich
const nearby = await places.query({
  coordinates: {
    $near: {
      coordinates: { lat: 47.3769, lng: 8.5417 },
      maxDistance: 10 // kilometers (Haversine distance)
    }
  }
});

// Find places within a bounding box
const inArea = await places.query({
  coordinates: {
    $within: {
      minLat: 47.0,
      maxLat: 48.0,
      minLng: 8.0,
      maxLng: 9.0
    }
  }
});
```

</details>

---

## Encryption

LacertaDB provides **AES-GCM-256** encryption with a **Master Key Wrapping** architecture powered entirely by the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API).

### Security Specifications

| Parameter | Value |
|-----------|-------|
| **Encryption Algorithm** | AES-GCM-256 |
| **Key Derivation** | PBKDF2 |
| **PBKDF2 Iterations** | 600,000 (OWASP 2024 recommendation) |
| **Hash Function** | SHA-256 |
| **Salt Length** | 32 bytes (256 bits) |
| **IV Length** | 12 bytes (96 bits, NIST SP 800-38D) |
| **HMAC** | HMAC-SHA-256 (32 bytes) on every encrypted document |
| **PIN Verification** | Constant-time comparison (timing-attack resistant) |

### How Master Key Wrapping Works

Unlike simple password-derived encryption, LacertaDB separates the *data encryption key* from the *user's PIN*:

```
User PIN  →  PBKDF2 (600k iterations)  →  KEK (Key Encryption Key)
                                              │
Random Master Key (256-bit)  ←── unwrap ──────┘
Random HMAC Key (256-bit)    ←── unwrap ──────┘
       │                            │
       ├── encrypts documents       ├── signs encrypted documents
       └── encrypts private keys    └── verifies on read
```

**Benefits:**
- **PIN change is instant** — only re-wraps the master key, no document re-encryption needed
- **Master key is cryptographically random** — not derived from a potentially weak PIN
- **Separate HMAC key** — tamper detection is independent of encryption

### Usage

```javascript
// Create encrypted database
const db = await lacerta.getSecureDatabase('vault', 'mySecretPin123');

// All documents in all collections are automatically encrypted
const secrets = await db.createCollection('secrets');
await secrets.add({
  apiKey: 'sk-live-xxx',
  privateData: 'sensitive information'
});

// Change PIN (instant — only re-wraps master key)
await db.changePin('mySecretPin123', 'newStrongerPin!');
```

### Private Key Vault

Store blockchain private keys, mnemonics, or other secrets with an additional authentication data layer:

```javascript
// Store with optional additional authentication data (AAD)
await db.storePrivateKey('wallet-main', privateKeyString, 'user@example.com');

// Retrieve — AAD must match exactly
const key = await db.getPrivateKey('wallet-main', 'user@example.com');
```

> **AAD** (Additional Authentication Data) is bound to the ciphertext via AES-GCM. If the AAD doesn't match on decryption, the operation fails even with the correct master key. Use it to bind keys to a specific context (user email, device ID, etc.).

### Secure PIN Generation

```javascript
import { SecureDatabaseEncryption } from '@pixagram/lacerta-db';

// Generate a cryptographically random, unbiased 6-digit PIN
const pin = SecureDatabaseEncryption.generateSecurePIN(6); // e.g., '839201'
const longPin = SecureDatabaseEncryption.generateSecurePIN(12); // e.g., '483920173856'
```

---

## Caching

Each collection has an independent, configurable query cache that avoids redundant IndexedDB reads. The cache is automatically invalidated after any write operation (add, update, delete).

### Strategies

| Strategy | Eviction Policy | Best For |
|----------|----------------|----------|
| `lru` | Evicts least recently accessed item | General purpose, read-heavy workloads |
| `lfu` | Evicts least frequently accessed item | Hot/cold data with stable access patterns |
| `ttl` | Evicts after fixed time-to-live expires | Data that becomes stale after a known period |
| `none` | Caching disabled | Write-heavy workloads, memory-constrained |

### Configuration

```javascript
collection.configureCacheStrategy({
  type: 'lru',        // 'lru' | 'lfu' | 'ttl' | 'none'
  maxSize: 200,       // Maximum number of cached query results
  ttl: 120000,        // Time-to-live in milliseconds (applies to LRU, LFU, and TTL)
  enabled: true       // Set to false to disable
});

// Manually clear cache
collection.clearCache();
```

> **Default:** Every collection starts with an LRU cache of 100 entries and a 60-second TTL.

---

## QuickStore

QuickStore provides **synchronous** key-value access backed by localStorage, ideal for user preferences, session tokens, feature flags, and other small data that needs to be available immediately without `await`.

```javascript
const quick = db.quickStore;

// Synchronous CRUD
quick.add('user-pref', { theme: 'dark', language: 'en' });
const prefs = quick.get('user-pref');     // null if not found
quick.update('user-pref', { theme: 'light', language: 'en' });
quick.delete('user-pref');

// Query (same MongoDB-style operators as Collection)
const darkThemePrefs = quick.query({ theme: 'dark' });

// Get all documents
const all = quick.getAll(); // [{ _id: 'user-pref', theme: 'light', ... }, ...]

// Size and cleanup
console.log(quick.size);   // number of stored items
quick.clear();             // remove all QuickStore data
```

**Implementation details:**
- Index is kept in memory (Set) to avoid parsing on every operation
- Index is persisted to localStorage via `requestIdleCallback` (debounced)
- `beforeunload` listener flushes pending index writes synchronously
- Data is serialized via TurboSerial and base64-encoded

> **Capacity:** localStorage is typically limited to 5–10 MB. Use Collections (IndexedDB) for larger datasets.

---

## Binary Attachments

LacertaDB stores binary files (images, PDFs, videos, etc.) in the **Origin Private File System** (OPFS), separate from document data in IndexedDB.

```javascript
// Add document with file attachments
const fileInput = document.querySelector('input[type="file"]');
const docId = await collection.add(
  { title: 'Report Q4', author: 'Alice' },
  { attachments: Array.from(fileInput.files) }
);

// Retrieve document with attachments
const doc = await collection.get(docId, { includeAttachments: true });
doc._attachments.forEach(att => {
  console.log(att.name, att.type, att.size);
  // att.data is a Uint8Array
});

// Prepare attachments programmatically
import { OPFSUtility } from '@pixagram/lacerta-db';

const attachment = await OPFSUtility.prepareAttachment(
  new Blob(['Hello'], { type: 'text/plain' }),
  'greeting.txt'
);
await collection.add({ title: 'Test' }, { attachments: [attachment] });
```

> **Note:** OPFS support varies by browser. Safari has partial support. See [Browser Compatibility](#browser-compatibility).

---

## Migrations

Manage schema changes across application versions. Migrations run per-document across all collections, with support for rollback.

```javascript
import { MigrationManager } from '@pixagram/lacerta-db';

const migration = new MigrationManager(db);

// Define forward and backward migrations
migration.addMigration({
  version: '1.1.0',
  name: 'Add user roles',
  up: async (doc) => ({
    ...doc,
    role: doc.role || 'user',
    permissions: doc.permissions || []
  }),
  down: async (doc) => {
    const { role, permissions, ...rest } = doc;
    return rest;
  }
});

migration.addMigration({
  version: '1.2.0',
  name: 'Normalize emails',
  up: async (doc) => ({
    ...doc,
    email: doc.email?.toLowerCase()
  }),
  down: async (doc) => doc
});

// Run all migrations up to target version
await migration.runMigrations('1.2.0');

// Rollback to a previous version
await migration.rollback('1.0.0');

// Check current version
console.log(migration.currentVersion); // '1.2.0'
```

> **How it works:** Migrations are applied in semver order. Each migration's `up` function receives a document and returns the transformed document (or `null` to skip). The current version is persisted in localStorage.

---

## Performance Monitoring

Built-in performance tracking with real-time metrics and optimization suggestions.

```javascript
const monitor = lacerta.performanceMonitor;

// Start collecting metrics
monitor.startMonitoring();

// ... perform operations ...

// Get real-time statistics
const stats = monitor.getStats();
// {
//   opsPerSec: 150,         // Operations in the last second
//   avgLatency: '2.34',     // Average operation latency in ms
//   cacheHitRate: '87.5',   // Cache hit rate percentage
//   memoryUsageMB: '45.20'  // JS heap usage (Chrome only)
// }

// Get automated optimization tips
const tips = monitor.getOptimizationTips();
// ['Performance is optimal. No issues detected.']
// or: ['High average latency detected. Consider enabling compression and indexing...']
// or: ['Low cache hit rate. Consider increasing cache size or optimizing query patterns.']

// Stop monitoring
monitor.stopMonitoring();
```

> **Note:** `memoryUsageMB` relies on `performance.memory` which is only available in Chromium-based browsers.

---

## Error Handling

All LacertaDB errors are instances of `LacertaDBError` with a machine-readable `code`, human-readable `message`, and ISO `timestamp`.

```javascript
import { LacertaDBError } from '@pixagram/lacerta-db';

try {
  await collection.get('nonexistent');
} catch (error) {
  if (error instanceof LacertaDBError) {
    console.log(error.code);           // 'DOCUMENT_NOT_FOUND'
    console.log(error.message);        // 'Document with id ...'
    console.log(error.timestamp);      // '2025-01-15T12:00:00.000Z'
    console.log(error.originalError);  // Underlying error (if any)
  }
}
```

### Error Codes

| Code | Description | Common Cause |
|------|-------------|--------------|
| `DOCUMENT_NOT_FOUND` | Document does not exist | Invalid or deleted document ID |
| `COLLECTION_NOT_FOUND` | Collection does not exist | Typo in collection name, or not yet created |
| `COLLECTION_EXISTS` | Collection already exists | Use `getCollection` instead of `createCollection` |
| `ENCRYPTION_NOT_INITIALIZED` | Document encryption requested without database encryption | Use `getSecureDatabase()` |
| `PERMANENT_DOCUMENT_PROTECTION` | Cannot delete a permanent document | Pass `{ force: true }` to `delete()` |
| `QUOTA_EXCEEDED` | localStorage storage limit reached | Clear QuickStore data or reduce usage |
| `TRANSACTION_FAILED` | IndexedDB transaction failed after retries | Check for database corruption or concurrent access |
| `DATABASE_OPEN_FAILED` | Failed to open IndexedDB connection | Browser may be in private mode or storage disabled |
| `PACK_FAILED` | Document serialization/compression/encryption failed | Check data types and encryption state |
| `IMPORT_PARSE_FAILED` | Import data could not be parsed | Corrupted or incompatible backup data |
| `INVALID_FORMAT` | Unsupported export format | Use `'json'` or `'encrypted'` |
| `ATTACHMENT_SAVE_FAILED` | OPFS write failed | OPFS not supported or storage full |
| `SYNC_DECRYPT_NOT_SUPPORTED` | Called `unpackSync()` on encrypted document | Use async `unpack()` instead |

---

## Examples

<details>
<summary><strong>User Management System</strong></summary>

```javascript
const lacerta = new LacertaDB();
const db = await lacerta.getSecureDatabase('app', 'adminPin123');

// Create collections with indexes
const users = await db.createCollection('users');
const sessions = await db.createCollection('sessions');

await users.createIndex('email', { unique: true });
await sessions.createIndex('userId', { type: 'hash' });
await sessions.createIndex('expiresAt');

// Register user
async function registerUser(data) {
  return await users.add({
    ...data,
    email: data.email.toLowerCase(),
    createdAt: Date.now(),
    status: 'pending'
  });
}

// Login — create session
async function login(email, passwordHash) {
  const [user] = await users.query({
    email: email.toLowerCase(),
    status: 'active'
  });

  if (!user || user.passwordHash !== passwordHash) {
    throw new Error('Invalid credentials');
  }

  const sessionId = await sessions.add({
    userId: user._id,
    createdAt: Date.now(),
    expiresAt: Date.now() + 24 * 60 * 60 * 1000
  });

  return { user, sessionId };
}

// Cleanup expired sessions
async function cleanupSessions() {
  const expired = await sessions.query({
    expiresAt: { $lt: Date.now() }
  });
  await sessions.batchDelete(expired.map(s => s._id));
}
```

</details>

<details>
<summary><strong>E-Commerce Cart</strong></summary>

```javascript
const db = await lacerta.getDatabase('shop');
const carts = await db.createCollection('carts');
const products = await db.createCollection('products');

await carts.createIndex('userId', { type: 'hash' });

// Add to cart (upsert pattern)
async function addToCart(userId, productId, quantity) {
  const [existing] = await carts.query({ userId, productId });

  if (existing) {
    await carts.update(existing._id, {
      quantity: existing.quantity + quantity,
      updatedAt: Date.now()
    });
  } else {
    await carts.add({ userId, productId, quantity, addedAt: Date.now() });
  }
}

// Cart with product details
async function getCart(userId) {
  const items = await carts.query({ userId });

  const enriched = await Promise.all(
    items.map(async (item) => {
      const product = await products.get(item.productId);
      return { ...item, product, subtotal: product.price * item.quantity };
    })
  );

  return {
    items: enriched,
    total: enriched.reduce((sum, i) => sum + i.subtotal, 0)
  };
}

// Cart analytics with aggregation
async function getTopProducts() {
  return await carts.aggregate([
    { $group: {
        _id: '$productId',
        totalQuantity: { $sum: '$quantity' },
        cartCount: { $count: 1 }
    }},
    { $sort: { totalQuantity: -1 } },
    { $limit: 10 }
  ]);
}
```

</details>

<details>
<summary><strong>Location-Based Service</strong></summary>

```javascript
const db = await lacerta.getDatabase('geo');
const places = await db.createCollection('places');

// Create geo and text indexes
await places.createIndex('location', { type: 'geo' });
await places.createIndex('name', { type: 'text' });

// Add a place
async function addPlace(data) {
  return await places.add({
    name: data.name,
    location: { lat: data.lat, lng: data.lng },
    category: data.category,
    rating: data.rating || 0,
    createdAt: Date.now()
  });
}

// Find nearby restaurants within 5km
async function findNearbyRestaurants(lat, lng, radiusKm = 5) {
  return await places.query({
    location: {
      $near: {
        coordinates: { lat, lng },
        maxDistance: radiusKm
      }
    },
    category: 'restaurant'
  }, {
    sort: { rating: -1 }
  });
}

// Search places by name within a bounding box
async function searchPlaces(query, bounds) {
  return await places.query({
    $and: [
      { name: { $text: query } },
      { location: { $within: bounds } }
    ]
  });
}
```

</details>

<details>
<summary><strong>Blockchain Wallet Key Management</strong></summary>

```javascript
const db = await lacerta.getSecureDatabase('wallet', userPin);

// Store wallet keys with additional authentication
async function storeWallet(walletName, privateKey, mnemonic) {
  await db.storePrivateKey(`${walletName}-key`, privateKey, walletName);
  await db.storePrivateKey(`${walletName}-mnemonic`, mnemonic, walletName);

  // Store public metadata (not the actual keys)
  const wallets = await db.createCollection('wallets').catch(() => db.getCollection('wallets'));
  await wallets.add({
    name: walletName,
    address: deriveAddress(privateKey),
    createdAt: Date.now()
  }, { id: walletName, permanent: true });
}

// Sign a transaction
async function signTransaction(walletName, tx) {
  const privateKey = await db.getPrivateKey(`${walletName}-key`, walletName);
  return signWithKey(tx, privateKey);
}

// Export encrypted backup
async function exportWallet(exportPassword) {
  return await db.export('encrypted', exportPassword);
}

// Import wallet from backup
async function importWallet(backupData, exportPassword) {
  return await db.import(backupData, 'encrypted', exportPassword);
}
```

</details>

<details>
<summary><strong>Backup and Restore</strong></summary>

```javascript
const lacerta = new LacertaDB();

// Full backup of all databases (optionally encrypted)
const backup = await lacerta.createBackup('backupPassword123');

// Save backup string (e.g., download as file or send to server)
downloadAsFile(backup, 'lacertadb-backup.dat');

// Restore from backup
const result = await lacerta.restoreBackup(backupString, 'backupPassword123');
console.log(`Restored ${result.databases} databases, ${result.collections} collections, ${result.documents} documents`);
```

</details>

---

## Exports

All public classes are available as named exports:

```javascript
import {
  // Core
  LacertaDB,               // Top-level manager
  Database,                 // Database instance
  Collection,               // Collection with CRUD, queries, indexes
  Document,                 // Document container

  // Storage
  QuickStore,               // Synchronous localStorage key-value store
  OPFSUtility,              // Binary attachment storage (OPFS)
  IndexedDBConnectionPool,  // Connection pooling for IndexedDB

  // Indexing
  IndexManager,             // Index lifecycle manager
  BTreeIndex,               // B-Tree index implementation
  TextIndex,                // Full-text inverted index
  GeoIndex,                 // QuadTree-backed spatial index

  // Caching
  CacheStrategy,            // Cache factory and wrapper
  LRUCache,                 // Least Recently Used cache
  LFUCache,                 // Least Frequently Used cache
  TTLCache,                 // Time-To-Live cache

  // Security
  SecureDatabaseEncryption, // Master key wrapping + AES-GCM + HMAC
  BrowserEncryptionUtility, // Standalone password-based AES-GCM encryption
  BrowserCompressionUtility,// CompressionStream wrapper with magic bytes

  // Utilities
  AsyncMutex,               // Promise-based mutual exclusion lock
  MigrationManager,         // Schema version management
  PerformanceMonitor,       // Metrics collection and optimization tips
  LacertaDBError            // Custom error class with codes
} from '@pixagram/lacerta-db';
```

---

## Browser Compatibility

LacertaDB requires a modern browser with IndexedDB, Web Crypto API, and CompressionStream support.

| Feature | Chrome | Firefox | Safari | Edge |
|---------|--------|---------|--------|------|
| IndexedDB | 24+ | 16+ | 10+ | 12+ |
| Web Crypto API | 37+ | 34+ | 11+ | 12+ |
| CompressionStream | 80+ | 113+ | 16.4+ | 80+ |
| OPFS | 86+ | 111+ | 15.2+ (partial) | 86+ |
| `Intl.Segmenter` (CJK text) | 87+ | ❌ (fallback used) | 15.4+ | 87+ |
| `requestIdleCallback` | 47+ | 55+ | ❌ (polyfilled) | 12+ |

> **Minimum recommended:** Chrome/Edge 86+, Firefox 113+, Safari 16.4+

> **Graceful degradation:** When `CompressionStream` is unavailable, data is stored uncompressed with a raw marker byte. When `Intl.Segmenter` is unavailable, text tokenization falls back to regex-based word splitting. When `requestIdleCallback` is unavailable, `setTimeout(fn, 0)` is used.

---

## License

MIT © [Pixagram SA](https://pixagram.io)

---

<p align="center">
  Made with 🦎 in Zug, Switzerland
</p>
