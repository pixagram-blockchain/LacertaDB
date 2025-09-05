# LacertaDB
![](https://github.com/pixagram-blockchain/LacertaDB/blob/main/logo.webp?raw=true)

> 🦎 **LacertaDB v4.0.3** - A powerful, feature-rich browser-based document database with encryption, compression, and advanced querying capabilities.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-4.0.3-blue.svg)]()
[![Browser Compatible](https://img.shields.io/badge/browser-compatible-green.svg)]()

## 📚 Table of Contents

- [✨ Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [📦 Installation](#-installation)
- [🎯 Basic Usage](#-basic-usage)
- [🔧 Core Concepts](#-core-concepts)
  - [Database](#database)
  - [Collections](#collections)
  - [Documents](#documents)
- [🔍 Querying](#-querying)
  - [Basic Queries](#basic-queries)
  - [Advanced Queries](#advanced-queries)
  - [Aggregation Pipeline](#aggregation-pipeline)
- [🔐 Security Features](#-security-features)
  - [Encryption](#encryption)
  - [Password Protection](#password-protection)
- [📎 Attachments](#-attachments)
- [⚡ Performance](#-performance)
  - [Compression](#compression)
  - [Performance Monitoring](#performance-monitoring)
  - [Query Caching](#query-caching)
- [🔄 Data Migration](#-data-migration)
- [💾 Backup & Restore](#-backup--restore)
- [🛠️ Advanced Features](#️-advanced-features)
  - [Batch Operations](#batch-operations)
  - [Event System](#event-system)
  - [Quick Store](#quick-store)
- [📊 Storage Management](#-storage-management)
- [🎨 API Reference](#-api-reference)
- [💡 Examples](#-examples)
- [🐛 Error Handling](#-error-handling)
- [📝 Best Practices](#-best-practices)
- [🤝 Contributing](#-contributing)

## ✨ Features

🎯 **Core Features**
- 📁 **Document-based storage** using IndexedDB
- 🔍 **MongoDB-like query syntax** for familiar operations
- 🔐 **AES-256-GCM encryption** with PBKDF2 key derivation
- 🗜️ **Built-in compression** using CompressionStream API
- 📎 **File attachments** via Origin Private File System (OPFS)
- ⚡ **High performance** with async operations and caching

🚀 **Advanced Capabilities**
- 📊 **Aggregation pipeline** for complex data processing
- 🔄 **Schema migration system** for version management
- 📈 **Performance monitoring** with real-time metrics
- 🎭 **Event-driven architecture** with hooks
- 💾 **Import/Export functionality** with encryption support
- 🔧 **Batch operations** for efficient bulk processing

## 🚀 Quick Start

```javascript
import { LacertaDB } from './lacertadb.js';

// Initialize LacertaDB
const lacerta = new LacertaDB();

// Get or create a database
const db = await lacerta.getDatabase('myApp');

// Create a collection
const users = await db.createCollection('users');

// Add a document
const userId = await users.add({
  name: 'Alice Johnson',
  email: 'alice@example.com',
  age: 28,
  tags: ['developer', 'javascript']
});

// Query documents
const results = await users.query({
  age: { $gte: 25 },
  tags: { $in: ['developer'] }
});

console.log('Found users:', results);
```

## 📦 Installation

### NPM/Yarn Installation

```bash
npm install @pixagram/lacertadb
# or
yarn add @pixagram/lacertadb
```

### Browser Module

```html
<script type="module">
  import { LacertaDB } from './lacertadb.js';
  const lacerta = new LacertaDB();
</script>
```

### Dependencies

LacertaDB requires:
- `@pixagram/turboserial` - High-performance serialization
- `@pixagram/turbobase64` - Optimized Base64 encoding

## 🎯 Basic Usage

### Creating a Database and Collection

```javascript
const lacerta = new LacertaDB();

// Create or get a database
const db = await lacerta.getDatabase('myDatabase');

// Create a collection with options
const products = await db.createCollection('products', {
  compressed: true,  // Enable compression by default
  encrypted: false   // Encryption disabled by default
});
```

### Adding Documents

```javascript
// Simple document
await products.add({
  name: 'Laptop',
  price: 999.99,
  inStock: true
});

// Document with options
await products.add(
  {
    name: 'Secure Document',
    data: 'sensitive information'
  },
  {
    id: 'custom-id-123',        // Custom ID
    encrypted: true,             // Encrypt this document
    password: 'secretPassword',  // Encryption password
    compressed: true,            // Compress the document
    permanent: true              // Mark as permanent (won't be auto-deleted)
  }
);
```

### Retrieving Documents

```javascript
// Get by ID
const product = await products.get('custom-id-123', {
  password: 'secretPassword'  // Required for encrypted documents
});

// Get all documents
const allProducts = await products.getAll();

// Get with attachments
const withFiles = await products.get('doc-id', {
  includeAttachments: true
});
```

## 🔧 Core Concepts

### Database

The database is the top-level container for your collections.

```javascript
// Get existing or create new database
const db = await lacerta.getDatabase('appDB');

// List all collections
const collections = db.listCollections();

// Get database statistics
const stats = db.getStats();
console.log(`Total size: ${stats.totalSizeKB} KB`);
console.log(`Total documents: ${stats.totalDocuments}`);

// Configure database settings
db.updateSettings({
  sizeLimitKB: 50000,      // 50MB limit
  bufferLimitKB: 40000,    // Start cleanup at 40MB
  freeSpaceEvery: 60000    // Run cleanup every minute
});
```

### Collections

Collections are containers for documents of similar type.

```javascript
// Create collection
const posts = await db.createCollection('posts');

// Get existing collection
const existingPosts = await db.getCollection('posts');

// Collection operations
await posts.clear();                    // Remove all documents
await db.dropCollection('posts');       // Delete collection entirely

// Collection events
posts.on('afterAdd', (doc) => {
  console.log('Document added:', doc._id);
});
```

### Documents

Documents are JavaScript objects with automatic metadata.

```javascript
// Document structure
const doc = {
  // User data
  title: 'My Post',
  content: 'Lorem ipsum...',
  
  // Automatic metadata (added by LacertaDB)
  _id: 'doc_1234567890_abc',  // Auto-generated unique ID
  _created: 1704067200000,     // Creation timestamp
  _modified: 1704067200000,    // Last modification timestamp
  _permanent: false,            // Deletion protection flag
};
```

## 🔍 Querying

### Basic Queries

```javascript
// Find all documents matching criteria
const results = await users.query({
  age: 30,                           // Exact match
  'address.city': 'New York'         // Nested field
});

// With options
const paginatedResults = await users.query(
  { status: 'active' },
  {
    sort: { createdAt: -1 },         // Sort descending
    skip: 10,                         // Skip first 10
    limit: 20,                        // Limit to 20 results
    projection: {                    // Select fields
      name: 1,
      email: 1,
      _id: 0
    }
  }
);
```

### Advanced Queries

LacertaDB supports MongoDB-style query operators:

#### Comparison Operators

```javascript
// $eq, $ne, $gt, $gte, $lt, $lte
await products.query({
  price: { $gte: 100, $lte: 500 }
});

// $in, $nin
await users.query({
  role: { $in: ['admin', 'moderator'] }
});
```

#### Logical Operators

```javascript
// $and
await products.query({
  $and: [
    { price: { $lt: 1000 } },
    { category: 'electronics' }
  ]
});

// $or
await users.query({
  $or: [
    { age: { $gte: 65 } },
    { status: 'premium' }
  ]
});

// $not
await products.query({
  discontinued: { $not: { $eq: true } }
});
```

#### Array Operators

```javascript
// $all - Array contains all values
await posts.query({
  tags: { $all: ['javascript', 'database'] }
});

// $elemMatch - Element matching
await orders.query({
  items: {
    $elemMatch: {
      product: 'laptop',
      quantity: { $gte: 2 }
    }
  }
});

// $size - Array length
await users.query({
  hobbies: { $size: 3 }
});
```

#### Text Search

```javascript
// $regex - Regular expression
await users.query({
  email: { $regex: '@company\\.com$' }
});

// $text - Case-insensitive text search
await posts.query({
  content: { $text: 'javascript' }
});
```

### Aggregation Pipeline

Powerful data processing with aggregation stages:

```javascript
// Sales analysis pipeline
const salesReport = await orders.aggregate([
  // Stage 1: Filter orders
  { $match: { status: 'completed' } },
  
  // Stage 2: Group by customer
  {
    $group: {
      _id: '$customerId',
      totalSpent: { $sum: '$amount' },
      orderCount: { $count: {} },
      avgOrderValue: { $avg: '$amount' }
    }
  },
  
  // Stage 3: Sort by total spent
  { $sort: { totalSpent: -1 } },
  
  // Stage 4: Limit to top 10
  { $limit: 10 },
  
  // Stage 5: Project final shape
  {
    $project: {
      customer: '$_id',
      metrics: {
        total: '$totalSpent',
        orders: '$orderCount',
        average: '$avgOrderValue'
      }
    }
  }
]);
```

#### Lookup (Join) Operations

```javascript
// Join with another collection
const ordersWithProducts = await orders.aggregate([
  {
    $lookup: {
      from: 'products',           // Foreign collection
      localField: 'productId',    // Field in orders
      foreignField: '_id',         // Field in products
      as: 'productDetails'         // Output array field
    }
  }
]);
```

## 🔐 Security Features

### Encryption

Documents can be individually encrypted with AES-256-GCM:

```javascript
// Add encrypted document
await users.add(
  {
    ssn: '123-45-6789',
    bankAccount: 'SECRET123',
    salary: 75000
  },
  {
    encrypted: true,
    password: 'strong-password-here',
    permanent: true  // Protect from auto-deletion
  }
);

// Retrieve encrypted document
const userData = await users.get('user-id', {
  password: 'strong-password-here'  // Required for decryption
});

// Update encrypted document
await users.update('user-id', 
  { salary: 80000 },
  { 
    encrypted: true,
    password: 'strong-password-here' 
  }
);
```

### Password Protection

Secure your exports and backups:

```javascript
// Export with encryption
const encryptedExport = await db.export('encrypted', 'export-password');

// Import encrypted data
await db.import(encryptedExport, 'encrypted', 'export-password');

// Create encrypted backup
const backup = await lacerta.createBackup('backup-password');

// Restore from encrypted backup
await lacerta.restoreBackup(backup, 'backup-password');
```

## 📎 Attachments

Store files using the Origin Private File System:

```javascript
// Prepare files
const file1 = new File(['content'], 'document.pdf', { type: 'application/pdf' });
const file2 = new Blob(['image data'], { type: 'image/png' });

// Add document with attachments
const docId = await documents.add(
  { title: 'Report with Files' },
  {
    attachments: [
      file1,
      file2,
      {
        name: 'custom.txt',
        type: 'text/plain',
        data: new TextEncoder().encode('Custom file content')
      }
    ]
  }
);

// Retrieve with attachments
const docWithFiles = await documents.get(docId, {
  includeAttachments: true
});

// Access attachments
docWithFiles._attachments.forEach(attachment => {
  console.log(`File: ${attachment.name} (${attachment.size} bytes)`);
  // attachment.data is Uint8Array
});
```

## ⚡ Performance

### Compression

Reduce storage size with automatic compression:

```javascript
// Enable compression for all documents in collection
const compressedColl = await db.createCollection('largeDocs', {
  compressed: true
});

// Per-document compression
await collection.add(largeData, {
  compressed: true  // Uses DeflateStream compression
});
```

### Performance Monitoring

Track database performance metrics:

```javascript
// Start monitoring
lacerta.performanceMonitor.startMonitoring();

// Perform operations...

// Get performance stats
const stats = lacerta.performanceMonitor.getStats();
console.log(`Operations/sec: ${stats.opsPerSec}`);
console.log(`Avg latency: ${stats.avgLatency}ms`);
console.log(`Cache hit rate: ${stats.cacheHitRate}%`);
console.log(`Memory usage: ${stats.memoryUsageMB}MB`);

// Get optimization tips
const tips = lacerta.performanceMonitor.getOptimizationTips();
tips.forEach(tip => console.log(`💡 ${tip}`));

// Stop monitoring
lacerta.performanceMonitor.stopMonitoring();
```

### Query Caching

Queries are automatically cached for 60 seconds:

```javascript
// First query - hits database
const results1 = await users.query({ status: 'active' });

// Second identical query - served from cache
const results2 = await users.query({ status: 'active' });

// Clear cache manually if needed
users.clearCache();
```

## 🔄 Data Migration

Version your schema changes:

```javascript
const migrationManager = new MigrationManager(db);

// Define migrations
migrationManager.addMigration({
  version: '2.0.0',
  name: 'Add user roles',
  up: async (doc) => {
    if (doc.type === 'user' && !doc.role) {
      return { ...doc, role: 'standard' };
    }
    return doc;
  },
  down: async (doc) => {
    if (doc.type === 'user') {
      const { role, ...rest } = doc;
      return rest;
    }
    return doc;
  }
});

// Run migrations
await migrationManager.runMigrations('2.0.0');

// Rollback if needed
await migrationManager.rollback('1.0.0');
```

## 💾 Backup & Restore

### Database Export/Import

```javascript
// Export single database
const exportData = await db.export('json');
// Save exportData to file or send to server

// Import data
const importResult = await db.import(exportData, 'json');
console.log(`Imported ${importResult.documents} documents`);

// Export with encryption
const secureExport = await db.export('encrypted', 'password123');
```

### Full System Backup

```javascript
// Backup all databases
const systemBackup = await lacerta.createBackup();
// Optional: encrypt the backup
const encryptedBackup = await lacerta.createBackup('backup-password');

// Restore from backup
const restoreResult = await lacerta.restoreBackup(systemBackup);
console.log(`Restored: ${restoreResult.databases} databases`);
console.log(`Total documents: ${restoreResult.documents}`);
```

## 🛠️ Advanced Features

### Batch Operations

Efficient bulk operations with transaction support:

```javascript
// Batch insert
const documents = [
  { name: 'Doc 1', value: 100 },
  { name: 'Doc 2', value: 200 },
  { name: 'Doc 3', value: 300 }
];

const results = await collection.batchAdd(documents, {
  compressed: true,
  encrypted: false
});

// Check results
results.forEach(result => {
  if (result.success) {
    console.log(`✅ Added: ${result.id}`);
  } else {
    console.log(`❌ Failed: ${result.error}`);
  }
});

// Batch update
const updates = [
  { id: 'doc1', data: { status: 'active' } },
  { id: 'doc2', data: { status: 'inactive' } }
];
await collection.batchUpdate(updates);

// Batch delete
const idsToDelete = ['doc3', 'doc4', 'doc5'];
await collection.batchDelete(idsToDelete);
```

### Event System

React to database operations:

```javascript
// Collection-level events
collection.on('beforeAdd', async (data) => {
  console.log('Validating document...');
  // Perform validation
});

collection.on('afterAdd', async (doc) => {
  console.log(`Document ${doc._id} added`);
  // Send notification, update cache, etc.
});

collection.on('beforeUpdate', async ({ docId, updates }) => {
  console.log(`Updating ${docId}`);
});

collection.on('afterDelete', async (docId) => {
  console.log(`Document ${docId} deleted`);
  // Cleanup related data
});

// Remove event listener
const handler = (doc) => console.log(doc);
collection.on('afterAdd', handler);
collection.off('afterAdd', handler);
```

### Quick Store

Fast localStorage-based storage for small data:

```javascript
// Access QuickStore
const quickStore = db.quickStore;

// Store data
quickStore.add('user-prefs', {
  theme: 'dark',
  language: 'en',
  notifications: true
});

// Retrieve data
const prefs = quickStore.get('user-prefs');

// Update
quickStore.update('user-prefs', { theme: 'light' });

// Get all stored items
const allItems = quickStore.getAll();

// Clear QuickStore
quickStore.clear();
```

## 📊 Storage Management

### Size Limits and Auto-Cleanup

```javascript
// Configure storage limits
db.updateSettings({
  sizeLimitKB: 100000,      // 100MB total limit
  bufferLimitKB: 80000,     // Start cleanup at 80MB
  freeSpaceEvery: 30000     // Check every 30 seconds
});

// Manual cleanup
await collection.freeSpace();

// Mark documents as permanent
await collection.add(importantData, {
  permanent: true  // Won't be deleted during cleanup
});

// Check collection size
const stats = collection.metadata;
console.log(`Collection size: ${stats.sizeKB} KB`);
console.log(`Document count: ${stats.length}`);
```

### Storage Information

```javascript
// Database statistics
const dbStats = db.getStats();
console.log(dbStats);
/* Output:
{
  name: 'myDatabase',
  totalSizeKB: 2457.3,
  totalDocuments: 1250,
  collections: [
    {
      name: 'users',
      sizeKB: 1024.5,
      documents: 500,
      createdAt: '2024-01-01T00:00:00.000Z',
      modifiedAt: '2024-01-15T10:30:00.000Z'
    }
  ]
}
*/

// List all databases
const allDatabases = lacerta.listDatabases();
console.log('Available databases:', allDatabases);
```

## 🎨 API Reference

### LacertaDB Class

| Method | Description | Returns |
|--------|-------------|---------|
| `getDatabase(name)` | Get or create a database | `Promise<Database>` |
| `dropDatabase(name)` | Delete a database | `Promise<void>` |
| `listDatabases()` | List all database names | `Array<string>` |
| `createBackup(password?)` | Create full system backup | `Promise<string>` |
| `restoreBackup(data, password?)` | Restore from backup | `Promise<Object>` |

### Database Class

| Method | Description | Returns |
|--------|-------------|---------|
| `createCollection(name, options?)` | Create new collection | `Promise<Collection>` |
| `getCollection(name)` | Get existing collection | `Promise<Collection>` |
| `dropCollection(name)` | Delete collection | `Promise<void>` |
| `listCollections()` | Get collection names | `Array<string>` |
| `getStats()` | Get database statistics | `Object` |
| `updateSettings(settings)` | Update configuration | `void` |
| `export(format, password?)` | Export database | `Promise<string>` |
| `import(data, format, password?)` | Import data | `Promise<Object>` |
| `clearAll()` | Delete all collections | `Promise<void>` |

### Collection Class

| Method | Description | Returns |
|--------|-------------|---------|
| `add(data, options?)` | Add document | `Promise<string>` |
| `get(id, options?)` | Get document by ID | `Promise<Object>` |
| `getAll(options?)` | Get all documents | `Promise<Array>` |
| `update(id, updates, options?)` | Update document | `Promise<string>` |
| `delete(id)` | Delete document | `Promise<void>` |
| `query(filter, options?)` | Query documents | `Promise<Array>` |
| `aggregate(pipeline)` | Run aggregation | `Promise<Array>` |
| `batchAdd(documents, options?)` | Add multiple documents | `Promise<Array>` |
| `batchUpdate(updates, options?)` | Update multiple documents | `Promise<Array>` |
| `batchDelete(ids)` | Delete multiple documents | `Promise<Array>` |
| `clear()` | Remove all documents | `Promise<void>` |
| `on(event, callback)` | Add event listener | `void` |
| `off(event, callback)` | Remove event listener | `void` |
| `clearCache()` | Clear query cache | `void` |

## 💡 Examples

### Todo Application

```javascript
// Initialize
const lacerta = new LacertaDB();
const db = await lacerta.getDatabase('todoApp');
const todos = await db.createCollection('todos');

// Add todos
await todos.add({
  title: 'Learn LacertaDB',
  completed: false,
  priority: 'high',
  tags: ['learning', 'database'],
  createdAt: Date.now()
});

// Query incomplete high-priority todos
const urgentTodos = await todos.query({
  completed: false,
  priority: 'high'
}, {
  sort: { createdAt: -1 }
});

// Mark as complete
await todos.update(todoId, {
  completed: true,
  completedAt: Date.now()
});

// Get statistics
const stats = await todos.aggregate([
  {
    $group: {
      _id: '$priority',
      count: { $count: {} },
      completed: { 
        $sum: { $cond: ['$completed', 1, 0] } 
      }
    }
  }
]);
```

### E-Commerce Inventory

```javascript
// Setup
const db = await lacerta.getDatabase('shop');
const products = await db.createCollection('products');
const orders = await db.createCollection('orders');

// Product with images
const productId = await products.add(
  {
    name: 'Wireless Mouse',
    price: 29.99,
    stock: 150,
    category: 'electronics'
  },
  {
    attachments: [productImage1, productImage2]
  }
);

// Complex inventory query
const lowStock = await products.query({
  $and: [
    { stock: { $lt: 20 } },
    { category: { $in: ['electronics', 'accessories'] } }
  ]
}, {
  projection: { name: 1, stock: 1, price: 1 }
});

// Sales report with joins
const salesReport = await orders.aggregate([
  { $match: { status: 'completed' } },
  {
    $lookup: {
      from: 'products',
      localField: 'productId',
      foreignField: '_id',
      as: 'product'
    }
  },
  {
    $group: {
      _id: '$product.category',
      revenue: { $sum: '$total' },
      orderCount: { $count: {} }
    }
  },
  { $sort: { revenue: -1 } }
]);
```

### User Session Management

```javascript
// Encrypted session storage
const sessions = await db.createCollection('sessions');

// Store session with encryption
await sessions.add(
  {
    userId: 'user123',
    token: 'secret-session-token',
    ipAddress: '192.168.1.1',
    userAgent: navigator.userAgent,
    expiresAt: Date.now() + (24 * 60 * 60 * 1000)
  },
  {
    encrypted: true,
    password: process.env.SESSION_KEY,
    permanent: false
  }
);

// Cleanup expired sessions
const now = Date.now();
const expired = await sessions.query({
  expiresAt: { $lt: now }
});

await sessions.batchDelete(expired.map(s => s._id));
```

## 🐛 Error Handling

LacertaDB provides detailed error information:

```javascript
try {
  await collection.get('non-existent-id');
} catch (error) {
  if (error instanceof LacertaDBError) {
    console.error('Error:', error.message);
    console.error('Code:', error.code);
    console.error('Timestamp:', error.timestamp);
    
    // Handle specific error codes
    switch(error.code) {
      case 'DOCUMENT_NOT_FOUND':
        // Handle missing document
        break;
      case 'ENCRYPTION_FAILED':
        // Handle encryption error
        break;
      case 'QUOTA_EXCEEDED':
        // Handle storage limit
        break;
    }
  }
}
```

### Common Error Codes

| Code | Description | Solution |
|------|-------------|----------|
| `DOCUMENT_NOT_FOUND` | Document ID doesn't exist | Check ID or use query |
| `COLLECTION_NOT_FOUND` | Collection doesn't exist | Create collection first |
| `ENCRYPTION_FAILED` | Encryption/decryption error | Check password |
| `COMPRESSION_FAILED` | Compression error | Check data format |
| `QUOTA_EXCEEDED` | Storage limit reached | Increase limit or cleanup |
| `INVALID_OPERATION` | Operation not allowed | Check document flags |
| `TRANSACTION_FAILED` | Database transaction error | Retry operation |

## 📝 Best Practices

### 1. 🎯 Design Your Schema

```javascript
// Good: Consistent document structure
const userSchema = {
  type: 'user',
  email: '', 
  profile: {
    name: '',
    avatar: '',
    bio: ''
  },
  settings: {},
  metadata: {
    createdAt: Date.now(),
    lastLogin: null
  }
};
```

### 2. 🔍 Index Planning

```javascript
// Create indexes for frequently queried fields
// (Indexes are automatically created for _id and _modified)
// For custom indexes, use query patterns to identify needs
```

### 3. 🔐 Security First

```javascript
// Always encrypt sensitive data
const sensitiveOps = {
  encrypted: true,
  password: await generateSecurePassword(),
  permanent: true  // Prevent accidental deletion
};
```

### 4. ⚡ Performance Optimization

```javascript
// Use batch operations for bulk actions
await collection.batchAdd(largeDataset, {
  compressed: true  // Compress large datasets
});

// Enable monitoring during development
lacerta.performanceMonitor.startMonitoring();
// ... test operations ...
const tips = lacerta.performanceMonitor.getOptimizationTips();
```

### 5. 🧹 Regular Maintenance

```javascript
// Set appropriate limits
db.updateSettings({
  sizeLimitKB: 50000,
  bufferLimitKB: 40000,
  freeSpaceEvery: 300000  // 5 minutes
});

// Regular backups
const dailyBackup = async () => {
  const backup = await lacerta.createBackup('secure-password');
  await saveToCloud(backup);
};
setInterval(dailyBackup, 24 * 60 * 60 * 1000);
```

### 6. 📊 Monitor Usage

```javascript
// Track database growth
const monitor = async () => {
  const stats = db.getStats();
  if (stats.totalSizeKB > 40000) {
    console.warn('Database size exceeds 40MB');
    // Trigger cleanup or alert
  }
};
```

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. 🐛 **Report Bugs**: Open an issue with reproduction steps
2. 💡 **Suggest Features**: Share your ideas in discussions
3. 📝 **Improve Docs**: Fix typos or add examples
4. 🔧 **Submit PRs**: Fork, code, test, and submit

### Development Setup

```bash
# Clone repository
git clone https://github.com/pixagram-blockchain/LacertaDB.git
cd LacertaDB

# Install dependencies
npm install @pixagram/lacerta-db

# Run tests
npm test

# Build
npm run build
```

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 🙏 Acknowledgments

- Built with ❤️ by the Pixagram team
- Uses TurboSerial and TurboBase64 for high performance
- Inspired by MongoDB's query language
- Powered by modern browser APIs

## 📮 Support

- 📧 Email: omnibus (at) pixagram.io
- 🐛 Issues: [GitHub Issues](https://github.com/pixagram-blockchain/LacertaDB/issues)

---

🦎 LacertaDB - Fast, Secure, Browser-Native Database
