LacertaDB (@pixagram/lacerta-db)
LacertaDB is a Javascript IndexedDB Database for Web Browsers. Simple, Fast, Secure.

LacertaDB offers a powerful, modern, and feature-rich interface for working with IndexedDB in the browser. It's designed as a document-oriented database, providing a developer-friendly API similar to MongoDB. It prioritizes security, performance, and advanced data handling capabilities right out of the box.

✨ Key Features
Simple API: An intuitive and modern API that makes database operations straightforward.

Strong Encryption: Built-in AES-GCM encryption to secure sensitive documents with a password.

Efficient Compression: Automatic data compression using the Compression Streams API to save storage space.

OPFS Attachments: Store large files like images or videos efficiently using the Origin Private File System (OPFS), linking them directly to your documents.

Advanced Queries: A powerful MongoDB-like query engine with support for complex operators ($gt, $in, $regex, etc.) and logical combinations ($and, $or).

Aggregation Pipeline: Perform complex data analysis and transformations directly in the database with a multi-stage aggregation pipeline ($match, $group, $sort, etc.).

High-Performance Serialization: Uses turboserial and turbobase64 instead of JSON for faster serialization and deserialization of data.

Automatic Cleanup: Set storage limits and let the database automatically manage space by removing the oldest, non-permanent documents.

Full-Featured: Includes batch operations, query caching, metadata management, and a migration system to handle schema changes over time.

🚀 Installation
Install the package using your favorite package manager.

npm install @pixagram/lacerta-db

⚡ Quick Start
Here's how to get up and running with LacertaDB in just a few lines of code.

// Import the default instance
import LacertaDB from '@pixagram/lacerta-db';

async function main() {
  try {
    // 1. Get a database instance
    const db = await LacertaDB.getDatabase('my-app-db');

    // 2. Get or create a collection
    // Collections are created automatically on first access
    const users = await db.getCollection('users');

    // 3. Add a new document
    const newUserId = await users.add({
      name: 'Alex',
      level: 10,
      joined: new Date()
    });
    console.log(`User created with ID: ${newUserId}`);

    // 4. Get a document by its ID
    const user = await users.get(newUserId);
    console.log('Retrieved user:', user);

    // 5. Query for documents
    const highLevelUsers = await users.query({ level: { '$gt': 5 } });
    console.log('High-level users:', highLevelUsers);

  } catch (error) {
    console.error('Database operation failed:', error);
  }
}

main();

📖 API Reference
Database
The Database object is your main entry point for managing collections.

getDatabase(name)
Retrieves a database instance. If it doesn't exist, it's created.

const db = await LacertaDB.getDatabase('my-app-db');

getCollection(name)
Retrieves a collection from the database. If it doesn't exist, it's created.

const usersCollection = await db.getCollection('users');

dropCollection(name)
Deletes a collection and all of its documents and attachments.

await db.dropCollection('users');

Collection
The Collection object provides methods to interact with documents.

add(data, [options])
Adds a new document to the collection.

data (Object): The document data.

options (Object, optional):

encrypted (boolean): Set to true to encrypt the document.

password (string): Required if encrypted is true.

permanent (boolean): If true, the document won't be deleted by the auto-cleanup process.

attachments (Array): An array of file attachments.

const userId = await users.add({ name: 'Zoe' }, { permanent: true });

get(id, [options])
Retrieves a single document by its _id.

id (string): The document ID.

options (Object, optional):

password (string): Required to decrypt an encrypted document.

includeAttachments (boolean): If true, retrieves file data from OPFS.

const user = await users.get(userId);

query(filter, [options])
Finds documents matching the filter object.

filter (Object): A MongoDB-style query object.

options (Object, optional):

sort (Object): Sort order (e.g., { level: -1 }).

limit (number): Max number of documents to return.

skip (number): Number of documents to skip.

const results = await users.query({ name: 'Alex' });

update(id, updates)
Updates the data of a specific document.

await users.update(userId, { level: 11 });

delete(id)
Removes a document from the collection.

await users.delete(userId);

aggregate(pipeline)
Processes documents through an aggregation pipeline.

const results = await users.aggregate([
  { '$match': { level: { '$gt': 5 } } },
  { '$group': { _id: null, averageLevel: { '$avg': '$level' } } }
]);

🛠️ Advanced Usage
Encryption 🔒
To store sensitive data, simply set the encrypted flag and provide a password. LacertaDB handles the rest.

const secretData = { account: '123-456', secret: 'my-secret-key' };

const docId = await db.collection('secrets').add(secretData, {
  encrypted: true,
  password: 'a-very-strong-password'
});

// You MUST provide the same password to retrieve it
const retrieved = await db.collection('secrets').get(docId, {
  password: 'a-very-strong-password'
});

File Attachments 📎
You can attach files (like File objects or Uint8Array data) to a document. They are stored efficiently in the browser's Origin Private File System.

// Create a sample file
const fileContent = new TextEncoder().encode('This is the content of my file.');
const attachment = {
    name: 'readme.txt',
    type: 'text/plain',
    data: fileContent
};

// Add a document with the attachment
const reportId = await db.collection('reports').add(
  { title: 'Q3 Report' },
  { attachments: [attachment] }
);

// Retrieve the document and its attachments
const report = await db.collection('reports').get(reportId, {
  includeAttachments: true
});

console.log(report.data._attachments[0].name); // "readme.txt"
const content = new TextDecoder().decode(report.data._attachments[0].data);
console.log(content); // "This is the content of my file."

⚙️ Serialization: TurboSerial
A key performance feature of LacertaDB is its use of turboserial instead of JSON. This provides several advantages:

⚡ Speed: turboserial is significantly faster at serializing and deserializing complex JavaScript objects.

📦 Efficiency: It produces a more compact binary output, especially when compression is enabled, saving storage space.

🔬 Type Support: It correctly handles more data types than JSON, including Date, Map, Set, BigInt, and typed arrays.

All data stored in localStorage (like metadata) or passed to IndexedDB is processed through turboserial and turbobase64, ensuring top-tier performance.

📜 License
LacertaDB is licensed under the MIT License.
