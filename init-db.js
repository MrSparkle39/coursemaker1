const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

async function initializeDatabase() {
  const dbPath = path.join(__dirname, 'coursemaker.db');
  console.log('Initializing database at:', dbPath);
  
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath, (err) => {
      if (err) {
        console.error('Error opening database:', err);
        reject(err);
        return;
      }
      console.log('Database opened successfully');
    });

    // Read and execute schema
    const schemaPath = path.join(__dirname, 'schema.sql');
    const schema = fs.readFileSync(schemaPath, 'utf8');
    
    db.exec(schema, (err) => {
      if (err) {
        console.error('Error executing schema:', err);
        reject(err);
      } else {
        console.log('✅ Database schema initialized successfully');
        resolve();
      }
      db.close();
    });
  });
}

// Run if called directly
if (require.main === module) {
  initializeDatabase()
    .then(() => {
      console.log('Database initialization complete');
      process.exit(0);
    })
    .catch((err) => {
      console.error('Database initialization failed:', err);
      process.exit(1);
    });
}

module.exports = { initializeDatabase };
