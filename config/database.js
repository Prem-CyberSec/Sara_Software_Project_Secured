const sqlite3 = require('sqlite3').verbose();
const path = require('path');

//Database file path from environemnt or fallback
const DB_path = process.env.DATABASE_PATH || path.resolve(__dirname, '../secureDocs.sqlite');

const db = new sqlite3.Database(DB_path, (err) => {
    if (err) {
        console.error('Error Opening Database:',err.message);
    } else {
        console.log('Connected to SQLite Database at ', DB_path)
    }
});

module.exports = db;