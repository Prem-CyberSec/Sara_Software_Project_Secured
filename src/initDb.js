require('dotenv').config();
const db = require('../config/database');

//Users table: Store user info, hashed password and role ID
const createUsersTable = `
    CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role_id INTEGER NOT NULL,
        refresh_token TEXT,
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (role_id) REFERENCES Roles(id)
    );
`;

//Roles table: Define user roles
const createRolesTable = `
    CREATE TABLE IF NOT EXISTS Roles(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role_name TEXT UNIQUE NOT NULL
    );
`;

// Documents table: Store documents metadat and owner
const createDocumentsTable = `
    CREATE TABLE IF NOT EXISTS Documents(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        filename TEXT NOT NULL,
        owner_id INTEGER NOT NULL,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES Users(id)
    );
`;

//Insert default roles if not present
const insertDefaultRoles = `
    INSERT OR IGNORE INTO Roles (role_name) VALUES
    ('Admin'), ('Manager'), ('Viewer'); 
`;

db.serialize(() => {
    db.run(createRolesTable);
    db.run(createUsersTable);
    db.run(createDocumentsTable);
    db.run(insertDefaultRoles, (err) => {
        if (err) {
            console.error('Error inserting default roles:', err.message);
        } else {
            console.log('Default roles ensured in Roles table:');
        }
    });
});

db.close(() => {
    console.log('Database setup completed and connection closed')
});