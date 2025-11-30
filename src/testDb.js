const db = require('../config/database');

db.serialize(() => {
  db.all("SELECT name FROM sqlite_master WHERE type='table'", (err, tables) => {
    if (err) {
      return console.error("Error fetching tables:", err.message);
    }
    console.log("Tables in DB:", tables.map(t => t.name));
  });

  db.all("SELECT * FROM Roles", (err, rows) => {
    if (err) {
      return console.error("Error querying Roles:", err.message);
    }
    console.log("Roles table contents:", rows);
  });
});

db.close();
