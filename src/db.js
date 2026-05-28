/**
 * Database module
 * WARNING: Intentional SQL injection vulnerabilities for GHAS demo.
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Use an in-memory SQLite database for the demo
const db = new sqlite3.Database(':memory:');

// Initialise schema and seed data
db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user',
    ssn TEXT,
    credit_card TEXT
  )`);

  db.run(`CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    price REAL
  )`);

  // Seed some users (plaintext passwords — another issue)
  db.run(`INSERT INTO users (username, password, email, role, ssn, credit_card)
    VALUES ('admin', 'admin123', 'admin@example.com', 'admin', '123-45-6789', '4111111111111111')`);
  db.run(`INSERT INTO users (username, password, email, role, ssn, credit_card)
    VALUES ('alice', 'password', 'alice@example.com', 'user', '987-65-4321', '4222222222222222')`);
  db.run(`INSERT INTO users (username, password, email, role, ssn, credit_card)
    VALUES ('bob', 'hunter2', 'bob@example.com', 'user', '111-22-3333', '4333333333333333')`);

  db.run(`INSERT INTO products (name, description, price) VALUES ('Widget A', 'A great widget', 9.99)`);
  db.run(`INSERT INTO products (name, description, price) VALUES ('Widget B', 'An even better widget', 19.99)`);
});

// ❌ SECURITY ISSUE: SQL injection — user input concatenated directly into query
function getUserByUsername(username) {
  return new Promise((resolve, reject) => {
    // Vulnerable: an attacker can pass "' OR '1'='1" to dump all users
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    db.get(query, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

// ❌ SECURITY ISSUE: SQL injection in search
function searchProducts(searchTerm) {
  return new Promise((resolve, reject) => {
    // Vulnerable: attacker can pass "'; DROP TABLE products; --"
    const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%' OR description LIKE '%${searchTerm}%'`;
    db.all(query, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

// ❌ SECURITY ISSUE: SQL injection — numeric ID not validated as integer
function getUserById(id) {
  return new Promise((resolve, reject) => {
    // Vulnerable: id could be "1 UNION SELECT username, password, email, role, ssn, credit_card, 1 FROM users--"
    const query = `SELECT * FROM users WHERE id = ${id}`;
    db.get(query, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

// ❌ SECURITY ISSUE: Returning ALL fields including sensitive PII and credentials
function getAllUsers() {
  return new Promise((resolve, reject) => {
    // Returns ssn, credit_card, password — should be excluded
    db.all('SELECT * FROM users', (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

module.exports = { getUserByUsername, searchProducts, getUserById, getAllUsers, db };
