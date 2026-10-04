/**
 * In-memory database for the demo target.
 *
 * Uses Node's built-in SQLite (node:sqlite) against `:memory:`, so there is no
 * external database dependency and nothing to install. It is still a real SQL
 * engine with a real parser, which is what makes the /search injection genuine
 * rather than a simulated string match.
 *
 * A fresh database is built per call, so each test gets a clean slate.
 */
import { DatabaseSync } from 'node:sqlite';

const SCHEMA = `
  CREATE TABLE products (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    price       REAL NOT NULL
  );
  CREATE TABLE users (
    id       INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email    TEXT NOT NULL
  );
`;

const PRODUCTS = [
  [1, 'Mechanical Keyboard', 'Clicky switches, 87 keys.', 89.0],
  [2, 'USB-C Hub', '7-in-1 aluminium hub.', 49.5],
  [3, 'Webcam 1080p', 'Auto-focus with privacy shutter.', 65.0],
  [4, 'Laptop Stand', 'Adjustable aluminium riser.', 29.99],
  [5, 'Blue Light Glasses', 'Anti-fatigue lenses.', 19.99],
];

// Plaintext passwords on purpose: this is a deliberately vulnerable demo, and a
// leaked credential is the clearest possible proof that the injection works.
const USERS = [
  [1, 'alice', 'alice-password', 'alice@example.com'],
  [2, 'bob', 'hunter2', 'bob@example.com'],
  [3, 'admin', 'S3cr3t-Adm1n-P@ss', 'admin@example.com'],
];

export function createDb() {
  const db = new DatabaseSync(':memory:');
  db.exec(SCHEMA);

  const insertProduct = db.prepare(
    'INSERT INTO products (id, name, description, price) VALUES (?, ?, ?, ?)',
  );
  for (const product of PRODUCTS) insertProduct.run(...product);

  const insertUser = db.prepare(
    'INSERT INTO users (id, username, password, email) VALUES (?, ?, ?, ?)',
  );
  for (const user of USERS) insertUser.run(...user);

  return db;
}
