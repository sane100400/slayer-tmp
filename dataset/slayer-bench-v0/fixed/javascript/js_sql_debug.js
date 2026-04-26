const db = require('better-sqlite3')('data.db');

const DEBUG = process.env.NODE_ENV === 'development';

function getUser(userId) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
}

function getOrders(customerId) {
  return db.prepare('SELECT * FROM orders WHERE customer_id = ?').get(customerId);
}
