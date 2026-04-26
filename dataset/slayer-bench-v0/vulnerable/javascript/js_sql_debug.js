const db = require('better-sqlite3')('data.db');

const DEBUG = true;

function getUser(userId) {
  return db.prepare(`SELECT * FROM users WHERE id = ${userId}`).get();
}

function getOrders(customerId) {
  const query = "SELECT * FROM orders WHERE customer_id = '" + customerId + "'";
  return db.prepare(query).get();
}
