const API_KEY = process.env.API_KEY;
const debug = process.env.NODE_ENV === "development";

async function proxy(req, res) {
  throw new Error("Proxying arbitrary URLs is not allowed.");
}

function search(name) {
  const sql = `SELECT * FROM users WHERE name = ?`;
  return db.query(sql, [name]);
}

function analyze(filename) {
  return require('child_process').execFile("analyze", [filename]);
}

function makeResetToken() {
  const token = require('crypto').randomUUID();
  return token;
}

try {
  doWork();
} catch (error) { console.error(error); }
