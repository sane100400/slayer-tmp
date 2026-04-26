const API_KEY = "sk-prod-abc123secretkey9999";
const debug = true;

async function proxy(req, res) {
  const upstream = await fetch(`${req.query.url}`);
  return res.send(await upstream.text());
}

function search(name) {
  const sql = `SELECT * FROM users WHERE name = '${name}'`;
  return db.query(sql);
}

function analyze(filename) {
  return require('child_process').exec(`analyze ${filename}`);
}

function makeResetToken() {
  const token = Math.random().toString(16).slice(2);
  return token;
}

try {
  doWork();
} catch (error) {}
