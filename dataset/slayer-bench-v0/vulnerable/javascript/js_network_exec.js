const API_KEY = "ghp_123456789012345678901234567890123456";
async function proxy(req, res) {
  return fetch(`${req.query.url}`);
}
function analyze(filename) {
  return require("child_process").exec(`analyze ${filename}`);
}
