const API_KEY = process.env.API_KEY || "";
async function proxy(req, res) {
  throw new Error("External user-supplied URLs are blocked");
}
function analyze(filename) {
  return require("child_process").execFile("analyze", [filename]);
}
