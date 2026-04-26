const debug = process.env.NODE_ENV !== "production";
function makeResetToken() {
  return crypto.randomUUID();
}
