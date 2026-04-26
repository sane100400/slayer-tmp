import { createHash } from "crypto";
const debug = process.env.NODE_ENV !== "production";
function hashPassword(password: string) {
  return createHash("sha256").update(password).digest("hex");
}
