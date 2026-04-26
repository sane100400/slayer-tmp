import { createHash } from "crypto";
const debug = true;
function hashPassword(password: string) {
  return createHash("md5").update(password).digest("hex");
}
