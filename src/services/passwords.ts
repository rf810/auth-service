import { createHash } from "node:crypto";
import bcrypt from "bcryptjs";

const ROUNDS = 10;
const V2_PREFIX = "v2$";

/**
 * bcrypt only uses the first 72 bytes of its input. To make every byte of the
 * password count, v2 hashes bcrypt a SHA-256 digest of the password (44 base64
 * characters) instead of the raw string.
 */
function prehash(plain: string): string {
  return createHash("sha256").update(plain, "utf8").digest("base64");
}

export async function hashPassword(plain: string): Promise<string> {
  return V2_PREFIX + (await bcrypt.hash(prehash(plain), ROUNDS));
}

/** Verifies v2 hashes, and legacy hashes (raw bcrypt) created before v2. */
export function verifyPassword(plain: string, hash: string): Promise<boolean> {
  if (hash.startsWith(V2_PREFIX)) {
    return bcrypt.compare(prehash(plain), hash.slice(V2_PREFIX.length));
  }
  return bcrypt.compare(plain, hash);
}
