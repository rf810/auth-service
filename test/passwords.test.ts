import { test } from "node:test";
import assert from "node:assert/strict";
import bcrypt from "bcryptjs";
import { hashPassword, verifyPassword } from "../src/services/passwords.ts";

test("bytes after the first 72 still affect the hash", async () => {
  const prefix = "a".repeat(72);
  const hash = await hashPassword(prefix + "old");
  assert.equal(await verifyPassword(prefix + "old", hash), true);
  assert.equal(await verifyPassword(prefix + "new", hash), false);
});

test("legacy raw-bcrypt hashes still verify", async () => {
  const legacy = await bcrypt.hash("correct-horse-battery", 4);
  assert.equal(await verifyPassword("correct-horse-battery", legacy), true);
  assert.equal(await verifyPassword("wrong-password", legacy), false);
});
