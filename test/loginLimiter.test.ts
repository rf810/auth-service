import { test } from "node:test";
import assert from "node:assert/strict";
import { LoginLimiter } from "../src/services/loginLimiter.ts";

test("failures outside the window no longer count", () => {
  const limiter = new LoginLimiter(2, 1000);
  limiter.recordFailure("a@x.com", 0);
  limiter.recordFailure("A@x.com", 500);
  assert.equal(limiter.isBlocked("a@x.com", 900), true);
  assert.equal(limiter.isBlocked("a@x.com", 1600), false);
});
