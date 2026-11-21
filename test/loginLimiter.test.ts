import { test } from "node:test";
import assert from "node:assert/strict";
import { LoginLimiter } from "../src/services/loginLimiter.ts";

test("in-flight attempts count toward the limit", () => {
  const limiter = new LoginLimiter(2, 1000);
  const a = limiter.begin("a@x.com", 0);
  const b = limiter.begin("A@x.com", 0);
  assert.ok(a && b);
  assert.equal(limiter.begin("a@x.com", 0), null, "third concurrent attempt must be blocked");
  b.release();
  assert.ok(limiter.begin("a@x.com", 0), "released slot can be reused");
});

test("fail records a failure, succeed clears history, release records nothing", (t) => {
  t.mock.method(Date, "now", () => 0);
  const limiter = new LoginLimiter(2, 1000);
  limiter.begin("a@x.com", 0)!.fail();
  limiter.begin("a@x.com", 0)!.release();
  const ok = limiter.begin("a@x.com", 0)!;
  ok.succeed();
  ok.fail(); // ignored: already settled
  limiter.begin("a@x.com", 0)!.fail();
  assert.ok(limiter.begin("a@x.com", 0), "only one failure since the success");
});

test("failures outside the window no longer count", (t) => {
  const now = t.mock.method(Date, "now", () => 0);
  const limiter = new LoginLimiter(2, 1000);
  limiter.begin("a@x.com", 0)!.fail();
  now.mock.mockImplementation(() => 500);
  limiter.begin("a@x.com", 500)!.fail();
  assert.equal(limiter.begin("a@x.com", 900), null);
  assert.ok(limiter.begin("a@x.com", 1600));
});

test("sweep removes failure records for inactive emails", (t) => {
  t.mock.method(Date, "now", () => 0);
  const limiter = new LoginLimiter(5, 1000);
  for (let i = 0; i < 100; i++) limiter.begin(`ghost${i}@x.com`, 0)!.fail();
  assert.equal(limiter.trackedEmails, 100);
  // The next attempt after a full window triggers the sweep.
  limiter.begin("someone@x.com", 1500)!.release();
  assert.equal(limiter.trackedEmails, 0);
});
