import { test } from "node:test";
import assert from "node:assert/strict";
import { TokenService } from "../src/services/tokens.ts";
import { loadConfig } from "../src/config.ts";

const service = () =>
  new TokenService(loadConfig({ JWT_SECRET: "test-secret-at-least-16-chars", REFRESH_TOKEN_TTL_SECONDS: "60" }));

test("pruneExpired removes only expired refresh tokens", () => {
  const tokens = service();
  const live = tokens.issueRefreshToken("user-1");
  tokens.issueRefreshToken("user-2");
  assert.equal(tokens.pruneExpired(Date.now()), 0);
  assert.equal(tokens.pruneExpired(Date.now() + 61_000), 2);
  assert.equal(tokens.consumeRefreshToken(live), undefined);
});

test("pruneExpired keeps tokens that are still valid", () => {
  const tokens = service();
  const live = tokens.issueRefreshToken("user-1");
  tokens.pruneExpired();
  assert.equal(tokens.consumeRefreshToken(live), "user-1");
});

test("pruneExpired is correct when the clock moved backwards between issuances", (t) => {
  const tokens = service();
  const now = t.mock.method(Date, "now", () => 10_000);
  const first = tokens.issueRefreshToken("user-1"); // expires at 70_000
  now.mock.mockImplementation(() => 5_000);
  const second = tokens.issueRefreshToken("user-2"); // expires at 65_000
  now.mock.mockImplementation(() => 67_000);
  // Only the second (earlier-expiring) token has expired at 67_000.
  assert.equal(tokens.pruneExpired(67_000), 1);
  assert.equal(tokens.pruneExpired(67_000), 0);
  assert.equal(tokens.consumeRefreshToken(second), undefined);
  assert.equal(tokens.consumeRefreshToken(first), "user-1");
});

test("pruneExpired skips tokens that were already consumed", () => {
  const tokens = service();
  const used = tokens.issueRefreshToken("user-1");
  tokens.issueRefreshToken("user-2");
  tokens.consumeRefreshToken(used);
  assert.equal(tokens.pruneExpired(Date.now() + 61_000), 1);
});

test("rotating tokens does not let stale expiry entries pile up", () => {
  const tokens = service();
  let token = tokens.issueRefreshToken("user-1");
  for (let i = 0; i < 5_000; i++) {
    assert.equal(tokens.consumeRefreshToken(token), "user-1");
    token = tokens.issueRefreshToken("user-1");
  }
  // One live token; the heap must stay bounded instead of holding ~5,000 stale entries.
  assert.ok(tokens.expiryIndexSize <= 2 * 1 + 64 + 1, `heap size ${tokens.expiryIndexSize}`);
  assert.equal(tokens.consumeRefreshToken(token), "user-1");
});

test("revoking tokens also compacts the expiry index", () => {
  const tokens = service();
  const issued = Array.from({ length: 500 }, () => tokens.issueRefreshToken("user-1"));
  for (const t of issued.slice(0, 450)) tokens.revokeRefreshToken(t);
  assert.ok(tokens.expiryIndexSize <= 2 * 50 + 64, `heap size ${tokens.expiryIndexSize}`);
  // Remaining tokens still expire and prune correctly after compaction.
  assert.equal(tokens.pruneExpired(Date.now() + 61_000), 50);
});
