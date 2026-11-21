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
