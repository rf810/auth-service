import { createHash, randomBytes } from "node:crypto";
import jwt from "jsonwebtoken";
import type { Config } from "../config.ts";

export interface AccessTokenClaims {
  sub: string;
  email: string;
}

interface RefreshRecord {
  userId: string;
  expiresAt: number;
}

/**
 * Issues short-lived JWT access tokens and opaque, single-use refresh tokens.
 * Refresh tokens are stored hashed so a leaked store does not leak usable tokens.
 */
export class TokenService {
  private refreshTokens = new Map<string, RefreshRecord>();
  private config: Config;

  constructor(config: Config) {
    this.config = config;
  }

  issueAccessToken(claims: AccessTokenClaims): string {
    return jwt.sign({ email: claims.email }, this.config.jwtSecret, {
      subject: claims.sub,
      expiresIn: this.config.accessTokenTtlSeconds,
      algorithm: "HS256",
    });
  }

  verifyAccessToken(token: string): AccessTokenClaims {
    const payload = jwt.verify(token, this.config.jwtSecret, { algorithms: ["HS256"] });
    if (typeof payload === "string" || !payload.sub) {
      throw new Error("Malformed token");
    }
    return { sub: payload.sub, email: String(payload.email) };
  }

  issueRefreshToken(userId: string): string {
    this.pruneExpired();
    const token = randomBytes(32).toString("base64url");
    this.refreshTokens.set(hash(token), {
      userId,
      expiresAt: Date.now() + this.config.refreshTokenTtlSeconds * 1000,
    });
    return token;
  }

  /** Consumes a refresh token (rotation): returns the user id, or undefined if invalid. */
  consumeRefreshToken(token: string): string | undefined {
    const key = hash(token);
    const record = this.refreshTokens.get(key);
    this.refreshTokens.delete(key);
    if (!record || record.expiresAt < Date.now()) return undefined;
    return record.userId;
  }

  revokeRefreshToken(token: string): void {
    this.refreshTokens.delete(hash(token));
  }

  /**
   * Drops expired refresh-token records so the in-memory store does not grow
   * without bound. Returns the number of records removed.
   */
  pruneExpired(now: number = Date.now()): number {
    let removed = 0;
    for (const [key, record] of this.refreshTokens) {
      if (record.expiresAt < now) {
        this.refreshTokens.delete(key);
        removed++;
      }
    }
    return removed;
  }
}

function hash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}
