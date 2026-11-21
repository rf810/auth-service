import { Router } from "express";
import { z } from "zod";
import { hashPassword, verifyPassword } from "../services/passwords.ts";
import type { TokenService } from "../services/tokens.ts";
import type { User, UserStore } from "../store/userStore.ts";
import { requireAuth } from "../middleware/requireAuth.ts";

const credentials = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(128),
});

const refreshBody = z.object({ refreshToken: z.string().min(1) });

export function authRouter(users: UserStore, tokens: TokenService): Router {
  const router = Router();

  const issueTokens = (user: User) => ({
    accessToken: tokens.issueAccessToken({ sub: user.id, email: user.email }),
    refreshToken: tokens.issueRefreshToken(user.id),
    tokenType: "Bearer",
  });

  router.post("/register", async (req, res, next) => {
    try {
      const { email, password } = credentials.parse(req.body);
      if (users.findByEmail(email)) {
        return res.status(409).json({ error: "email_taken" });
      }
      const user = users.create(email, await hashPassword(password));
      res.status(201).json({ user: publicUser(user), ...issueTokens(user) });
    } catch (err) {
      next(err);
    }
  });

  router.post("/login", async (req, res, next) => {
    try {
      const { email, password } = credentials.parse(req.body);
      const user = users.findByEmail(email);
      // Same response for unknown email and wrong password to avoid account enumeration.
      if (!user || !(await verifyPassword(password, user.passwordHash))) {
        return res.status(401).json({ error: "invalid_credentials" });
      }
      res.json({ user: publicUser(user), ...issueTokens(user) });
    } catch (err) {
      next(err);
    }
  });

  router.post("/refresh", (req, res, next) => {
    try {
      const { refreshToken } = refreshBody.parse(req.body);
      const userId = tokens.consumeRefreshToken(refreshToken);
      const user = userId ? users.findById(userId) : undefined;
      if (!user) {
        return res.status(401).json({ error: "invalid_refresh_token" });
      }
      res.json(issueTokens(user));
    } catch (err) {
      next(err);
    }
  });

  router.post("/logout", (req, res, next) => {
    try {
      const { refreshToken } = refreshBody.parse(req.body);
      tokens.revokeRefreshToken(refreshToken);
      res.status(204).end();
    } catch (err) {
      next(err);
    }
  });

  router.get("/me", requireAuth(tokens), (req, res) => {
    const user = users.findById(req.auth!.sub);
    if (!user) return res.status(404).json({ error: "user_not_found" });
    res.json({ user: publicUser(user) });
  });

  return router;
}

function publicUser(user: User) {
  return { id: user.id, email: user.email, createdAt: user.createdAt.toISOString() };
}
