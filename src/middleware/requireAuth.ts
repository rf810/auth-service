import type { NextFunction, Request, Response } from "express";
import type { AccessTokenClaims, TokenService } from "../services/tokens.ts";

declare module "express-serve-static-core" {
  interface Request {
    auth?: AccessTokenClaims;
  }
}

export function requireAuth(tokens: TokenService) {
  return (req: Request, res: Response, next: NextFunction) => {
    const header = req.headers.authorization ?? "";
    const [scheme, token] = header.split(" ");
    if (scheme !== "Bearer" || !token) {
      return res.status(401).json({ error: "missing_token" });
    }
    try {
      req.auth = tokens.verifyAccessToken(token);
      next();
    } catch {
      res.status(401).json({ error: "invalid_token" });
    }
  };
}
