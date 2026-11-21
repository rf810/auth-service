import express from "express";
import type { Config } from "./config.ts";
import { authRouter } from "./routes/auth.ts";
import { errorHandler } from "./middleware/errorHandler.ts";
import { TokenService } from "./services/tokens.ts";
import { UserStore } from "./store/userStore.ts";

export function createApp(config: Config) {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "10kb" }));

  app.get("/health", (_req, res) => res.json({ status: "ok" }));
  app.use("/auth", authRouter(new UserStore(), new TokenService(config)));
  app.use((_req, res) => res.status(404).json({ error: "not_found" }));
  app.use(errorHandler);

  return app;
}
