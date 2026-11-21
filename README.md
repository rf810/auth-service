# auth-service

A small, readable demo authentication service built with Node.js, TypeScript and Express.

- Email + password registration and login (bcrypt hashing)
- Short-lived JWT access tokens (HS256)
- Opaque, single-use **rotating** refresh tokens, stored hashed
- Logout / refresh-token revocation
- Request validation with zod
- In-memory storage behind a small interface, easy to swap for a database

> This is a demo. It keeps users and tokens in memory, so all data is lost on restart.

## Quick start

Requires Node.js 24+ (runs TypeScript directly, no build step).

```bash
npm install
cp .env.example .env   # then set JWT_SECRET
export $(cat .env | xargs)
npm start
```

## API

| Method | Path             | Body                      | Auth   |
|--------|------------------|---------------------------|--------|
| GET    | `/health`        |                           |        |
| POST   | `/auth/register` | `{ email, password }`     |        |
| POST   | `/auth/login`    | `{ email, password }`     |        |
| POST   | `/auth/refresh`  | `{ refreshToken }`        |        |
| POST   | `/auth/logout`   | `{ refreshToken }`        |        |
| GET    | `/auth/me`       |                           | Bearer |

Example:

```bash
curl -s localhost:3000/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"ada@example.com","password":"correct-horse-battery"}'
```

## Project layout

```
src/
  app.ts                 Express app wiring
  server.ts              Entry point
  config.ts              Env-based configuration
  routes/auth.ts         Auth endpoints
  services/passwords.ts  bcrypt helpers
  services/tokens.ts     JWT + refresh-token logic
  middleware/            Bearer auth guard, error handler
  store/userStore.ts     In-memory user store
test/auth.test.ts        End-to-end API tests (node:test + supertest)
```

## Development

```bash
npm run dev        # restart on change
npm test           # run tests
npm run typecheck  # tsc --noEmit
```

## License

MIT
