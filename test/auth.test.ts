import { test } from "node:test";
import assert from "node:assert/strict";
import request from "supertest";
import { createApp } from "../src/app.ts";
import { loadConfig } from "../src/config.ts";

const app = () => createApp(loadConfig({ JWT_SECRET: "test-secret-at-least-16-chars" }));
const creds = { email: "Ada@Example.com", password: "correct-horse-battery" };

test("register returns tokens and normalizes email", async () => {
  const res = await request(app()).post("/auth/register").send(creds).expect(201);
  assert.equal(res.body.user.email, "ada@example.com");
  assert.ok(res.body.accessToken);
  assert.ok(res.body.refreshToken);
});

test("register rejects duplicate email", async () => {
  const a = app();
  await request(a).post("/auth/register").send(creds).expect(201);
  await request(a).post("/auth/register").send(creds).expect(409);
});

test("register validates input", async () => {
  const res = await request(app()).post("/auth/register").send({ email: "nope", password: "x" }).expect(400);
  assert.equal(res.body.error, "validation_error");
});

test("login succeeds with correct password and fails otherwise", async () => {
  const a = app();
  await request(a).post("/auth/register").send(creds).expect(201);
  await request(a).post("/auth/login").send(creds).expect(200);
  const bad = await request(a).post("/auth/login").send({ ...creds, password: "wrong-password" }).expect(401);
  assert.equal(bad.body.error, "invalid_credentials");
});

test("/auth/me requires a valid bearer token", async () => {
  const a = app();
  const { body } = await request(a).post("/auth/register").send(creds);
  await request(a).get("/auth/me").expect(401);
  await request(a).get("/auth/me").set("Authorization", "Bearer garbage").expect(401);
  const me = await request(a).get("/auth/me").set("Authorization", `Bearer ${body.accessToken}`).expect(200);
  assert.equal(me.body.user.id, body.user.id);
});

test("refresh tokens rotate and cannot be reused", async () => {
  const a = app();
  const { body } = await request(a).post("/auth/register").send(creds);
  const first = await request(a).post("/auth/refresh").send({ refreshToken: body.refreshToken }).expect(200);
  assert.notEqual(first.body.refreshToken, body.refreshToken);
  await request(a).post("/auth/refresh").send({ refreshToken: body.refreshToken }).expect(401);
});

test("logout revokes the refresh token", async () => {
  const a = app();
  const { body } = await request(a).post("/auth/register").send(creds);
  await request(a).post("/auth/logout").send({ refreshToken: body.refreshToken }).expect(204);
  await request(a).post("/auth/refresh").send({ refreshToken: body.refreshToken }).expect(401);
});

test("change password requires auth and the current password", async () => {
  const a = app();
  const { body } = await request(a).post("/auth/register").send(creds);
  const auth = `Bearer ${body.accessToken}`;
  await request(a).post("/auth/password").send({ currentPassword: creds.password, newPassword: "new-password-123" }).expect(401);
  const bad = await request(a)
    .post("/auth/password")
    .set("Authorization", auth)
    .send({ currentPassword: "wrong-password", newPassword: "new-password-123" })
    .expect(401);
  assert.equal(bad.body.error, "invalid_credentials");
  await request(a)
    .post("/auth/password")
    .set("Authorization", auth)
    .send({ currentPassword: creds.password, newPassword: "short" })
    .expect(400);
});

test("change password updates login and revokes existing refresh tokens", async () => {
  const a = app();
  const { body } = await request(a).post("/auth/register").send(creds);
  const other = await request(a).post("/auth/login").send(creds).expect(200);
  const newPassword = "new-password-123";
  const changed = await request(a)
    .post("/auth/password")
    .set("Authorization", `Bearer ${body.accessToken}`)
    .send({ currentPassword: creds.password, newPassword })
    .expect(200);
  assert.ok(changed.body.accessToken);
  await request(a).post("/auth/refresh").send({ refreshToken: body.refreshToken }).expect(401);
  await request(a).post("/auth/refresh").send({ refreshToken: other.body.refreshToken }).expect(401);
  await request(a).post("/auth/refresh").send({ refreshToken: changed.body.refreshToken }).expect(200);
  await request(a).post("/auth/login").send(creds).expect(401);
  await request(a).post("/auth/login").send({ ...creds, password: newPassword }).expect(200);
});

test("changing to a password with the same 72-byte prefix revokes the old one", async () => {
  const a = app();
  const prefix = "a".repeat(72);
  const user = { email: "long@example.com", password: prefix + "old" };
  const { body } = await request(a).post("/auth/register").send(user).expect(201);
  await request(a)
    .post("/auth/password")
    .set("Authorization", `Bearer ${body.accessToken}`)
    .send({ currentPassword: user.password, newPassword: prefix + "new" })
    .expect(200);
  await request(a).post("/auth/login").send(user).expect(401);
  await request(a).post("/auth/login").send({ ...user, password: prefix + "new" }).expect(200);
});

test("a login racing a password change never keeps a working refresh token", async () => {
  for (let i = 0; i < 5; i++) {
    const a = app();
    const { body } = await request(a).post("/auth/register").send(creds);
    const [login] = await Promise.all([
      request(a).post("/auth/login").send(creds),
      request(a)
        .post("/auth/password")
        .set("Authorization", `Bearer ${body.accessToken}`)
        .send({ currentPassword: creds.password, newPassword: "new-password-123" })
        .expect(200),
    ]);
    if (login.status === 200) {
      await request(a).post("/auth/refresh").send({ refreshToken: login.body.refreshToken }).expect(401);
    } else {
      assert.equal(login.status, 401);
    }
  }
});

test("two concurrent password changes cannot both succeed", async () => {
  const a = app();
  const { body } = await request(a).post("/auth/register").send(creds);
  const change = (newPassword: string) =>
    request(a)
      .post("/auth/password")
      .set("Authorization", `Bearer ${body.accessToken}`)
      .send({ currentPassword: creds.password, newPassword });
  const results = await Promise.all([change("first-new-password"), change("second-new-password")]);
  const statuses = results.map((r) => r.status).sort();
  assert.ok(statuses.filter((s) => s === 200).length === 1, `got ${statuses}`);
});
