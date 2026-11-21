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
