import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import app from "../src/app.js";

describe("Express App & Route Mounting Integration", () => {
  let server;
  let baseUrl;

  before(async () => {
    await new Promise((resolve) => {
      server = app.listen(0, () => {
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  after(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
  });

  it("GET /api/v1/healthcheck should return 200 with ApiResponse", async () => {
    const res = await fetch(`${baseUrl}/api/v1/healthcheck`);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.success, true);
    assert.strictEqual(body.statusCode, 200);
  });

  it("POST /api/v1/auth/register without body should fail with 422", async () => {
    const res = await fetch(`${baseUrl}/api/v1/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.strictEqual(res.status, 422);
    const body = await res.json();
    assert.strictEqual(body.success, false);
    assert.strictEqual(body.statusCode, 422);
    assert.ok(Array.isArray(body.errors));
  });

  it("POST /api/v1/auth/login without body should fail with 422", async () => {
    const res = await fetch(`${baseUrl}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.strictEqual(res.status, 422);
    const body = await res.json();
    assert.strictEqual(body.success, false);
  });

  it("POST /api/v1/auth/refresh-token without token should return 401", async () => {
    const res = await fetch(`${baseUrl}/api/v1/auth/refresh-token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    assert.strictEqual(res.status, 401);
    const body = await res.json();
    assert.strictEqual(body.success, false);
    assert.strictEqual(body.statusCode, 401);
  });

  it("GET /api/v1/users alias router should be mounted and handle routes", async () => {
    // Calling refresh-token on /users alias
    const res = await fetch(`${baseUrl}/api/v1/users/refresh-token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    assert.strictEqual(res.status, 401);
  });
});
