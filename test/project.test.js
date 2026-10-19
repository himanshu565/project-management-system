import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { validationResult } from "express-validator";
import {
  createProjectValidator,
  updateProjectValidator,
  addMembertoProjectValidator,
} from "../src/validators/index.js";
import app from "../src/app.js";

async function runValidation(validators, body = {}) {
  const req = { body, params: {}, query: {}, headers: {} };
  for (const validator of validators) {
    await validator.run(req);
  }
  return { result: validationResult(req), req };
}

describe("Project Validation Suites", () => {
  it("createProjectValidator should reject empty name", async () => {
    const { result } = await runValidation(createProjectValidator(), {
      name: "   ",
    });
    assert.strictEqual(result.isEmpty(), false);
    const errors = result.array();
    assert.ok(errors.some((e) => e.path === "name"));
  });

  it("createProjectValidator should accept valid full payload", async () => {
    const { result } = await runValidation(createProjectValidator(), {
      name: "Website Redesign",
      description: "Complete redesign of public portal",
      status: "In Progress",
      startDate: "2026-11-01",
      endDate: "2026-12-01",
    });
    assert.strictEqual(result.isEmpty(), true);
  });

  it("createProjectValidator should accept empty string optional fields", async () => {
    const { result } = await runValidation(createProjectValidator(), {
      name: "Minimal Project",
      description: "",
      startDate: "",
      endDate: "",
      status: "",
    });
    assert.strictEqual(result.isEmpty(), true);
  });

  it("createProjectValidator should reject invalid status", async () => {
    const { result } = await runValidation(createProjectValidator(), {
      name: "Invalid Status Project",
      status: "Archived_Unknown",
    });
    assert.strictEqual(result.isEmpty(), false);
    const errors = result.array();
    assert.ok(errors.some((e) => e.path === "status"));
  });

  it("createProjectValidator should reject endDate before startDate", async () => {
    const { result } = await runValidation(createProjectValidator(), {
      name: "Time Travel Project",
      startDate: "2026-12-01",
      endDate: "2026-11-01",
    });
    assert.strictEqual(result.isEmpty(), false);
    const errors = result.array();
    assert.ok(errors.some((e) => e.path === "endDate"));
  });

  it("updateProjectValidator should accept partial updates", async () => {
    const { result } = await runValidation(updateProjectValidator(), {
      status: "Completed",
    });
    assert.strictEqual(result.isEmpty(), true);
  });

  it("updateProjectValidator should reject empty name when provided", async () => {
    const { result } = await runValidation(updateProjectValidator(), {
      name: "   ",
    });
    assert.strictEqual(result.isEmpty(), false);
    const errors = result.array();
    assert.ok(errors.some((e) => e.path === "name"));
  });

  it("addMembertoProjectValidator should require valid email", async () => {
    const { result } = await runValidation(addMembertoProjectValidator(), {
      email: "not-an-email",
      role: "member",
    });
    assert.strictEqual(result.isEmpty(), false);
    const errors = result.array();
    assert.ok(errors.some((e) => e.path === "email"));
  });

  it("addMembertoProjectValidator should sanitize and accept valid roles", async () => {
    const { result, req } = await runValidation(addMembertoProjectValidator(), {
      email: "colleague@example.com",
      role: "project_admin",
    });
    assert.strictEqual(result.isEmpty(), true);
    assert.strictEqual(req.body.role, "project_admin");
  });

  it("addMembertoProjectValidator should reject unknown roles", async () => {
    const { result } = await runValidation(addMembertoProjectValidator(), {
      email: "colleague@example.com",
      role: "super_admin_unauthorized",
    });
    assert.strictEqual(result.isEmpty(), false);
    const errors = result.array();
    assert.ok(errors.some((e) => e.path === "role"));
  });
});

describe("Project Routes Authorization Boundaries", () => {
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

  it("GET /api/v1/projects requires authentication", async () => {
    const res = await fetch(`${baseUrl}/api/v1/projects`);
    assert.strictEqual(res.status, 401);
  });

  it("POST /api/v1/projects requires authentication", async () => {
    const res = await fetch(`${baseUrl}/api/v1/projects`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "Unauth Project" }),
    });
    assert.strictEqual(res.status, 401);
  });

  it("GET /api/v1/projects/:projectId requires authentication", async () => {
    const res = await fetch(`${baseUrl}/api/v1/projects/507f1f77bcf86cd799439011`);
    assert.strictEqual(res.status, 401);
  });

  it("GET /api/v1/projects/:projectId/members requires authentication", async () => {
    const res = await fetch(
      `${baseUrl}/api/v1/projects/507f1f77bcf86cd799439011/members`
    );
    assert.strictEqual(res.status, 401);
  });

  it("POST /api/v1/projects/:projectId/members requires authentication", async () => {
    const res = await fetch(
      `${baseUrl}/api/v1/projects/507f1f77bcf86cd799439011/members`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "user@example.com", role: "member" }),
      }
    );
    assert.strictEqual(res.status, 401);
  });

  it("DELETE /api/v1/projects/:projectId/members/:userId requires authentication", async () => {
    const res = await fetch(
      `${baseUrl}/api/v1/projects/507f1f77bcf86cd799439011/members/507f1f77bcf86cd799439012`,
      {
        method: "DELETE",
      }
    );
    assert.strictEqual(res.status, 401);
  });

  it("GET /api/v1/projects/:projectId/activities requires authentication", async () => {
    const res = await fetch(
      `${baseUrl}/api/v1/projects/507f1f77bcf86cd799439011/activities`
    );
    assert.strictEqual(res.status, 401);
  });

  it("GET /api/v1/projects/:projectId/health-summary requires authentication", async () => {
    const res = await fetch(
      `${baseUrl}/api/v1/projects/507f1f77bcf86cd799439011/health-summary`
    );
    assert.strictEqual(res.status, 401);
  });
});
