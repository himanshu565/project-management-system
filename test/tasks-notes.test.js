import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  createTaskValidator,
  updateTaskValidator,
  createSubtaskValidator,
  updateSubtaskValidator,
  createNoteValidator,
} from "../src/validators/index.js";
import { fileFilter, allowedMimeTypes } from "../src/middlewares/multer.middleware.js";
import { runValidator } from "./test-utils.js";
import app from "../src/app.js";

describe("Task, Subtask, Note & Upload Validation Suites", () => {
  it("createTaskValidator should reject empty title", async () => {
    const { result } = await runValidator(createTaskValidator, {
      title: "   ",
    });
    assert.strictEqual(result.isEmpty(), false);
    assert.ok(result.array().some((e) => e.path === "title"));
  });

  it("createTaskValidator should accept valid task payload", async () => {
    const { result } = await runValidator(createTaskValidator, {
      title: "Implement OAuth2",
      description: "Support GitHub and Google sign in",
      status: "in_progress",
      assignedTo: "507f1f77bcf86cd799439011",
    });
    assert.strictEqual(result.isEmpty(), true);
  });

  it("createTaskValidator should reject invalid status", async () => {
    const { result } = await runValidator(createTaskValidator, {
      title: "Task with bad status",
      status: "invalid_status_enum",
    });
    assert.strictEqual(result.isEmpty(), false);
    assert.ok(result.array().some((e) => e.path === "status"));
  });

  it("createTaskValidator should reject malformed assignedTo ObjectId", async () => {
    const { result } = await runValidator(createTaskValidator, {
      title: "Task with bad assignee",
      assignedTo: "not-a-mongo-id",
    });
    assert.strictEqual(result.isEmpty(), false);
    assert.ok(result.array().some((e) => e.path === "assignedTo"));
  });

  it("updateTaskValidator should accept valid partial updates", async () => {
    const { result } = await runValidator(updateTaskValidator, {
      status: "done",
    });
    assert.strictEqual(result.isEmpty(), true);
  });

  it("updateTaskValidator should reject empty title when specified", async () => {
    const { result } = await runValidator(updateTaskValidator, {
      title: "  ",
    });
    assert.strictEqual(result.isEmpty(), false);
    assert.ok(result.array().some((e) => e.path === "title"));
  });

  it("createSubtaskValidator should require title", async () => {
    const { result } = await runValidator(createSubtaskValidator, {
      title: "",
    });
    assert.strictEqual(result.isEmpty(), false);
    assert.ok(result.array().some((e) => e.path === "title"));
  });

  it("createSubtaskValidator should accept valid title", async () => {
    const { result } = await runValidator(createSubtaskValidator, {
      title: "Write integration tests",
    });
    assert.strictEqual(result.isEmpty(), true);
  });

  it("updateSubtaskValidator should reject non-boolean isCompleted", async () => {
    const { result } = await runValidator(updateSubtaskValidator, {
      isCompleted: "not_a_boolean",
    });
    assert.strictEqual(result.isEmpty(), false);
    assert.ok(result.array().some((e) => e.path === "isCompleted"));
  });

  it("updateSubtaskValidator should accept boolean isCompleted", async () => {
    const { result } = await runValidator(updateSubtaskValidator, {
      isCompleted: true,
    });
    assert.strictEqual(result.isEmpty(), true);
  });

  it("createNoteValidator should require content", async () => {
    const { result } = await runValidator(createNoteValidator, {
      title: "Meeting notes",
      content: "   ",
    });
    assert.strictEqual(result.isEmpty(), false);
    assert.ok(result.array().some((e) => e.path === "content"));
  });

  it("createNoteValidator should accept content with optional metadata", async () => {
    const { result } = await runValidator(createNoteValidator, {
      title: "Sprint Retrospective",
      content: "Discussed key deliverables and test coverage goals.",
      category: "Process",
    });
    assert.strictEqual(result.isEmpty(), true);
  });

  it("fileFilter should accept all allowed MIME types", () => {
    for (const mime of allowedMimeTypes) {
      let accepted = false;
      fileFilter({}, { mimetype: mime }, (err, result) => {
        assert.strictEqual(err, null);
        accepted = result;
      });
      assert.strictEqual(accepted, true, `MIME type ${mime} should be accepted`);
    }
  });

  it("fileFilter should reject unsafe MIME types with ApiError 400", () => {
    const unsafeMimes = [
      "application/x-msdownload",
      "application/javascript",
      "text/html",
      "application/x-sh",
    ];

    for (const mime of unsafeMimes) {
      let rejected = false;
      fileFilter({}, { mimetype: mime }, (err, result) => {
        assert.ok(err, `Unsafe MIME type ${mime} should throw an error`);
        assert.strictEqual(err.statusCode, 400);
        assert.strictEqual(result, false);
        rejected = true;
      });
      assert.strictEqual(rejected, true);
    }
  });
});

describe("Task and Note Route Authentication Boundaries", () => {
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

  const unauthEndpoints = [
    { method: "GET", path: "/api/v1/tasks/507f1f77bcf86cd799439011" },
    { method: "POST", path: "/api/v1/tasks/507f1f77bcf86cd799439011" },
    { method: "GET", path: "/api/v1/tasks/507f1f77bcf86cd799439011/t/507f1f77bcf86cd799439012" },
    { method: "PUT", path: "/api/v1/tasks/507f1f77bcf86cd799439011/t/507f1f77bcf86cd799439012" },
    { method: "DELETE", path: "/api/v1/tasks/507f1f77bcf86cd799439011/t/507f1f77bcf86cd799439012" },
    { method: "POST", path: "/api/v1/tasks/507f1f77bcf86cd799439011/t/507f1f77bcf86cd799439012/subtasks" },
    { method: "PUT", path: "/api/v1/tasks/507f1f77bcf86cd799439011/st/507f1f77bcf86cd799439013" },
    { method: "DELETE", path: "/api/v1/tasks/507f1f77bcf86cd799439011/st/507f1f77bcf86cd799439013" },
    { method: "GET", path: "/api/v1/notes/507f1f77bcf86cd799439011" },
    { method: "POST", path: "/api/v1/notes/507f1f77bcf86cd799439011" },
    { method: "GET", path: "/api/v1/notes/507f1f77bcf86cd799439011/507f1f77bcf86cd799439014" },
    { method: "PUT", path: "/api/v1/notes/507f1f77bcf86cd799439011/507f1f77bcf86cd799439014" },
    { method: "DELETE", path: "/api/v1/notes/507f1f77bcf86cd799439011/507f1f77bcf86cd799439014" },
  ];

  for (const endpoint of unauthEndpoints) {
    it(`${endpoint.method} ${endpoint.path} without credentials returns 401`, async () => {
      const res = await fetch(`${baseUrl}${endpoint.path}`, {
        method: endpoint.method,
        headers: { "Content-Type": "application/json" },
      });
      assert.strictEqual(res.status, 401);
      const data = await res.json();
      assert.strictEqual(data.success, false);
      assert.strictEqual(data.statusCode, 401);
    });
  }
});

