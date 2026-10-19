import { describe, it } from "node:test";
import assert from "node:assert/strict";
import mongoose from "mongoose";
import errorHandler from "../src/middlewares/errorHandler.js";
import {
  validateObjectIdParam,
  validateProjectPermission,
  verifyJWT,
} from "../src/middlewares/auth.middleware.js";
import { ApiError } from "../src/utils/api-error.js";
import { ApiResponse } from "../src/utils/Api-Response.js";
import { UserRolesEnum, AvailableUserRole } from "../src/utils/constants.js";
import { ProjectMember } from "../src/models/projectmember.models.js";
import {
  createMockResponse,
  generateExpiredToken,
  generateTamperedToken,
  generateTestToken,
} from "./test-utils.js";

describe("API Envelope and Error Response Contract", () => {
  it("ApiResponse should construct consistent success envelope", () => {
    const payload = { id: "123", name: "Sample" };
    const response = new ApiResponse(200, payload, "Success message");
    assert.strictEqual(response.statusCode, 200);
    assert.strictEqual(response.success, true);
    assert.strictEqual(response.message, "Success message");
    assert.deepStrictEqual(response.data, payload);
  });

  it("ApiError should construct consistent error envelope", () => {
    const error = new ApiError(403, "Access denied", [{ field: "role" }]);
    assert.strictEqual(error.statusCode, 403);
    assert.strictEqual(error.success, false);
    assert.strictEqual(error.message, "Access denied");
    assert.strictEqual(error.data, null);
    assert.deepStrictEqual(error.errors, [{ field: "role" }]);
  });

  it("errorHandler should format ApiError with stable JSON envelope", () => {
    const res = createMockResponse();
    const err = new ApiError(404, "Project not found", ["Resource missing"]);
    errorHandler(err, {}, res, () => {});

    assert.strictEqual(res.statusCode, 404);
    assert.strictEqual(res.body.success, false);
    assert.strictEqual(res.body.statusCode, 404);
    assert.strictEqual(res.body.message, "Project not found");
    assert.deepStrictEqual(res.body.errors, ["Resource missing"]);
    assert.strictEqual(res.body.data, null);
  });

  it("errorHandler should map Mongoose CastError to 400 Invalid resource ID", () => {
    const res = createMockResponse();
    const castError = new Error("Cast to ObjectId failed");
    castError.name = "CastError";
    errorHandler(castError, {}, res, () => {});

    assert.strictEqual(res.statusCode, 400);
    assert.strictEqual(res.body.success, false);
    assert.strictEqual(res.body.message, "Invalid resource ID");
  });

  it("errorHandler should map Mongoose ValidationError to 400", () => {
    const res = createMockResponse();
    const valError = new Error("Validation failed");
    valError.name = "ValidationError";
    valError.errors = {
      title: { path: "title", message: "Title is required" },
    };
    errorHandler(valError, {}, res, () => {});

    assert.strictEqual(res.statusCode, 400);
    assert.strictEqual(res.body.success, false);
    assert.strictEqual(res.body.message, "Database validation failed");
    assert.deepStrictEqual(res.body.errors, [{ title: "Title is required" }]);
  });

  it("errorHandler should map Multer LIMIT_FILE_SIZE to 400 with 1MB notice", () => {
    const res = createMockResponse();
    const multerError = new Error("File too large");
    multerError.name = "MulterError";
    multerError.code = "LIMIT_FILE_SIZE";
    errorHandler(multerError, {}, res, () => {});

    assert.strictEqual(res.statusCode, 400);
    assert.strictEqual(res.body.success, false);
    assert.strictEqual(res.body.message, "File size exceeds the 1MB limit");
  });

  it("errorHandler should map duplicate key error (code 11000) to 409 Conflict", () => {
    const res = createMockResponse();
    const dupError = new Error("E11000 duplicate key error");
    dupError.code = 11000;
    dupError.keyValue = { name: "Existing Project" };
    errorHandler(dupError, {}, res, () => {});

    assert.strictEqual(res.statusCode, 409);
    assert.strictEqual(res.body.success, false);
    assert.strictEqual(res.body.message, "A record with this value already exists");
    assert.deepStrictEqual(res.body.errors, { name: "Existing Project" });
  });
});

describe("Malformed ObjectId Parameter Middleware", () => {
  it("validateObjectIdParam should reject invalid MongoDB ObjectIds", () => {
    const middleware = validateObjectIdParam("taskId", "task");
    const invalidIds = ["123", "not-valid-hex", "507f1f77bcf86cd79943901z", "", null];

    for (const badId of invalidIds) {
      const req = { params: { taskId: badId } };
      let capturedError = null;
      try {
        middleware(req, {}, () => {});
      } catch (err) {
        capturedError = err;
      }
      assert.ok(capturedError instanceof ApiError, `ID '${badId}' should throw ApiError`);
      assert.strictEqual(capturedError.statusCode, 400);
      assert.strictEqual(capturedError.message, "Invalid task ID");
    }
  });

  it("validateObjectIdParam should accept valid 24-character hexadecimal ObjectId", () => {
    const middleware = validateObjectIdParam("projectId", "project");
    const validId = "507f1f77bcf86cd799439011";
    let nextCalled = false;
    middleware({ params: { projectId: validId } }, {}, () => {
      nextCalled = true;
    });
    assert.strictEqual(nextCalled, true);
  });
});

function executeMiddleware(middleware, req, res = {}) {
  return new Promise((resolve) => {
    try {
      middleware(req, res, (err) => {
        resolve(err || null);
      });
    } catch (syncErr) {
      resolve(syncErr);
    }
  });
}

describe("JWT Verification & Token Expiry Security Boundaries", () => {
  it("verifyJWT should reject missing token with 401", async () => {
    const req = { cookies: {}, header: () => null };
    const err = await executeMiddleware(verifyJWT, req);
    assert.ok(err instanceof ApiError);
    assert.strictEqual(err.statusCode, 401);
    assert.strictEqual(err.message, "unauthorized request");
  });

  it("verifyJWT should reject expired access token with 401", async () => {
    process.env.ACCESS_TOKEN_SECRET = "test_token_secret_32_characters_long!";
    const expiredToken = generateExpiredToken({ _id: "507f1f77bcf86cd799439011" });
    const req = {
      cookies: { accessToken: expiredToken },
      header: () => null,
    };
    const err = await executeMiddleware(verifyJWT, req);
    assert.ok(err instanceof ApiError);
    assert.strictEqual(err.statusCode, 401);
    assert.strictEqual(err.message, "Invalid access token");
  });

  it("verifyJWT should reject tampered signature with 401", async () => {
    process.env.ACCESS_TOKEN_SECRET = "test_token_secret_32_characters_long!";
    const tamperedToken = generateTamperedToken({ _id: "507f1f77bcf86cd799439011" });
    const req = {
      cookies: { accessToken: tamperedToken },
      header: () => null,
    };
    const err = await executeMiddleware(verifyJWT, req);
    assert.ok(err instanceof ApiError);
    assert.strictEqual(err.statusCode, 401);
    assert.strictEqual(err.message, "Invalid access token");
  });
});

describe("Role Matrix and Resource Isolation (validateProjectPermission)", () => {
  const originalFindOne = ProjectMember.findOne;

  it("should reject missing projectId with 400", async () => {
    const middleware = validateProjectPermission([UserRolesEnum.ADMIN]);
    const req = { params: {}, user: { _id: "507f1f77bcf86cd799439011" } };
    const err = await executeMiddleware(middleware, req);
    assert.ok(err instanceof ApiError);
    assert.strictEqual(err.statusCode, 400);
    assert.strictEqual(err.message, "project id is missing");
  });

  it("should reject malformed projectId with 400", async () => {
    const middleware = validateProjectPermission([UserRolesEnum.ADMIN]);
    const req = {
      params: { projectId: "malformed_project_id" },
      user: { _id: "507f1f77bcf86cd799439011" },
    };
    const err = await executeMiddleware(middleware, req);
    assert.ok(err instanceof ApiError);
    assert.strictEqual(err.statusCode, 400);
    assert.strictEqual(err.message, "Invalid project ID");
  });

  it("should reject non-member with 404 (Cross-project resource isolation)", async () => {
    ProjectMember.findOne = () => Promise.resolve(null);
    try {
      const middleware = validateProjectPermission(AvailableUserRole);
      const req = {
        params: { projectId: "507f1f77bcf86cd799439011" },
        user: { _id: "507f1f77bcf86cd799439012" },
      };
      const err = await executeMiddleware(middleware, req);
      assert.ok(err instanceof ApiError);
      assert.strictEqual(err.statusCode, 404);
      assert.strictEqual(err.message, "Project not found");
    } finally {
      ProjectMember.findOne = originalFindOne;
    }
  });

  it("should enforce admin-only operations (403 for member and project_admin)", async () => {
    const rolesToTest = [
      { role: UserRolesEnum.MEMBER, expectAllowed: false },
      { role: UserRolesEnum.PROJECT_ADMIN, expectAllowed: false },
      { role: UserRolesEnum.ADMIN, expectAllowed: true },
    ];

    for (const { role, expectAllowed } of rolesToTest) {
      ProjectMember.findOne = () => Promise.resolve({ role });
      try {
        const middleware = validateProjectPermission([UserRolesEnum.ADMIN]);
        const req = {
          params: { projectId: "507f1f77bcf86cd799439011" },
          user: { _id: "507f1f77bcf86cd799439012" },
        };
        const err = await executeMiddleware(middleware, req);

        if (expectAllowed) {
          assert.strictEqual(err, null);
          assert.strictEqual(req.user.role, UserRolesEnum.ADMIN);
        } else {
          assert.ok(err instanceof ApiError);
          assert.strictEqual(err.statusCode, 403);
          assert.strictEqual(
            err.message,
            "You do not have permission to perform this action"
          );
        }
      } finally {
        ProjectMember.findOne = originalFindOne;
      }
    }
  });

  it("should enforce task management roles (Admin and Project Admin allowed, Member 403)", async () => {
    const canManageTasks = [UserRolesEnum.ADMIN, UserRolesEnum.PROJECT_ADMIN];
    const rolesToTest = [
      { role: UserRolesEnum.MEMBER, expectAllowed: false },
      { role: UserRolesEnum.PROJECT_ADMIN, expectAllowed: true },
      { role: UserRolesEnum.ADMIN, expectAllowed: true },
    ];

    for (const { role, expectAllowed } of rolesToTest) {
      ProjectMember.findOne = () => Promise.resolve({ role });
      try {
        const middleware = validateProjectPermission(canManageTasks);
        const req = {
          params: { projectId: "507f1f77bcf86cd799439011" },
          user: { _id: "507f1f77bcf86cd799439012" },
        };
        const err = await executeMiddleware(middleware, req);

        if (expectAllowed) {
          assert.strictEqual(err, null);
          assert.strictEqual(req.user.role, role);
        } else {
          assert.ok(err instanceof ApiError);
          assert.strictEqual(err.statusCode, 403);
        }
      } finally {
        ProjectMember.findOne = originalFindOne;
      }
    }
  });

  it("should permit all project members on read/toggle routes (AvailableUserRole)", async () => {
    for (const role of AvailableUserRole) {
      ProjectMember.findOne = () => Promise.resolve({ role });
      try {
        const middleware = validateProjectPermission(AvailableUserRole);
        const req = {
          params: { projectId: "507f1f77bcf86cd799439011" },
          user: { _id: "507f1f77bcf86cd799439012" },
        };
        let nextCalled = false;
        await middleware(req, {}, () => {
          nextCalled = true;
        });
        assert.strictEqual(nextCalled, true, `Role '${role}' should be permitted`);
        assert.strictEqual(req.user.role, role);
      } finally {
        ProjectMember.findOne = originalFindOne;
      }
    }
  });
});

describe("Environment Configuration Validation", () => {
  it("validateEnvironment should detect missing database URI and JWT secrets", async () => {
    const { validateEnvironment } = await import("../src/utils/env-validator.js");
    const result = validateEnvironment({});
    assert.strictEqual(result.valid, false);
    assert.ok(result.missing.includes("MONGO_URI (or MONGODB_URI)"));
    assert.ok(result.missing.includes("ACCESS_TOKEN_SECRET"));
    assert.ok(result.missing.includes("REFRESH_TOKEN_SECRET"));
  });

  it("validateEnvironment should succeed when required configuration is provided", async () => {
    const { validateEnvironment } = await import("../src/utils/env-validator.js");
    const validConfig = {
      MONGODB_URI: "mongodb://127.0.0.1:27017/test",
      ACCESS_TOKEN_SECRET: "test_access_token_secret_32_characters!",
      REFRESH_TOKEN_SECRET: "test_refresh_token_secret_32_characters!",
      CORS_ORIGIN: "http://localhost:3000",
      MAILTRAP_SMTP_HOST: "sandbox.smtp.mailtrap.io",
      MAILTRAP_SMTP_USER: "user",
      MAILTRAP_SMTP_PASS: "pass",
    };
    const result = validateEnvironment(validConfig);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.missing.length, 0);
  });
});
