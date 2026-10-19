import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { validationResult } from "express-validator";
import {
  userRegisterValidator,
  userLoginValidator,
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userResetForgotPasswordValidator,
} from "../src/validators/index.js";
import { ApiResponse } from "../src/utils/Api-Response.js";
import { ApiError } from "../src/utils/api-error.js";

async function runValidation(validators, body = {}) {
  const req = { body, params: {}, query: {}, headers: {} };
  for (const validator of validators) {
    await validator.run(req);
  }
  return validationResult(req);
}

describe("Auth Input Validation Suites", () => {
  it("userRegisterValidator should reject missing required fields", async () => {
    const result = await runValidation(userRegisterValidator(), {});
    assert.strictEqual(result.isEmpty(), false);
    const errors = result.array();
    assert.ok(errors.some((e) => e.path === "email"));
    assert.ok(errors.some((e) => e.path === "username"));
    assert.ok(errors.some((e) => e.path === "password"));
  });

  it("userRegisterValidator should reject uppercase or short usernames", async () => {
    const result = await runValidation(userRegisterValidator(), {
      email: "valid@example.com",
      username: "Ab",
      password: "secretpassword",
    });
    assert.strictEqual(result.isEmpty(), false);
    const errors = result.array();
    assert.ok(errors.some((e) => e.path === "username"));
  });

  it("userRegisterValidator should accept valid user data", async () => {
    const result = await runValidation(userRegisterValidator(), {
      email: "valid@example.com",
      username: "validuser",
      password: "secretpassword123",
    });
    assert.strictEqual(result.isEmpty(), true);
  });

  it("userLoginValidator should require password and reject invalid email", async () => {
    const result = await runValidation(userLoginValidator(), {
      email: "notanemail",
      password: "",
    });
    assert.strictEqual(result.isEmpty(), false);
    const errors = result.array();
    assert.ok(errors.some((e) => e.path === "password"));
    assert.ok(errors.some((e) => e.path === "email"));
  });

  it("userLoginValidator should accept valid email and password", async () => {
    const result = await runValidation(userLoginValidator(), {
      email: "user@example.com",
      password: "mypassword",
    });
    assert.strictEqual(result.isEmpty(), true);
  });

  it("userForgotPasswordValidator requires valid email", async () => {
    const invalidResult = await runValidation(userForgotPasswordValidator(), {
      email: "invalid",
    });
    assert.strictEqual(invalidResult.isEmpty(), false);

    const validResult = await runValidation(userForgotPasswordValidator(), {
      email: "reset@example.com",
    });
    assert.strictEqual(validResult.isEmpty(), true);
  });

  it("userResetForgotPasswordValidator requires newPassword", async () => {
    const invalidResult = await runValidation(
      userResetForgotPasswordValidator(),
      {}
    );
    assert.strictEqual(invalidResult.isEmpty(), false);

    const validResult = await runValidation(
      userResetForgotPasswordValidator(),
      { newPassword: "newsecretpassword" }
    );
    assert.strictEqual(validResult.isEmpty(), true);
  });

  it("userChangeCurrentPasswordValidator requires oldPassword and newPassword", async () => {
    const invalidResult = await runValidation(
      userChangeCurrentPasswordValidator(),
      { oldPassword: "old" }
    );
    assert.strictEqual(invalidResult.isEmpty(), false);

    const validResult = await runValidation(
      userChangeCurrentPasswordValidator(),
      { oldPassword: "oldpassword", newPassword: "newpassword" }
    );
    assert.strictEqual(validResult.isEmpty(), true);
  });
});

describe("API Envelope and Error Response Contract", () => {
  it("ApiResponse constructs expected envelope with success flag", () => {
    const res200 = new ApiResponse(200, { user: { id: "123" } }, "All good");
    assert.strictEqual(res200.statusCode, 200);
    assert.strictEqual(res200.success, true);
    assert.strictEqual(res200.message, "All good");
    assert.deepStrictEqual(res200.data, { user: { id: "123" } });

    const res201 = new ApiResponse(201, { created: true }, "Created");
    assert.strictEqual(res201.statusCode, 201);
    assert.strictEqual(res201.success, true);
  });

  it("ApiError constructs expected envelope properties", () => {
    const err = new ApiError(401, "Session expired", ["token_invalid"]);
    assert.strictEqual(err.statusCode, 401);
    assert.strictEqual(err.success, false);
    assert.strictEqual(err.message, "Session expired");
    assert.deepStrictEqual(err.errors, ["token_invalid"]);
    assert.strictEqual(err.data, null);
  });
});

