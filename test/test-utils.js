import jwt from "jsonwebtoken";
import { validationResult } from "express-validator";

const TEST_SECRET = "projectcamp_test_secret_for_jwt_verification_12345";

export function createMockResponse() {
  const res = {
    statusCode: 200,
    headers: {},
    body: null,
    status(code) {
      res.statusCode = code;
      return res;
    },
    json(data) {
      res.body = data;
      return res;
    },
    setHeader(key, value) {
      res.headers[key.toLowerCase()] = value;
      return res;
    },
  };
  return res;
}

export function generateTestToken(payload, options = {}) {
  const secret = process.env.ACCESS_TOKEN_SECRET || TEST_SECRET;
  return jwt.sign(payload, secret, {
    expiresIn: options.expiresIn || "1h",
    ...options,
  });
}

export function generateExpiredToken(payload) {
  const secret = process.env.ACCESS_TOKEN_SECRET || TEST_SECRET;
  return jwt.sign(payload, secret, {
    expiresIn: "-1s",
  });
}

export function generateTamperedToken(payload) {
  const token = generateTestToken(payload);
  const parts = token.split(".");
  // Corrupt signature part
  parts[2] = "invalid_signature_" + parts[2].slice(18);
  return parts.join(".");
}

export async function runValidator(validatorFn, body = {}, params = {}, query = {}) {
  const req = {
    body,
    params,
    query,
    headers: {},
  };
  const validators = validatorFn();
  for (const validator of validators) {
    await validator.run(req);
  }
  return {
    result: validationResult(req),
    req,
  };
}

