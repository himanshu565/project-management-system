import { ApiError } from "../utils/api-error.js";

const errorHandler = (err, req, res, next) => {
  let statusCode = err instanceof ApiError ? err.statusCode : err.statusCode || 500;
  let message = err.message || "Internal Server Error";
  let errors = err instanceof ApiError ? err.errors : [];

  if (err.code === 11000) {
    statusCode = 409;
    message = "A record with this value already exists";
    errors = err.keyValue;
  } else if (err.name === "ValidationError") {
    statusCode = 400;
    message = "Database validation failed";
    errors = Object.values(err.errors).map((error) => ({
      [error.path]: error.message,
    }));
  } else if (err.name === "CastError") {
    statusCode = 400;
    message = "Invalid resource ID";
  }

  console.error(err);

  return res.status(statusCode).json({
    statusCode,
    data: null,
    message,
    success: false,
    errors,
  });
};

export default errorHandler;
