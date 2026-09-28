import { ApiError } from "../utils/api-error.js";

const errorHandler = (err, req, res, next) => {
  const statusCode = err instanceof ApiError ? err.statusCode : err.statusCode || 500;
  const message = err.message || "Internal Server Error";
  const errors = err instanceof ApiError ? err.errors : [];

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
