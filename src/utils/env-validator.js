/**
 * Validates essential environment variables at application startup.
 * Logs actionable guidance and names of missing variables without revealing secret values.
 */
export function validateEnvironment(env = process.env) {
  const missing = [];
  const warnings = [];

  const isProduction = env.NODE_ENV === "production";

  // Database connection string (supports MONGO_URI or MONGODB_URI)
  if (!env.MONGO_URI && !env.MONGODB_URI) {
    missing.push("MONGO_URI (or MONGODB_URI)");
  }

  // JWT Signing Secrets
  if (!env.ACCESS_TOKEN_SECRET) {
    missing.push("ACCESS_TOKEN_SECRET");
  }
  if (!env.REFRESH_TOKEN_SECRET) {
    missing.push("REFRESH_TOKEN_SECRET");
  }

  // Production-specific requirements
  if (isProduction && !env.CORS_ORIGIN) {
    warnings.push(
      "CORS_ORIGIN is not explicitly configured for production. Browser requests with credentials may fail."
    );
  }

  // Email service
  if (
    !env.MAILTRAP_SMTP_HOST ||
    !env.MAILTRAP_SMTP_USER ||
    !env.MAILTRAP_SMTP_PASS
  ) {
    warnings.push(
      "SMTP credentials (MAILTRAP_SMTP_HOST, MAILTRAP_SMTP_USER, MAILTRAP_SMTP_PASS) are incomplete. Email verification and password resets will not send emails."
    );
  }

  return {
    valid: missing.length === 0,
    missing,
    warnings,
  };
}

export function assertRequiredEnvironment(env = process.env) {
  const { valid, missing, warnings } = validateEnvironment(env);

  if (warnings.length > 0) {
    for (const warning of warnings) {
      console.warn(`[CONFIG WARNING] ${warning}`);
    }
  }

  if (!valid) {
    const errorList = missing.map((item) => `  - ${item}`).join("\n");
    const errorMessage = `[CONFIG ERROR] Cannot start application. Missing required environment variables:\n${errorList}\nPlease check your .env file or copy .env.example.`;
    console.error(errorMessage);
    if (env.NODE_ENV === "production") {
      throw new Error(errorMessage);
    }
  }
}

