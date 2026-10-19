import { Activity } from "../models/activity.models.js";

/**
 * Strips all sensitive data (passwords, tokens, verification secrets)
 * and truncates overly long content fields to ensure safe audit persistence.
 */
export function sanitizeMetadata(metadata = {}) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    return {};
  }

  const sanitized = {};
  const sensitivePattern = /password|token|secret|verification|cookie|auth/i;

  for (const [key, value] of Object.entries(metadata)) {
    if (sensitivePattern.test(key)) {
      continue; // Strictly omit any password, token, or secret field
    }

    if (typeof value === "string") {
      // Truncate long descriptions or text payloads to prevent unbounded storage
      sanitized[key] = value.length > 200 ? `${value.substring(0, 197)}...` : value;
    } else if (typeof value === "number" || typeof value === "boolean") {
      sanitized[key] = value;
    } else if (value instanceof Date) {
      sanitized[key] = value.toISOString();
    } else if (value && typeof value === "object" && !Array.isArray(value)) {
      sanitized[key] = sanitizeMetadata(value);
    }
  }

  return sanitized;
}

/**
 * Records an activity event in MongoDB.
 *
 * Architecture & Resilience Decision:
 * We persist audit records immediately after the primary business action completes.
 * The operation is wrapped in a guarded try/catch block so that in environments where
 * distributed transactions are unavailable (e.g., standalone MongoDB instances without replica sets),
 * a transient audit logging hiccup does not abort or crash an already-successful user operation.
 */
export async function recordActivity({
  project,
  actor,
  actionType,
  resourceType,
  resourceId,
  summary,
  metadata = {},
}) {
  if (!project || !actor || !actionType || !resourceType || !summary) {
    return null;
  }

  try {
    const activity = await Activity.create({
      project,
      actor,
      actionType,
      resourceType,
      resourceId,
      summary: summary.trim().substring(0, 300),
      metadata: sanitizeMetadata(metadata),
    });
    return activity;
  } catch (error) {
    console.error("Non-fatal: Failed to record activity log:", error.message);
    return null;
  }
}

