import type { ArgSchema } from "../types/policy.js";

/**
 * Result of validating tool arguments against an ArgSchema.
 */
export interface ArgValidationResult {
  valid: boolean;
  /** Human-readable dotted path describing the failing constraint, e.g. "arguments.options.timeout: expected number". */
  reason?: string;
}

function validateValue(
  value: unknown,
  schema: ArgSchema,
  path: string
): ArgValidationResult {
  switch (schema.type) {
    case "boolean": {
      if (typeof value !== "boolean") {
        return { valid: false, reason: `${path}: expected boolean, got ${typeof value}` };
      }
      return { valid: true };
    }

    case "number": {
      if (typeof value !== "number") {
        return { valid: false, reason: `${path}: expected number, got ${typeof value}` };
      }
      if (schema.minimum !== undefined && value < schema.minimum) {
        return { valid: false, reason: `${path}: ${value} is less than minimum ${schema.minimum}` };
      }
      if (schema.maximum !== undefined && value > schema.maximum) {
        return { valid: false, reason: `${path}: ${value} exceeds maximum ${schema.maximum}` };
      }
      if (schema.enum !== undefined && !schema.enum.includes(value)) {
        return { valid: false, reason: `${path}: ${String(value)} is not one of [${schema.enum.join(", ")}]` };
      }
      return { valid: true };
    }

    case "string": {
      if (typeof value !== "string") {
        return { valid: false, reason: `${path}: expected string, got ${typeof value}` };
      }
      if (schema.minLength !== undefined && value.length < schema.minLength) {
        return { valid: false, reason: `${path}: string length ${value.length} is less than minLength ${schema.minLength}` };
      }
      if (schema.maxLength !== undefined && value.length > schema.maxLength) {
        return { valid: false, reason: `${path}: string length ${value.length} exceeds maxLength ${schema.maxLength}` };
      }
      if (schema.enum !== undefined && !schema.enum.includes(value)) {
        return { valid: false, reason: `${path}: "${value}" is not one of [${schema.enum.map((v) => `"${String(v)}"`).join(", ")}]` };
      }
      return { valid: true };
    }

    case "array": {
      if (!Array.isArray(value)) {
        return { valid: false, reason: `${path}: expected array, got ${typeof value}` };
      }
      if (schema.items) {
        for (let i = 0; i < value.length; i++) {
          const result = validateValue(value[i], schema.items, `${path}[${i}]`);
          if (!result.valid) return result;
        }
      }
      return { valid: true };
    }

    case "object": {
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        return { valid: false, reason: `${path}: expected object, got ${Array.isArray(value) ? "array" : typeof value}` };
      }
      const record = value as Record<string, unknown>;

      // Check required fields
      if (schema.required) {
        for (const key of schema.required) {
          if (!(key in record)) {
            return { valid: false, reason: `${path}.${key}: required field missing` };
          }
        }
      }

      // Recurse into defined properties
      if (schema.properties) {
        for (const [key, propSchema] of Object.entries(schema.properties)) {
          if (key in record) {
            const result = validateValue(record[key], propSchema, `${path}.${key}`);
            if (!result.valid) return result;
          }
        }
      }

      return { valid: true };
    }
  }
}

/**
 * Validates tool arguments against an ArgSchema descriptor.
 *
 * Returns `{ valid: true }` on success or `{ valid: false, reason: "..." }` with
 * a dotted-path description of the first failing constraint.
 */
export function validateArgs(args: unknown, schema: ArgSchema): ArgValidationResult {
  return validateValue(args, schema, "arguments");
}
