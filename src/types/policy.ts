/**
 * Enumerates the supported access modes for protected filesystem locations.
 * - `read-only`: reads are allowed and write/delete operations are denied.
 * - `blocked`: all access is denied.
 */
export type PathRestrictionMode = "read-only" | "blocked";

/**
 * Declares a protected filesystem path and the enforcement mode applied to it.
 */
export interface PathRestriction {
  /** Directory path to protect. Absolute paths are recommended for reliability. */
  path: string;
  /** Restriction mode for the directory. */
  mode: PathRestrictionMode;
}

/**
 * Rule that identifies which tools are allowed by policy.
 * - A string value matches a specific tool name.
 * - A regular expression supports pattern-based matching.
 */
export type ToolRule = string | RegExp;

/**
 * Lightweight schema descriptor for validating tool argument shapes.
 */
export interface ArgSchema {
  type: "object" | "string" | "number" | "boolean" | "array";
  required?: string[];
  properties?: Record<string, ArgSchema>;
  items?: ArgSchema;
  enum?: (string | number | boolean | null)[];
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
}

/**
 * Defines the complete guardian policy used to authorize and throttle tool calls.
 */
export interface GuardianPolicy {
  /** Tools that an agent is allowed to execute. Supports exact matches and regex-based matching. */
  allowedTools: ToolRule[];
  /** Filesystem directories with explicit read-only or blocked behavior. */
  restrictedPaths: PathRestriction[];
  /** Maximum number of tool calls allowed in a rolling one-minute window. */
  maxCallsPerMinute: number;
  /** If true, destructive actions require explicit approval. */
  approvalRequired: boolean;
  /** Optional per-tool argument shape constraints. Key is exact tool name. */
  toolArgSchemas?: Record<string, ArgSchema>;
}

// ---------------------------------------------------------------------------
// Internal validators
// ---------------------------------------------------------------------------

const VALID_MODES = new Set<string>(["read-only", "blocked"]);

function isNonNullObject(v: unknown): v is Record<string, unknown> {
  return Boolean(v) && typeof v === "object" && !Array.isArray(v);
}

function validatePathRestriction(entry: unknown, index: number): PathRestriction {
  if (!isNonNullObject(entry)) {
    throw new Error(`restrictedPaths[${index}] must be an object`);
  }
  if (typeof entry.path !== "string" || entry.path.trim().length === 0) {
    throw new Error(`restrictedPaths[${index}].path must be a non-empty string`);
  }
  if (typeof entry.mode !== "string" || !VALID_MODES.has(entry.mode)) {
    throw new Error(`restrictedPaths[${index}].mode must be 'read-only' or 'blocked'`);
  }
  return { path: entry.path, mode: entry.mode as PathRestrictionMode };
}

function validateToolRule(entry: unknown, index: number): ToolRule {
  if (typeof entry === "string") {
    if (entry.length === 0) throw new Error(`allowedTools[${index}] must be a non-empty string`);
    return entry;
  }
  if (entry instanceof RegExp) {
    return entry;
  }
  throw new Error(`allowedTools[${index}] must be a string or RegExp`);
}

function validateArgSchema(schema: unknown, path: string): ArgSchema {
  const VALID_TYPES = new Set(["object", "string", "number", "boolean", "array"]);
  if (!isNonNullObject(schema)) throw new Error(`${path} must be an object`);
  if (typeof schema.type !== "string" || !VALID_TYPES.has(schema.type)) {
    throw new Error(`${path}.type must be one of: object, string, number, boolean, array`);
  }
  return schema as unknown as ArgSchema;
}

function parseGuardianPolicy(input: unknown): GuardianPolicy {
  if (!isNonNullObject(input)) {
    throw new Error("policy must be a non-null object");
  }

  // allowedTools
  if (!Array.isArray(input.allowedTools) || input.allowedTools.length === 0) {
    throw new Error("allowedTools must be a non-empty array of strings or RegExps");
  }
  const allowedTools: ToolRule[] = input.allowedTools.map(
    (entry, i) => validateToolRule(entry, i)
  );

  // restrictedPaths
  if (!Array.isArray(input.restrictedPaths)) {
    throw new Error("restrictedPaths must be an array");
  }
  const restrictedPaths: PathRestriction[] = input.restrictedPaths.map(
    (entry, i) => validatePathRestriction(entry, i)
  );

  // maxCallsPerMinute
  if (!Number.isInteger(input.maxCallsPerMinute) || (input.maxCallsPerMinute as number) < 1) {
    throw new Error("maxCallsPerMinute must be a positive integer");
  }

  // approvalRequired
  if (typeof input.approvalRequired !== "boolean") {
    throw new Error("approvalRequired must be a boolean");
  }

  // toolArgSchemas (optional)
  let toolArgSchemas: Record<string, ArgSchema> | undefined;
  if (input.toolArgSchemas !== undefined) {
    if (!isNonNullObject(input.toolArgSchemas)) {
      throw new Error("toolArgSchemas must be a plain object");
    }
    toolArgSchemas = {};
    for (const [toolName, schema] of Object.entries(input.toolArgSchemas)) {
      toolArgSchemas[toolName] = validateArgSchema(schema, `toolArgSchemas.${toolName}`);
    }
  }

  return {
    allowedTools,
    restrictedPaths,
    maxCallsPerMinute: input.maxCallsPerMinute as number,
    approvalRequired: input.approvalRequired,
    ...(toolArgSchemas ? { toolArgSchemas } : {})
  };
}

// ---------------------------------------------------------------------------
// Public schema-like objects (backwards-compatible API — .parse() preserved)
// ---------------------------------------------------------------------------

/**
 * Validates and parses a raw value into a `PathRestrictionMode`.
 */
export const PathRestrictionModeSchema = {
  parse(input: unknown): PathRestrictionMode {
    if (typeof input !== "string" || !VALID_MODES.has(input)) {
      throw new Error("mode must be 'read-only' or 'blocked'");
    }
    return input as PathRestrictionMode;
  }
};

/**
 * Validates and parses a raw value into a `PathRestriction`.
 */
export const PathRestrictionSchema = {
  parse(input: unknown): PathRestriction {
    return validatePathRestriction(input, 0);
  }
};

/**
 * Validates and parses a raw value into a `ToolRule`.
 */
export const ToolRuleSchema = {
  parse(input: unknown): ToolRule {
    return validateToolRule(input, 0);
  }
};

/**
 * Validates and parses a raw value into a `GuardianPolicy`.
 * Exposes `.parse()` for validation that throws on failure and
 * `.safeParse()` for result-based error handling without try/catch.
 */
export const GuardianPolicySchema = {
  parse: parseGuardianPolicy,

  safeParse(
    input: unknown
  ): { success: true; data: GuardianPolicy } | { success: false; error: Error } {
    try {
      return { success: true, data: parseGuardianPolicy(input) };
    } catch (err) {
      return {
        success: false,
        error: err instanceof Error ? err : new Error(String(err))
      };
    }
  }
};
