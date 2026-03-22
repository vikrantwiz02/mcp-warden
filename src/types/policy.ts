import { z } from "zod";

/**
 * Enumerates the supported access modes for protected filesystem locations.
 * - `read-only`: reads are allowed and write/delete operations are denied.
 * - `blocked`: all access is denied.
 */
export const PathRestrictionModeSchema = z.enum(["read-only", "blocked"]);

/**
 * Declares a protected filesystem path and the enforcement mode applied to it.
 */
export const PathRestrictionSchema = z.object({
  /**
   * Directory path to protect. Absolute paths are recommended for reliability.
   */
  path: z.string().min(1, "path cannot be empty"),
  /**
   * Restriction mode for the directory.
   */
  mode: PathRestrictionModeSchema
});

/**
 * Rule that identifies which tools are allowed by policy.
 * - A string value matches a specific tool name.
 * - A regular expression supports pattern-based matching.
 */
export const ToolRuleSchema = z.union([z.string().min(1), z.instanceof(RegExp)]);

/**
 * Defines the complete guardian policy used to authorize and throttle tool calls.
 */
export const GuardianPolicySchema = z.object({
  /**
   * Tools that an agent is allowed to execute.
   * Supports exact matches and regex-based matching.
   */
  allowedTools: z.array(ToolRuleSchema).min(1, "at least one tool rule is required"),

  /**
   * Filesystem directories with explicit read-only or blocked behavior.
   */
  restrictedPaths: z.array(PathRestrictionSchema),

  /**
   * Maximum number of tool calls allowed in a rolling one-minute window.
   */
  maxCallsPerMinute: z.number().int().positive(),

  /**
   * If true, destructive actions (for example: delete/write) require explicit approval.
   */
  approvalRequired: z.boolean()
});

/**
 * Type-safe representation of a single path restriction entry.
 */
export type PathRestriction = z.infer<typeof PathRestrictionSchema>;

/**
 * Type-safe representation of the guardian policy payload.
 */
export type GuardianPolicy = z.infer<typeof GuardianPolicySchema>;
