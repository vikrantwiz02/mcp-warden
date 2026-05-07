import { GuardianPolicySchema } from "../types/policy.js";
import type { ArgSchema, GuardianPolicy, PathRestriction, ToolRule } from "../types/policy.js";

/**
 * Fluent builder for constructing a `GuardianPolicy` without writing object literals.
 *
 * @example
 * ```ts
 * const policy = new PolicyBuilder()
 *   .allow("read_file")
 *   .allow(/^search_/)
 *   .block("/etc")
 *   .readOnly("/home")
 *   .rateLimit(30)
 *   .argSchema("read_file", {
 *     type: "object",
 *     required: ["path"],
 *     properties: { path: { type: "string" } }
 *   })
 *   .build();
 * ```
 */
export class PolicyBuilder {
  private readonly _tools: ToolRule[] = [];

  private readonly _paths: PathRestriction[] = [];

  private _limit = 60;

  private _approval = false;

  private readonly _schemas: Record<string, ArgSchema> = {};

  /**
   * Allow a tool by exact name or regex pattern.
   * Call multiple times to allow multiple tools.
   */
  allow(tool: string | RegExp): this {
    this._tools.push(tool);
    return this;
  }

  /**
   * Block all access (reads and writes) to a filesystem path.
   */
  block(path: string): this {
    this._paths.push({ path, mode: "blocked" });
    return this;
  }

  /**
   * Allow reads but deny write-intent tool calls on a filesystem path.
   */
  readOnly(path: string): this {
    this._paths.push({ path, mode: "read-only" });
    return this;
  }

  /**
   * Set the global tool-call rate limit (calls per rolling minute).
   * Default: 60.
   */
  rateLimit(maxPerMinute: number): this {
    this._limit = maxPerMinute;
    return this;
  }

  /**
   * Require human approval before any tool call executes.
   * Pass `false` to disable (useful when composing builders).
   */
  requireApproval(required = true): this {
    this._approval = required;
    return this;
  }

  /**
   * Attach an argument shape schema to a specific tool.
   * Requests with non-conforming arguments will be rejected.
   */
  argSchema(tool: string, schema: ArgSchema): this {
    this._schemas[tool] = schema;
    return this;
  }

  /**
   * Validate and return the constructed `GuardianPolicy`.
   * Throws if the accumulated configuration is invalid.
   */
  build(): GuardianPolicy {
    const hasSchemas = Object.keys(this._schemas).length > 0;
    return GuardianPolicySchema.parse({
      allowedTools: [...this._tools],
      restrictedPaths: [...this._paths],
      maxCallsPerMinute: this._limit,
      approvalRequired: this._approval,
      ...(hasSchemas ? { toolArgSchemas: { ...this._schemas } } : {})
    });
  }
}
