import { GuardianPolicySchema, type GuardianPolicy } from "../types/policy.js";
import {
  CircuitBreaker,
  type CircuitBreakerOptions
} from "../security/circuit-breaker.js";
import {
  DEFAULT_INJECTION_KEYWORDS,
  scanForPromptInjection
} from "../security/injection-scanner.js";
import { redactSensitiveData } from "../security/pii-redactor.js";
import { RateLimiter } from "../security/rate-limiter.js";

/**
 * JSON-RPC request identifier shape.
 */
export type JsonRpcId = string | number | null;

/**
 * Minimal JSON-RPC 2.0 request payload used by MCP transports.
 */
export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: JsonRpcId;
  method: string;
  params?: unknown;
}

/**
 * Standardized JSON-RPC 2.0 error object.
 */
export interface JsonRpcError {
  code: number;
  message: string;
  data?: Record<string, unknown>;
}

/**
 * Standardized JSON-RPC 2.0 error response payload.
 */
export interface JsonRpcErrorResponse {
  jsonrpc: "2.0";
  id: JsonRpcId;
  error: JsonRpcError;
}

export type GuardianViolationCode = "PERMISSION_DENIED" | "REQUIRES_APPROVAL";

/**
 * Security violation metadata emitted by the guardian engine.
 */
export interface GuardianViolation {
  code: GuardianViolationCode;
  reason: string;
  method: string;
  toolName?: string;
}

/**
 * Validation result produced by the guardian engine.
 */
export interface ValidationResult {
  isAllowed: boolean;
  error?: JsonRpcErrorResponse;
  violation?: GuardianViolation;
}

/**
 * Decision object returned by guardian middleware.
 */
export interface MiddlewareDecision {
  allowed: boolean;
  code?: GuardianViolationCode;
  reason?: string;
}

/**
 * Execution context provided to each middleware stage.
 */
export interface GuardianContext {
  readonly request: JsonRpcRequest;
  readonly policy: GuardianPolicy;
  readonly isDryRun: boolean;
  readonly toolName?: string;
  readonly toolArgs?: unknown;
}

/**
 * Async middleware function signature used by the guardian engine.
 */
export type GuardianMiddleware = (
  context: GuardianContext,
  next: () => Promise<MiddlewareDecision>
) => Promise<MiddlewareDecision>;

/**
 * Logging function for policy violations.
 */
export type GuardianLogger = (violation: GuardianViolation) => void;

/**
 * Metrics snapshot emitted after each validated request.
 */
export interface GuardianMetrics {
  /** Unix timestamp (ms) when the request was processed. */
  timestamp: number;
  /** JSON-RPC method name. */
  method: string;
  /** Tool name if this was a tools/call request. Undefined for non-tool-call methods. */
  toolName: string | undefined;
  /** Whether the request was allowed. */
  allowed: boolean;
  /** Violation code when blocked. Undefined when allowed. */
  violationCode: GuardianViolationCode | undefined;
  /** Processing time in milliseconds. */
  durationMs: number;
}

/**
 * Callback invoked after every request validation with observability data.
 */
export type GuardianMetricsHook = (metrics: GuardianMetrics) => void;

/**
 * Per-tool rate-limit override. Takes precedence over the global
 * `maxCallsPerMinute` when the tool name matches.
 */
export interface ToolRateLimit {
  /** Exact tool name or regex pattern this override applies to. */
  tool: string | RegExp;
  /** Max calls per minute for this tool. */
  maxCallsPerMinute: number;
}

/**
 * Configuration object for McpGuardian construction.
 */
export interface McpGuardianOptions {
  dryRun?: boolean;
  logger?: GuardianLogger;
  injectionKeywords?: readonly string[];
  circuitBreaker?: CircuitBreakerOptions;
  redactToolOutputs?: boolean;
  nowProvider?: () => number;
  /** Called after every request with observability data. */
  metricsHook?: GuardianMetricsHook;
  /** Per-tool rate limit overrides. First match wins. */
  toolRateLimits?: ToolRateLimit[];
  /**
   * Maximum allowed depth of a tool arguments object.
   * Requests exceeding this are rejected. Default: 20.
   */
  maxArgDepth?: number;
  /**
   * Maximum allowed byte size of the serialized tool arguments.
   * Requests exceeding this are rejected. Default: 512 KB.
   */
  maxArgBytes?: number;
}

/**
 * Constant JSON-RPC code used for permission-denied failures.
 */
const PERMISSION_DENIED_NUMERIC_CODE = -32001;
const REQUIRES_APPROVAL_NUMERIC_CODE = -32002;

const DEFAULT_MAX_ARG_DEPTH = 20;
const DEFAULT_MAX_ARG_BYTES = 512 * 1024; // 512 KB

const PATH_ARG_KEYS = new Set([
  "path",
  "paths",
  "root",
  "roots",
  "directory",
  "directories",
  "dir",
  "cwd",
  "filepath",
  "file_path"
]);

/** Write-intent verbs used to detect mutating operations for read-only enforcement. */
const WRITE_INTENT_VERBS = new Set([
  "write",
  "create",
  "delete",
  "remove",
  "rm",
  "mv",
  "move",
  "rename",
  "mkdir",
  "touch",
  "truncate",
  "append",
  "overwrite",
  "put",
  "patch",
  "post",
  "upload"
]);

/**
 * Detects whether a request looks like an MCP tool call.
 */
function isToolCallRequest(request: JsonRpcRequest): boolean {
  return request.method === "tools/call";
}

/**
 * Best-effort extraction of tool name from standard MCP params.
 */
function extractToolName(params: unknown): string | undefined {
  if (!params || typeof params !== "object") {
    return undefined;
  }

  const payload = params as Record<string, unknown>;
  const candidate = payload.name ?? payload.toolName;
  return typeof candidate === "string" && candidate.length > 0 ? candidate : undefined;
}

/**
 * Best-effort extraction of tool arguments from standard MCP params.
 */
function extractToolArgs(params: unknown): unknown {
  if (!params || typeof params !== "object") {
    return undefined;
  }

  const payload = params as Record<string, unknown>;
  if ("arguments" in payload) {
    return payload.arguments;
  }

  if ("args" in payload) {
    return payload.args;
  }

  if ("input" in payload) {
    return payload.input;
  }

  return undefined;
}

/**
 * Type guard for JSON-RPC error responses.
 */
function isJsonRpcErrorResponse(response: unknown): response is JsonRpcErrorResponse {
  if (!response || typeof response !== "object") {
    return false;
  }

  const payload = response as Record<string, unknown>;
  return payload.jsonrpc === "2.0" && typeof payload.error === "object";
}

/**
 * Creates a standardized JSON-RPC permission error response.
 */
function createPolicyError(
  request: JsonRpcRequest,
  code: GuardianViolationCode,
  reason: string,
  toolName?: string
): JsonRpcErrorResponse {
  return {
    jsonrpc: "2.0",
    id: request.id ?? null,
    error: {
      code: code === "REQUIRES_APPROVAL" ? REQUIRES_APPROVAL_NUMERIC_CODE : PERMISSION_DENIED_NUMERIC_CODE,
      message: code,
      data: {
        reason,
        method: request.method,
        toolName
      }
    }
  };
}

function normalizePolicyPath(value: string): string {
  let normalized = value.trim().replaceAll("\\", "/").toLowerCase();
  if (normalized.length > 1 && normalized.endsWith("/")) {
    normalized = normalized.slice(0, -1);
  }

  return normalized;
}

function matchesBlockedPath(candidatePath: string, blockedPath: string): boolean {
  if (blockedPath === "/") {
    return candidatePath.startsWith("/");
  }

  return candidatePath === blockedPath || candidatePath.startsWith(`${blockedPath}/`);
}

function collectCandidatePaths(payload: unknown, parentKey?: string): string[] {
  if (typeof payload === "string") {
    if (parentKey && PATH_ARG_KEYS.has(parentKey)) {
      return [payload];
    }

    return [];
  }

  if (Array.isArray(payload)) {
    return payload.flatMap((entry) => collectCandidatePaths(entry, parentKey));
  }

  if (!payload || typeof payload !== "object") {
    return [];
  }

  const result: string[] = [];
  for (const [key, value] of Object.entries(payload as Record<string, unknown>)) {
    result.push(...collectCandidatePaths(value, key.toLowerCase()));
  }

  return result;
}

/**
 * Returns the depth of a nested object/array structure.
 */
function measureDepth(value: unknown, current: number = 0): number {
  if (current > DEFAULT_MAX_ARG_DEPTH) {
    return current;
  }

  if (Array.isArray(value)) {
    let max = current;
    for (const entry of value) {
      max = Math.max(max, measureDepth(entry, current + 1));
    }
    return max;
  }

  if (value && typeof value === "object") {
    let max = current;
    for (const entry of Object.values(value as Record<string, unknown>)) {
      max = Math.max(max, measureDepth(entry, current + 1));
    }
    return max;
  }

  return current;
}

/**
 * Returns true if the tool name suggests a write/mutating operation.
 */
function toolImpliesWrite(toolName: string): boolean {
  const lower = toolName.toLowerCase();
  for (const verb of WRITE_INTENT_VERBS) {
    if (lower.includes(verb)) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Built-in middleware
// ---------------------------------------------------------------------------

/**
 * Middleware that enforces `allowedTools` policy for tool calls.
 */
async function enforceAllowedTools(
  context: GuardianContext,
  next: () => Promise<MiddlewareDecision>
): Promise<MiddlewareDecision> {
  if (!isToolCallRequest(context.request)) {
    return next();
  }

  if (!context.toolName) {
    return {
      allowed: false,
      reason: "Tool call did not include a valid tool name."
    };
  }

  const toolName = context.toolName;

  const isAllowed = context.policy.allowedTools.some((rule) => {
    if (typeof rule === "string") {
      return rule === toolName;
    }

    return rule.test(toolName);
  });

  if (!isAllowed) {
    return {
      allowed: false,
      reason: `Tool '${context.toolName}' is not allowed by policy.`
    };
  }

  return next();
}

/**
 * Middleware that rejects requests when prompt-injection signatures are present.
 */
async function enforceInjectionPolicy(
  context: GuardianContext,
  next: () => Promise<MiddlewareDecision>,
  keywords: readonly string[]
): Promise<MiddlewareDecision> {
  if (!isToolCallRequest(context.request)) {
    return next();
  }

  const scanResult = scanForPromptInjection(context.toolArgs, keywords);
  if (scanResult.detected) {
    const signatures = scanResult.matchedKeywords.join(", ");
    return {
      allowed: false,
      reason: `Prompt injection signature detected: ${signatures}.`
    };
  }

  return next();
}

/**
 * Middleware that denies tool calls targeting blocked filesystem paths, and
 * denies write-intent tool calls targeting read-only filesystem paths.
 */
async function enforceRestrictedPaths(
  context: GuardianContext,
  next: () => Promise<MiddlewareDecision>
): Promise<MiddlewareDecision> {
  if (!isToolCallRequest(context.request)) {
    return next();
  }

  const { restrictedPaths } = context.policy;
  if (restrictedPaths.length === 0) {
    return next();
  }

  const blockedPaths = restrictedPaths
    .filter((entry) => entry.mode === "blocked")
    .map((entry) => normalizePolicyPath(entry.path));

  const readOnlyPaths = restrictedPaths
    .filter((entry) => entry.mode === "read-only")
    .map((entry) => normalizePolicyPath(entry.path));

  const candidatePaths = collectCandidatePaths(context.toolArgs)
    .map((value) => normalizePolicyPath(value))
    .filter((value) => value.length > 0);

  for (const candidatePath of candidatePaths) {
    // Blocked paths: all access denied
    const matchedBlocked = blockedPaths.find((blocked) =>
      matchesBlockedPath(candidatePath, blocked)
    );
    if (matchedBlocked) {
      return {
        allowed: false,
        code: "PERMISSION_DENIED",
        reason: `Tool arguments include restricted path '${candidatePath}' blocked by policy.`
      };
    }

    // Read-only paths: write-intent operations denied
    if (context.toolName && toolImpliesWrite(context.toolName)) {
      const matchedReadOnly = readOnlyPaths.find((ro) =>
        matchesBlockedPath(candidatePath, ro)
      );
      if (matchedReadOnly) {
        return {
          allowed: false,
          code: "PERMISSION_DENIED",
          reason: `Tool '${context.toolName}' attempts a write operation on read-only path '${candidatePath}'.`
        };
      }
    }
  }

  return next();
}

/**
 * Middleware that marks tool calls as requiring human approval.
 */
async function enforceApprovalRequired(
  context: GuardianContext,
  next: () => Promise<MiddlewareDecision>
): Promise<MiddlewareDecision> {
  if (!isToolCallRequest(context.request)) {
    return next();
  }

  if (!context.policy.approvalRequired) {
    return next();
  }

  return {
    allowed: false,
    code: "REQUIRES_APPROVAL",
    reason: "Human approval is required by policy before executing this tool call."
  };
}

/**
 * Middleware that blocks tools with an open circuit.
 */
async function enforceCircuitState(
  context: GuardianContext,
  next: () => Promise<MiddlewareDecision>,
  circuitBreaker: CircuitBreaker,
  nowProvider: () => number
): Promise<MiddlewareDecision> {
  if (!isToolCallRequest(context.request) || !context.toolName) {
    return next();
  }

  const decision = circuitBreaker.canExecute(context.toolName, nowProvider());
  if (!decision.allowed) {
    const retryMs = Math.max(0, decision.retryAfterMs ?? 0);
    const retrySeconds = Math.ceil(retryMs / 1000);
    return {
      allowed: false,
      reason: `Circuit breaker open for tool '${context.toolName}'. Retry in ${retrySeconds}s.`
    };
  }

  return next();
}

/**
 * Middleware that enforces global and per-tool max-calls-per-minute policy.
 */
async function enforceRateLimit(
  context: GuardianContext,
  next: () => Promise<MiddlewareDecision>,
  globalLimiter: RateLimiter,
  toolLimiters: Map<string, RateLimiter>,
  toolRateLimits: ToolRateLimit[],
  nowProvider: () => number
): Promise<MiddlewareDecision> {
  if (!isToolCallRequest(context.request)) {
    return next();
  }

  const now = nowProvider();

  // Per-tool rate limit (first matching rule wins)
  if (context.toolName) {
    const toolName = context.toolName;
    const matchingRule = toolRateLimits.find((rule) => {
      if (typeof rule.tool === "string") {
        return rule.tool === toolName;
      }
      return rule.tool.test(toolName);
    });

    if (matchingRule) {
      let limiter = toolLimiters.get(toolName);
      if (!limiter) {
        limiter = new RateLimiter({ maxCallsPerMinute: matchingRule.maxCallsPerMinute });
        toolLimiters.set(toolName, limiter);
      }

      const decision = limiter.consume(now);
      if (!decision.allowed) {
        const retrySeconds = Math.ceil(Math.max(0, decision.retryAfterMs ?? 0) / 1000);
        return {
          allowed: false,
          reason: `Per-tool rate limit exceeded for '${toolName}'. Retry in ${retrySeconds}s.`
        };
      }

      return next();
    }
  }

  // Global rate limit
  const decision = globalLimiter.consume(now);
  if (!decision.allowed) {
    const retrySeconds = Math.ceil(Math.max(0, decision.retryAfterMs ?? 0) / 1000);
    return {
      allowed: false,
      reason: `Rate limit exceeded. Retry in ${retrySeconds}s.`
    };
  }

  return next();
}

/**
 * Middleware that rejects payloads exceeding depth or byte-size limits.
 */
async function enforceInputLimits(
  context: GuardianContext,
  next: () => Promise<MiddlewareDecision>,
  maxDepth: number,
  maxBytes: number
): Promise<MiddlewareDecision> {
  if (!isToolCallRequest(context.request) || context.toolArgs === undefined) {
    return next();
  }

  const depth = measureDepth(context.toolArgs);
  if (depth > maxDepth) {
    return {
      allowed: false,
      reason: `Tool arguments exceed maximum nesting depth of ${maxDepth}.`
    };
  }

  try {
    const serialized = JSON.stringify(context.toolArgs);
    if (serialized.length > maxBytes) {
      return {
        allowed: false,
        reason: `Tool arguments exceed maximum size of ${maxBytes} bytes.`
      };
    }
  } catch {
    return {
      allowed: false,
      reason: "Tool arguments could not be serialized for size validation."
    };
  }

  return next();
}

// ---------------------------------------------------------------------------
// McpGuardian
// ---------------------------------------------------------------------------

/**
 * Core policy guard for intercepting JSON-RPC tool calls.
 *
 * This class can be used as a standalone validator (`validateRequest`) or as a
 * transport wrapper through `wrapHandler` to gate downstream request handlers.
 */
export class McpGuardian {
  private readonly policy: GuardianPolicy;

  private readonly isDryRun: boolean;

  private readonly logger: GuardianLogger;

  private readonly middlewares: GuardianMiddleware[];

  private readonly circuitBreaker: CircuitBreaker;

  private readonly injectionKeywords: readonly string[];

  private readonly redactToolOutputs: boolean;

  private readonly rateLimiter: RateLimiter;

  private readonly toolLimiters: Map<string, RateLimiter>;

  private readonly nowProvider: () => number;

  private readonly metricsHook: GuardianMetricsHook | undefined;

  /**
   * Creates a guardian instance with policy and optional runtime controls.
   */
  public constructor(policy: GuardianPolicy, options: McpGuardianOptions = {}) {
    this.policy = GuardianPolicySchema.parse(policy);
    this.isDryRun = options.dryRun ?? false;
    this.logger = options.logger ?? ((violation) => console.warn("[mcp-warden]", violation));
    this.circuitBreaker = new CircuitBreaker(options.circuitBreaker);
    this.injectionKeywords = options.injectionKeywords ?? DEFAULT_INJECTION_KEYWORDS;
    this.redactToolOutputs = options.redactToolOutputs ?? true;
    this.rateLimiter = new RateLimiter({ maxCallsPerMinute: this.policy.maxCallsPerMinute });
    this.toolLimiters = new Map<string, RateLimiter>();
    this.nowProvider = options.nowProvider ?? (() => Date.now());
    this.metricsHook = options.metricsHook;

    const toolRateLimits = options.toolRateLimits ?? [];
    const maxDepth = options.maxArgDepth ?? DEFAULT_MAX_ARG_DEPTH;
    const maxBytes = options.maxArgBytes ?? DEFAULT_MAX_ARG_BYTES;

    this.middlewares = [
      enforceAllowedTools,
      (context, next) => enforceInputLimits(context, next, maxDepth, maxBytes),
      enforceRestrictedPaths,
      enforceApprovalRequired,
      (context, next) =>
        enforceRateLimit(
          context,
          next,
          this.rateLimiter,
          this.toolLimiters,
          toolRateLimits,
          this.nowProvider
        ),
      (context, next) => enforceInjectionPolicy(context, next, this.injectionKeywords),
      (context, next) => enforceCircuitState(context, next, this.circuitBreaker, this.nowProvider)
    ];
  }

  /**
   * Registers additional middleware checks that run after the built-in policy checks.
   */
  public use(middleware: GuardianMiddleware): this {
    this.middlewares.push(middleware);
    return this;
  }

  /**
   * Validates an incoming JSON-RPC request against the configured guardrail chain.
   */
  public async validateRequest(request: JsonRpcRequest): Promise<ValidationResult> {
    const start = this.nowProvider();
    const toolName = extractToolName(request.params);
    const toolArgs = extractToolArgs(request.params);
    const context: GuardianContext = {
      request,
      policy: this.policy,
      isDryRun: this.isDryRun,
      ...(toolName ? { toolName } : {}),
      ...(toolArgs !== undefined ? { toolArgs } : {})
    };

    const decision = await this.runMiddlewares(context);
    const durationMs = this.nowProvider() - start;

    if (decision.allowed) {
      this.metricsHook?.({
        timestamp: start,
        method: request.method,
        toolName,
        allowed: true,
        violationCode: undefined,
        durationMs
      });
      return { isAllowed: true };
    }

    const violationCode = decision.code ?? "PERMISSION_DENIED";
    const violation: GuardianViolation = {
      code: violationCode,
      reason:
        decision.reason ??
        (violationCode === "REQUIRES_APPROVAL"
          ? "Human approval is required before executing this request."
          : "Request violated guardian policy."),
      method: request.method,
      ...(toolName ? { toolName } : {})
    };

    this.logger(violation);
    this.metricsHook?.({
      timestamp: start,
      method: request.method,
      toolName,
      allowed: false,
      violationCode: violationCode,
      durationMs
    });

    if (this.isDryRun) {
      return { isAllowed: true, violation };
    }

    return {
      isAllowed: false,
      violation,
      error: createPolicyError(request, violation.code, violation.reason, toolName)
    };
  }

  /**
   * Wraps a JSON-RPC handler and blocks requests that violate policy.
   */
  public wrapHandler<TResponse>(
    handler: (request: JsonRpcRequest) => Promise<TResponse | JsonRpcErrorResponse>
  ): (request: JsonRpcRequest) => Promise<TResponse | JsonRpcErrorResponse> {
    return async (request: JsonRpcRequest): Promise<TResponse | JsonRpcErrorResponse> => {
      const toolName = extractToolName(request.params);
      const shouldTrackCircuit = isToolCallRequest(request) && !!toolName;
      const now = this.nowProvider();

      const result = await this.validateRequest(request);
      if (!result.isAllowed && result.error) {
        return result.error;
      }

      try {
        const response = await handler(request);

        if (shouldTrackCircuit && toolName) {
          if (isJsonRpcErrorResponse(response)) {
            this.circuitBreaker.recordFailure(toolName, now);
          } else {
            this.circuitBreaker.recordSuccess(toolName, now);
          }
        }

        if (!this.redactToolOutputs || !isToolCallRequest(request)) {
          return response;
        }

        return redactSensitiveData(response);
      } catch (error) {
        if (shouldTrackCircuit && toolName) {
          this.circuitBreaker.recordFailure(toolName, now);
        }

        throw error;
      }
    };
  }

  /**
   * Runs middleware chain using a deterministic Koa-style composition model.
   */
  private async runMiddlewares(context: GuardianContext): Promise<MiddlewareDecision> {
    const middlewares = this.middlewares;

    const dispatch = async (index: number): Promise<MiddlewareDecision> => {
      if (index >= middlewares.length) {
        return { allowed: true };
      }

      const middleware = middlewares[index];
      if (!middleware) {
        return { allowed: true };
      }

      return middleware(context, () => dispatch(index + 1));
    };

    return dispatch(0);
  }
}
