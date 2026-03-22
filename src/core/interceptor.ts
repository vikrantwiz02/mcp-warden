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

/**
 * Security violation metadata emitted by the guardian engine.
 */
export interface GuardianViolation {
  code: "PERMISSION_DENIED";
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
 * Configuration object for McpGuardian construction.
 */
export interface McpGuardianOptions {
  dryRun?: boolean;
  logger?: GuardianLogger;
  injectionKeywords?: readonly string[];
  circuitBreaker?: CircuitBreakerOptions;
  redactToolOutputs?: boolean;
  nowProvider?: () => number;
}

/**
 * Constant JSON-RPC code used for permission-denied failures.
 */
const PERMISSION_DENIED_NUMERIC_CODE = -32001;

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
function createPermissionDeniedError(
  request: JsonRpcRequest,
  reason: string,
  toolName?: string
): JsonRpcErrorResponse {
  return {
    jsonrpc: "2.0",
    id: request.id ?? null,
    error: {
      code: PERMISSION_DENIED_NUMERIC_CODE,
      message: "PERMISSION_DENIED",
      data: {
        reason,
        method: request.method,
        toolName
      }
    }
  };
}

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
 * Middleware that blocks tools with an open circuit.
 */
async function enforceCircuitState(
  context: GuardianContext,
  next: () => Promise<MiddlewareDecision>,
  circuitBreaker: CircuitBreaker
): Promise<MiddlewareDecision> {
  if (!isToolCallRequest(context.request) || !context.toolName) {
    return next();
  }

  const decision = circuitBreaker.canExecute(context.toolName);
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
 * Middleware that enforces global max-calls-per-minute policy.
 */
async function enforceRateLimit(
  context: GuardianContext,
  next: () => Promise<MiddlewareDecision>,
  rateLimiter: RateLimiter,
  nowProvider: () => number
): Promise<MiddlewareDecision> {
  if (!isToolCallRequest(context.request)) {
    return next();
  }

  const decision = rateLimiter.consume(nowProvider());
  if (!decision.allowed) {
    const retryMs = Math.max(0, decision.retryAfterMs ?? 0);
    const retrySeconds = Math.ceil(retryMs / 1000);
    return {
      allowed: false,
      reason: `Rate limit exceeded. Retry in ${retrySeconds}s.`
    };
  }

  return next();
}

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

  private readonly nowProvider: () => number;

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
    this.rateLimiter = new RateLimiter({
      maxCallsPerMinute: this.policy.maxCallsPerMinute
    });
    this.nowProvider = options.nowProvider ?? (() => Date.now());

    this.middlewares = [
      enforceAllowedTools,
      async (context, next) =>
        enforceRateLimit(context, next, this.rateLimiter, this.nowProvider),
      async (context, next) => enforceInjectionPolicy(context, next, this.injectionKeywords),
      async (context, next) => enforceCircuitState(context, next, this.circuitBreaker)
    ];
  }

  /**
   * Registers additional middleware checks that run after the built-in policy check.
   */
  public use(middleware: GuardianMiddleware): this {
    this.middlewares.push(middleware);
    return this;
  }

  /**
   * Validates an incoming JSON-RPC request against the configured guardrail chain.
   */
  public async validateRequest(request: JsonRpcRequest): Promise<ValidationResult> {
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
    if (decision.allowed) {
      return { isAllowed: true };
    }

    const violation: GuardianViolation = {
      code: "PERMISSION_DENIED",
      reason: decision.reason ?? "Request violated guardian policy.",
      method: request.method,
      ...(toolName ? { toolName } : {})
    };

    this.logger(violation);
    if (this.isDryRun) {
      return {
        isAllowed: true,
        violation
      };
    }

    return {
      isAllowed: false,
      violation,
      error: createPermissionDeniedError(request, violation.reason, toolName)
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

      const result = await this.validateRequest(request);
      if (!result.isAllowed && result.error) {
        return result.error;
      }

      try {
        const response = await handler(request);

        if (shouldTrackCircuit && toolName) {
          if (isJsonRpcErrorResponse(response)) {
            this.circuitBreaker.recordFailure(toolName);
          } else {
            this.circuitBreaker.recordSuccess(toolName);
          }
        }

        if (!this.redactToolOutputs || !isToolCallRequest(request)) {
          return response;
        }

        return redactSensitiveData(response);
      } catch (error) {
        if (shouldTrackCircuit && toolName) {
          this.circuitBreaker.recordFailure(toolName);
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