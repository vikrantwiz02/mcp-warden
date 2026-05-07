/**
 * Public API for mcp-warden.
 */

// Policy types and schema utilities
export {
  GuardianPolicySchema,
  GuardianPolicySchema as guardianPolicySchema,
  PathRestrictionModeSchema,
  PathRestrictionSchema,
  ToolRuleSchema,
  type ArgSchema,
  type GuardianPolicy,
  type PathRestriction,
  type PathRestrictionMode,
  type ToolRule
} from "./types/policy.js";

// Core guardian — validator, handler wrapper, and event emitter
export {
  McpGuardian,
  type GuardianContext,
  type GuardianEvent,
  type GuardianEventMap,
  type GuardianLogger,
  type GuardianMetrics,
  type GuardianMetricsHook,
  type GuardianMiddleware,
  type GuardianViolation,
  type JsonRpcError,
  type JsonRpcErrorResponse,
  type JsonRpcId,
  type JsonRpcRequest,
  type McpGuardianOptions,
  type MiddlewareDecision,
  type ToolRateLimit,
  type ValidationResult
} from "./core/interceptor.js";

// Fluent policy builder
export { PolicyBuilder } from "./builder/policy-builder.js";

// Typed event emitter (base class — useful for extending)
export { TypedEmitter } from "./events/typed-emitter.js";

// Circuit breaker
export {
  CircuitBreaker,
  type CircuitBreakerOptions,
  type CircuitDecision,
  type CircuitState
} from "./security/circuit-breaker.js";

// Injection scanner
export {
  DEFAULT_INJECTION_KEYWORDS,
  scanForPromptInjection,
  type InjectionScanResult
} from "./security/injection-scanner.js";

// PII redaction
export {
  REDACTION_TOKEN,
  redactSensitiveData as redactPii,
  redactSensitiveData,
  redactSensitiveText,
  type RedactionSummary
} from "./security/pii-redactor.js";

// Rate limiter
export {
  RateLimiter,
  type RateLimitDecision,
  type RateLimiterOptions
} from "./security/rate-limiter.js";

// Argument schema validation
export {
  validateArgs,
  type ArgValidationResult
} from "./security/arg-validator.js";
