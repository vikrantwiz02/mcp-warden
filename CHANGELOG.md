# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-03-30

### Added

- **Per-tool rate limits** — `McpGuardianOptions.toolRateLimits` accepts an array of `{ tool, maxCallsPerMinute }` overrides. The first matching rule (string or RegExp) takes precedence over the global limit.
- **Read-only path enforcement** — `restrictedPaths` entries with `mode: "read-only"` now actively block write-intent tool calls (tools whose name contains verbs such as `write`, `delete`, `move`, `rename`, etc.) targeting those paths. Read-only tools are allowed through.
- **Input size limits** — `McpGuardianOptions.maxArgDepth` (default 20) and `maxArgBytes` (default 512 KB) guard against deeply nested or oversized payloads before any other middleware runs.
- **Metrics hook** — `McpGuardianOptions.metricsHook` receives a `GuardianMetrics` object after every request containing timestamp, method, tool name, allow/block decision, violation code, and processing duration.
- **CircuitBreaker TTL** — `CircuitBreakerOptions.stateTtlMs` (default 10 min) evicts stale per-tool state entries to prevent unbounded memory growth for ephemeral tool names. A `size` getter exposes the current entry count.
- **ESLint + Prettier** — `eslint.config.js` and `.prettierrc.json` added for consistent code style. `lint` and `format` scripts added to `package.json`.
- **`prepublishOnly` script** — runs `typecheck` then `build` before every `npm publish` to prevent shipping broken packages.
- **Coverage script** — `npm run coverage` runs vitest with v8 coverage via `@vitest/coverage-v8`.
- **`sideEffects: false`** in `package.json` for bundler tree-shaking.
- **New public types exported** — `GuardianMetrics`, `GuardianMetricsHook`, `ToolRateLimit`.

### Changed

- **Rate limiter rewritten** — replaced `Array.shift()` sliding-window with a fixed-size circular buffer (`Float64Array`). All operations are now O(1) regardless of quota size.
- **PII redactor** — three sequential regex passes merged into a single combined pass. Added coverage for **IPv6 addresses** (full and compressed forms) and **phone numbers** (E.164, US, and common international formats).
- **Injection scanner** — switched from plain `String.includes` substring matching to per-keyword compiled `RegExp` patterns with word-boundary anchors (`\b`). This eliminates false positives such as "disregarding" triggering the "disregard all prior rules" rule.
- **`enforceCircuitState` middleware** — now passes the `nowProvider` clock through to `CircuitBreaker.canExecute` and `recordFailure`/`recordSuccess` for deterministic testability.
- **`package.json` metadata** — added `repository`, `bugs`, `sideEffects`, and expanded `keywords`.

### Tests

- Expanded from 5 unit tests to **26 tests** covering:
  - Tool authorization (exact string, regex, missing name, non-tool-call passthrough)
  - PII redaction (on/off, email, API key, Stripe key, IPv4)
  - Path restrictions (blocked, read-only allow, read-only write-block)
  - Approval required
  - Global and per-tool rate limits
  - Circuit breaker (open on threshold, reset after cooldown)
  - Injection scanner (detection, word-boundary false-positive guard, nested args)
  - Input size limits (depth, byte size)
  - Metrics hook (allowed and blocked events)
  - Custom middleware (passthrough and block)
  - Dry-run mode
  - Logger callback

## [0.1.5] - 2026-03-22

### Fixed

- Updated test fixtures to avoid raw Stripe-like secret literals that can trigger false-positive secret-scanner warnings.
- Improved `stress-test.ts` typing safety for policy error reason handling.

### Tests

- Kept chaos stress scenario coverage intact while using scanner-friendly runtime fixture generation.

## [0.1.4] - 2026-03-22

### Security

- Enforced `restrictedPaths` in the interceptor by scanning tool arguments for path-like keys and denying calls targeting blocked paths.
- Added human-in-the-loop enforcement for `approvalRequired`, returning `REQUIRES_APPROVAL` before tool execution.
- Expanded policy error handling to return explicit status-aware JSON-RPC errors for permission denial and approval-required outcomes.
- Hardened PII redaction to detect and mask Stripe-style keys (`sk_test_...` and `sk_live_...`).

### Fixed

- Synced CLI version reporting with `package.json` by resolving the version dynamically at runtime instead of using a hardcoded value.
- Added workflow-level smart publish guard to skip npm publication when the current package version already exists on the registry, preventing false-negative release failures.

### Tests

- Added coverage to verify blocked filesystem paths are denied.
- Added coverage to verify `REQUIRES_APPROVAL` behavior when policy requires manual approval.

## [0.1.3] - 2026-03-22

### Fixed

- Updated README license badge to a stable MIT badge to avoid intermittent "package not found" rendering on npm package page.

## [0.1.2] - 2026-03-22

### Added

- Kept `mcp-warden` as the primary CLI command for backward compatibility.

## [0.1.0] - 2026-03-22

### Added

- Introduced the core `McpGuardian` interceptor engine for MCP-compatible JSON-RPC 2.0 flows.
- Added middleware-driven request validation with support for policy chaining and extensibility through `guardian.use(...)`.
- Implemented standardized permission-denied handling for policy violations with JSON-RPC error responses.
- Added dry-run mode to log violations without blocking execution, enabling safe rollout and observability.
- Delivered CLI tooling with:
  - `mcp-warden audit <config-path>` for auditing MCP server configuration risk.
  - `mcp-warden init` for generating a default `mcp-policy.json` policy template.
- Added package exports and TypeScript declaration output for clean IntelliSense and typed consumption.
- Added CI publish workflow with gated test/build checks before npm publication.

### Security

- Added policy-based tool authorization using exact and regex tool rules.
- Added prompt injection scanning for high-risk control phrases in tool arguments.
- Added PII redaction utilities for sensitive output patterns, including:
  - Email addresses
  - API key-like tokens (for example `sk-`, `key-`, `api-`, `token-`)
  - IPv4 addresses
- Added in-memory rate limiting based on `maxCallsPerMinute` to mitigate abuse and runaway call storms.
- Added per-tool circuit breaker protection to temporarily disable tools after repeated failures.
- Added CLI risk detection for excessive permissions, including broad filesystem access and dangerous runtime flags.
- Added security documentation and release packaging checks to reduce accidental exposure in published artifacts.
