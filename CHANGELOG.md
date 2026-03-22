# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
