# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
