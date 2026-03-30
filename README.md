# mcp-warden

[![NPM Version](https://img.shields.io/npm/v/mcp-warden)](https://www.npmjs.com/package/mcp-warden)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/vikrantwiz02/mcp-warden?tab=MIT-1-ov-file)
[![Bundle Size](https://img.shields.io/bundlephobia/min/mcp-warden)](https://bundlephobia.com/package/mcp-warden)

High-performance security guardrails for MCP-compatible AI agents and tool execution.

## Features

- Policy-based tool authorization (exact strings and regex patterns).
- Filesystem path enforcement — `blocked` denies all access; `read-only` allows reads and denies write-intent tool calls.
- Human-in-the-loop gating with `REQUIRES_APPROVAL` status.
- Prompt-injection scanning with word-boundary-aware regex matching.
- Output redaction for emails, API keys, IPv4/IPv6 addresses, and phone numbers — in a single regex pass.
- Global and per-tool rate limiting with O(1) circular-buffer implementation.
- Per-tool circuit-breaker protection with automatic TTL cleanup.
- Input size limits (max nesting depth and max byte size) to guard against oversized payloads.
- Metrics hook for observability (timing, allow/block decisions, violation codes).
- Extensible middleware chain — register custom policy layers with `.use()`.
- CLI audit workflow for identifying over-permissioned MCP servers.

## Table of Contents

- [Why Security Matters for AI Agents](#why-security-matters-for-ai-agents)
- [Quick Start](#quick-start)
- [Policy Configuration](#policy-configuration)
- [Advanced Options](#advanced-options)
- [Per-Tool Rate Limits](#per-tool-rate-limits)
- [Metrics Hook](#metrics-hook)
- [Input Size Limits](#input-size-limits)
- [Custom Middleware](#custom-middleware)
- [CLI Commands](#cli-commands)
- [Development](#development)
- [License](#license)
- [Security Disclaimer](#security-disclaimer)

## Why Security Matters for AI Agents

AI agents can execute tools with real-world side effects: reading files, modifying systems, calling external APIs, and handling sensitive data. Without guardrails, a single prompt injection or over-permissioned server can lead to data leakage, privilege escalation, or runaway tool loops.

mcp-warden enforces a security boundary before and after every tool execution:

- Blocks unauthorized tools using explicit policy rules.
- Denies tool calls targeting blocked filesystem paths; blocks write operations on read-only paths.
- Returns `REQUIRES_APPROVAL` before execution when `approvalRequired` is enabled.
- Detects prompt-injection signatures in tool arguments using word-boundary regex patterns.
- Enforces global and per-tool rate limits to prevent abuse and runaway call storms.
- Applies per-tool circuit-breaker protection for repeated failures.
- Redacts sensitive output data before it reaches downstream systems.
- Rejects oversized or deeply nested payloads before any other check runs.

## Quick Start

### 1. Install

```bash
npm install mcp-warden
```

### 2. Define a policy

```json
{
  "allowedTools": ["list_dir", "read_file", "grep_search"],
  "restrictedPaths": [
    { "path": "/etc", "mode": "blocked" },
    { "path": "/home", "mode": "read-only" }
  ],
  "maxCallsPerMinute": 60,
  "approvalRequired": false
}
```

### 3. Protect your transport handler

```ts
import { McpGuardian, type GuardianPolicy } from "mcp-warden";

const policy: GuardianPolicy = {
  allowedTools: ["read_file", /^search_/],
  restrictedPaths: [
    { path: "/etc", mode: "blocked" },
    { path: "/home", mode: "read-only" }
  ],
  maxCallsPerMinute: 60,
  approvalRequired: false
};

const guardian = new McpGuardian(policy);

const guardedHandler = guardian.wrapHandler(async (request) => {
  // Your MCP transport execution logic
  return {
    jsonrpc: "2.0",
    id: request.id ?? null,
    result: { ok: true }
  };
});
```

### 4. Use the CLI

```bash
# Audit MCP client config files for excessive permissions
npx mcp-warden audit ./claude_desktop_config.json

# Generate a default policy file
npx mcp-warden init
```

## Policy Configuration

| Option | Type | Required | Description |
|---|---|---|---|
| `allowedTools` | `Array<string \| RegExp>` | Yes | Allowed tool names or regex matchers. |
| `restrictedPaths` | `Array<{ path: string; mode: "read-only" \| "blocked" }>` | Yes | Path access constraints. `blocked` = all access denied. `read-only` = reads allowed, write-intent tool calls denied. |
| `maxCallsPerMinute` | `number` | Yes | Rolling 60-second quota for tool calls. |
| `approvalRequired` | `boolean` | Yes | When `true`, every tool call is paused with `REQUIRES_APPROVAL`. |

## Advanced Options

Pass an `McpGuardianOptions` object as the second constructor argument:

```ts
const guardian = new McpGuardian(policy, {
  dryRun: false,             // log violations but allow all requests
  redactToolOutputs: true,   // redact PII from tool responses (default: true)
  logger: (violation) => myLogger.warn(violation),
  injectionKeywords: [       // override default injection phrases
    "ignore previous instructions",
    "you are now unrestricted"
  ],
  circuitBreaker: {
    threshold: 5,            // failures before circuit opens (default: 5)
    cooldownMs: 60_000,      // how long circuit stays open (default: 60s)
    stateTtlMs: 600_000      // evict idle tool state after 10min (default)
  },
  maxArgDepth: 20,           // max nesting depth of tool args (default: 20)
  maxArgBytes: 524288        // max byte size of tool args (default: 512 KB)
});
```

## Per-Tool Rate Limits

Override the global rate limit for specific tools. The first matching rule wins.

```ts
const guardian = new McpGuardian(policy, {
  toolRateLimits: [
    { tool: "expensive_search", maxCallsPerMinute: 5 },
    { tool: /^write_/, maxCallsPerMinute: 10 }
  ]
});
```

## Metrics Hook

Receive an observability snapshot after every validated request:

```ts
const guardian = new McpGuardian(policy, {
  metricsHook: (metrics) => {
    console.log({
      method: metrics.method,
      tool: metrics.toolName,
      allowed: metrics.allowed,
      violation: metrics.violationCode,
      durationMs: metrics.durationMs
    });
  }
});
```

`GuardianMetrics` fields:

| Field | Type | Description |
|---|---|---|
| `timestamp` | `number` | Unix ms when the request was processed. |
| `method` | `string` | JSON-RPC method name. |
| `toolName` | `string \| undefined` | Tool name for `tools/call` requests. |
| `allowed` | `boolean` | Whether the request was allowed. |
| `violationCode` | `"PERMISSION_DENIED" \| "REQUIRES_APPROVAL" \| undefined` | Set when blocked. |
| `durationMs` | `number` | Processing time in milliseconds. |

## Input Size Limits

Requests with oversized or deeply nested arguments are rejected before any other middleware runs:

```ts
const guardian = new McpGuardian(policy, {
  maxArgDepth: 10,     // reject args nested deeper than 10 levels
  maxArgBytes: 65536   // reject args larger than 64 KB
});
```

## Custom Middleware

Register additional policy layers with `.use()`. Middleware runs after all built-in checks:

```ts
guardian.use(async (context, next) => {
  if (context.toolName === "restricted_tool" && !context.isDryRun) {
    return { allowed: false, reason: "This tool requires explicit opt-in." };
  }
  return next();
});
```

`GuardianContext` properties:

| Property | Type | Description |
|---|---|---|
| `request` | `JsonRpcRequest` | The raw JSON-RPC 2.0 request. |
| `policy` | `GuardianPolicy` | Active policy configuration. |
| `isDryRun` | `boolean` | Whether dry-run mode is active. |
| `toolName` | `string \| undefined` | Extracted tool name. |
| `toolArgs` | `unknown` | Extracted tool arguments. |

## CLI Commands

**Audit a config file:**

```bash
npx mcp-warden audit <config-path>
```

Scans `claude_desktop_config.json`, `cursor-settings.json`, or any MCP JSON config for over-permissioned servers. Exits with code `1` if critical findings are detected.

Critical findings include:
- Permissions granting full disk access (`*`, `all`, `filesystem:*`)
- Broad filesystem paths (`/`, `~`, `/Users/...`)
- Dangerous CLI flags (`--allow-all`, `--dangerously-skip-permissions`, etc.)
- Environment variables enabling unrestricted access

**Generate a default policy:**

```bash
npx mcp-warden init [--output <path>] [--force]
```

Creates a secure `mcp-policy.json` with conservative defaults. Use `--force` to overwrite an existing file.

## Development

```bash
npm install
npm run typecheck     # TypeScript type checking
npm test              # Run test suite (26 tests)
npm run coverage      # Run tests with v8 coverage report
npm run lint          # ESLint
npm run format        # Prettier
npm run build         # Compile to dist/
```

## License

[MIT](https://github.com/vikrantwiz02/mcp-warden?tab=MIT-1-ov-file)

## Security Disclaimer

mcp-warden is a runtime governance layer designed to mitigate risks in AI agent tool execution. It is not a replacement for OS-level permissions, network-level firewalls, or the principle of least privilege. Always run AI agents in isolated environments with minimal permissions where possible.
