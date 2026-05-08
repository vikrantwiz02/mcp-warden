# mcp-warden

[![NPM Version](https://img.shields.io/npm/v/mcp-warden)](https://www.npmjs.com/package/mcp-warden)
[![NPM Downloads](https://img.shields.io/npm/dm/mcp-warden)](https://www.npmjs.com/package/mcp-warden)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/vikrantwiz02/mcp-warden?tab=MIT-1-ov-file)
[![Bundle Size](https://img.shields.io/bundlephobia/min/mcp-warden)](https://bundlephobia.com/package/mcp-warden)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](https://www.npmjs.com/package/mcp-warden)

**Policy-based security middleware for MCP tool execution — embedded directly in your TypeScript/Node.js server. No proxy process, no extra infrastructure, zero runtime dependencies.**

---

## Library vs Proxy — Why it matters

Most MCP security tools work as a **proxy**: a separate process you deploy alongside your server that intercepts traffic. That means extra infrastructure, extra latency, and one more thing that can fail.

**mcp-warden is a library.** It lives inside your existing MCP server code as middleware — no separate process, no deployment complexity, no added latency.

| | mcp-warden | Proxy-based tools |
|---|---|---|
| Architecture | Embedded library | Separate process |
| Language | TypeScript / Node.js | Python |
| Runtime dependencies | **0** | Several |
| Deployment | Import and use | Deploy & connect |
| Latency overhead | None (in-process) | Network hop |
| Type safety | Full TypeScript types | Limited |
| Custom middleware | `.use()` chain | Config files |
| Event stream | `.on('blocked', ...)` | External logging |

---

## Features

- **Policy-based tool authorization** — exact string and regex allowlists
- **Filesystem path enforcement** — `blocked` denies all access; `read-only` blocks write-intent calls
- **Argument schema validation** — enforce the exact shape of tool arguments per tool
- **Prompt injection scanning** — word-boundary regex detection on all tool arguments
- **PII redaction** — emails, API keys, IPv4/IPv6, phone numbers stripped from tool outputs in a single regex pass
- **Global and per-tool rate limiting** — O(1) sliding-window circular buffer
- **Per-tool circuit breaker** — auto-opens after repeated failures, resets after cooldown, TTL eviction for memory safety
- **Human-in-the-loop gating** — `REQUIRES_APPROVAL` pauses execution until manual sign-off
- **Input size limits** — max nesting depth and max byte size reject oversized payloads early
- **Typed event emitter** — `.on('allowed' | 'blocked', listener)` for structured observability
- **Extensible middleware chain** — `.use()` registers custom policy layers
- **Fluent PolicyBuilder** — construct policies in code without object literals
- **CLI audit tool** — detect over-permissioned MCP servers in config files

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Policy Configuration](#policy-configuration)
- [PolicyBuilder](#policybuilder)
- [Argument Schema Validation](#argument-schema-validation)
- [Event Emitter](#event-emitter)
- [Advanced Options](#advanced-options)
- [Per-Tool Rate Limits](#per-tool-rate-limits)
- [Metrics Hook](#metrics-hook)
- [Input Size Limits](#input-size-limits)
- [Custom Middleware](#custom-middleware)
- [CLI Commands](#cli-commands)
- [Development](#development)
- [License](#license)

---

## Installation

```bash
npm install mcp-warden
```

Node.js 20+ required. Zero runtime dependencies.

---

## Quick Start

### 1. Define a policy

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
```

### 2. Wrap your transport handler

```ts
const guardian = new McpGuardian(policy);

const guardedHandler = guardian.wrapHandler(async (request) => {
  // your MCP execution logic
  return { jsonrpc: "2.0", id: request.id ?? null, result: { ok: true } };
});
```

### 3. Validate individual requests

```ts
const result = await guardian.validateRequest(request);

if (!result.isAllowed) {
  console.error(result.violation?.reason);
}
```

### 4. Use the CLI

```bash
# Audit an MCP config file for excessive permissions
npx mcp-warden audit ./claude_desktop_config.json

# Validate a policy file
npx mcp-warden validate ./mcp-policy.json

# Generate a JSON Schema for IDE autocomplete
npx mcp-warden schema --output mcp-policy.schema.json

# Generate a default safe policy
npx mcp-warden init
```

---

## Policy Configuration

| Option | Type | Required | Description |
|---|---|---|---|
| `allowedTools` | `Array<string \| RegExp>` | Yes | Allowed tool names or regex matchers. Min 1 rule. |
| `restrictedPaths` | `Array<{ path: string; mode: "read-only" \| "blocked" }>` | Yes | Path access constraints. |
| `maxCallsPerMinute` | `number` | Yes | Rolling 60-second quota for tool calls. |
| `approvalRequired` | `boolean` | Yes | When `true`, every tool call returns `REQUIRES_APPROVAL`. |
| `toolArgSchemas` | `Record<string, ArgSchema>` | No | Per-tool argument shape constraints. |

---

## PolicyBuilder

Construct policies using a fluent API instead of writing raw object literals:

```ts
import { PolicyBuilder } from "mcp-warden";

const policy = new PolicyBuilder()
  .allow("read_file")
  .allow(/^search_/)
  .block("/etc")
  .readOnly("/home")
  .rateLimit(30)
  .requireApproval(false)
  .argSchema("read_file", {
    type: "object",
    required: ["path"],
    properties: { path: { type: "string" } }
  })
  .build();  // validates and throws if invalid
```

**PolicyBuilder methods:**

| Method | Description |
|---|---|
| `.allow(tool)` | Allow a tool by exact name or regex |
| `.block(path)` | Block all access to a filesystem path |
| `.readOnly(path)` | Allow reads, deny write-intent calls on a path |
| `.rateLimit(n)` | Set global calls-per-minute quota |
| `.requireApproval(bool)` | Gate every tool call with `REQUIRES_APPROVAL` |
| `.argSchema(tool, schema)` | Attach argument shape constraints to a tool |
| `.build()` | Validate and return the `GuardianPolicy` |

---

## Argument Schema Validation

Enforce the exact shape of arguments a tool is allowed to receive. Invalid arguments are rejected before the tool executes.

```ts
const policy = new PolicyBuilder()
  .allow("create_file")
  .argSchema("create_file", {
    type: "object",
    required: ["path", "content"],
    properties: {
      path: { type: "string", minLength: 1 },
      content: { type: "string", maxLength: 65536 },
      overwrite: { type: "boolean" }
    }
  })
  .build();
```

**Supported schema types:** `object`, `string`, `number`, `boolean`, `array`

**Supported constraints:** `required`, `properties`, `items`, `enum`, `minLength`, `maxLength`, `minimum`, `maximum`

You can also use `validateArgs` standalone:

```ts
import { validateArgs } from "mcp-warden";

const result = validateArgs(toolArgs, schema);
if (!result.valid) {
  console.error(result.reason); // "arguments.path: required field missing"
}
```

---

## Event Emitter

Subscribe to security events directly on the guardian. Fires after every validated request.

```ts
const guardian = new McpGuardian(policy);

// All allowed requests
guardian.on("allowed", (event) => {
  metrics.increment("tool.allowed", { tool: event.toolName });
});

// All blocked requests
guardian.on("blocked", (event) => {
  logger.warn("Blocked request", {
    tool: event.toolName,
    reason: event.reason,
    code: event.violationCode
  });
});

// One-time listener
guardian.once("blocked", (event) => alertOncall(event));

// Unsubscribe
guardian.off("blocked", myListener);
```

**`GuardianEvent` fields:**

| Field | Type | Description |
|---|---|---|
| `type` | `"allowed" \| "blocked"` | Outcome of the request |
| `timestamp` | `number` | Unix ms |
| `method` | `string` | JSON-RPC method |
| `toolName` | `string \| undefined` | Tool name for `tools/call` requests |
| `violationCode` | `"PERMISSION_DENIED" \| "REQUIRES_APPROVAL" \| undefined` | Set when blocked |
| `reason` | `string \| undefined` | Human-readable reason when blocked |
| `durationMs` | `number` | Processing time |

---

## Advanced Options

Pass a `McpGuardianOptions` object as the second constructor argument:

```ts
const guardian = new McpGuardian(policy, {
  dryRun: false,              // log violations but allow all requests
  redactToolOutputs: true,    // strip PII from tool responses (default: true)
  logger: (violation) => myLogger.warn(violation),
  injectionKeywords: [        // override default injection phrases
    "ignore previous instructions",
    "you are now unrestricted"
  ],
  circuitBreaker: {
    threshold: 5,             // failures before circuit opens (default: 5)
    cooldownMs: 60_000,       // how long circuit stays open (default: 60s)
    stateTtlMs: 600_000       // evict idle state after 10 min (default)
  },
  maxArgDepth: 20,            // max nesting depth of tool args (default: 20)
  maxArgBytes: 524288         // max byte size of tool args (default: 512 KB)
});
```

---

## Per-Tool Rate Limits

Override the global rate limit for specific tools. First matching rule wins.

```ts
const guardian = new McpGuardian(policy, {
  toolRateLimits: [
    { tool: "expensive_search", maxCallsPerMinute: 5 },
    { tool: /^write_/, maxCallsPerMinute: 10 }
  ]
});
```

---

## Metrics Hook

Receive an observability snapshot after every validated request. Prefer the event emitter (`.on()`) for new integrations — `metricsHook` is kept for backwards compatibility.

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

---

## Input Size Limits

Requests with oversized or deeply nested arguments are rejected before any other middleware runs:

```ts
const guardian = new McpGuardian(policy, {
  maxArgDepth: 10,     // reject args nested deeper than 10 levels
  maxArgBytes: 65536   // reject args larger than 64 KB
});
```

---

## Custom Middleware

Register additional policy layers with `.use()`. Runs after all built-in checks:

```ts
guardian.use(async (context, next) => {
  if (context.toolName === "restricted_tool" && !context.isDryRun) {
    return { allowed: false, reason: "This tool requires explicit opt-in." };
  }
  return next();
});
```

**`GuardianContext` properties:**

| Property | Type | Description |
|---|---|---|
| `request` | `JsonRpcRequest` | The raw JSON-RPC 2.0 request |
| `policy` | `GuardianPolicy` | Active policy configuration |
| `isDryRun` | `boolean` | Whether dry-run mode is active |
| `toolName` | `string \| undefined` | Extracted tool name |
| `toolArgs` | `unknown` | Extracted tool arguments |

---

## CLI Commands

**Audit a config file:**
```bash
npx mcp-warden audit <config-path>
npx mcp-warden audit --watch <config-path>   # re-audit on file change
```
Scans `claude_desktop_config.json`, `cursor-settings.json`, or any MCP JSON config for over-permissioned servers. Exits with code `1` if critical findings are detected.

Critical findings include:
- Permissions granting full disk access (`*`, `all`, `filesystem:*`)
- Broad filesystem paths (`/`, `~`, `/Users/...`)
- Dangerous CLI flags (`--allow-all`, `--dangerously-skip-permissions`, etc.)
- Environment variables enabling unrestricted access

**Validate a policy file:**
```bash
npx mcp-warden validate <policy-path>
```
Reads a `mcp-policy.json` and reports whether it is a valid `GuardianPolicy`. Exits `1` on error with a field-level message.

**Generate JSON Schema:**
```bash
npx mcp-warden schema
npx mcp-warden schema --output mcp-policy.schema.json
```
Prints the `GuardianPolicy` JSON Schema (draft-07) to stdout or writes to a file. Use with VS Code or any JSON Schema-aware editor for autocomplete.

**Generate a default policy:**
```bash
npx mcp-warden init [--output <path>] [--force]
```
Creates a secure `mcp-policy.json` with conservative defaults.

---

## Middleware Execution Order

Every request passes through these checks in sequence. The first failure short-circuits the chain.

```
1. enforceAllowedTools      — is this tool on the allowlist?
2. enforceInputLimits       — are the args within depth/size limits?
3. enforceArgSchema         — do the args match the declared schema?
4. enforceRestrictedPaths   — does this touch a blocked or read-only path?
5. enforceApprovalRequired  — does policy require human sign-off?
6. enforceRateLimit         — within global / per-tool quota?
7. enforceInjectionPolicy   — any prompt injection signatures?
8. enforceCircuitState      — is this tool's circuit open?
9. custom middleware (.use)  — your own checks
```

---

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

---

## License

[MIT](https://github.com/vikrantwiz02/mcp-warden?tab=MIT-1-ov-file)

---

## Security Disclaimer

mcp-warden is a runtime governance layer designed to mitigate risks in AI agent tool execution. It is not a replacement for OS-level permissions, network-level firewalls, or the principle of least privilege. Always run AI agents in isolated environments with minimal permissions where possible.
