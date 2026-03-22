# mcp-warden

[![NPM Version](https://img.shields.io/npm/v/mcp-warden)](https://www.npmjs.com/package/mcp-warden)
[![License](https://img.shields.io/npm/l/mcp-warden)](https://www.npmjs.com/package/mcp-warden)
[![Bundle Size](https://img.shields.io/bundlephobia/min/mcp-warden)](https://bundlephobia.com/package/mcp-warden)

High-performance security guardrails for MCP-compatible AI agents and tool execution.

## Features

- Policy-based tool authorization for MCP tool calls.
- Prompt-injection scanning for high-risk control phrases.
- Output redaction for email addresses, API keys, and IP addresses.
- Built-in rate limiting and circuit-breaker protection.
- CLI audit workflow for identifying over-permissioned MCP servers.

## Table of Contents

- [Why Security Matters for AI Agents](#why-security-matters-for-ai-agents)
- [Quick Start](#quick-start)
- [Policy Configuration](#policy-configuration)
- [CLI Commands](#cli-commands)
- [Development](#development)
- [License](#license)
- [Security Disclaimer](#security-disclaimer)

## Why Security Matters for AI Agents

AI agents can execute tools with real-world side effects: reading files, modifying systems, calling external APIs, and handling sensitive data. Without guardrails, a single prompt injection or over-permissioned server can lead to data leakage, privilege escalation, or runaway tool loops.

mcp-warden helps enforce a security boundary before and after tool execution:
- Blocks unauthorized tools using explicit policy rules.
- Detects prompt-injection signatures in tool arguments.
- Enforces rate limits to reduce abuse and runaway call storms.
- Applies circuit-breaker protection for repeated tool failures.
- Redacts sensitive output data before it reaches downstream systems.

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
    {
      "path": "/",
      "mode": "blocked"
    }
  ],
  "maxCallsPerMinute": 60,
  "approvalRequired": true
}
```

### 3. Protect your transport handler

```ts
import { McpGuardian, type GuardianPolicy } from "mcp-warden";

const policy: GuardianPolicy = {
  allowedTools: ["read_file", /^search_/],
  restrictedPaths: [{ path: "/", mode: "blocked" }],
  maxCallsPerMinute: 60,
  approvalRequired: true
};

const guardian = new McpGuardian(policy, { dryRun: false });

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

If you install globally, you can use the short command directly:

```bash
mcp-warden audit ./claude_desktop_config.json
mcp-warden init
```

## Policy Configuration

| Option | Type | Required | Description | Example |
|---|---|---|---|---|
| allowedTools | Array<string \| RegExp> | Yes | Allowed tool names or regex matchers for tools/call requests. | ["read_file", /^search_/] |
| restrictedPaths | Array<{ path: string; mode: "read-only" \| "blocked" }> | Yes | Directory access constraints used by filesystem-aware middleware. | [{ "path": "/", "mode": "blocked" }] |
| maxCallsPerMinute | number | Yes | Rolling 60-second budget for tool calls. Requests above this limit are denied. | 60 |
| approvalRequired | boolean | Yes | Indicates destructive actions should require explicit approval in your orchestration flow. | true |

## CLI Commands

- npx mcp-warden audit <config-path>
- npx mcp-warden init [--output <path>] [--force]

CLI output uses color-coded alerts:
- Green: SAFE
- Red: CRITICAL

## Development

```bash
npm install
npm run typecheck
npm test
npm run build
```

## License

[MIT](https://github.com/vikrantwiz02/mcp-warden?tab=MIT-1-ov-file)

## Security Disclaimer

mcp-warden is a runtime governance layer designed to mitigate risks. It is not a replacement for OS-level permissions, network-level firewalls, or the principle of least privilege. Always run AI agents in isolated environments when possible.
