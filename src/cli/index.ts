#!/usr/bin/env node

import { promises as fs } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { GuardianPolicySchema, type GuardianPolicy } from "../types/policy.js";

// ---------------------------------------------------------------------------
// ANSI color helpers (replaces chalk — zero dependencies)
// ---------------------------------------------------------------------------

const c = {
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  bold: (s: string) => `\x1b[1m${s}\x1b[0m`
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Minimal server configuration shape extracted from MCP client config files.
 */
interface McpServerConfig {
  args?: unknown;
  env?: unknown;
  permissions?: unknown;
  roots?: unknown;
  allowedPaths?: unknown;
  [key: string]: unknown;
}

/**
 * Named server entry used by the audit report.
 */
interface ServerEntry {
  name: string;
  config: McpServerConfig;
}

// ---------------------------------------------------------------------------
// Default policy for `init`
// ---------------------------------------------------------------------------

const DEFAULT_POLICY: GuardianPolicy = {
  allowedTools: ["list_dir", "read_file", "grep_search"],
  restrictedPaths: [
    {
      path: "/",
      mode: "blocked"
    }
  ],
  maxCallsPerMinute: 60,
  approvalRequired: true
};

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((entry): entry is string => typeof entry === "string");
}

/**
 * Best-effort extraction of MCP servers from common config layouts.
 */
function extractServers(config: unknown): ServerEntry[] {
  if (!isRecord(config)) {
    return [];
  }

  const candidates: unknown[] = [
    config.mcpServers,
    isRecord(config.mcp) ? config.mcp.servers : undefined,
    config.servers
  ];

  for (const candidate of candidates) {
    if (!isRecord(candidate)) {
      continue;
    }

    return Object.entries(candidate)
      .filter(([, server]) => isRecord(server))
      .map(([name, server]) => ({
        name,
        config: server as McpServerConfig
      }));
  }

  return [];
}

/**
 * Returns true when a path represents broad filesystem access.
 */
function isBroadPath(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return (
    normalized === "/" ||
    normalized === "~" ||
    normalized === "$home" ||
    normalized === "${home}" ||
    normalized === "c:\\" ||
    normalized.startsWith("/users")
  );
}

/**
 * Detects critical full-access permissions in a server config.
 */
function getCriticalFindings(server: McpServerConfig): string[] {
  const findings: string[] = [];

  const permissions = toStringArray(server.permissions);
  if (
    permissions.some((entry) =>
      ["*", "all", "full-disk-access", "filesystem:*"].includes(entry.trim().toLowerCase())
    )
  ) {
    findings.push("Permission set grants full disk access.");
  }

  const roots = toStringArray(server.roots);
  const allowedPaths = toStringArray(server.allowedPaths);
  const broadPath = [...roots, ...allowedPaths].find((entry) => isBroadPath(entry));
  if (broadPath) {
    findings.push(`Broad filesystem path is allowed: ${broadPath}`);
  }

  const args = toStringArray(server.args).map((arg) => arg.toLowerCase());
  if (
    args.some((arg) =>
      [
        "--allow-all",
        "--dangerously-skip-permissions",
        "--full-disk-access",
        "--allow-read=/",
        "--allow-write=/"
      ].some((flag) => arg.includes(flag))
    )
  ) {
    findings.push("Command-line flags indicate unrestricted filesystem access.");
  }

  if (isRecord(server.env)) {
    const envPairs = Object.entries(server.env);
    const hasWideEnvAccess = envPairs.some(([key, rawValue]) => {
      if (typeof rawValue !== "string") {
        return false;
      }

      const envKey = key.toLowerCase();
      const envValue = rawValue.trim().toLowerCase();
      return (
        ["full_disk_access", "allow_all", "dangerously_skip_permissions"].includes(envKey) &&
        ["1", "true", "yes", "on"].includes(envValue)
      );
    });

    if (hasWideEnvAccess) {
      findings.push("Environment variables enable unrestricted permissions.");
    }
  }

  return findings;
}

/**
 * Reads and parses a JSON configuration file from disk.
 */
async function readJsonFile(filePath: string): Promise<unknown> {
  const content = await fs.readFile(filePath, "utf8");
  return JSON.parse(content) as unknown;
}

/**
 * Resolves CLI version from package.json to avoid hardcoded drift.
 */
async function resolveCliVersion(): Promise<string> {
  const currentFilePath = fileURLToPath(import.meta.url);
  const currentDir = path.dirname(currentFilePath);
  const packageJsonPath = path.resolve(currentDir, "../../package.json");

  try {
    const content = await fs.readFile(packageJsonPath, "utf8");
    const parsed = JSON.parse(content) as { version?: unknown };
    if (typeof parsed.version === "string" && parsed.version.length > 0) {
      return parsed.version;
    }
  } catch {
    // Fall back to a safe placeholder if package metadata cannot be read.
  }

  return "0.0.0";
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

/**
 * Core audit logic — runs once over a config file and prints findings.
 * Returns true when no critical findings exist.
 */
async function runAudit(configPath: string): Promise<boolean> {
  const absolutePath = path.resolve(process.cwd(), configPath);
  const config = await readJsonFile(absolutePath);
  const servers = extractServers(config);

  console.log(c.bold(`Audit file: ${absolutePath}`));

  if (servers.length === 0) {
    console.log(c.red("CRITICAL: No MCP servers found. Verify config structure before deployment."));
    return false;
  }

  let criticalCount = 0;

  for (const server of servers) {
    const findings = getCriticalFindings(server.config);
    if (findings.length === 0) {
      console.log(c.green(`SAFE: ${server.name}`));
      continue;
    }

    criticalCount += 1;
    console.log(c.red(`CRITICAL: ${server.name}`));
    for (const finding of findings) {
      console.log(c.red(`  - ${finding}`));
    }
  }

  if (criticalCount > 0) {
    console.log(c.red(`\nCritical servers: ${criticalCount}/${servers.length}`));
    return false;
  }

  console.log(c.green(`\nAll servers safe: ${servers.length}/${servers.length}`));
  return true;
}

/**
 * Creates a default guardian policy JSON file.
 */
async function runInit(outputPath: string, force: boolean): Promise<void> {
  const absolutePath = path.resolve(process.cwd(), outputPath);

  if (!force) {
    try {
      await fs.access(absolutePath);
      console.log(c.red(`CRITICAL: ${outputPath} already exists. Use --force to overwrite.`));
      process.exitCode = 1;
      return;
    } catch {
      // File does not exist and can be created.
    }
  }

  const policy = GuardianPolicySchema.parse(DEFAULT_POLICY);
  const serialized = `${JSON.stringify(policy, null, 2)}\n`;
  await fs.writeFile(absolutePath, serialized, "utf8");

  console.log(c.green(`SAFE: Created ${outputPath}`));
}

/**
 * Validates a policy JSON file against the GuardianPolicy schema.
 */
async function runValidate(policyPath: string): Promise<void> {
  const absolutePath = path.resolve(process.cwd(), policyPath);
  let raw: unknown;

  try {
    raw = await readJsonFile(absolutePath);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.log(c.red(`CRITICAL: Failed to read file — ${message}`));
    process.exitCode = 1;
    return;
  }

  const result = GuardianPolicySchema.safeParse(raw);
  if (result.success) {
    console.log(c.green(`SAFE: ${policyPath} is a valid GuardianPolicy.`));
  } else {
    console.log(c.red(`CRITICAL: ${policyPath} — ${result.error.message}`));
    process.exitCode = 1;
  }
}

/**
 * Static JSON Schema (draft-07) for GuardianPolicy.
 * Hardcoded because the shape is fixed and reflection-based generation would add complexity.
 */
function buildPolicyJsonSchema(): object {
  const argSchemaRef = {
    $ref: "#/$defs/ArgSchema"
  };

  return {
    $schema: "http://json-schema.org/draft-07/schema#",
    title: "GuardianPolicy",
    description: "Policy configuration for McpGuardian.",
    type: "object",
    required: ["allowedTools", "restrictedPaths", "maxCallsPerMinute", "approvalRequired"],
    additionalProperties: false,
    properties: {
      allowedTools: {
        type: "array",
        minItems: 1,
        description: "Tool names allowed to execute. Strings only in JSON; use RegExp programmatically.",
        items: { type: "string", minLength: 1 }
      },
      restrictedPaths: {
        type: "array",
        description: "Filesystem path access constraints.",
        items: {
          type: "object",
          required: ["path", "mode"],
          additionalProperties: false,
          properties: {
            path: { type: "string", minLength: 1, description: "Absolute directory path to protect." },
            mode: {
              type: "string",
              enum: ["read-only", "blocked"],
              description: "'blocked' denies all access. 'read-only' allows reads, denies write-intent calls."
            }
          }
        }
      },
      maxCallsPerMinute: {
        type: "integer",
        minimum: 1,
        description: "Rolling 60-second quota for tool calls."
      },
      approvalRequired: {
        type: "boolean",
        description: "When true, every tool call is paused with REQUIRES_APPROVAL."
      },
      toolArgSchemas: {
        type: "object",
        description: "Per-tool argument shape constraints. Key is the exact tool name.",
        additionalProperties: argSchemaRef
      }
    },
    $defs: {
      ArgSchema: {
        type: "object",
        required: ["type"],
        additionalProperties: false,
        properties: {
          type: {
            type: "string",
            enum: ["object", "string", "number", "boolean", "array"]
          },
          required: { type: "array", items: { type: "string" } },
          properties: {
            type: "object",
            additionalProperties: argSchemaRef
          },
          items: argSchemaRef,
          enum: {
            type: "array",
            items: { type: ["string", "number", "boolean", "null"] }
          },
          minLength: { type: "integer", minimum: 0 },
          maxLength: { type: "integer", minimum: 0 },
          minimum: { type: "number" },
          maximum: { type: "number" }
        }
      }
    }
  };
}

/**
 * Prints or writes the GuardianPolicy JSON Schema.
 */
async function runSchema(outputPath?: string): Promise<void> {
  const schema = buildPolicyJsonSchema();
  const serialized = `${JSON.stringify(schema, null, 2)}\n`;

  if (outputPath) {
    const absolutePath = path.resolve(process.cwd(), outputPath);
    await fs.writeFile(absolutePath, serialized, "utf8");
    console.log(c.green(`SAFE: JSON Schema written to ${outputPath}`));
  } else {
    process.stdout.write(serialized);
  }
}

// ---------------------------------------------------------------------------
// CLI argument parsing (replaces commander — zero dependencies)
// ---------------------------------------------------------------------------

function parseFlags(args: string[]): { flags: Record<string, string | boolean>; positional: string[] } {
  const flags: Record<string, string | boolean> = {};
  const positional: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg) continue;

    if (arg === "--output" || arg === "-o") {
      const next = args[++i];
      if (next) flags.output = next;
    } else if (arg === "--force" || arg === "-f") {
      flags.force = true;
    } else if (arg === "--watch" || arg === "-w") {
      flags.watch = true;
    } else if (arg.startsWith("--output=")) {
      flags.output = arg.slice("--output=".length);
    } else if (!arg.startsWith("-")) {
      positional.push(arg);
    }
  }

  return { flags, positional };
}

function printUsage(version: string): void {
  const lines = [
    `mcp-warden v${version}`,
    `Security auditing and policy tooling for MCP servers`,
    ``,
    `Commands:`,
    `  audit <config-path>         Audit a JSON config file for over-permissioned servers`,
    `  audit --watch <config-path> Re-audit on file change (Ctrl-C to stop)`,
    `  init [options]              Generate a default mcp-policy.json`,
    `  validate <policy-path>      Validate a policy JSON file against the GuardianPolicy schema`,
    `  schema [options]            Print the GuardianPolicy JSON Schema to stdout`,
    ``,
    `Options for init:`,
    `  -o, --output <path>         Output path  (default: mcp-policy.json)`,
    `  -f, --force                 Overwrite existing file`,
    ``,
    `Options for schema:`,
    `  -o, --output <path>         Write schema to file instead of stdout`,
    ``,
    `Global:`,
    `  --version, -V               Print version and exit`,
    `  --help, -h                  Show this help`
  ];
  console.log(lines.join("\n"));
}

// ---------------------------------------------------------------------------
// Command handlers (thin wrappers that parse args and delegate)
// ---------------------------------------------------------------------------

async function runAuditCmd(rest: string[]): Promise<void> {
  const { flags, positional } = parseFlags(rest);

  const configPath = positional[0];
  if (!configPath) {
    console.error(c.red("CRITICAL: Missing required argument <config-path>"));
    process.exitCode = 1;
    return;
  }

  if (flags.watch) {
    const absolutePath = path.resolve(process.cwd(), configPath);
    const ok = await runAudit(configPath);
    if (!ok) process.exitCode = 1;

    let debounceTimer: ReturnType<typeof setTimeout> | undefined;

    console.log(c.bold(`\nWatching ${absolutePath} for changes…`));
    const watcher = fs.watch(absolutePath, { persistent: true });

    const handle = async (): Promise<void> => {
      console.log(c.bold(`\n[${new Date().toISOString()}] File changed — re-auditing…`));
      const clean = await runAudit(configPath);
      process.exitCode = clean ? 0 : 1;
    };

    for await (const event of watcher) {
      if (event.eventType === "change" || event.eventType === "rename") {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
          handle().catch((err: unknown) => {
            console.error(c.red(`CRITICAL: ${err instanceof Error ? err.message : String(err)}`));
          });
        }, 100);
      }
    }
    return;
  }

  const ok = await runAudit(configPath);
  if (!ok) process.exitCode = 1;
}

async function runInitCmd(rest: string[]): Promise<void> {
  const { flags } = parseFlags(rest);
  const output = typeof flags.output === "string" ? flags.output : "mcp-policy.json";
  await runInit(output, flags.force === true);
}

async function runValidateCmd(rest: string[]): Promise<void> {
  const { positional } = parseFlags(rest);
  const policyPath = positional[0];
  if (!policyPath) {
    console.error(c.red("CRITICAL: Missing required argument <policy-path>"));
    process.exitCode = 1;
    return;
  }
  await runValidate(policyPath);
}

async function runSchemaCmd(rest: string[]): Promise<void> {
  const { flags } = parseFlags(rest);
  const output = typeof flags.output === "string" ? flags.output : undefined;
  await runSchema(output);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const [, , command, ...rest] = process.argv;
  const version = await resolveCliVersion();

  if (!command || command === "--help" || command === "-h") {
    printUsage(version);
    return;
  }

  if (command === "--version" || command === "-V" || command === "-v") {
    console.log(version);
    return;
  }

  if (command === "audit") {
    await runAuditCmd(rest);
    return;
  }

  if (command === "init") {
    await runInitCmd(rest);
    return;
  }

  if (command === "validate") {
    await runValidateCmd(rest);
    return;
  }

  if (command === "schema") {
    await runSchemaCmd(rest);
    return;
  }

  console.error(c.red(`CRITICAL: Unknown command '${command}'. Run --help for usage.`));
  process.exitCode = 1;
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Unknown CLI error";
  console.error(c.red(`CRITICAL: ${message}`));
  process.exitCode = 1;
});
