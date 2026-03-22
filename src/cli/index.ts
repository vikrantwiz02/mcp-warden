#!/usr/bin/env node

import { promises as fs } from "node:fs";
import * as path from "node:path";
import chalk from "chalk";
import { Command } from "commander";
import { GuardianPolicySchema, type GuardianPolicy } from "../types/policy.js";

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

/**
 * Policy file created by `mcp-warden init`.
 */
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

/**
 * True if a value is a plain object.
 */
function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

/**
 * Converts unknown values to a string array.
 */
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
 * Runs audit mode and prints color-coded findings.
 */
async function runAudit(configPath: string): Promise<void> {
  const absolutePath = path.resolve(process.cwd(), configPath);
  const config = await readJsonFile(absolutePath);
  const servers = extractServers(config);

  console.log(chalk.bold(`Audit file: ${absolutePath}`));

  if (servers.length === 0) {
    console.log(chalk.red("CRITICAL: No MCP servers found. Verify config structure before deployment."));
    process.exitCode = 1;
    return;
  }

  let criticalCount = 0;

  for (const server of servers) {
    const findings = getCriticalFindings(server.config);
    if (findings.length === 0) {
      console.log(chalk.green(`SAFE: ${server.name}`));
      continue;
    }

    criticalCount += 1;
    console.log(chalk.red(`CRITICAL: ${server.name}`));
    for (const finding of findings) {
      console.log(chalk.red(`  - ${finding}`));
    }
  }

  if (criticalCount > 0) {
    console.log(chalk.red(`\nCritical servers: ${criticalCount}/${servers.length}`));
    process.exitCode = 1;
    return;
  }

  console.log(chalk.green(`\nAll servers safe: ${servers.length}/${servers.length}`));
}

/**
 * Creates a default guardian policy JSON file.
 */
async function runInit(outputPath: string, force: boolean): Promise<void> {
  const absolutePath = path.resolve(process.cwd(), outputPath);

  if (!force) {
    try {
      await fs.access(absolutePath);
      console.log(chalk.red(`CRITICAL: ${outputPath} already exists. Use --force to overwrite.`));
      process.exitCode = 1;
      return;
    } catch {
      // File does not exist and can be created.
    }
  }

  const policy = GuardianPolicySchema.parse(DEFAULT_POLICY);
  const serialized = `${JSON.stringify(policy, null, 2)}\n`;
  await fs.writeFile(absolutePath, serialized, "utf8");

  console.log(chalk.green(`SAFE: Created ${outputPath}`));
}

/**
 * Boots the mcp-warden CLI.
 */
async function main(): Promise<void> {
  const program = new Command();

  program
    .name("mcp-warden")
    .description("Security auditing and policy tooling for MCP servers")
    .version("0.1.0");

  program
    .command("audit")
    .description("Audit a claude_desktop_config.json or cursor-settings.json file")
    .argument("<config-path>", "Path to a JSON config file")
    .action(async (configPath: string) => {
      await runAudit(configPath);
    });

  program
    .command("init")
    .description("Generate a default mcp-policy.json")
    .option("-o, --output <path>", "Output path for generated policy", "mcp-policy.json")
    .option("-f, --force", "Overwrite existing file")
    .action(async (options: { output: string; force?: boolean }) => {
      await runInit(options.output, Boolean(options.force));
    });

  await program.parseAsync(process.argv);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Unknown CLI error";
  console.error(chalk.red(`CRITICAL: ${message}`));
  process.exitCode = 1;
});
