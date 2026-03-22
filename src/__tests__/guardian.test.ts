import { describe, expect, it } from "vitest";
import { McpGuardian } from "../core/interceptor.js";
import type { GuardianPolicy } from "../types/policy.js";

/**
 * Creates a baseline policy used by test cases.
 */
function createPolicy(overrides: Partial<GuardianPolicy> = {}): GuardianPolicy {
  return {
    allowedTools: ["safe-tool"],
    restrictedPaths: [],
    maxCallsPerMinute: 10,
    approvalRequired: true,
    ...overrides
  };
}

describe("McpGuardian", () => {
  it("blocks unauthorized tool calls", async () => {
    const guardian = new McpGuardian(createPolicy());

    const result = await guardian.validateRequest({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "unsafe-tool",
        arguments: { query: "test" }
      }
    });

    expect(result.isAllowed).toBe(false);
    expect(result.error?.error.message).toBe("PERMISSION_DENIED");
    expect(result.violation?.reason).toContain("not allowed by policy");
  });

  it("redacts sensitive data in tool responses", async () => {
    const guardian = new McpGuardian(createPolicy());

    const guardedHandler = guardian.wrapHandler(async () => ({
      jsonrpc: "2.0" as const,
      id: 22,
      result: {
        email: "user@example.com",
        secret: "sk-ABCDEF12345678",
        ip: "192.168.1.24"
      }
    }));

    const response = await guardedHandler({
      jsonrpc: "2.0",
      id: 22,
      method: "tools/call",
      params: {
        name: "safe-tool",
        arguments: { input: "ok" }
      }
    });

    const payload = response as { result?: Record<string, unknown> };
    expect(payload.result?.email).toBe("[REDACTED]");
    expect(payload.result?.secret).toBe("[REDACTED]");
    expect(payload.result?.ip).toBe("[REDACTED]");
  });

  it("triggers rate limiting after max calls per minute", async () => {
    let now = 1_000;
    const guardian = new McpGuardian(createPolicy({ maxCallsPerMinute: 2 }), {
      nowProvider: () => now
    });

    const request = {
      jsonrpc: "2.0" as const,
      id: 7,
      method: "tools/call",
      params: {
        name: "safe-tool",
        arguments: { input: "go" }
      }
    };

    const first = await guardian.validateRequest(request);
    now += 1;
    const second = await guardian.validateRequest(request);
    now += 1;
    const third = await guardian.validateRequest(request);

    expect(first.isAllowed).toBe(true);
    expect(second.isAllowed).toBe(true);
    expect(third.isAllowed).toBe(false);
    expect(third.error?.error.message).toBe("PERMISSION_DENIED");
    expect(third.violation?.reason).toContain("Rate limit exceeded");
  });
});
