import { McpGuardian, type GuardianPolicy } from "./src/index.ts";

type JsonRpcResult = {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: {
    message?: string;
    data?: {
      reason?: string;
    };
  };
};

interface ScenarioResult {
  name: string;
  passed: boolean;
  details: string;
}

function buildPolicy(overrides: Partial<GuardianPolicy> = {}): GuardianPolicy {
  return {
    allowedTools: ["safe-tool"],
    restrictedPaths: [
      { path: "/etc", mode: "blocked" },
      { path: "..", mode: "blocked" }
    ],
    maxCallsPerMinute: 5,
    approvalRequired: false,
    ...overrides
  };
}

function isErrorWithMessage(response: JsonRpcResult, message: string): boolean {
  return response.error?.message === message;
}

function toSafeString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

async function runPathEscapeScenario(): Promise<ScenarioResult> {
  const guardian = new McpGuardian(buildPolicy());

  const attempts = [
    {
      key: "cwd",
      value: "/etc/shadow"
    },
    {
      key: "filepath",
      value: "../../.env"
    }
  ];

  const results = await Promise.all(
    attempts.map(async (attempt, index) => {
      const response = await guardian.validateRequest({
        jsonrpc: "2.0",
        id: `path-${index}`,
        method: "tools/call",
        params: {
          name: "safe-tool",
          arguments: {
            [attempt.key]: attempt.value
          }
        }
      });

      return {
        blocked: response.isAllowed === false && response.error?.error.message === "PERMISSION_DENIED",
        reason: toSafeString(response.error?.error.data?.reason)
      };
    })
  );

  const passed = results.every((entry) => entry.blocked && entry.reason.toLowerCase().includes("restricted path"));
  return {
    name: "Path Escape",
    passed,
    details: passed
      ? "Blocked both /etc/shadow and ../../.env attempts via path-like keys."
      : "One or more path escape attempts were not blocked as expected."
  };
}

async function runPiiLeakScenario(): Promise<ScenarioResult> {
  const guardian = new McpGuardian(buildPolicy({ restrictedPaths: [] }));
  const stripeLikeFixture = ["sk", "test", "51M0cha0sExampleSecret"].join("_");

  const guardedHandler = guardian.wrapHandler(async () => ({
    jsonrpc: "2.0" as const,
    id: 99,
    result: {
      message: `Contact alice@company.com and use stripe key ${stripeLikeFixture} to complete payment.`
    }
  }));

  const response = (await guardedHandler({
    jsonrpc: "2.0",
    id: 99,
    method: "tools/call",
    params: {
      name: "safe-tool",
      arguments: {
        input: "run"
      }
    }
  })) as JsonRpcResult;

  const redactedMessage = (response.result as { message?: string } | undefined)?.message ?? "";
  const emailRedacted = !redactedMessage.includes("alice@company.com") && redactedMessage.includes("[REDACTED]");
  const stripeRedacted = !redactedMessage.includes("sk_test_") && redactedMessage.includes("[REDACTED]");
  const passed = emailRedacted && stripeRedacted;

  return {
    name: "PII Leak",
    passed,
    details: passed
      ? "Redacted email and Stripe-style API key output before returning to caller."
      : "PII redaction missed either the email or the Stripe-style API key."
  };
}

async function runApprovalLoopScenario(): Promise<ScenarioResult> {
  const guardian = new McpGuardian(buildPolicy({ approvalRequired: true, restrictedPaths: [] }));
  let executeCount = 0;

  const guardedHandler = guardian.wrapHandler(async () => {
    executeCount += 1;
    return {
      jsonrpc: "2.0" as const,
      id: 7,
      result: { ok: true }
    };
  });

  const responses: JsonRpcResult[] = [];
  for (let i = 0; i < 3; i += 1) {
    const response = (await guardedHandler({
      jsonrpc: "2.0",
      id: i,
      method: "tools/call",
      params: {
        name: "safe-tool",
        arguments: { input: `attempt-${i}` }
      }
    })) as JsonRpcResult;
    responses.push(response);
  }

  const allRequireApproval = responses.every((response) => isErrorWithMessage(response, "REQUIRES_APPROVAL"));
  const passed = allRequireApproval && executeCount === 0;

  return {
    name: "Approval Loop",
    passed,
    details: passed
      ? "Returned REQUIRES_APPROVAL for every call and never executed underlying handler."
      : "Approval loop failed: handler executed or REQUIRES_APPROVAL was not consistently returned."
  };
}

async function runRateLimitScenario(): Promise<ScenarioResult> {
  let now = 1_000;
  const guardian = new McpGuardian(
    buildPolicy({ maxCallsPerMinute: 3, restrictedPaths: [], approvalRequired: false }),
    { nowProvider: () => now }
  );

  let deniedCount = 0;
  for (let i = 0; i < 10; i += 1) {
    const response = await guardian.validateRequest({
      jsonrpc: "2.0",
      id: i,
      method: "tools/call",
      params: {
        name: "safe-tool",
        arguments: { input: `burst-${i}` }
      }
    });

    if (!response.isAllowed && response.error?.error.message === "PERMISSION_DENIED") {
      const reason = toSafeString(response.error.error.data?.reason);
      if (reason.toLowerCase().includes("rate limit")) {
        deniedCount += 1;
      }
    }

    now += 1;
  }

  const passed = deniedCount >= 1;
  return {
    name: "Rate Limit",
    passed,
    details: passed
      ? `Rate limiter denied ${deniedCount} burst requests.`
      : "No rate-limit denial observed across 10 rapid calls."
  };
}

async function main(): Promise<void> {
  const scenarios = await Promise.all([
    runPathEscapeScenario(),
    runPiiLeakScenario(),
    runApprovalLoopScenario(),
    runRateLimitScenario()
  ]);

  let hasFailure = false;

  for (const scenario of scenarios) {
    const status = scenario.passed ? "PASS" : "FAIL";
    console.log(`[${status}] ${scenario.name}: ${scenario.details}`);
    if (!scenario.passed) {
      hasFailure = true;
    }
  }

  if (hasFailure) {
    console.error("TEST FAILED");
    process.exitCode = 1;
    return;
  }

  console.log("TEST PASSED");
}

main().catch((error) => {
  console.error("TEST FAILED");
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});