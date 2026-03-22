/**
 * Default signatures associated with prompt-injection attempts.
 */
export const DEFAULT_INJECTION_KEYWORDS = [
  "ignore previous instructions",
  "now you are an admin",
  "disregard all prior rules",
  "override your safety policy"
] as const;

/**
 * Result produced by an injection scan.
 */
export interface InjectionScanResult {
  detected: boolean;
  matchedKeywords: string[];
}

/**
 * Scans tool arguments for known prompt-injection signatures.
 */
export function scanForPromptInjection(
  payload: unknown,
  keywords: readonly string[] = DEFAULT_INJECTION_KEYWORDS
): InjectionScanResult {
  const normalizedKeywords = keywords
    .map((keyword) => keyword.trim().toLowerCase())
    .filter((keyword) => keyword.length > 0);

  const matchedKeywords = new Set<string>();
  const seen = new WeakSet<object>();

  const visit = (candidate: unknown): void => {
    if (typeof candidate === "string") {
      const normalized = candidate.toLowerCase();
      for (const keyword of normalizedKeywords) {
        if (normalized.includes(keyword)) {
          matchedKeywords.add(keyword);
        }
      }
      return;
    }

    if (Array.isArray(candidate)) {
      for (const entry of candidate) {
        visit(entry);
      }
      return;
    }

    if (!candidate || typeof candidate !== "object") {
      return;
    }

    if (seen.has(candidate)) {
      return;
    }
    seen.add(candidate);

    for (const entry of Object.values(candidate as Record<string, unknown>)) {
      visit(entry);
    }
  };

  visit(payload);

  return {
    detected: matchedKeywords.size > 0,
    matchedKeywords: [...matchedKeywords]
  };
}