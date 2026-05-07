/**
 * Placeholder used when sensitive values are removed.
 */
export const REDACTION_TOKEN = "[REDACTED]";

/**
 * Combined pattern that matches emails, API keys, IPv4, IPv6, and phone numbers
 * in a single pass for efficiency.
 *
 * Named capture groups identify which category matched so the replacer
 * can be extended without reordering.
 */
const COMBINED_SENSITIVE_REGEX = new RegExp(
  [
    // Email addresses
    "(?<email>\\b[A-Z0-9._%+\\-]+@[A-Z0-9.\\-]+\\.[A-Z]{2,}\\b)",
    // Common key-value secret assignments
    "(?<kvsecret>\\b(?:api[_-]?key|token|secret|password)\\s*[:=]\\s*[\"']?[^\"'\\s;]+[\"']?)",
    // Stripe-style and generic API keys / tokens
    "(?<apikey>\\b(?:sk_(?:test|live)_[A-Z0-9]{8,}|(?:sk|key|api|token)-[A-Z0-9_\\-]{8,})\\b)",
    // IPv6 — full and compressed forms (must come before IPv4 to avoid partial matches)
    "(?<ipv6>(?:[0-9A-F]{1,4}:){7}[0-9A-F]{1,4}|(?:[0-9A-F]{1,4}:){1,7}:|(?:[0-9A-F]{1,4}:){1,6}:[0-9A-F]{1,4}|::(?:[0-9A-F]{1,4}:){0,5}[0-9A-F]{1,4}|::)",
    // IPv4 addresses with valid octet ranges
    "(?<ipv4>\\b(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\b)",
    // Phone numbers — E.164, US, and common international formats
    "(?<phone>(?:\\+?1[\\s.\\-]?)?\\(?\\d{3}\\)?[\\s.\\-]?\\d{3}[\\s.\\-]?\\d{4})"
  ].join("|"),
  "gi"
);

/**
 * Summary of a single text redaction operation.
 */
export interface RedactionSummary {
  value: string;
  redactedCount: number;
}

/**
 * Redacts sensitive values from a plain string in a single regex pass.
 */
export function redactSensitiveText(input: string): RedactionSummary {
  let redactedCount = 0;

  const value = input.replace(COMBINED_SENSITIVE_REGEX, () => {
    redactedCount += 1;
    return REDACTION_TOKEN;
  });

  return { value, redactedCount };
}

/**
 * Recursively redacts sensitive content from arbitrary JSON-like payloads.
 */
export function redactSensitiveData<T>(value: T): T {
  const seen = new WeakMap<object, unknown>();

  const transform = (candidate: unknown): unknown => {
    if (typeof candidate === "string") {
      return redactSensitiveText(candidate).value;
    }

    if (Array.isArray(candidate)) {
      return candidate.map((entry) => transform(entry));
    }

    if (!candidate || typeof candidate !== "object") {
      return candidate;
    }

    if (seen.has(candidate)) {
      return seen.get(candidate);
    }

    const inputRecord = candidate as Record<string, unknown>;
    const outputRecord: Record<string, unknown> = {};
    seen.set(candidate, outputRecord);

    for (const [key, entry] of Object.entries(inputRecord)) {
      outputRecord[key] = transform(entry);
    }

    return outputRecord;
  };

  return transform(value) as T;
}
