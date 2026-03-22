/**
 * Placeholder used when sensitive values are removed.
 */
export const REDACTION_TOKEN = "[REDACTED]";

/**
 * Finds common email address patterns.
 */
const EMAIL_REGEX = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;

/**
 * Finds key-like secrets with common prefixes such as sk- and key-.
 */
const API_KEY_REGEX =
  /\b(?:sk_(?:test|live)_[A-Z0-9]{8,}|(?:sk|key|api|token)-[A-Z0-9_-]{8,})\b/gi;

/**
 * Finds IPv4 addresses and excludes impossible octets.
 */
const IPV4_REGEX =
  /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;

/**
 * Summary of a single text redaction operation.
 */
export interface RedactionSummary {
  value: string;
  redactedCount: number;
}

/**
 * Redacts sensitive values from a plain string.
 */
export function redactSensitiveText(input: string): RedactionSummary {
  let redactedCount = 0;

  const replacer = (): string => {
    redactedCount += 1;
    return REDACTION_TOKEN;
  };

  let value = input.replace(EMAIL_REGEX, replacer);
  value = value.replace(API_KEY_REGEX, replacer);
  value = value.replace(IPV4_REGEX, replacer);

  return {
    value,
    redactedCount
  };
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