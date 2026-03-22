/**
 * Sliding-window limiter configuration.
 */
export interface RateLimiterOptions {
  maxCallsPerMinute: number;
}

/**
 * Result of evaluating a rate-limited request.
 */
export interface RateLimitDecision {
  allowed: boolean;
  retryAfterMs?: number;
}

/**
 * In-memory sliding-window limiter for tool call volume.
 */
export class RateLimiter {
  private readonly maxCallsPerMinute: number;

  private readonly callTimestampsMs: number[];

  /**
   * Creates a new limiter using calls per rolling minute as the quota.
   */
  public constructor(options: RateLimiterOptions) {
    this.maxCallsPerMinute = Math.max(1, options.maxCallsPerMinute);
    this.callTimestampsMs = [];
  }

  /**
   * Checks whether a request can proceed and records it when allowed.
   */
  public consume(now: number = Date.now()): RateLimitDecision {
    const oneMinuteAgo = now - 60_000;

    while (this.callTimestampsMs.length > 0) {
      const head = this.callTimestampsMs[0];
      if (head === undefined || head > oneMinuteAgo) {
        break;
      }

      this.callTimestampsMs.shift();
    }

    if (this.callTimestampsMs.length >= this.maxCallsPerMinute) {
      const oldest = this.callTimestampsMs[0] ?? now;
      return {
        allowed: false,
        retryAfterMs: Math.max(0, 60_000 - (now - oldest))
      };
    }

    this.callTimestampsMs.push(now);
    return { allowed: true };
  }

  /**
   * Returns current limiter occupancy for diagnostics and testing.
   */
  public getCount(): number {
    return this.callTimestampsMs.length;
  }
}