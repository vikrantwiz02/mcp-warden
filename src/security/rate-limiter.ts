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
 * In-memory sliding-window limiter using a circular buffer for O(1) operations.
 */
export class RateLimiter {
  private readonly maxCallsPerMinute: number;

  /** Circular buffer storing call timestamps. */
  private readonly buffer: Float64Array;

  /** Write head: next slot to write into. */
  private head: number;

  /** Number of valid entries currently in the buffer. */
  private count: number;

  /**
   * Creates a new limiter using calls per rolling minute as the quota.
   */
  public constructor(options: RateLimiterOptions) {
    this.maxCallsPerMinute = Math.max(1, options.maxCallsPerMinute);
    this.buffer = new Float64Array(this.maxCallsPerMinute);
    this.head = 0;
    this.count = 0;
  }

  /**
   * Checks whether a request can proceed and records it when allowed.
   */
  public consume(now: number = Date.now()): RateLimitDecision {
    const windowStart = now - 60_000;

    // Evict expired entries from the tail (oldest) of the circular buffer.
    while (this.count > 0) {
      const tail = (this.head - this.count + this.maxCallsPerMinute) % this.maxCallsPerMinute;
      const oldest = this.buffer[tail] ?? 0;
      if (oldest > windowStart) {
        break;
      }
      this.count -= 1;
    }

    if (this.count >= this.maxCallsPerMinute) {
      const tail = (this.head - this.count + this.maxCallsPerMinute) % this.maxCallsPerMinute;
      const oldest = this.buffer[tail] ?? now;
      return {
        allowed: false,
        retryAfterMs: Math.max(0, 60_000 - (now - oldest))
      };
    }

    this.buffer[this.head] = now;
    this.head = (this.head + 1) % this.maxCallsPerMinute;
    this.count += 1;

    return { allowed: true };
  }

  /**
   * Returns current limiter occupancy for diagnostics and testing.
   */
  public getCount(): number {
    return this.count;
  }
}
