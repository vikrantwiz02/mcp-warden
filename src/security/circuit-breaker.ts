/**
 * Runtime configuration for circuit-breaker behavior.
 */
export interface CircuitBreakerOptions {
  threshold?: number;
  cooldownMs?: number;
  /**
   * How long after a circuit last had activity before its state entry is
   * evicted from memory. Defaults to 10 minutes. Set to 0 to disable cleanup.
   */
  stateTtlMs?: number;
}

/**
 * Per-tool circuit state snapshot.
 */
export interface CircuitState {
  consecutiveFailures: number;
  openUntil: number | null;
}

/**
 * Evaluation result for whether a tool may run.
 */
export interface CircuitDecision {
  allowed: boolean;
  retryAfterMs?: number;
}

/** Internal state entry with last-touched timestamp for TTL eviction. */
interface CircuitEntry extends CircuitState {
  lastUsedAt: number;
}

/**
 * Simple per-tool circuit breaker that opens after repeated failures.
 * Stale entries are evicted after `stateTtlMs` of inactivity to prevent
 * unbounded memory growth for ephemeral tool names.
 */
export class CircuitBreaker {
  private readonly threshold: number;

  private readonly cooldownMs: number;

  private readonly stateTtlMs: number;

  private readonly states: Map<string, CircuitEntry>;

  /**
   * Creates a circuit-breaker instance.
   */
  public constructor(options: CircuitBreakerOptions = {}) {
    this.threshold = Math.max(1, options.threshold ?? 5);
    this.cooldownMs = Math.max(1, options.cooldownMs ?? 60_000);
    this.stateTtlMs = options.stateTtlMs ?? 10 * 60_000;
    this.states = new Map<string, CircuitEntry>();
  }

  /**
   * Determines if a tool is currently allowed to execute.
   */
  public canExecute(toolName: string, now: number = Date.now()): CircuitDecision {
    this.evictStaleEntries(now);

    const state = this.states.get(toolName);
    if (!state || state.openUntil === null) {
      return { allowed: true };
    }

    if (now >= state.openUntil) {
      this.states.set(toolName, {
        consecutiveFailures: 0,
        openUntil: null,
        lastUsedAt: now
      });
      return { allowed: true };
    }

    state.lastUsedAt = now;
    return {
      allowed: false,
      retryAfterMs: state.openUntil - now
    };
  }

  /**
   * Records a successful execution and resets failure counters.
   */
  public recordSuccess(toolName: string, now: number = Date.now()): void {
    this.states.set(toolName, {
      consecutiveFailures: 0,
      openUntil: null,
      lastUsedAt: now
    });
  }

  /**
   * Records a failed execution and opens the circuit when threshold is reached.
   */
  public recordFailure(toolName: string, now: number = Date.now()): void {
    const current = this.states.get(toolName) ?? {
      consecutiveFailures: 0,
      openUntil: null,
      lastUsedAt: now
    };

    const consecutiveFailures = current.consecutiveFailures + 1;
    if (consecutiveFailures >= this.threshold) {
      this.states.set(toolName, {
        consecutiveFailures,
        openUntil: now + this.cooldownMs,
        lastUsedAt: now
      });
      return;
    }

    this.states.set(toolName, {
      consecutiveFailures,
      openUntil: null,
      lastUsedAt: now
    });
  }

  /**
   * Returns a copy of current state for observability.
   */
  public getState(toolName: string): CircuitState {
    const state = this.states.get(toolName);
    return state
      ? { consecutiveFailures: state.consecutiveFailures, openUntil: state.openUntil }
      : { consecutiveFailures: 0, openUntil: null };
  }

  /**
   * Returns the number of tool entries currently tracked.
   */
  public get size(): number {
    return this.states.size;
  }

  /**
   * Removes entries that have been idle longer than `stateTtlMs`.
   */
  private evictStaleEntries(now: number): void {
    if (this.stateTtlMs <= 0) {
      return;
    }

    for (const [key, entry] of this.states) {
      if (now - entry.lastUsedAt > this.stateTtlMs) {
        this.states.delete(key);
      }
    }
  }
}
