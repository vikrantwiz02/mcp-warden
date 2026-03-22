/**
 * Runtime configuration for circuit-breaker behavior.
 */
export interface CircuitBreakerOptions {
  threshold?: number;
  cooldownMs?: number;
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

/**
 * Simple per-tool circuit breaker that opens after repeated failures.
 */
export class CircuitBreaker {
  private readonly threshold: number;

  private readonly cooldownMs: number;

  private readonly states: Map<string, CircuitState>;

  /**
   * Creates a circuit-breaker instance.
   */
  public constructor(options: CircuitBreakerOptions = {}) {
    this.threshold = Math.max(1, options.threshold ?? 5);
    this.cooldownMs = Math.max(1, options.cooldownMs ?? 60_000);
    this.states = new Map<string, CircuitState>();
  }

  /**
   * Determines if a tool is currently allowed to execute.
   */
  public canExecute(toolName: string, now: number = Date.now()): CircuitDecision {
    const state = this.states.get(toolName);
    if (!state || state.openUntil === null) {
      return { allowed: true };
    }

    if (now >= state.openUntil) {
      this.states.set(toolName, {
        consecutiveFailures: 0,
        openUntil: null
      });
      return { allowed: true };
    }

    return {
      allowed: false,
      retryAfterMs: state.openUntil - now
    };
  }

  /**
   * Records a successful execution and resets failure counters.
   */
  public recordSuccess(toolName: string): void {
    this.states.set(toolName, {
      consecutiveFailures: 0,
      openUntil: null
    });
  }

  /**
   * Records a failed execution and opens the circuit when threshold is reached.
   */
  public recordFailure(toolName: string, now: number = Date.now()): void {
    const current = this.states.get(toolName) ?? {
      consecutiveFailures: 0,
      openUntil: null
    };

    const consecutiveFailures = current.consecutiveFailures + 1;
    if (consecutiveFailures >= this.threshold) {
      this.states.set(toolName, {
        consecutiveFailures,
        openUntil: now + this.cooldownMs
      });
      return;
    }

    this.states.set(toolName, {
      consecutiveFailures,
      openUntil: null
    });
  }

  /**
   * Returns a copy of current state for observability.
   */
  public getState(toolName: string): CircuitState {
    const state = this.states.get(toolName);
    return state
      ? { ...state }
      : {
          consecutiveFailures: 0,
          openUntil: null
        };
  }
}