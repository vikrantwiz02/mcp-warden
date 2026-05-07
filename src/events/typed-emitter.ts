type Listener<T> = (event: T) => void;

/**
 * Zero-dependency typed event emitter with subscribe, unsubscribe, and one-shot support.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export class TypedEmitter<TMap extends Record<string, any>> {
  private readonly _listeners = new Map<keyof TMap, Set<Listener<unknown>>>();

  /**
   * Subscribe to an event type. Returns `this` for chaining.
   */
  on<K extends keyof TMap>(type: K, listener: Listener<TMap[K]>): this {
    let set = this._listeners.get(type);
    if (!set) {
      set = new Set();
      this._listeners.set(type, set);
    }
    set.add(listener as Listener<unknown>);
    return this;
  }

  /**
   * Unsubscribe a previously registered listener. Returns `this` for chaining.
   */
  off<K extends keyof TMap>(type: K, listener: Listener<TMap[K]>): this {
    this._listeners.get(type)?.delete(listener as Listener<unknown>);
    return this;
  }

  /**
   * Subscribe to an event type for a single invocation, then auto-unsubscribe.
   */
  once<K extends keyof TMap>(type: K, listener: Listener<TMap[K]>): this {
    const wrapper: Listener<TMap[K]> = (event) => {
      this.off(type, wrapper);
      listener(event);
    };
    return this.on(type, wrapper);
  }

  /**
   * Emit an event to all registered listeners for the given type.
   */
  protected _emit<K extends keyof TMap>(type: K, event: TMap[K]): void {
    const set = this._listeners.get(type);
    if (!set) return;
    for (const listener of set) {
      listener(event);
    }
  }
}
