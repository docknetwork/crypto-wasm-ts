import { IAccumulatorState, IUniversalAccumulatorState } from './IAccumulatorState';
import { IInitialElementsStore } from './IInitialElementsStore';

/**
 * In memory implementation of the state. For testing only
 */
export class InMemoryState implements IAccumulatorState {
  state: Set<string>;
  constructor() {
    this.state = new Set<string>();
  }

  async add(element: Uint8Array): Promise<void> {
    const key = InMemoryState.key(element);
    if (this.state.has(key)) {
      throw new Error(`${element} already present`);
    }
    this.state.add(key);
    return Promise.resolve();
  }

  async remove(element: Uint8Array): Promise<void> {
    const key = InMemoryState.key(element);
    if (!this.state.has(key)) {
      throw new Error(`${element} not present`);
    }
    this.state.delete(key);
    return Promise.resolve();
  }

  async has(element: Uint8Array): Promise<boolean> {
    const key = InMemoryState.key(element);
    return Promise.resolve(this.state.has(key));
  }

  static key(element: Uint8Array) {
    return JSON.stringify(Array.from(element));
  }
}

export class InMemoryUniversalState extends InMemoryState implements IUniversalAccumulatorState {
  elements(): Promise<Iterable<Uint8Array>> {
    function* y(state: Set<string>) {
      for (const k of state) {
        yield new Uint8Array(JSON.parse(k));
      }
    }
    return Promise.resolve(y(this.state));
  }
}

export class InMemoryInitialElementsStore implements IInitialElementsStore {
  store: Set<string>;
  constructor() {
    this.store = new Set<string>();
  }

  async add(element: Uint8Array): Promise<void> {
    const key = InMemoryInitialElementsStore.key(element);
    if (this.store.has(key)) {
      throw new Error(`${element} already present`);
    }
    this.store.add(key);
    return Promise.resolve();
  }

  async has(element: Uint8Array): Promise<boolean> {
    const key = InMemoryInitialElementsStore.key(element);
    return Promise.resolve(this.store.has(key));
  }

  static key(element: Uint8Array) {
    return JSON.stringify(Array.from(element));
  }
}
