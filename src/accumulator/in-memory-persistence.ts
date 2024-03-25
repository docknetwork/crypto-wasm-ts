import { IAccumulatorState, IKBUniversalAccumulatorState, IUniversalAccumulatorState } from './IAccumulatorState';
import { IInitialElementsStore } from './IInitialElementsStore';

/**
 * In memory implementation of the state. For testing only
 */
export class InMemoryState implements IAccumulatorState {
  // Converts item to string (JSON.stringify) before adding to set as equality checks wont work with Uint8Array.
  state: Set<string>;
  constructor() {
    this.state = new Set<string>();
  }

  get size(): number {
    return this.state.size;
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
  // Converts item to string (JSON.stringify) before adding to set as equality checks wont work with Uint8Array.
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

/**
 * In memory implementation of the state. For testing only
 */
export class InMemoryKBUniversalState implements IKBUniversalAccumulatorState {
  memState: Set<string>;
  nonMemState: Set<string>;

  constructor() {
    this.memState = new Set<string>();
    this.nonMemState = new Set<string>();
  }

  get size(): number {
    return this.memState.size;
  }

  add(element: Uint8Array): Promise<void> {
    const key = InMemoryKBUniversalState.key(element);
    if (this.memState.has(key)) {
      throw new Error(`${element} already present in mem state`);
    }
    if (!this.nonMemState.has(key)) {
      throw new Error(`${element} not present in non mem state`);
    }
    this.memState.add(key);
    this.nonMemState.delete(key);
    return Promise.resolve();
  }

  has(element: Uint8Array): Promise<boolean> {
    const key = InMemoryKBUniversalState.key(element);
    // Ideally, something present in `memState` should not be present in `nonMemState` and vice-versa
    const b = this.memState.has(key) && !this.nonMemState.has(key);
    return Promise.resolve(b);
  }

  remove(element: Uint8Array): Promise<void> {
    const key = InMemoryKBUniversalState.key(element);
    if (!this.memState.has(key)) {
      throw new Error(`${element} not present in mem state`);
    }
    if (this.nonMemState.has(key)) {
      throw new Error(`${element} already present in non mem state`);
    }
    this.memState.delete(key);
    this.nonMemState.add(key);
    return Promise.resolve();
  }

  static key(element: Uint8Array) {
    return JSON.stringify(Array.from(element));
  }

  inDomain(element: Uint8Array): Promise<boolean> {
    const key = InMemoryKBUniversalState.key(element);
    const b = this.nonMemState.has(key) || this.memState.has(key);
    return Promise.resolve(b);
  }

  async addToDomain(element: Uint8Array) {
    const key = InMemoryKBUniversalState.key(element);
    this.nonMemState.add(key);
    return Promise.resolve();
  }
}
