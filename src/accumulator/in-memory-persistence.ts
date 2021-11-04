import { IAccumulatorState, IUniversalAccumulatorState } from './IAccumulatorState';
import { IInitialElementsStore } from './IInitialElementsStore';

/**
 * In memory implementation of the state. For testing only
 */
export class InMemoryState implements IAccumulatorState {
  state: Set<Uint8Array>;
  constructor() {
    this.state = new Set<Uint8Array>();
  }

  async add(element: Uint8Array): Promise<void> {
    if (this.state.has(element)) {
      throw new Error(`${element} already present`);
    }
    this.state.add(element);
    return Promise.resolve();
  }

  async remove(element: Uint8Array): Promise<void> {
    if (!this.state.has(element)) {
      throw new Error(`${element} not present`);
    }
    this.state.delete(element);
    return Promise.resolve();
  }

  async has(element: Uint8Array): Promise<boolean> {
    return Promise.resolve(this.state.has(element));
  }
}

export class InMemoryUniversalState extends InMemoryState implements IUniversalAccumulatorState {
  elements(): Promise<Iterable<Uint8Array>> {
    return Promise.resolve(this.state[Symbol.iterator]());
  }
}

export class InMemoryInitialElementsStore implements IInitialElementsStore {
  store: Set<Uint8Array>;
  constructor() {
    this.store = new Set<Uint8Array>();
  }

  async add(element: Uint8Array): Promise<void> {
    if (this.store.has(element)) {
      throw new Error(`${element} already present`);
    }
    this.store.add(element);
    return Promise.resolve();
  }

  async has(element: Uint8Array): Promise<boolean> {
    return Promise.resolve(this.store.has(element));
  }
}
