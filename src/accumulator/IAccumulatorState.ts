/**
 * Interface for accumulator state. This should be implemented by the persistence layer that stores the accumulator
 * members. It is advised to update the state when elements are added or removed from the accumulator.
 */
export interface IAccumulatorState {
  add(element: Uint8Array): Promise<void>;
  remove(element: Uint8Array): Promise<void>;

  /**
   * Check if element is a member of the state.
   * @param element
   */
  has(element: Uint8Array): Promise<boolean>;
}

/**
 * Additional interface for universal accumulator to expose a method that allows to iterate over the
 * accumulator members.
 */
export interface IUniversalAccumulatorState extends IAccumulatorState {
  elements(): Promise<Iterable<Uint8Array>>;
}

export interface IKBUniversalAccumulatorState extends IAccumulatorState {
  /**
   * Whether this element is in the domain (could be a member or not)
   * @param element
   */
  inDomain(element: Uint8Array): Promise<boolean>;

  /**
   * Takes an element not in the domain and adds it.
   * @param element
   */
  addToDomain(element: Uint8Array): Promise<void>;
}
