/**
 * Interface for persistence layer storing the elements of the universal accumulator created during initialization.
 * This persistence layer should not be modified once the accumulator is initialized. It is only read after initialization.
 */
export interface IInitialElementsStore {
    add(element: Uint8Array): Promise<void>;
    has(element: Uint8Array): Promise<boolean>;
}
