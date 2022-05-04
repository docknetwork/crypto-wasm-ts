import {
  generateFieldElementFromBytes,
  generateFieldElementFromNumber,
  generateRandomFieldElement,
  positiveAccumulatorAdd,
  positiveAccumulatorAddBatch,
  positiveAccumulatorBatchUpdates,
  positiveAccumulatorInitialize,
  positiveAccumulatorMembershipWitness,
  positiveAccumulatorMembershipWitnessesForBatch,
  positiveAccumulatorRemove,
  positiveAccumulatorRemoveBatch,
  positiveAccumulatorVerifyMembership,
  universalAccumulatorAdd,
  universalAccumulatorAddBatch,
  universalAccumulatorBatchUpdates,
  universalAccumulatorCombineMultipleD,
  universalAccumulatorCombineMultipleInitialFv,
  universalAccumulatorComputeD,
  universalAccumulatorComputeDForBatch,
  universalAccumulatorComputeInitialFv,
  universalAccumulatorFixedInitialElements,
  universalAccumulatorInitialiseGivenFv,
  universalAccumulatorMembershipWitness,
  universalAccumulatorMembershipWitnessesForBatch,
  universalAccumulatorNonMembershipWitness,
  universalAccumulatorNonMembershipWitnessesForBatch,
  universalAccumulatorRemove,
  universalAccumulatorRemoveBatch,
  universalAccumulatorVerifyMembership,
  universalAccumulatorVerifyNonMembership
} from '@docknetwork/crypto-wasm';
import { MembershipWitness, NonMembershipWitness } from './accumulatorWitness';
import { ensurePositiveIntegerOfSize, getUint8ArraysFromObject } from '../util';
import { IAccumulatorState, IUniversalAccumulatorState } from './IAccumulatorState';
import { IInitialElementsStore } from './IInitialElementsStore';
import {
  AccumulatorKeypair,
  AccumulatorParams,
  AccumulatorPublicKey,
  AccumulatorSecretKey,
  MembershipProvingKey,
  NonMembershipProvingKey
} from './params-and-keys';

/**
 * Interface implemented by both Positive and Universal accumulator. Contains implementations for parameter and key generation.
 * Note:
 * - The secret key and params are optional in functions like `add`, `remove`, etc. as they can be stored in the accumulator
 * object. If exposure to the secret key needs to be minimized, don't pass it to the constructor but only to functions that need it.
 * - Methods to update the accumulator optionally accept a state, i.e. an object implementing `IAccumulatorState` which
 * should be updated when the new elements are added or old elements are removed from the accumulator. An additional purpose of passing
 * the state object is to check if duplicate elements are not added or already absent elements are not removed or membership witness
 * for absent elements is not created. If checks in the `state` fail, they throw errors.
 */
export abstract class Accumulator {
  value: Uint8Array | object;
  secretKey: AccumulatorSecretKey | undefined;
  params: AccumulatorParams | undefined;

  /**
   * Construct an accumulator object.
   * @param value - The accumulated value
   * @param sk - The secret key. Is optional.
   * @param params - The params. Is optional.
   */
  constructor({ value, sk, params }: any) {
    if (value === undefined) {
      throw new Error('Needs to pass the accumulated value.');
    }
    this.value = value;
    this.secretKey = sk;
    this.params = params;
  }

  setNew(value: any) {
    this.value = value;
  }

  /**
   * To add arbitrary bytes like byte representation of UUID or some other user id or something else as an accumulator
   * member, encode it first using this. This is an irreversible encoding as a hash function is used to convert a message
   * of arbitrary length to a fixed length encoding.
   * @param bytes
   */
  static encodeBytesAsAccumulatorMember(bytes: Uint8Array): Uint8Array {
    return generateFieldElementFromBytes(bytes);
  }

  /**
   * To add a positive number as an accumulator member, encode it first using this.
   * Encodes a positive integer of at most 4 bytes
   * @param num - should be a positive integer
   */
  static encodePositiveNumberAsAccumulatorMember(num: number): Uint8Array {
    ensurePositiveIntegerOfSize(num, 32);
    return generateFieldElementFromNumber(num);
  }

  /**
   *  Generate accumulator parameters. They are needed to generate public key and initialize the accumulator.
   * @param label - Pass to generate parameters deterministically.
   * @returns
   */
  static generateParams(label?: Uint8Array): AccumulatorParams {
    return AccumulatorParams.generate(label);
  }

  /**
   * Generate secret key for the accumulator manager who updates the accumulator and creates witnesses.
   * @param seed - Pass to generate key deterministically.
   * @returns
   */
  static generateSecretKey(seed?: Uint8Array): AccumulatorSecretKey {
    return AccumulatorSecretKey.generate(seed);
  }

  /**
   * Generate public key from given params and secret key.
   * @param secretKey
   * @param params
   * @returns
   */
  static generatePublicKeyFromSecretKey(
    secretKey: AccumulatorSecretKey,
    params: AccumulatorParams
  ): AccumulatorPublicKey {
    return secretKey.generatePublicKey(params);
  }

  /**
   * Generate private and public key from given params and optional `seed`.
   * @param params
   * @param seed - Pass to generate keys deterministically.
   * @returns
   */
  static generateKeypair(params: AccumulatorParams, seed?: Uint8Array): AccumulatorKeypair {
    return AccumulatorKeypair.generate(params, seed);
  }

  /**
   * Generate proving key for proving membership in an accumulator in zero knowledge. Proving key is
   * public data that must be known to both the prover and verifier. Any prover and verifier pair can mutually agree
   * on a proving key and the manager does not need to be aware of any proving key.
   * @param label - The bytearray that is hashed to deterministically generate the proving key.
   */
  static generateMembershipProvingKey(label?: Uint8Array): MembershipProvingKey {
    return MembershipProvingKey.generate(label);
  }

  /**
   * Generate proving key for proving non-membership in a universal accumulator in zero knowledge.
   * @param label - The bytearray that is hashed to deterministically generate the proving key.
   */
  static generateNonMembershipProvingKey(label?: Uint8Array): NonMembershipProvingKey {
    return NonMembershipProvingKey.generate(label);
  }

  static deriveMembershipKeyFromNonMembershipProvingKey(
    nonMembershipKey: NonMembershipProvingKey
  ): MembershipProvingKey {
    return nonMembershipKey.deriveMembershipProvingKey();
  }

  /**
   * Return the secret key if provided as an argument else look for secret key on `this`.
   * @param secretKey
   * @returns secret key or throws error if cannot find secret key
   */
  protected getSecretKey(secretKey?: AccumulatorSecretKey): AccumulatorSecretKey {
    if (secretKey === undefined) {
      if (this.secretKey === undefined) {
        throw new Error('Secret key needs to be provided');
      }
      return this.secretKey;
    }
    return secretKey;
  }

  /**
   * Return the params if provided as an argument else look for params on `this`.
   * @param params
   * @returns params or throws error if cannot find params
   */
  protected getParams(params?: AccumulatorParams): AccumulatorParams {
    if (params === undefined) {
      if (this.params === undefined) {
        throw new Error('Params needs to be provided');
      }
      return this.params;
    }
    return params;
  }

  /**
   * Get the accumulated value.
   */
  abstract get accumulated(): Uint8Array;

  // The following functions optionally take secret key as an argument as its better to not store secret key in memory for
  // long time.
  // If secret key is not provided, it looks in the object's fields for secret key.

  /**
   * Add a single element to the accumulator
   * @param element - The element to add.
   * @param secretKey - If secret key is not provided, its expected to find the secret key on the object.
   * @param state - If state is provided it is checked before computing the new accumulator and updated with new element after
   * computing the new accumulator. Throws error if element present.
   */
  abstract add(element: Uint8Array, secretKey?: AccumulatorSecretKey, state?: IAccumulatorState): void;

  /**
   * Remove a single element from the accumulator
   * @param element
   * @param secretKey
   * @param state - If state is provided it is checked before computing the new accumulator and element is removed from it after
   * computing the new accumulator. Throws error if element is not present.
   */
  abstract remove(element: Uint8Array, secretKey?: AccumulatorSecretKey, state?: IAccumulatorState): void;

  /**
   * Add a batch of elements to the accumulator.
   * @param elements
   * @param secretKey
   * @param state - If state is provided it is checked before computing the new accumulator and updated with new elements after
   * computing the new accumulator
   */
  abstract addBatch(elements: Uint8Array[], secretKey?: AccumulatorSecretKey, state?: IAccumulatorState): void;

  /**
   * Remove a batch of elements from the accumulator.
   * @param elements
   * @param secretKey
   * @param state - If state is provided it is checked before computing the new accumulator and updated by removing those elements
   * after computing the new accumulator
   */
  abstract removeBatch(elements: Uint8Array[], secretKey?: AccumulatorSecretKey, state?: IAccumulatorState): void;

  /**
   * Add and remove batches of elements.
   * @param additions - The batch to be added
   * @param removals - The batch to be removed.
   * @param secretKey
   * @param state - If state is provided it is checked before computing the new accumulator and updated by adding and
   * removing given elements after computing the new accumulator.
   */
  abstract addRemoveBatches(
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey?: AccumulatorSecretKey,
    state?: IAccumulatorState
  ): void;

  /**
   * Calculate the membership witness for the given element
   * @param element - Whose witness is calculated.
   * @param secretKey
   * @param state - If state is provided it is checked for presence of the element before calculating the witness
   */
  abstract membershipWitness(
    element: Uint8Array,
    secretKey?: AccumulatorSecretKey,
    state?: IAccumulatorState
  ): Promise<MembershipWitness>;

  /**
   * Calculate the membership witnesses for the given batch of elements
   * @param elements - Whose witness is calculated.
   * @param secretKey
   * @param state - If state is provided it is checked for presence of all the elements before calculating the witnesses
   */
  abstract membershipWitnessesForBatch(
    elements: Uint8Array[],
    secretKey?: AccumulatorSecretKey,
    state?: IAccumulatorState
  ): Promise<MembershipWitness[]>;

  /**
   * Verify the membership witness.
   * @param member
   * @param witness
   * @param pk
   * @param params
   */
  abstract verifyMembershipWitness(
    member: Uint8Array,
    witness: MembershipWitness,
    pk: AccumulatorPublicKey,
    params?: AccumulatorParams
  ): boolean;

  /**
   * Check if element is absent in the state and throws an error if its present. Only checks if the state is passed
   * @param element
   * @param state
   * @protected
   */
  protected async ensureAbsence(element: Uint8Array, state?: IAccumulatorState): Promise<void> {
    if (state !== undefined) {
      const isPresent = await state.has(element);
      if (isPresent) {
        throw new Error(`${element} already present`);
      }
    }
  }

  /**
   * Check if element is present in the state and throws an error if its absent. Only checks if the state is passed
   * @param element
   * @param state
   * @protected
   */
  protected async ensurePresence(element: Uint8Array, state?: IAccumulatorState): Promise<void> {
    if (state !== undefined) {
      const isPresent = await state.has(element);
      if (!isPresent) {
        throw new Error(`${element} not present`);
      }
    }
  }

  /**
   * Check if a batch of elements is absent in the state and throws an error any of them is present. Only checks if the state is passed
   * @param elements
   * @param state
   * @protected
   */
  protected async ensureAbsenceOfBatch(elements: Uint8Array[], state?: IAccumulatorState): Promise<void> {
    if (state !== undefined) {
      for (const e of elements) {
        await this.ensureAbsence(e, state);
      }
    }
  }

  /**
   * Check if a batch of elements is present in the state and throws an error any of them is absent. Only checks if the state is passed
   * @param elements
   * @param state
   * @protected
   */
  protected async ensurePresenceOfBatch(elements: Uint8Array[], state?: IAccumulatorState): Promise<void> {
    if (state !== undefined) {
      for (const e of elements) {
        await this.ensurePresence(e, state);
      }
    }
  }

  /**
   * If state is provided, add the element to the state
   * @param element
   * @param state
   * @protected
   */
  protected async addToState(element: Uint8Array, state?: IAccumulatorState): Promise<void> {
    if (state !== undefined) {
      await state.add(element);
    }
  }

  /**
   * If state is provided, remove the element from the state
   * @param element
   * @param state
   * @protected
   */
  protected async removeFromState(element: Uint8Array, state?: IAccumulatorState): Promise<void> {
    if (state !== undefined) {
      await state.remove(element);
    }
  }

  /**
   * If state is provided, add the batch of elements to the state
   * @param elements
   * @param state
   * @protected
   */
  protected async addBatchToState(elements: Uint8Array[], state?: IAccumulatorState): Promise<void> {
    if (state !== undefined) {
      for (const e of elements) {
        await this.addToState(e, state);
      }
    }
  }

  /**
   * If state is provided, remove the batch of elements from the state
   * @param elements
   * @param state
   * @protected
   */
  protected async removeBatchFromState(elements: Uint8Array[], state?: IAccumulatorState): Promise<void> {
    if (state !== undefined) {
      for (const e of elements) {
        await this.removeFromState(e, state);
      }
    }
  }
}

/**
 * Accumulator that supports only membership proofs.
 */
export class PositiveAccumulator extends Accumulator {
  // @ts-ignore
  value: Uint8Array;

  /**
   * Get the current accumulated value
   */
  get accumulated(): Uint8Array {
    return this.value;
  }

  /**
   * Initialize a positive accumulator
   * @param params
   * @param secretKey - Optional. If provided, its stored to do any future updates.
   */
  static initialize(params: AccumulatorParams, secretKey?: AccumulatorSecretKey): PositiveAccumulator {
    const value = positiveAccumulatorInitialize(params.value);
    return new PositiveAccumulator({ value, params, sk: secretKey });
  }

  /**
   * Add a single element to the accumulator
   * @param element
   * @param secretKey
   * @param state - Optional. If provided, checked before adding and updated with the new element
   */
  async add(element: Uint8Array, secretKey?: AccumulatorSecretKey, state?: IAccumulatorState) {
    await this.ensureAbsence(element, state);
    const sk = this.getSecretKey(secretKey);
    this.value = positiveAccumulatorAdd(this.value, element, sk.value);
    await this.addToState(element, state);
  }

  /**
   * Remove a single element from the accumulator
   * @param element
   * @param secretKey
   * @param state- Optional. If provided, checked before removing and element is removed
   */
  async remove(element: Uint8Array, secretKey?: AccumulatorSecretKey, state?: IAccumulatorState) {
    await this.ensurePresence(element, state);
    const sk = this.getSecretKey(secretKey);
    this.value = positiveAccumulatorRemove(this.value, element, sk.value);
    await this.removeFromState(element, state);
  }

  /**
   * Add multiple elements in a batch.
   * @param elements
   * @param secretKey
   * @param state
   */
  async addBatch(elements: Uint8Array[], secretKey?: AccumulatorSecretKey, state?: IAccumulatorState) {
    await this.ensureAbsenceOfBatch(elements, state);
    const sk = this.getSecretKey(secretKey);
    this.value = positiveAccumulatorAddBatch(this.value, elements, sk.value);
    await this.addBatchToState(elements, state);
  }

  /**
   * Remove multiple elements in a batch.
   * @param elements
   * @param secretKey
   * @param state
   */
  async removeBatch(elements: Uint8Array[], secretKey?: AccumulatorSecretKey, state?: IAccumulatorState) {
    await this.ensurePresenceOfBatch(elements, state);
    const sk = this.getSecretKey(secretKey);
    this.value = positiveAccumulatorRemoveBatch(this.value, elements, sk.value);
    await this.removeBatchFromState(elements, state);
  }

  /**
   * Add and remove 1 batch of elements each.
   * @param additions
   * @param removals
   * @param secretKey
   * @param state
   */
  async addRemoveBatches(
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey?: AccumulatorSecretKey,
    state?: IAccumulatorState
  ) {
    await this.ensureAbsenceOfBatch(additions, state);
    await this.ensurePresenceOfBatch(removals, state);
    const sk = this.getSecretKey(secretKey);
    this.value = positiveAccumulatorBatchUpdates(this.value, additions, removals, sk.value);
    await this.addBatchToState(additions, state);
    await this.removeBatchFromState(removals, state);
  }

  /**
   * Create membership witness for a single member.
   * @param member - for which the witness is created.
   * @param secretKey
   * @param state - Optional. If provided, checks that `member` is present in state
   * @returns - Promise that resolves to the membership witness
   */
  async membershipWitness(
    member: Uint8Array,
    secretKey?: AccumulatorSecretKey,
    state?: IAccumulatorState
  ): Promise<MembershipWitness> {
    await this.ensurePresence(member, state);
    const sk = this.getSecretKey(secretKey);
    const wit = positiveAccumulatorMembershipWitness(this.value, member, sk.value);
    return new MembershipWitness(wit);
  }

  /**
   * Create membership witnesses for a batch of members. More efficient than creating witness for 1 member at a time.
   * @param members - array of members for which witnesses need to be creates
   * @param secretKey
   * @param state - Optional. If provided, checks that all `members` are present in state
   * @returns - Promise that resolves to array of membership witnesses
   */
  async membershipWitnessesForBatch(
    members: Uint8Array[],
    secretKey?: AccumulatorSecretKey,
    state?: IAccumulatorState
  ): Promise<MembershipWitness[]> {
    await this.ensurePresenceOfBatch(members, state);
    const sk = this.getSecretKey(secretKey);
    return positiveAccumulatorMembershipWitnessesForBatch(this.value, members, sk.value).map(
      (m) => new MembershipWitness(m)
    );
  }

  /**
   * Verify that membership witness is valid for the member.
   * @param member
   * @param witness
   * @param publicKey
   * @param params
   * @returns - true if witness is valid, false otherwise
   */
  verifyMembershipWitness(
    member: Uint8Array,
    witness: MembershipWitness,
    publicKey: AccumulatorPublicKey,
    params?: AccumulatorParams
  ): boolean {
    const params_ = this.getParams(params);
    return positiveAccumulatorVerifyMembership(this.value, member, witness.value, publicKey.value, params_.value);
  }

  toJSON(): string {
    return JSON.stringify({
      value: Array.from(this.value),
      sk: this.secretKey,
      params: this.params
    });
  }

  static fromJSON(json: string): PositiveAccumulator {
    const obj = JSON.parse(json);
    const [value] = getUint8ArraysFromObject(obj, ['value']);
    return new PositiveAccumulator({ value: value, sk: obj.sk, params: obj.params });
  }

  /**
   * Used by the verifier to create the accumulator.
   * @param accumulated
   */
  static fromAccumulated(accumulated: Uint8Array): PositiveAccumulator {
    return new PositiveAccumulator({ value: accumulated });
  }
}

/**
 * Accumulator that supports both membership proofs and non-membership proofs. For guarding against forgery of
 * non-membership proofs (details in the paper), during initialization, it should generate several accumulator members
 * and never remove them from accumulator, nor it should allow duplicates of them to be added. Thus, several methods
 * accept an optional persistent database `IInitialElementsStore` which stores those initial elements.
 */
export class UniversalAccumulator extends Accumulator {
  /**
   * `f_V` is supposed to kept private by the accumulator manager. `V` is the accumulated value.
   */
  // @ts-ignore
  value: { f_V: Uint8Array; V: Uint8Array; maxSize: number };

  /**
   * Initialize a universal accumulator of the given `maxSize`. The function takes time proportional to `maxSize` as it
   * generates about the same number of elements as the `maxSize` and takes their product in the end. These "initial elements"
   * should not be added or removed from the accumulator.
   * @param maxSize - Maximum members the accumulator can have at any instant.
   * @param params
   * @param secretKey
   * @param initialElementsStore - Optional, stores "initial elements" generated during initialization.
   * @param batchSize - Breaks down this large computation in batches of size `batchSize`.
   */
  static async initialize(
    maxSize: number,
    params: AccumulatorParams,
    secretKey: AccumulatorSecretKey,
    initialElementsStore?: IInitialElementsStore,
    batchSize = 100
  ): Promise<UniversalAccumulator> {
    const storePresent = initialElementsStore !== undefined;

    // store the products of each batch
    const products: Uint8Array[] = [];
    // The first batch of products is the elements fixed for each curve
    const fixed = UniversalAccumulator.fixedInitialElements();
    if (storePresent) {
      for (const i of fixed) {
        await initialElementsStore.add(i);
      }
    }
    products.push(universalAccumulatorComputeInitialFv(fixed, secretKey.value));

    // store a batch of generated elements and take the product once the batch is full
    let currentBatch = [];
    // Accumulate 1 more than the maximum number of allowed members as specified in the paper
    for (let i = 0; i <= maxSize; i++) {
      const e = generateRandomFieldElement();
      currentBatch.push(e);
      if (storePresent) {
        await initialElementsStore.add(e);
      }
      if (currentBatch.length == batchSize) {
        // Batch full, take product
        products.push(universalAccumulatorComputeInitialFv(currentBatch, secretKey.value));
        currentBatch = [];
      }
    }
    if (currentBatch.length > 0) {
      products.push(universalAccumulatorComputeInitialFv(currentBatch, secretKey.value));
    }
    // take the product of the products from each batch
    const product = universalAccumulatorCombineMultipleInitialFv(products);
    return UniversalAccumulator.initializeGivenInitialElementsProduct(maxSize, product, params, secretKey);
  }

  /***
   * Assumes that the initial elements are generated and their product is taken, initialize the accumulator.
   * @param maxSize
   * @param initialElementsProduct
   * @param params
   * @param secretKey
   */
  static initializeGivenInitialElementsProduct(
    maxSize: number,
    initialElementsProduct: Uint8Array,
    params: AccumulatorParams,
    secretKey?: AccumulatorSecretKey
  ): UniversalAccumulator {
    const value = universalAccumulatorInitialiseGivenFv(initialElementsProduct, params.value, maxSize);
    return new UniversalAccumulator({ value, params, sk: secretKey });
  }

  get accumulated(): Uint8Array {
    return this.value.V;
  }

  // The following functions optionally take secret key as an argument as its better to not store secret key in memory for
  // long time.
  // If secret key is not provided, it looks in the object's fields for secret key.

  /**
   * Add a single element to the accumulator
   * @param element - The element to add.
   * @param secretKey - If secret key is not provided, its expected to find the secret key on the object.
   * @param state - If state is provided it is checked before computing the new accumulator and updated with new element after
   * computing the new accumulator. Throws error if element present.
   * @param initialElementsStore - if provided, check that the element is not part of the initial elements, throws error if it is.
   */
  async add(
    element: Uint8Array,
    secretKey?: AccumulatorSecretKey,
    state?: IAccumulatorState,
    initialElementsStore?: IInitialElementsStore
  ) {
    await this.checkBeforeAdd(element, state, initialElementsStore);
    const sk = this.getSecretKey(secretKey);
    this.value = universalAccumulatorAdd(this.value, element, sk.value);
    await this.addToState(element, state);
  }

  /**
   * Remove a single element from the accumulator
   * @param element
   * @param secretKey
   * @param state - If state is provided it is checked before computing the new accumulator and element is removed from it after
   * computing the new accumulator. Throws error if element is not present.
   * @param initialElementsStore - if provided, check that the element is not part of the initial elements, throws error if it is.
   */
  async remove(
    element: Uint8Array,
    secretKey?: AccumulatorSecretKey,
    state?: IAccumulatorState,
    initialElementsStore?: IInitialElementsStore
  ) {
    await this.checkBeforeRemove(element, state, initialElementsStore);
    const sk = this.getSecretKey(secretKey);
    this.value = universalAccumulatorRemove(this.value, element, sk.value);
    await this.removeFromState(element, state);
  }

  async addBatch(
    elements: Uint8Array[],
    secretKey?: AccumulatorSecretKey,
    state?: IAccumulatorState,
    initialElementsStore?: IInitialElementsStore
  ) {
    await this.checkBeforeAddBatch(elements, state, initialElementsStore);
    const sk = this.getSecretKey(secretKey);
    this.value = universalAccumulatorAddBatch(this.value, elements, sk.value);
    await this.addBatchToState(elements, state);
  }

  async removeBatch(
    elements: Uint8Array[],
    secretKey?: AccumulatorSecretKey,
    state?: IAccumulatorState,
    initialElementsStore?: IInitialElementsStore
  ) {
    await this.checkBeforeRemoveBatch(elements, state, initialElementsStore);
    const sk = this.getSecretKey(secretKey);
    this.value = universalAccumulatorRemoveBatch(this.value, elements, sk.value);
    await this.removeBatchFromState(elements, state);
  }

  async addRemoveBatches(
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey?: AccumulatorSecretKey,
    state?: IAccumulatorState,
    initialElementsStore?: IInitialElementsStore
  ) {
    await this.checkBeforeAddBatch(additions, state, initialElementsStore);
    await this.checkBeforeRemoveBatch(removals, state, initialElementsStore);
    const sk = this.getSecretKey(secretKey);
    this.value = universalAccumulatorBatchUpdates(this.value, additions, removals, sk.value);
    await this.addBatchToState(additions, state);
    await this.removeBatchFromState(removals, state);
  }

  async membershipWitness(
    member: Uint8Array,
    secretKey?: AccumulatorSecretKey,
    state?: IAccumulatorState,
    initialElementsStore?: IInitialElementsStore
  ): Promise<MembershipWitness> {
    await this.checkElementAcceptable(member, initialElementsStore);
    await this.ensurePresence(member, state);
    const sk = this.getSecretKey(secretKey);
    const wit = universalAccumulatorMembershipWitness(this.value, member, sk.value);
    return new MembershipWitness(wit);
  }

  async membershipWitnessesForBatch(
    members: Uint8Array[],
    secretKey?: AccumulatorSecretKey,
    state?: IAccumulatorState,
    initialElementsStore?: IInitialElementsStore
  ): Promise<MembershipWitness[]> {
    await this.checkElementBatchAcceptable(members, initialElementsStore);
    await this.ensurePresenceOfBatch(members, state);
    const sk = this.getSecretKey(secretKey);
    return universalAccumulatorMembershipWitnessesForBatch(this.value, members, sk.value).map(
      (m) => new MembershipWitness(m)
    );
  }

  /**
   * Calculate the non-membership witness for the given element. The function takes time proportional to the current
   * size of the accumulator as it takes the product of difference of all members and the non-member. To avoid taking too
   * much memory, it breaks the computation into smaller batches.
   * @param nonMember
   * @param state
   * @param secretKey
   * @param params
   * @param initialElementsStore
   * @param batchSize - Breaks down this large computation in batches of size `batchSize`.
   */
  async nonMembershipWitness(
    nonMember: Uint8Array,
    state: IUniversalAccumulatorState,
    secretKey?: AccumulatorSecretKey,
    params?: AccumulatorParams,
    initialElementsStore?: IInitialElementsStore,
    batchSize = 100
  ): Promise<NonMembershipWitness> {
    await this.checkElementAcceptable(nonMember, initialElementsStore);
    await this.ensureAbsence(nonMember, state);
    const sk = this.getSecretKey(secretKey);
    const params_ = this.getParams(params);
    const members = await state.elements();
    let currentBatch = [];
    const ds: Uint8Array[] = [];
    for (const member of members) {
      currentBatch.push(member);
      if (currentBatch.length == batchSize) {
        ds.push(universalAccumulatorComputeD(nonMember, currentBatch));
        currentBatch = [];
      }
    }
    if (currentBatch.length > 0) {
      ds.push(universalAccumulatorComputeD(nonMember, currentBatch));
    }
    const d = universalAccumulatorCombineMultipleD(ds);
    const wit = universalAccumulatorNonMembershipWitness(this.value, d, nonMember, sk.value, params_.value);
    return new NonMembershipWitness(wit);
  }

  /**
   * Calculate the non-membership witness for the given element when the product of differences of all members and
   * non-member (`d`) is already computed.
   * @param nonMember
   * @param d - the product of difference of all members and the non-member.
   * @param secretKey
   * @param params
   * @param state
   * @param initialElementsStore
   */
  async nonMembershipWitnessGivenD(
    nonMember: Uint8Array,
    d: Uint8Array,
    secretKey?: AccumulatorSecretKey,
    params?: AccumulatorParams,
    state?: IUniversalAccumulatorState,
    initialElementsStore?: IInitialElementsStore
  ): Promise<NonMembershipWitness> {
    await this.checkElementAcceptable(nonMember, initialElementsStore);
    await this.ensureAbsence(nonMember, state);
    const sk = this.getSecretKey(secretKey);
    const params_ = this.getParams(params);
    const wit = universalAccumulatorNonMembershipWitness(this.value, d, nonMember, sk.value, params_.value);
    return new NonMembershipWitness(wit);
  }

  /**
   * Calculate the non-membership witnesses for given batch of elements. The function takes time proportional to the current
   * members and the number of non-members. To avoid taking too much memory, it breaks the computation into smaller batches.
   * @param nonMembers
   * @param secretKey
   * @param params
   * @param state
   * @param initialElementsStore
   * @param batchSize - Breaks down this large computation in batches of size `batchSize`.
   */
  async nonMembershipWitnessesForBatch(
    nonMembers: Uint8Array[],
    state: IUniversalAccumulatorState,
    secretKey?: AccumulatorSecretKey,
    params?: AccumulatorParams,
    initialElementsStore?: IInitialElementsStore,
    batchSize = 100
  ): Promise<NonMembershipWitness[]> {
    await this.checkElementBatchAcceptable(nonMembers, initialElementsStore);
    await this.ensureAbsenceOfBatch(nonMembers, state);
    const sk = this.getSecretKey(secretKey);
    const params_ = this.getParams(params);
    const members = await state.elements();
    let currentBatch = [];
    // store multiple `d`s for each non-member
    const dsForAll: Uint8Array[][] = new Array(nonMembers.length);
    for (const member of members) {
      currentBatch.push(member);
      if (currentBatch.length == batchSize) {
        // Current batch is full, compute `d` for all non-members
        for (let i = 0; i < nonMembers.length; i++) {
          dsForAll[i].push(universalAccumulatorComputeD(nonMembers[i], currentBatch));
        }
        currentBatch = [];
      }
    }
    if (currentBatch.length > 0) {
      for (let i = 0; i < nonMembers.length; i++) {
        dsForAll[i].push(universalAccumulatorComputeD(nonMembers[i], currentBatch));
      }
    }
    const ds: Uint8Array[] = new Array(nonMembers.length);
    for (let i = 0; i < nonMembers.length; i++) {
      // Combine `d`s corresponding to each non-member
      ds[i] = universalAccumulatorCombineMultipleD(dsForAll[i]);
    }
    return universalAccumulatorNonMembershipWitnessesForBatch(this.value, ds, nonMembers, sk.value, params_.value).map(
      (m) => new NonMembershipWitness(m)
    );
  }

  /**
   * Calculate the non-membership witnesses for given batch of elements when the product of differences of all members and
   * non-member (`d`) for each non-member is already computed.
   * @param nonMembers
   * @param d - array of products of difference of all members and each non-member
   * @param secretKey
   * @param params
   * @param state
   * @param initialElementsStore
   */
  async nonMembershipWitnessesForBatchGivenD(
    nonMembers: Uint8Array[],
    d: Uint8Array[],
    secretKey?: AccumulatorSecretKey,
    params?: AccumulatorParams,
    state?: IUniversalAccumulatorState,
    initialElementsStore?: IInitialElementsStore
  ): Promise<NonMembershipWitness[]> {
    await this.checkElementBatchAcceptable(nonMembers, initialElementsStore);
    await this.ensureAbsenceOfBatch(nonMembers, state);
    const sk = this.getSecretKey(secretKey);
    const params_ = this.getParams(params);
    return universalAccumulatorNonMembershipWitnessesForBatch(this.value, d, nonMembers, sk.value, params_.value).map(
      (m) => new NonMembershipWitness(m)
    );
  }

  verifyMembershipWitness(
    member: Uint8Array,
    witness: MembershipWitness,
    pk: AccumulatorPublicKey,
    params?: AccumulatorParams
  ): boolean {
    const params_ = this.getParams(params);
    return universalAccumulatorVerifyMembership(this.value.V, member, witness.value, pk.value, params_.value);
  }

  verifyNonMembershipWitness(
    nonMember: Uint8Array,
    witness: NonMembershipWitness,
    pk: AccumulatorPublicKey,
    params?: AccumulatorParams
  ): boolean {
    const params_ = this.getParams(params);
    return universalAccumulatorVerifyNonMembership(this.value.V, nonMember, witness.value, pk.value, params_.value);
  }

  /**
   * The first few members of a universal accumulator are fixed for each curve. These should be added to the curve
   * before creating any witness and must never be removed.
   */
  static fixedInitialElements(): Uint8Array[] {
    return universalAccumulatorFixedInitialElements();
  }

  /**
   * Takes product of the form `initial_element_i + secret_key`.
   * @param initialElements
   * @param secretKey
   */
  static initialElementsProduct(initialElements: Uint8Array[], secretKey: AccumulatorSecretKey): Uint8Array {
    return universalAccumulatorComputeInitialFv(initialElements, secretKey.value);
  }

  static combineInitialElementsProducts(products: Uint8Array[]): Uint8Array {
    return universalAccumulatorCombineMultipleInitialFv(products);
  }

  static dForNonMembershipWitness(nonMember: Uint8Array, members: Uint8Array[]): Uint8Array {
    return universalAccumulatorComputeD(nonMember, members);
  }

  static dBatchForNonMembershipWitnesses(nonMembers: Uint8Array[], members: Uint8Array[]): Uint8Array[] {
    return universalAccumulatorComputeDForBatch(nonMembers, members);
  }

  /**
   * Throws an error if the element is part of the initial elements given that the initial element store is provided
   * @param element
   * @param store
   */
  async checkElementAcceptable(element: Uint8Array, store?: IInitialElementsStore): Promise<void> {
    if (store !== undefined) {
      const isPresent = await store.has(element);
      if (isPresent) {
        throw new Error(`${element} isn't acceptable`);
      }
    }
  }

  /**
   * Throws an error if any element of the batch is part of the initial elements given that the initial element store is provided
   * @param elements
   * @param store
   */
  async checkElementBatchAcceptable(elements: Uint8Array[], store?: IInitialElementsStore): Promise<void> {
    if (store !== undefined) {
      for (const e of elements) {
        await this.checkElementAcceptable(e, store);
      }
    }
  }

  /**
   * Checks to do before adding a new element
   * @param element
   * @param state
   * @param initialElementsStore
   * @protected
   */
  protected async checkBeforeAdd(
    element: Uint8Array,
    state?: IAccumulatorState,
    initialElementsStore?: IInitialElementsStore
  ): Promise<void> {
    await this.checkElementAcceptable(element, initialElementsStore);
    await super.ensureAbsence(element, state);
  }

  /**
   * Checks to do before removing an existing element
   * @param element
   * @param state
   * @param initialElementsStore
   * @protected
   */
  protected async checkBeforeRemove(
    element: Uint8Array,
    state?: IAccumulatorState,
    initialElementsStore?: IInitialElementsStore
  ): Promise<void> {
    await this.checkElementAcceptable(element, initialElementsStore);
    await super.ensurePresence(element, state);
  }

  /**
   * Checks to do before adding several elements as a batch
   * @param elements
   * @param state
   * @param initialElementsStore
   * @protected
   */
  protected async checkBeforeAddBatch(
    elements: Uint8Array[],
    state?: IAccumulatorState,
    initialElementsStore?: IInitialElementsStore
  ): Promise<void> {
    if (state !== undefined) {
      for (const e of elements) {
        await this.checkElementAcceptable(e, initialElementsStore);
        await super.ensureAbsence(e, state);
      }
    }
  }

  /**
   * Checks to do before removing several elements as a batch
   * @param elements
   * @param state
   * @param initialElementsStore
   * @protected
   */
  protected async checkBeforeRemoveBatch(
    elements: Uint8Array[],
    state?: IAccumulatorState,
    initialElementsStore?: IInitialElementsStore
  ): Promise<void> {
    if (state !== undefined) {
      for (const e of elements) {
        await this.checkElementAcceptable(e, initialElementsStore);
        await super.ensurePresence(e, state);
      }
    }
  }

  toJSON(): string {
    return JSON.stringify({
      value: { f_V: Array.from(this.value.f_V), V: Array.from(this.value.V) },
      sk: this.secretKey,
      params: this.params
    });
  }

  static fromJSON(json: string): UniversalAccumulator {
    const obj = JSON.parse(json);
    const [f_V, V] = getUint8ArraysFromObject(obj.value, ['f_V', 'V']);
    return new UniversalAccumulator({ value: { f_V, V }, sk: obj.sk, params: obj.params });
  }

  static fromAccumulated(accumulated: Uint8Array): UniversalAccumulator {
    return new UniversalAccumulator({ value: { V: accumulated } });
  }
}
