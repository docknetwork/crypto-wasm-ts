import {
  IKBUniversalAccumulator,
  kbUniversalAccumulatorAdd,
  kbUniversalAccumulatorAddBatch,
  kbUniversalAccumulatorBatchUpdates,
  kbUniversalAccumulatorComputeExtended,
  kbUniversalAccumulatorInitialise,
  kbUniversalAccumulatorMembershipWitness,
  kbUniversalAccumulatorMembershipWitnessesForBatch,
  kbUniversalAccumulatorNonMembershipWitness,
  kbUniversalAccumulatorNonMembershipWitnessesForBatch,
  kbUniversalAccumulatorRemove,
  kbUniversalAccumulatorRemoveBatch,
  kbUniversalAccumulatorVerifyMembership,
  kbUniversalAccumulatorVerifyNonMembership,
  kbUpdateBothWitnessesPostBatchUpdates,
  publicInfoForBothKBUniversalWitnessUpdate,
  publicInfoForKBUniversalMemWitnessUpdate,
  publicInfoForKBUniversalNonMemWitnessUpdate,
  publicInfoForKBUniversalNonMemWitnessUpdateOnDomainExtension
} from 'crypto-wasm-new';
import { Accumulator } from './accumulator';
import { IKBUniversalAccumulatorState } from './IAccumulatorState';
import { KBUniversalMembershipWitness, KBUniversalNonMembershipWitness } from './kb-acccumulator-witness';
import { AccumulatorParams, AccumulatorPublicKey, AccumulatorSecretKey } from './params-and-keys';
import {
  KBUniversalMembershipWitnessUpdateInfo,
  KBUniversalNonMembershipWitnessUpdateInfo
} from './witness-update-info';

/**
 * KB universal accumulator. Its composed of 2 accumulators, one for accumulating elements that are "members" and one
 * for "non-members". But this detail is largely abstracted away. All possible "members" and "non-members" of this
 * accumulator are called its domain and during initialization, the domain needs to be known/passed. The domain can be
 * extended at any point and any number of times.
 */
export class KBUniversalAccumulator extends Accumulator<KBUniversalAccumulatorValue> {
  // @ts-ignore
  value: KBUniversalAccumulatorValue;

  /**
   *
   * @param domain - All possible members or non-members of this accumulator
   * @param params
   * @param secretKey
   * @param state
   */
  static async initialize(
    domain: Uint8Array[],
    params: AccumulatorParams,
    secretKey: AccumulatorSecretKey,
    state?: IKBUniversalAccumulatorState
  ): Promise<KBUniversalAccumulator> {
    const v = kbUniversalAccumulatorInitialise(domain, secretKey.value, params.value);
    const acc = new KBUniversalAccumulator({
      value: new KBUniversalAccumulatorValue(v.mem, v.non_mem),
      sk: secretKey,
      params
    });
    if (state) {
      for (const d of domain) {
        await state.addToDomain(d);
      }
    }
    return acc;
  }

  /**
   * Extend the domain
   * @param newElements - Add these elements to the domain. These should not be part of the domain
   * @param secretKey
   * @param state
   */
  async extend(newElements: Uint8Array[], secretKey: AccumulatorSecretKey, state?: IKBUniversalAccumulatorState) {
    if (state !== undefined) {
      for (const e of newElements) {
        const r = await state.inDomain(e);
        if (r) {
          throw new Error(`Element ${e} already part of domain`);
        }
      }
    }
    this.value = KBUniversalAccumulatorValue.fromInternalType(
      kbUniversalAccumulatorComputeExtended(this.value.asInternalType, newElements, secretKey.value)
    );
    if (state) {
      for (const d of newElements) {
        await state.addToDomain(d);
      }
    }
  }

  get accumulated(): KBUniversalAccumulatorValue {
    return this.value;
  }

  static fromAccumulated(accumulated: KBUniversalAccumulatorValue): KBUniversalAccumulator {
    return new KBUniversalAccumulator({ value: accumulated });
  }

  async add(element: Uint8Array, secretKey?: AccumulatorSecretKey, state?: IKBUniversalAccumulatorState) {
    await this.checkBeforeAdd(element, state);
    const sk = this.getSecretKey(secretKey);
    this.value = KBUniversalAccumulatorValue.fromInternalType(
      kbUniversalAccumulatorAdd(this.value.asInternalType, element, sk.value)
    );
    await this.addToState(element, state);
  }

  async addBatch(elements: Uint8Array[], secretKey?: AccumulatorSecretKey, state?: IKBUniversalAccumulatorState) {
    await this.checkBeforeAddBatch(elements, state);
    const sk = this.getSecretKey(secretKey);
    this.value = KBUniversalAccumulatorValue.fromInternalType(
      kbUniversalAccumulatorAddBatch(this.value.asInternalType, elements, sk.value)
    );
    await this.addBatchToState(elements, state);
  }

  async addRemoveBatches(
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey?: AccumulatorSecretKey,
    state?: IKBUniversalAccumulatorState
  ) {
    await this.checkBeforeAddBatch(additions, state);
    await this.ensurePresenceOfBatch(removals, state);
    const sk = this.getSecretKey(secretKey);
    this.value = KBUniversalAccumulatorValue.fromInternalType(
      kbUniversalAccumulatorBatchUpdates(this.value.asInternalType, additions, removals, sk.value)
    );
    await this.addBatchToState(additions, state);
    await this.removeBatchFromState(removals, state);
  }

  async membershipWitness(
    member: Uint8Array,
    secretKey?: AccumulatorSecretKey,
    state?: IKBUniversalAccumulatorState
  ): Promise<KBUniversalMembershipWitness> {
    await this.ensurePresence(member, state);
    const sk = this.getSecretKey(secretKey);
    const wit = kbUniversalAccumulatorMembershipWitness(this.value.asInternalType, member, sk.value);
    return new KBUniversalMembershipWitness(wit);
  }

  async nonMembershipWitness(
    nonMember: Uint8Array,
    secretKey?: AccumulatorSecretKey,
    state?: IKBUniversalAccumulatorState
  ): Promise<KBUniversalNonMembershipWitness> {
    await this.ensureAbsence(nonMember, state);
    const sk = this.getSecretKey(secretKey);
    const wit = kbUniversalAccumulatorNonMembershipWitness(this.value.asInternalType, nonMember, sk.value);
    return new KBUniversalNonMembershipWitness(wit);
  }

  async membershipWitnessesForBatch(
    members: Uint8Array[],
    secretKey?: AccumulatorSecretKey,
    state?: IKBUniversalAccumulatorState
  ): Promise<KBUniversalMembershipWitness[]> {
    await this.ensurePresenceOfBatch(members, state);
    const sk = this.getSecretKey(secretKey);
    return kbUniversalAccumulatorMembershipWitnessesForBatch(this.value.asInternalType, members, sk.value).map(
      (m) => new KBUniversalMembershipWitness(m)
    );
  }

  async nonMembershipWitnessesForBatch(
    nonMembers: Uint8Array[],
    secretKey?: AccumulatorSecretKey,
    state?: IKBUniversalAccumulatorState
  ): Promise<KBUniversalNonMembershipWitness[]> {
    await this.ensureAbsenceOfBatch(nonMembers, state);
    const sk = this.getSecretKey(secretKey);
    return kbUniversalAccumulatorNonMembershipWitnessesForBatch(this.value.asInternalType, nonMembers, sk.value).map(
      (m) => new KBUniversalNonMembershipWitness(m)
    );
  }

  async remove(element: Uint8Array, secretKey?: AccumulatorSecretKey, state?: IKBUniversalAccumulatorState) {
    await this.ensurePresence(element, state);
    const sk = this.getSecretKey(secretKey);
    this.value = KBUniversalAccumulatorValue.fromInternalType(
      kbUniversalAccumulatorRemove(this.value.asInternalType, element, sk.value)
    );
    await this.removeFromState(element, state);
  }

  async removeBatch(elements: Uint8Array[], secretKey?: AccumulatorSecretKey, state?: IKBUniversalAccumulatorState) {
    await this.ensurePresenceOfBatch(elements, state);
    const sk = this.getSecretKey(secretKey);
    this.value = KBUniversalAccumulatorValue.fromInternalType(
      kbUniversalAccumulatorRemoveBatch(this.value.asInternalType, elements, sk.value)
    );
    await this.removeBatchFromState(elements, state);
  }

  verifyMembershipWitness(
    member: Uint8Array,
    witness: KBUniversalMembershipWitness,
    pk: AccumulatorPublicKey,
    params?: AccumulatorParams
  ): boolean {
    const params_ = this.getParams(params);
    return kbUniversalAccumulatorVerifyMembership(
      this.value.asInternalType,
      member,
      witness.value,
      pk.value,
      params_.value
    );
  }

  verifyNonMembershipWitness(
    nonMember: Uint8Array,
    witness: KBUniversalNonMembershipWitness,
    pk: AccumulatorPublicKey,
    params?: AccumulatorParams
  ): boolean {
    const params_ = this.getParams(params);
    return kbUniversalAccumulatorVerifyNonMembership(
      this.value.asInternalType,
      nonMember,
      witness.value,
      pk.value,
      params_.value
    );
  }

  updateMultipleMemberAndNonMemberWitnessesPostBatchUpdates(
    memWitnesses: KBUniversalMembershipWitness[],
    members: Uint8Array[],
    nonMemWitnesses: KBUniversalMembershipWitness[],
    nonMembers: Uint8Array[],
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey?: AccumulatorSecretKey
  ): [KBUniversalMembershipWitness[], KBUniversalNonMembershipWitness[]] {
    const m = memWitnesses.map((m) => m.value);
    const nm = nonMemWitnesses.map((m) => m.value);
    const sk = this.getSecretKey(secretKey);
    const [mw, nmw] = kbUpdateBothWitnessesPostBatchUpdates(
      m,
      members,
      nm,
      nonMembers,
      additions,
      removals,
      this.value.asInternalType,
      sk.value
    );
    return [mw.map((v) => new KBUniversalMembershipWitness(v)), nmw.map((v) => new KBUniversalNonMembershipWitness(v))];
  }

  witnessUpdateInfoForMembershipWitness(
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey?: AccumulatorSecretKey
  ): KBUniversalMembershipWitnessUpdateInfo {
    const sk = this.getSecretKey(secretKey);
    return new KBUniversalMembershipWitnessUpdateInfo(
      publicInfoForKBUniversalMemWitnessUpdate(this.value.asInternalType, additions, removals, sk.value)
    );
  }

  witnessUpdateInfoForNonMembershipWitness(
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey?: AccumulatorSecretKey
  ): KBUniversalNonMembershipWitnessUpdateInfo {
    const sk = this.getSecretKey(secretKey);
    return new KBUniversalNonMembershipWitnessUpdateInfo(
      publicInfoForKBUniversalNonMemWitnessUpdate(this.value.asInternalType, additions, removals, sk.value)
    );
  }

  witnessUpdateInfoForNonMembershipWitnessAfterDomainExtension(
    newElements: Uint8Array[],
    secretKey?: AccumulatorSecretKey
  ): KBUniversalNonMembershipWitnessUpdateInfo {
    const sk = this.getSecretKey(secretKey);
    return new KBUniversalNonMembershipWitnessUpdateInfo(
      publicInfoForKBUniversalNonMemWitnessUpdateOnDomainExtension(this.value.asInternalType, newElements, sk.value)
    );
  }

  witnessUpdateInfoForBothWitnessTypes(
    additions: Uint8Array[],
    removals: Uint8Array[],
    secretKey?: AccumulatorSecretKey
  ): [KBUniversalMembershipWitnessUpdateInfo, KBUniversalNonMembershipWitnessUpdateInfo] {
    const sk = this.getSecretKey(secretKey);
    const [m, nm] = publicInfoForBothKBUniversalWitnessUpdate(this.value.asInternalType, additions, removals, sk.value);
    return [new KBUniversalMembershipWitnessUpdateInfo(m), new KBUniversalNonMembershipWitnessUpdateInfo(nm)];
  }

  protected async checkBeforeAdd(element: Uint8Array, state?: IKBUniversalAccumulatorState) {
    await this.checkElementAcceptable(element, state);
    await this.ensureAbsence(element, state);
  }

  protected async checkBeforeAddBatch(elements: Uint8Array[], state?: IKBUniversalAccumulatorState) {
    await this.checkElementsAcceptable(elements, state);
    await this.ensureAbsenceOfBatch(elements, state);
  }

  async checkElementAcceptable(element: Uint8Array, state?: IKBUniversalAccumulatorState): Promise<void> {
    if (state !== undefined) {
      const valid = await state.inDomain(element);
      if (!valid) {
        throw new Error(`${element} isn't acceptable`);
      }
    }
  }

  async checkElementsAcceptable(elements: Uint8Array[], state?: IKBUniversalAccumulatorState): Promise<void> {
    if (state) {
      for (const element of elements) {
        await this.checkElementAcceptable(element, state);
      }
    }
  }
}

/**
 * Value of KB universal accumulator
 */
export class KBUniversalAccumulatorValue {
  // Value of the accumulator accumulating members
  mem: Uint8Array;
  // Value of the accumulator accumulating non-members
  nonMem: Uint8Array;

  constructor(mem: Uint8Array, nonMem: Uint8Array) {
    this.mem = mem;
    this.nonMem = nonMem;
  }

  /**
   * Object expected by wasm. Used when calling wasm functions
   */
  get asInternalType(): IKBUniversalAccumulator {
    return {
      mem: this.mem,
      non_mem: this.nonMem
    };
  }

  static fromInternalType(o: IKBUniversalAccumulator): KBUniversalAccumulatorValue {
    return new KBUniversalAccumulatorValue(o.mem, o.non_mem);
  }

  toBytes(): Uint8Array {
    const merged = new Uint8Array(this.mem.length + this.nonMem.length);
    merged.set(this.mem);
    merged.set(this.nonMem, this.mem.length);
    return merged;
  }

  static fromBytes(bytes: Uint8Array): KBUniversalAccumulatorValue {
    // Create 2 Uint8Array from this hex. The 2 are guaranteed to be of the same length
    const mem = bytes.subarray(0, bytes.length / 2);
    const nonMem = bytes.subarray(bytes.length / 2);
    return new KBUniversalAccumulatorValue(mem, nonMem);
  }
}
