import {
  kbUniversalUpdateMembershipWitnessPostAdd,
  kbUniversalUpdateMembershipWitnessPostRemove,
  kbUniversalUpdateNonMembershipWitnessPostAdd,
  kbUniversalUpdateNonMembershipWitnessPostRemove,
  kbUpdateMembershipWitnessesPostBatchUpdates,
  kbUpdateNonMembershipWitnessesPostBatchUpdates,
  kbUpdateNonMembershipWitnessesPostDomainExtension,
  updateKBUniversalMembershipWitnessUsingPublicInfoAfterBatchUpdate,
  updateKBUniversalMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates,
  updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterBatchUpdate,
  updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterDomainExtension,
  updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates,
  updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterMultipleDomainExtensions
} from 'crypto-wasm-new';
import { getUint8ArraysFromObject } from '../util';
import { AccumulatorWitness } from './accumulatorWitness';
import { KBUniversalAccumulatorValue } from './kb-universal-accumulator';
import { AccumulatorSecretKey } from './params-and-keys';
import {
  KBUniversalMembershipWitnessUpdateInfo,
  KBUniversalNonMembershipWitnessUpdateInfo
} from './witness-update-info';

export class KBUniversalMembershipWitness extends AccumulatorWitness<KBUniversalAccumulatorValue> {
  // @ts-ignore
  value: Uint8Array;

  updatePostAdd(addition: Uint8Array, member: Uint8Array, accumulatorValueBeforeAddition: KBUniversalAccumulatorValue) {
    this.value = kbUniversalUpdateMembershipWitnessPostAdd(
      this.value,
      member,
      addition,
      accumulatorValueBeforeAddition.asInternalType
    );
  }

  updatePostRemove(removal: Uint8Array, member: Uint8Array, accumulatorValueAfterRemoval: KBUniversalAccumulatorValue) {
    this.value = kbUniversalUpdateMembershipWitnessPostRemove(
      this.value,
      member,
      removal,
      accumulatorValueAfterRemoval.asInternalType
    );
  }

  static updateMultiplePostBatchUpdates(
    witnesses: KBUniversalMembershipWitness[],
    members: Uint8Array[],
    additions: Uint8Array[],
    removals: Uint8Array[],
    accumulatorValueBeforeUpdates: KBUniversalAccumulatorValue,
    secretKey: AccumulatorSecretKey
  ): KBUniversalMembershipWitness[] {
    const wits = witnesses.map((m) => m.value);
    return kbUpdateMembershipWitnessesPostBatchUpdates(
      wits,
      members,
      additions,
      removals,
      accumulatorValueBeforeUpdates.asInternalType,
      secretKey.value
    ).map((m) => new KBUniversalMembershipWitness(m));
  }

  updateUsingPublicInfoPostBatchUpdate(
    member: Uint8Array,
    additions: Uint8Array[],
    removals: Uint8Array[],
    publicInfo: KBUniversalMembershipWitnessUpdateInfo
  ) {
    this.value = updateKBUniversalMembershipWitnessUsingPublicInfoAfterBatchUpdate(
      this.value,
      member,
      additions,
      removals,
      publicInfo.value
    );
  }

  updateUsingPublicInfoPostMultipleBatchUpdates(
    member: Uint8Array,
    additions: Uint8Array[][],
    removals: Uint8Array[][],
    publicInfo: KBUniversalMembershipWitnessUpdateInfo[]
  ) {
    this.value = updateKBUniversalMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(
      this.value,
      member,
      additions,
      removals,
      publicInfo.map((i) => i.value)
    );
  }

  toJSON(): string {
    return JSON.stringify({
      value: Array.from(this.value)
    });
  }

  static fromJSON(json: string): KBUniversalMembershipWitness {
    const obj = JSON.parse(json);
    const [value] = getUint8ArraysFromObject(obj, ['value']);
    return new KBUniversalMembershipWitness(value);
  }
}

export class KBUniversalNonMembershipWitness extends AccumulatorWitness<KBUniversalAccumulatorValue> {
  // @ts-ignore
  value: Uint8Array;

  updatePostAdd(
    addition: Uint8Array,
    nonMember: Uint8Array,
    accumulatorValueBeforeAddition: KBUniversalAccumulatorValue
  ) {
    this.value = kbUniversalUpdateNonMembershipWitnessPostAdd(
      this.value,
      nonMember,
      addition,
      accumulatorValueBeforeAddition.asInternalType
    );
  }

  updatePostRemove(
    removal: Uint8Array,
    nonMember: Uint8Array,
    accumulatorValueAfterRemoval: KBUniversalAccumulatorValue
  ) {
    this.value = kbUniversalUpdateNonMembershipWitnessPostRemove(
      this.value,
      nonMember,
      removal,
      accumulatorValueAfterRemoval.asInternalType
    );
  }

  static updateMultiplePostBatchUpdates(
    witnesses: KBUniversalNonMembershipWitness[],
    members: Uint8Array[],
    additions: Uint8Array[],
    removals: Uint8Array[],
    accumulatorValueBeforeUpdates: KBUniversalAccumulatorValue,
    secretKey: AccumulatorSecretKey
  ): KBUniversalNonMembershipWitness[] {
    const wits = witnesses.map((m) => m.value);
    return kbUpdateNonMembershipWitnessesPostBatchUpdates(
      wits,
      members,
      additions,
      removals,
      accumulatorValueBeforeUpdates.asInternalType,
      secretKey.value
    ).map((m) => new KBUniversalNonMembershipWitness(m));
  }

  static updateMultiplePostDomainExtension(
    witnesses: KBUniversalNonMembershipWitness[],
    members: Uint8Array[],
    newElements: Uint8Array[],
    accumulatorValueBeforeUpdates: KBUniversalAccumulatorValue,
    secretKey: AccumulatorSecretKey
  ): KBUniversalNonMembershipWitness[] {
    const wits = witnesses.map((m) => m.value);
    return kbUpdateNonMembershipWitnessesPostDomainExtension(
      wits,
      members,
      newElements,
      accumulatorValueBeforeUpdates.asInternalType,
      secretKey.value
    ).map((m) => new KBUniversalNonMembershipWitness(m));
  }

  updateUsingPublicInfoPostBatchUpdate(
    nonMember: Uint8Array,
    additions: Uint8Array[],
    removals: Uint8Array[],
    publicInfo: KBUniversalNonMembershipWitnessUpdateInfo
  ): void {
    this.value = updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterBatchUpdate(
      this.value,
      nonMember,
      additions,
      removals,
      publicInfo.value
    );
  }

  updateUsingPublicInfoPostMultipleBatchUpdates(
    nonMember: Uint8Array,
    additions: Uint8Array[][],
    removals: Uint8Array[][],
    publicInfo: KBUniversalNonMembershipWitnessUpdateInfo[]
  ): void {
    this.value = updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(
      this.value,
      nonMember,
      additions,
      removals,
      publicInfo.map((i) => i.value)
    );
  }

  updateUsingPublicInfoPostDomainExtension(
    nonMember: Uint8Array,
    newElements: Uint8Array[],
    publicInfo: KBUniversalNonMembershipWitnessUpdateInfo
  ): void {
    this.value = updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterDomainExtension(
      this.value,
      nonMember,
      newElements,
      publicInfo.value
    );
  }

  updateUsingPublicInfoPostMultipleDomainExtensions(
    nonMember: Uint8Array,
    newElements: Uint8Array[][],
    publicInfo: KBUniversalNonMembershipWitnessUpdateInfo[]
  ): void {
    this.value = updateKBUniversalNonMembershipWitnessUsingPublicInfoAfterMultipleDomainExtensions(
      this.value,
      nonMember,
      newElements,
      publicInfo.map((i) => i.value)
    );
  }
}
