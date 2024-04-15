import {
  publicInfoForWitnessUpdate,
  publicInfoForKBUniversalMemWitnessUpdate,
  publicInfoForKBUniversalNonMemWitnessUpdate, publicInfoForKBUniversalNonMemWitnessUpdateOnDomainExtension
} from 'crypto-wasm-new';
import { BytearrayWrapper } from '../bytearray-wrapper';
import { jsonObjToUint8Array } from '../util';
import { KBUniversalAccumulatorValue } from './kb-universal-accumulator';
import { AccumulatorSecretKey } from './params-and-keys';

export class WitnessUpdateInfo extends BytearrayWrapper {
  toJSON(): string {
    return JSON.stringify({
      value: this.value
    });
  }
}

/**
 * Public info published by the accumulator manager used to update witnesses after several additions and removals.
 */
export class VBWitnessUpdateInfo extends WitnessUpdateInfo {
  fromJSON(json: string): VBWitnessUpdateInfo {
    return new VBWitnessUpdateInfo(jsonObjToUint8Array(json));
  }

  /**
   * Accumulator manager creates the witness update info corresponding to the additions and removals.
   * @param accumulatorValueBeforeUpdates - accumulator value before the additions and removals
   * @param additions
   * @param removals
   * @param sk
   */
  static new(
    accumulatorValueBeforeUpdates: Uint8Array,
    additions: Uint8Array[],
    removals: Uint8Array[],
    sk: AccumulatorSecretKey
  ): VBWitnessUpdateInfo {
    const value = publicInfoForWitnessUpdate(accumulatorValueBeforeUpdates, additions, removals, sk.value);
    return new VBWitnessUpdateInfo(value);
  }
}

export class KBUniversalMembershipWitnessUpdateInfo extends WitnessUpdateInfo {
  fromJSON(json: string): KBUniversalMembershipWitnessUpdateInfo {
    return new KBUniversalMembershipWitnessUpdateInfo(jsonObjToUint8Array(json));
  }

  /**
   * Accumulator manager creates the membership witness update info corresponding to the additions and removals.
   * @param accumulatorValueBeforeUpdates
   * @param additions
   * @param removals
   * @param sk
   */
  static new(
    accumulatorValueBeforeUpdates: KBUniversalAccumulatorValue,
    additions: Uint8Array[],
    removals: Uint8Array[],
    sk: AccumulatorSecretKey
  ): KBUniversalMembershipWitnessUpdateInfo {
    return new KBUniversalMembershipWitnessUpdateInfo(
      publicInfoForKBUniversalMemWitnessUpdate(
        accumulatorValueBeforeUpdates.asInternalType,
        additions,
        removals,
        sk.value
      )
    );
  }
}

export class KBUniversalNonMembershipWitnessUpdateInfo extends WitnessUpdateInfo {
  fromJSON(json: string): KBUniversalNonMembershipWitnessUpdateInfo {
    return new KBUniversalNonMembershipWitnessUpdateInfo(jsonObjToUint8Array(json));
  }

  /**
   * Accumulator manager creates the non-membership witness update info corresponding to the additions and removals.
   * @param accumulatorValueBeforeUpdates
   * @param additions
   * @param removals
   * @param sk
   */
  static new(
    accumulatorValueBeforeUpdates: KBUniversalAccumulatorValue,
    additions: Uint8Array[],
    removals: Uint8Array[],
    sk: AccumulatorSecretKey
  ): KBUniversalNonMembershipWitnessUpdateInfo {
    return new KBUniversalNonMembershipWitnessUpdateInfo(
      publicInfoForKBUniversalNonMemWitnessUpdate(
        accumulatorValueBeforeUpdates.asInternalType,
        additions,
        removals,
        sk.value
      )
    );
  }

  /**
   * Accumulator manager creates the non-membership witness update info corresponding to the domain extension.
   * @param accumulatorValueBeforeExtension
   * @param newElements - the elements with which the domain was extended
   * @param sk
   */
  static newAfterDomainExtension(
    accumulatorValueBeforeExtension: KBUniversalAccumulatorValue,
    newElements: Uint8Array[],
    sk: AccumulatorSecretKey
  ): KBUniversalNonMembershipWitnessUpdateInfo {
    return new KBUniversalNonMembershipWitnessUpdateInfo(
      publicInfoForKBUniversalNonMemWitnessUpdateOnDomainExtension(
        accumulatorValueBeforeExtension.asInternalType,
        newElements,
        sk.value
      )
    );
  }
}
