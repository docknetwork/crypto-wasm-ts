import {
  publicInfoForWitnessUpdate,
  publicInfoForKBUniversalMemWitnessUpdate,
  publicInfoForKBUniversalNonMemWitnessUpdate, publicInfoForKBUniversalNonMemWitnessUpdateOnDomainExtension
} from 'crypto-wasm-new';
import { BytearrayWrapper } from '../bytearray-wrapper';
import { fromLeToBigInt, jsonObjToUint8Array } from '../util';
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
 * Public info published by the VB accumulator manager used to update witnesses after several additions and removals.
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

/**
 * Public info published by the KB universal accumulator manager used to update non-membership witnesses after several additions and removals.
 */
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

/**
 * Public info published by the KB universal accumulator manager used to update membership and non-membership witnesses after several additions and removals.
 */
export class KBUniversalWitnessUpdateInfo {
  readonly mem?: KBUniversalMembershipWitnessUpdateInfo;
  readonly nonMem?: KBUniversalNonMembershipWitnessUpdateInfo;
  // Maximum size in bytes of the membership witness update info can be `2^maxByteSize`
  static readonly maxByteSize = 4;
  static readonly maxLength = BigInt(1) << BigInt(32);

  constructor(mem?: KBUniversalMembershipWitnessUpdateInfo, nonMem?: KBUniversalNonMembershipWitnessUpdateInfo) {
    this.mem = mem;
    this.nonMem = nonMem;
  }

  /**
   * Returns a bytearray containing both the membership and non-membership witness update info. The first `maxByteSize` byte
   * of the result contains the byte size of the membership witness update info. This is followed by the bytes of membership
   * witness update info, followed by the bytes of non-membership witness update info.
   */
  toBytes(): Uint8Array {
    const memLength = this.mem ? this.mem.value.length : 0;
    if (memLength > KBUniversalWitnessUpdateInfo.maxLength) {
      throw new Error(`Cannot support sizes greater than ${KBUniversalWitnessUpdateInfo.maxLength}`)
    }
    const buf = Buffer.allocUnsafe(KBUniversalWitnessUpdateInfo.maxByteSize + memLength + (this.nonMem ? this.nonMem.value.length : 0));
    // Write the byte size of membership witness update info in the first `maxByteSize` bytes in little-endian format
    buf.writeUIntLE(memLength, 0, KBUniversalWitnessUpdateInfo.maxByteSize);
    const merged = new Uint8Array(buf);
    if (this.mem) {
      merged.set(this.mem.value, KBUniversalWitnessUpdateInfo.maxByteSize);
    }
    if (this.nonMem) {
      merged.set(this.nonMem.value, KBUniversalWitnessUpdateInfo.maxByteSize + memLength);
    }
    return merged;
  }

  /**
   * Creates `KBUniversalWitnessUpdateInfo` from its byte representation
   * @param bytes - This is the result of `KBUniversalWitnessUpdateInfo.toBytes`
   */
  static fromBytes(bytes: Uint8Array): KBUniversalWitnessUpdateInfo {
    const memLength = fromLeToBigInt(bytes, KBUniversalWitnessUpdateInfo.maxByteSize);
    if (memLength > KBUniversalWitnessUpdateInfo.maxLength) {
      throw new Error(`Cannot support sizes greater than ${KBUniversalWitnessUpdateInfo.maxLength}`)
    }
    // Create the update info if non-zero byte size found
    const mem = memLength > 0 ? new KBUniversalMembershipWitnessUpdateInfo(bytes.slice(KBUniversalWitnessUpdateInfo.maxByteSize, KBUniversalWitnessUpdateInfo.maxByteSize + Number(memLength))) : undefined;
    const nonMemVal = bytes.slice(KBUniversalWitnessUpdateInfo.maxByteSize + Number(memLength));
    const nonMem = nonMemVal.length > 0 ? new KBUniversalNonMembershipWitnessUpdateInfo(nonMemVal) : undefined;
    return new KBUniversalWitnessUpdateInfo(mem, nonMem);
  }
}
