import {
  VerifyResult,
  verifyBDDT16KeyedProof,
  verifyVBAccumMembershipKeyedProof,
  verifyKBUniAccumMembershipKeyedProof,
  verifyKBUniAccumNonMembershipKeyedProof
} from 'crypto-wasm-new';
import { AccumulatorSecretKey } from './accumulator';
import { BBDT16MacSecretKey } from './bbdt16-mac';
import { BytearrayWrapper } from './bytearray-wrapper';

/**
 * Keyed proof of BBDT16 MAC.
 */
export class BBDT16KeyedProof extends BytearrayWrapper {
  verify(secretKey: BBDT16MacSecretKey): VerifyResult {
    return verifyBDDT16KeyedProof(this.value, secretKey.value);
  }
}

/**
 * Keyed proof of membership in keyed-verification of VB accumulator.
 */
export class VBAccumMembershipKeyedProof extends BytearrayWrapper {
  verify(secretKey: AccumulatorSecretKey): VerifyResult {
    return verifyVBAccumMembershipKeyedProof(this.value, secretKey.value);
  }
}

/**
 * Keyed proof of membership in keyed-verification of KB universal accumulator.
 */
export class KBUniAccumMembershipKeyedProof extends BytearrayWrapper {
  verify(secretKey: AccumulatorSecretKey): VerifyResult {
    return verifyKBUniAccumMembershipKeyedProof(this.value, secretKey.value);
  }
}

/**
 * Keyed proof of non-membership in keyed-verification of KB universal accumulator.
 */
export class KBUniAccumNonMembershipKeyedProof extends BytearrayWrapper {
  verify(secretKey: AccumulatorSecretKey): VerifyResult {
    return verifyKBUniAccumNonMembershipKeyedProof(this.value, secretKey.value);
  }
}
