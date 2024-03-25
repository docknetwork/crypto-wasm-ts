import {
  VerifyResult,
  verifyBDDT16DelegatedProof,
  verifyVBAccumMembershipDelegatedProof,
  verifyKBUniAccumMembershipDelegatedProof,
  verifyKBUniAccumNonMembershipDelegatedProof
} from 'crypto-wasm-new';
import { AccumulatorSecretKey } from './accumulator';
import { BDDT16MacSecretKey } from './bddt16-mac';
import { BytearrayWrapper } from './bytearray-wrapper';

/**
 * Delegated proof of BDDT16 MAC.
 */
export class BDDT16DelegatedProof extends BytearrayWrapper {
  verify(secretKey: BDDT16MacSecretKey): VerifyResult {
    return verifyBDDT16DelegatedProof(this.value, secretKey.value);
  }
}

/**
 * Delegated proof of membership in keyed-verification of VB accumulator.
 */
export class VBAccumMembershipDelegatedProof extends BytearrayWrapper {
  verify(secretKey: AccumulatorSecretKey): VerifyResult {
    return verifyVBAccumMembershipDelegatedProof(this.value, secretKey.value);
  }
}

/**
 * Delegated proof of membership in keyed-verification of KB universal accumulator.
 */
export class KBUniAccumMembershipDelegatedProof extends BytearrayWrapper {
  verify(secretKey: AccumulatorSecretKey): VerifyResult {
    return verifyKBUniAccumMembershipDelegatedProof(this.value, secretKey.value);
  }
}

/**
 * Delegated proof of non-membership in keyed-verification of KB universal accumulator.
 */
export class KBUniAccumNonMembershipDelegatedProof extends BytearrayWrapper {
  verify(secretKey: AccumulatorSecretKey): VerifyResult {
    return verifyKBUniAccumNonMembershipDelegatedProof(this.value, secretKey.value);
  }
}
