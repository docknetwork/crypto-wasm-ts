import { VerifyResult, verifyBDDT16DelegatedProof, verifyVBAccumMembershipDelegatedProof } from 'crypto-wasm-new';
import { AccumulatorSecretKey } from './accumulator';
import { BDDT16MacSecretKey } from './bddt16-mac';
import { BytearrayWrapper } from './bytearray-wrapper';

/**
 * Delegated proof of BDDT16 MAC.
 */
export class BDDT16DelegatedProof extends BytearrayWrapper {
  verify(secretKey: BDDT16MacSecretKey): VerifyResult {
    return verifyBDDT16DelegatedProof(this.value, secretKey.value)
  }
}

/**
 * Delegated proof of membership in keyed-verification of VB accumulator.
 */
export class VBAccumMembershipDelegatedProof extends BytearrayWrapper {
  verify(secretKey: AccumulatorSecretKey): VerifyResult {
    return verifyVBAccumMembershipDelegatedProof(this.value, secretKey.value)
  }
}