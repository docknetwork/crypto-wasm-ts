import {
  VerifyResult,
  verifyBDDT16KeyedProof,
  verifyVBAccumMembershipKeyedProof,
  verifyKBUniAccumMembershipKeyedProof,
  verifyKBUniAccumNonMembershipKeyedProof,
  proofOfInvalidityOfBDDT16KeyedProof,
  proofOfValidityOfBDDT16KeyedProof, verifyProofOfInvalidityOfBDDT16KeyedProof,
  verifyProofOfValidityOfBDDT16KeyedProof,
  proofOfInvalidityOfVBAccumMembershipKeyedProof,
  proofOfValidityOfVBAccumMembershipKeyedProof,
  verifyProofOfInvalidityOfVBAccumMembershipKeyedProof,
  verifyProofOfValidityOfVBAccumMembershipKeyedProof,
  proofOfInvalidityOfKBUniAccumMembershipKeyedProof,
  proofOfValidityOfKBUniAccumMembershipKeyedProof,
  verifyProofOfInvalidityOfKBUniAccumMembershipKeyedProof,
  verifyProofOfValidityOfKBUniAccumMembershipKeyedProof,
  proofOfInvalidityOfKBUniAccumNonMembershipKeyedProof,
  proofOfValidityOfKBUniAccumNonMembershipKeyedProof,
  verifyProofOfInvalidityOfKBUniAccumNonMembershipKeyedProof,
  verifyProofOfValidityOfKBUniAccumNonMembershipKeyedProof
} from 'crypto-wasm-new';
import { AccumulatorParamsForKeyedVerification,
  AccumulatorPublicKeyForKeyedVerification,
  AccumulatorSecretKey } from './accumulator';
import { BBDT16MacParams, BBDT16MacPublicKeyG1, BBDT16MacSecretKey } from './bbdt16-mac';
import { BytearrayWrapper } from './bytearray-wrapper';

/**
 * Keyed proof of BBDT16 MAC.
 */
export class BBDT16KeyedProof extends BytearrayWrapper {
  verify(secretKey: BBDT16MacSecretKey): VerifyResult {
    return verifyBDDT16KeyedProof(this.value, secretKey.value);
  }

  /**
   * Create proof that given `BBDT16KeyedProof` is valid
   * @param secretKey
   * @param publicKey
   * @param params
   */
  proofOfValidity(secretKey: BBDT16MacSecretKey, publicKey: BBDT16MacPublicKeyG1, params: BBDT16MacParams): ProofOfValidityBDDT16KeyedProof {
    return new ProofOfValidityBDDT16KeyedProof(proofOfValidityOfBDDT16KeyedProof(this.value, secretKey.value, publicKey.value, params.value));
  }

  /**
   * Create proof that given `BBDT16KeyedProof` is invalid
   * @param secretKey
   * @param publicKey
   * @param params
   */
  proofOfInvalidity(secretKey: BBDT16MacSecretKey, publicKey: BBDT16MacPublicKeyG1, params: BBDT16MacParams): ProofOfInvalidityBDDT16KeyedProof {
    return new ProofOfInvalidityBDDT16KeyedProof(proofOfInvalidityOfBDDT16KeyedProof(this.value, secretKey.value, publicKey.value, params.value));
  }
}

/**
 * Proof of validity of keyed proof of BBDT16 MAC.
 */
export class ProofOfValidityBDDT16KeyedProof extends BytearrayWrapper {
  verify(proof: BBDT16KeyedProof, publicKey: BBDT16MacPublicKeyG1, params: BBDT16MacParams): VerifyResult {
    return verifyProofOfValidityOfBDDT16KeyedProof(this.value, proof.value, publicKey.value, params.value);
  }
}

/**
 * Proof of invalidity of keyed proof of BBDT16 MAC.
 */
export class ProofOfInvalidityBDDT16KeyedProof extends BytearrayWrapper {
  verify(proof: BBDT16KeyedProof, publicKey: BBDT16MacPublicKeyG1, params: BBDT16MacParams): VerifyResult {
    return verifyProofOfInvalidityOfBDDT16KeyedProof(this.value, proof.value, publicKey.value, params.value);
  }
}

/**
 * Keyed proof of membership in keyed-verification of VB accumulator.
 */
export class VBAccumMembershipKeyedProof extends BytearrayWrapper {
  verify(secretKey: AccumulatorSecretKey): VerifyResult {
    return verifyVBAccumMembershipKeyedProof(this.value, secretKey.value);
  }

  /**
   * Create proof that given `VBAccumMembershipKeyedProof` is valid
   * @param secretKey
   * @param publicKey
   * @param params
   */
  proofOfValidity(secretKey: AccumulatorSecretKey, publicKey: AccumulatorPublicKeyForKeyedVerification, params: AccumulatorParamsForKeyedVerification): ProofOfValidityVBAccumMembershipKeyedProof {
    return new ProofOfValidityVBAccumMembershipKeyedProof(proofOfValidityOfVBAccumMembershipKeyedProof(this.value, secretKey.value, publicKey.value, params.value));
  }

  /**
   * Create proof that given `VBAccumMembershipKeyedProof` is invalid
   * @param secretKey
   * @param publicKey
   * @param params
   */
  proofOfInvalidity(secretKey: AccumulatorSecretKey, publicKey: AccumulatorPublicKeyForKeyedVerification, params: AccumulatorParamsForKeyedVerification): ProofOfInvalidityVBAccumMembershipKeyedProof {
    return new ProofOfInvalidityVBAccumMembershipKeyedProof(proofOfInvalidityOfVBAccumMembershipKeyedProof(this.value, secretKey.value, publicKey.value, params.value));
  }
}

/**
 * Proof of validity of keyed proof of membership in keyed-verification of VB accumulator.
 */
export class ProofOfValidityVBAccumMembershipKeyedProof extends BytearrayWrapper {
  verify(proof: VBAccumMembershipKeyedProof, publicKey: AccumulatorPublicKeyForKeyedVerification, params: AccumulatorParamsForKeyedVerification): VerifyResult {
    return verifyProofOfValidityOfVBAccumMembershipKeyedProof(this.value, proof.value, publicKey.value, params.value);
  }
}

/**
 * Proof of invalidity of keyed proof of membership in keyed-verification of VB accumulator.
 */
export class ProofOfInvalidityVBAccumMembershipKeyedProof extends BytearrayWrapper {
  verify(proof: VBAccumMembershipKeyedProof, publicKey: AccumulatorPublicKeyForKeyedVerification, params: AccumulatorParamsForKeyedVerification): VerifyResult {
    return verifyProofOfInvalidityOfVBAccumMembershipKeyedProof(this.value, proof.value, publicKey.value, params.value);
  }
}

/**
 * Keyed proof of membership in keyed-verification of KB universal accumulator.
 */
export class KBUniAccumMembershipKeyedProof extends BytearrayWrapper {
  verify(secretKey: AccumulatorSecretKey): VerifyResult {
    return verifyKBUniAccumMembershipKeyedProof(this.value, secretKey.value);
  }

  /**
   * Create proof that given `KBUniAccumMembershipKeyedProof` is valid
   * @param secretKey
   * @param publicKey
   * @param params
   */
  proofOfValidity(secretKey: AccumulatorSecretKey, publicKey: AccumulatorPublicKeyForKeyedVerification, params: AccumulatorParamsForKeyedVerification): ProofOfValidityKBUniAccumMembershipKeyedProof {
    return new ProofOfValidityKBUniAccumMembershipKeyedProof(proofOfValidityOfKBUniAccumMembershipKeyedProof(this.value, secretKey.value, publicKey.value, params.value));
  }

  /**
   * Create proof that given `KBUniAccumMembershipKeyedProof` is invalid
   * @param secretKey
   * @param publicKey
   * @param params
   */
  proofOfInvalidity(secretKey: AccumulatorSecretKey, publicKey: AccumulatorPublicKeyForKeyedVerification, params: AccumulatorParamsForKeyedVerification): ProofOfInvalidityKBUniAccumMembershipKeyedProof {
    return new ProofOfInvalidityKBUniAccumMembershipKeyedProof(proofOfInvalidityOfKBUniAccumMembershipKeyedProof(this.value, secretKey.value, publicKey.value, params.value));
  }
}

/**
 * Proof of validity of keyed proof of membership in keyed-verification of KB universal accumulator.
 */
export class ProofOfValidityKBUniAccumMembershipKeyedProof extends BytearrayWrapper {
  verify(proof: KBUniAccumMembershipKeyedProof, publicKey: AccumulatorPublicKeyForKeyedVerification, params: AccumulatorParamsForKeyedVerification): VerifyResult {
    return verifyProofOfValidityOfKBUniAccumMembershipKeyedProof(this.value, proof.value, publicKey.value, params.value);
  }
}

/**
 * Proof of invalidity of keyed proof of membership in keyed-verification of KB universal accumulator.
 */
export class ProofOfInvalidityKBUniAccumMembershipKeyedProof extends BytearrayWrapper {
  verify(proof: KBUniAccumMembershipKeyedProof, publicKey: AccumulatorPublicKeyForKeyedVerification, params: AccumulatorParamsForKeyedVerification): VerifyResult {
    return verifyProofOfInvalidityOfKBUniAccumMembershipKeyedProof(this.value, proof.value, publicKey.value, params.value);
  }
}

/**
 * Keyed proof of non-membership in keyed-verification of KB universal accumulator.
 */
export class KBUniAccumNonMembershipKeyedProof extends BytearrayWrapper {
  verify(secretKey: AccumulatorSecretKey): VerifyResult {
    return verifyKBUniAccumNonMembershipKeyedProof(this.value, secretKey.value);
  }

  /**
   * Create proof that given `KBUniAccumNonMembershipKeyedProof` is valid
   * @param secretKey
   * @param publicKey
   * @param params
   */
  proofOfValidity(secretKey: AccumulatorSecretKey, publicKey: AccumulatorPublicKeyForKeyedVerification, params: AccumulatorParamsForKeyedVerification): ProofOfValidityKBUniAccumNonMembershipKeyedProof {
    return new ProofOfValidityKBUniAccumNonMembershipKeyedProof(proofOfValidityOfKBUniAccumNonMembershipKeyedProof(this.value, secretKey.value, publicKey.value, params.value));
  }

  /**
   * Create proof that given `KBUniAccumNonMembershipKeyedProof` is invalid
   * @param secretKey
   * @param publicKey
   * @param params
   */
  proofOfInvalidity(secretKey: AccumulatorSecretKey, publicKey: AccumulatorPublicKeyForKeyedVerification, params: AccumulatorParamsForKeyedVerification): ProofOfInvalidityKBUniAccumNonMembershipKeyedProof {
    return new ProofOfInvalidityKBUniAccumNonMembershipKeyedProof(proofOfInvalidityOfKBUniAccumNonMembershipKeyedProof(this.value, secretKey.value, publicKey.value, params.value));
  }
}

/**
 * Proof of validity of keyed proof of non-membership in keyed-verification of KB universal accumulator.
 */
export class ProofOfValidityKBUniAccumNonMembershipKeyedProof extends BytearrayWrapper {
  verify(proof: KBUniAccumNonMembershipKeyedProof, publicKey: AccumulatorPublicKeyForKeyedVerification, params: AccumulatorParamsForKeyedVerification): VerifyResult {
    return verifyProofOfValidityOfKBUniAccumNonMembershipKeyedProof(this.value, proof.value, publicKey.value, params.value);
  }
}

/**
 * Proof of invalidity of keyed proof of non-membership in keyed-verification of KB universal accumulator.
 */
export class ProofOfInvalidityKBUniAccumNonMembershipKeyedProof extends BytearrayWrapper {
  verify(proof: KBUniAccumNonMembershipKeyedProof, publicKey: AccumulatorPublicKeyForKeyedVerification, params: AccumulatorParamsForKeyedVerification): VerifyResult {
    return verifyProofOfInvalidityOfKBUniAccumNonMembershipKeyedProof(this.value, proof.value, publicKey.value, params.value);
  }
}
