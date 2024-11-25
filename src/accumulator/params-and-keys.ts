import { BytearrayWrapper } from '../bytearray-wrapper';
import {
  accumulatorDeriveMembershipProvingKeyFromNonMembershipKey,
  generateAccumulatorKeyPair,
  generateAccumulatorParams,
  generateAccumulatorPublicKey,
  generateAccumulatorSecretKey,
  generateMembershipProvingKey,
  generateNonMembershipProvingKey,
  isAccumulatorParamsValid,
  isAccumulatorPublicKeyValid,
  generateAccumulatorParamsForKeyedVerification,
  generateAccumulatorPublicKeyForKeyedVerification
} from 'crypto-wasm-new';

export class AccumulatorParams extends BytearrayWrapper {
  /**
   *  Generate accumulator parameters. They are needed to generate public key and initialize the accumulator.
   * @param label - Pass to generate parameters deterministically.
   * @returns
   */
  static generate(label?: Uint8Array): AccumulatorParams {
    return new AccumulatorParams(generateAccumulatorParams(label));
  }

  /**
   * Check if parameters are valid. Before verifying witness or using for proof verification,
   * make sure the params are valid.
   * @returns true if key is valid, false otherwise
   */
  isValid(): boolean {
    return isAccumulatorParamsValid(this.value);
  }
}

export class AccumulatorSecretKey extends BytearrayWrapper {
  /**
   * Generate secret key for the accumulator manager who updates the accumulator and creates witnesses.
   * @param seed - Pass to generate key deterministically.
   * @returns
   */
  static generate(seed?: Uint8Array): AccumulatorSecretKey {
    return new AccumulatorSecretKey(generateAccumulatorSecretKey(seed));
  }

  /**
   * Generate public key from given params and secret key.
   * @param params
   * @returns
   */
  generatePublicKey(params: AccumulatorParams): AccumulatorPublicKey {
    return new AccumulatorPublicKey(generateAccumulatorPublicKey(this.value, params.value));
  }
}

export class AccumulatorPublicKey extends BytearrayWrapper {
  static generate(secretKey: AccumulatorSecretKey, params: AccumulatorParams): AccumulatorPublicKey {
    return secretKey.generatePublicKey(params);
  }

  /**
   * Check if public key is valid. Before verifying witness or using for proof verification,
   * make sure the public key is valid.
   * @returns true if key is valid, false otherwise
   */
  isValid(): boolean {
    return isAccumulatorPublicKeyValid(this.value);
  }
}

export class AccumulatorKeypair {
  sk: AccumulatorSecretKey;
  pk: AccumulatorPublicKey;

  static generate(params: AccumulatorParams, seed?: Uint8Array): AccumulatorKeypair {
    const keypair = generateAccumulatorKeyPair(params.value, seed);
    return new AccumulatorKeypair(
      new AccumulatorSecretKey(keypair.secret_key),
      new AccumulatorPublicKey(keypair.public_key)
    );
  }

  constructor(sk: AccumulatorSecretKey, pk: AccumulatorPublicKey) {
    this.sk = sk;
    this.pk = pk;
  }

  get secretKey(): AccumulatorSecretKey {
    return this.sk;
  }

  get publicKey(): AccumulatorPublicKey {
    return this.pk;
  }
}

/**
 * Generate proving key for proving membership in an accumulator in zero knowledge. Proving key is
 * public data that must be known to both the prover and verifier. Any prover and verifier pair can mutually agree
 * on a proving key and the manager does not need to be aware of any proving key.
 * @param label - The bytearray that is hashed to deterministically generate the proving key.
 */
export class MembershipProvingKey extends BytearrayWrapper {
  static generate(label?: Uint8Array): MembershipProvingKey {
    return new MembershipProvingKey(generateMembershipProvingKey(label));
  }
}

/**
 * Generate proving key for proving non-membership in a universal accumulator in zero knowledge.
 * @param label - The bytearray that is hashed to deterministically generate the proving key.
 */
export class NonMembershipProvingKey extends BytearrayWrapper {
  static generate(label?: Uint8Array): NonMembershipProvingKey {
    return new NonMembershipProvingKey(generateNonMembershipProvingKey(label));
  }

  deriveMembershipProvingKey(): MembershipProvingKey {
    return new MembershipProvingKey(accumulatorDeriveMembershipProvingKeyFromNonMembershipKey(this.value));
  }
}

export class AccumulatorParamsForKeyedVerification extends BytearrayWrapper {
  /**
   *  Generate accumulator parameters for keyed-verification.
   * @param label - Pass to generate parameters deterministically.
   * @returns
   */
  static generate(label?: Uint8Array): AccumulatorParamsForKeyedVerification {
    return new AccumulatorParamsForKeyedVerification(generateAccumulatorParamsForKeyedVerification(label));
  }
}

export class AccumulatorPublicKeyForKeyedVerification extends BytearrayWrapper {
  static generate(
    secretKey: AccumulatorSecretKey,
    params: AccumulatorParamsForKeyedVerification
  ): AccumulatorPublicKeyForKeyedVerification {
    return new AccumulatorPublicKeyForKeyedVerification(
      generateAccumulatorPublicKeyForKeyedVerification(secretKey.value, params.value)
    );
  }
}
