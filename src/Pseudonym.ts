import { pedersenCommitmentG1, generateRandomG1Element } from 'crypto-wasm-new';
import { BytearrayWrapper } from './bytearray-wrapper';
import { base58ToBytearray, bytearrayToBase58 } from './util';

/**
 * A pseudonym is meant to be used as a unique identifier. It can be considered as a public key where the creator of the
 * pseudonym has the secret key, and it can prove the knowledge of this secret key. This is useful when verifier wants
 * to attach a unique identifier to a prover without either learning anything unintended (by prover) nor can that unique
 * identifier be used by other verifiers to identify the prover, eg. a seller (as a verifier) should be able to identify
 * repeat customers (prover) by using a unique identifier, but verifier should not be able to share that unique identifier
 * with other sellers using their own identifier for that prover. This is done by making the prover go through a one-time
 * registration process with the verifier where the prover creates a pseudonym and shares the pseudonym with the verifier.
 * The prover on subsequent interactions share the pseudonym and proof of knowledge of the pseudonym's secret key with the verifier.
 * Thus, pseudonyms allow for verifier-local and opt-in linkability.
 * This concept was introduced in Attribute-based Credentials for Trust, ref. https://link.springer.com/book/10.1007/978-3-319-14439-9.
 * This implementation of pseudonym uses a non-hiding Pedersen commitment
 */
export class Pseudonym extends BytearrayWrapper {
  /**
   *
   * @param base - usually created by the verifier or created in a trustless manner by hashing a public string and serves
   * as the commitment key
   * @param secretKey - the secret key known only to the creator of the pseudonym
   */
  static new(base: Uint8Array, secretKey: Uint8Array): Pseudonym {
    return new Pseudonym(pedersenCommitmentG1([base], [secretKey]));
  }

  static decode(value: Uint8Array): string {
    return bytearrayToBase58(value);
  }

  static encode(value: string): Uint8Array {
    return base58ToBytearray(value);
  }
}

/**
 * Similar to `Pseudonym` above but can be additionally bound to one or more attributes from multiple credentials.
 * This is also usable when a verifier wants to restrict a prover from having multiple pseudonyms from the same set of
 * attributes by not allowing it to use a secret key but only its attributes. Note that such pseudonyms are vulnerable
 * to brute force attack where all possible combinations of attribute values can be checked against the pseudonym thus
 * potentially de-anonymizing the prover. The implementation uses Pedersen commitment
 */
export class AttributeBoundPseudonym extends BytearrayWrapper {
  /**
   *
   * @param basesForAttributes - The part of commitment key used for attributes
   * @param attributes
   * @param baseForSecretKey - The part of commitment key used for secret key
   * @param secretKey
   */
  static new(
    basesForAttributes: Uint8Array[],
    attributes: Uint8Array[],
    baseForSecretKey?: Uint8Array,
    secretKey?: Uint8Array
  ): Pseudonym {
    const b = [...basesForAttributes];
    if (baseForSecretKey !== undefined) {
      b.push(baseForSecretKey);
    }

    const m = [...attributes];
    if (secretKey !== undefined) {
      m.push(secretKey);
    }
    return new AttributeBoundPseudonym(pedersenCommitmentG1(b, m));
  }
}

/**
 * Used to create commitment key for pseudonyms
 */
export class PseudonymBases {
  static decode(base: Uint8Array): string {
    return bytearrayToBase58(base);
  }

  static encode(base: string): Uint8Array {
    return base58ToBytearray(base);
  }

  /**
   * Public parameter created by the verifier
   * @param scope - A seed which is hashed to create the base. Each verifier should have a unique scope
   */
  static generateBaseForSecretKey(scope?: Uint8Array): Uint8Array {
    return generateRandomG1Element(scope);
  }

  /**
   * Public parameters created by the verifier
   * @param attributeCount
   * @param scope - A seed which is hashed to create the base. For attributes, the scope is suffixed with a counter.
   * Each verifier should have a unique scope
   */
  static generateBasesForAttributes(attributeCount: number, scope?: Uint8Array): Uint8Array[] {
    const b: Uint8Array[] = [];
    let s: number[];
    if (scope !== undefined) {
      s = Array.from(scope);
      s.push(0);
    } else {
      s = [0];
    }
    // Only supports upto 254 attributes but that should be sufficient.
    for (let i = 0; i < attributeCount; i++) {
      s[s.length - 1] = i + 1;
      b.push(generateRandomG1Element(new Uint8Array(s)));
    }
    return b;
  }

  static encodeBasesForAttributes(basesForAttributes: string[]): Uint8Array[] {
    return basesForAttributes.map((base) => PseudonymBases.encode(base));
  }

  static encodeBaseForSecretKey(baseForSecretKey: string): Uint8Array {
    return PseudonymBases.encode(baseForSecretKey);
  }

  static decodeBasesForAttributes(encodedBasesForAttributes: Uint8Array[]): string[] {
    return encodedBasesForAttributes.map((base) => PseudonymBases.decode(base));
  }

  static decodeBaseForSecretKey(encodedBaseForSecretKey: Uint8Array): string {
    return PseudonymBases.decode(encodedBaseForSecretKey);
  }
}
