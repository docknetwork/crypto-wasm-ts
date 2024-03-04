import {
  boundCheckSnarkSetup,
  boundCheckBppSetup,
  boundCheckSmcSetup,
  decompressBppParams,
  decompressSmcParams,
  boundCheckSmcWithKVSetup,
  decompressSmcParamsAndSk
} from 'crypto-wasm-new';
import { LegoProvingKey } from '../legosnark';
import { BytearrayWrapper } from '../bytearray-wrapper';
import { ICompressed, IUncompressed } from '../ICompressed';

/**
 * Create SNARK proving key for verifying bounds of a message, i.e. range proof.
 * This protocol only works with positive integers so any negative integers or decimal numbers
 * must be converted to positive integers
 */
export function BoundCheckSnarkSetup(): LegoProvingKey {
  const pk = boundCheckSnarkSetup(false);
  return new LegoProvingKey(pk);
}

/**
 * Setup for verifying bounds of a message, i.e. range proof. This uses set-membership check based
 * range proof with Keyed-Verification, i.e. the verifier possess a secret key to verify the proofs.
 * This is more efficient than the set membership check where the public params are same for everyone.
 * This returns separate params for prover and verifier and the verifier should never share his params
 * with the prover as they contain a secret.
 * This protocol only works with positive integers so any negative integers or decimal numbers
 * must be converted to positive integers
 */
export function BoundCheckSmcWithKVSetup(
  label: Uint8Array,
  base: number = 2
): [BoundCheckSmcWithKVProverParams, BoundCheckSmcWithKVVerifierParams] {
  const [p, v] = boundCheckSmcWithKVSetup(label, base, false);
  return [new BoundCheckSmcWithKVProverParams(p), new BoundCheckSmcWithKVVerifierParams(v)];
}

/**
 * Uncompressed version of `BoundCheckBppParams`
 */
export class BoundCheckBppParamsUncompressed extends BytearrayWrapper implements IUncompressed {}

/**
 * Setup params for verifying bounds of a message, i.e. range proof using Bulletproofs++
 * This protocol only works with positive integers so any negative integers or decimal numbers
 * must be converted to positive integers
 * @constructor
 */
export class BoundCheckBppParams extends BytearrayWrapper implements ICompressed<BoundCheckBppParamsUncompressed> {
  /**
   *
   * @param label - Some publicly known bytes that are hashed to create the params. The same label will generate
   * the same params
   * @param base
   * @param valueBitSize
   */
  constructor(label: Uint8Array, base: number = 2, valueBitSize: number = 64) {
    const params = boundCheckBppSetup(label, base, valueBitSize, false);
    super(params);
  }

  decompress(): BoundCheckBppParamsUncompressed {
    return new BoundCheckBppParamsUncompressed(decompressBppParams(this.value));
  }
}

/**
 * Uncompressed version of `BoundCheckSmcParams`
 */
export class BoundCheckSmcParamsUncompressed extends BytearrayWrapper implements IUncompressed {}

/**
 * Setup params for verifying bounds of a message, i.e. range proof using set-membership check
 * This protocol only works with positive integers so any negative integers or decimal numbers
 * must be converted to positive integers
 * @constructor
 */
export class BoundCheckSmcParams extends BytearrayWrapper implements ICompressed<BoundCheckSmcParamsUncompressed> {
  /**
   *
   * @param label - Some publicly known bytes that are hashed to create the params. The same label will not
   * generate the same params
   * @param base
   */
  constructor(label: Uint8Array, base: number = 2) {
    const params = boundCheckSmcSetup(label, base, false);
    super(params);
  }

  decompress(): BoundCheckSmcParamsUncompressed {
    return new BoundCheckSmcParamsUncompressed(decompressSmcParams(this.value));
  }
}

/**
 * Uncompressed version of `BoundCheckSmcWithKVVerifierParams`
 */
export class BoundCheckSmcWithKVProverParamsUncompressed extends BytearrayWrapper implements IUncompressed {}

/**
 * Params used by the prover for set-membership check based range proof with keyed verification
 */
export class BoundCheckSmcWithKVProverParams
  extends BytearrayWrapper
  implements ICompressed<BoundCheckSmcWithKVProverParamsUncompressed>
{
  decompress(): BoundCheckSmcWithKVProverParamsUncompressed {
    return new BoundCheckSmcWithKVProverParamsUncompressed(decompressSmcParams(this.value));
  }
}

/**
 * Uncompressed version of `BoundCheckSmcWithKVVerifierParams`
 */
export class BoundCheckSmcWithKVVerifierParamsUncompressed extends BytearrayWrapper implements IUncompressed {}

/**
 * Params used by the verifier for set-membership check based range proof with keyed verification. The verifier should not share these
 * with anyone as they contain a secret
 */
export class BoundCheckSmcWithKVVerifierParams
  extends BytearrayWrapper
  implements ICompressed<BoundCheckSmcWithKVVerifierParamsUncompressed>
{
  decompress(): BoundCheckSmcWithKVVerifierParamsUncompressed {
    return new BoundCheckSmcWithKVVerifierParamsUncompressed(decompressSmcParamsAndSk(this.value));
  }
}
