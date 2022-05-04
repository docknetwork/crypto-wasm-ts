import { BytearrayWrapper } from '../bytearray-wrapper';
import { ICompressed, IUncompressed } from '../ICompressed';
import {
  saverGenerateChunkedCommitmentGenerators,
  saverDecompressChunkedCommitmentGenerators
} from '@docknetwork/crypto-wasm';

/**
 * Same as `SaverChunkedCommitmentGens` but in uncompressed form.
 */
export class SaverChunkedCommitmentGensUncompressed extends BytearrayWrapper implements IUncompressed {}

/**
 * Generators used by the prover and verifier to connect the commitment to the message in SAVER's ciphertext to the
 * commitment to message under BBS+ signature
 */
export class SaverChunkedCommitmentGens extends BytearrayWrapper
  implements ICompressed<SaverChunkedCommitmentGensUncompressed> {
  static generate(label?: Uint8Array): SaverChunkedCommitmentGens {
    const gens = saverGenerateChunkedCommitmentGenerators(label);
    return new SaverChunkedCommitmentGens(gens);
  }

  decompress(): SaverChunkedCommitmentGensUncompressed {
    return new SaverChunkedCommitmentGensUncompressed(saverDecompressChunkedCommitmentGenerators(this.value));
  }
}
