import { BytearrayWrapper } from '../bytearray-wrapper';
import { ICompressed, IUncompressed } from '../ICompressed';
import { saverGenerateChunkedCommitmentGenerators, saverDecompressChunkedCommitmentGenerators } from 'crypto-wasm-new';

/**
 * Same as `SaverChunkedCommitmentKey` but in uncompressed form.
 */
export class SaverChunkedCommitmentKeyUncompressed extends BytearrayWrapper implements IUncompressed {}

/**
 * Generators used by the prover and verifier to connect the commitment to the message in SAVER's ciphertext to the
 * commitment to message under BBS/BBS+/PS signature
 */
export class SaverChunkedCommitmentKey
  extends BytearrayWrapper
  implements ICompressed<SaverChunkedCommitmentKeyUncompressed>
{
  static generate(label?: Uint8Array): SaverChunkedCommitmentKey {
    const gens = saverGenerateChunkedCommitmentGenerators(label);
    return new SaverChunkedCommitmentKey(gens);
  }

  decompress(): SaverChunkedCommitmentKeyUncompressed {
    return new SaverChunkedCommitmentKeyUncompressed(saverDecompressChunkedCommitmentGenerators(this.value));
  }
}
