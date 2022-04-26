import { BytearrayWrapper } from '../bytearray-wrapper';
import { ICompressed, IUncompressed } from '../ICompressed';
import {
  saverGenerateChunkedCommitmentGenerators,
  saverDecompressChunkedCommitmentGenerators
} from '@docknetwork/crypto-wasm';

export class SaverChunkedCommitmentGensUncompressed extends BytearrayWrapper implements IUncompressed {}

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
