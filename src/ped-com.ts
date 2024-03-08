import { BytearrayWrapper } from './bytearray-wrapper';
import { ICompressed, IUncompressed } from './ICompressed';
import { generatePedersenCommKeyG1, decompressPedersenCommKeyG1 } from 'crypto-wasm-new';

export class PederCommKeyUncompressed extends BytearrayWrapper implements IUncompressed {}

// Pedersen commitment key
export class PederCommKey extends BytearrayWrapper implements ICompressed<PederCommKeyUncompressed> {
  constructor(label: Uint8Array) {
    super(generatePedersenCommKeyG1(label, false));
  }

  decompress(): PederCommKeyUncompressed {
    return new PederCommKeyUncompressed(decompressPedersenCommKeyG1(this.value));
  }
}
