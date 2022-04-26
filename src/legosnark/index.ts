import { BytearrayWrapper } from '../bytearray-wrapper';
import { ICompressed, IUncompressed } from '../ICompressed';
import { legosnarkDecompressPk, legosnarkDecompressVk, legosnarkVkFromPk } from '@docknetwork/crypto-wasm';

export class LegoProvingKeyUncompressed extends BytearrayWrapper implements IUncompressed {}

export class LegoProvingKey extends BytearrayWrapper implements ICompressed<LegoProvingKeyUncompressed> {
  decompress(): LegoProvingKeyUncompressed {
    return new LegoProvingKeyUncompressed(legosnarkDecompressPk(this.value));
  }

  getVerifyingKey(): LegoVerifyingKey {
    return new LegoVerifyingKey(legosnarkVkFromPk(this.value, false));
  }

  getVerifyingKeyUncompressed(): LegoVerifyingKeyUncompressed {
    return new LegoVerifyingKeyUncompressed(legosnarkVkFromPk(this.value, true));
  }
}

export class LegoVerifyingKeyUncompressed extends BytearrayWrapper implements IUncompressed {}

export class LegoVerifyingKey extends BytearrayWrapper implements ICompressed<LegoVerifyingKeyUncompressed> {
  decompress(): LegoVerifyingKeyUncompressed {
    return new LegoVerifyingKeyUncompressed(legosnarkDecompressVk(this.value));
  }
}
