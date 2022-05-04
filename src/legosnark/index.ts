import { BytearrayWrapper } from '../bytearray-wrapper';
import { ICompressed, IUncompressed } from '../ICompressed';
import { legosnarkDecompressPk, legosnarkDecompressVk, legosnarkVkFromPk } from '@docknetwork/crypto-wasm';

/**
 * Uncompressed proving key of LegoGroth16
 */
export class LegoProvingKeyUncompressed extends BytearrayWrapper implements IUncompressed {}

/**
 * Compressed proving key of LegoGroth16
 */
export class LegoProvingKey extends BytearrayWrapper implements ICompressed<LegoProvingKeyUncompressed> {
  decompress(): LegoProvingKeyUncompressed {
    return new LegoProvingKeyUncompressed(legosnarkDecompressPk(this.value));
  }

  /**
   * Get the compressed verifying key from this proving key
   */
  getVerifyingKey(): LegoVerifyingKey {
    return new LegoVerifyingKey(legosnarkVkFromPk(this.value, false));
  }

  /**
   * Get the uncompressed verifying key from this proving key
   */
  getVerifyingKeyUncompressed(): LegoVerifyingKeyUncompressed {
    return new LegoVerifyingKeyUncompressed(legosnarkVkFromPk(this.value, true));
  }
}

/**
 * Uncompressed verifying key of LegoGroth16
 */
export class LegoVerifyingKeyUncompressed extends BytearrayWrapper implements IUncompressed {}

/**
 * Compressed verifying key of LegoGroth16
 */
export class LegoVerifyingKey extends BytearrayWrapper implements ICompressed<LegoVerifyingKeyUncompressed> {
  decompress(): LegoVerifyingKeyUncompressed {
    return new LegoVerifyingKeyUncompressed(legosnarkDecompressVk(this.value));
  }
}
