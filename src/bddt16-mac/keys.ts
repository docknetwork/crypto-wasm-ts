import { BytearrayWrapper } from '../bytearray-wrapper';
import { bddt16MacGenerateSecretKey } from 'crypto-wasm-new';

/**
 * BDDT16 MAC secret key.
 */
export class BDDT16MacSecretKey extends BytearrayWrapper {
  static generate(seed?: Uint8Array) {
    return new this(bddt16MacGenerateSecretKey(seed));
  }
}