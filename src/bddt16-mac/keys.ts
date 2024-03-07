import { BytearrayWrapper } from '../bytearray-wrapper';
import {
  bddt16MacGenerateSecretKey,
  bddt16MacGeneratePublicKeyG1,
  bddt16MacIsPublicKeyG1Valid,
} from 'crypto-wasm-new';
import { BDDT16MacParams } from './params';

/**
 * BDDT16 MAC secret key.
 */
export class BDDT16MacSecretKey extends BytearrayWrapper {
  static generate(seed?: Uint8Array) {
    return new this(bddt16MacGenerateSecretKey(seed));
  }

  generatePublicKeyG1(params: BDDT16MacParams): BDDT16MacPublicKeyG1 {
    return new BDDT16MacPublicKeyG1(bddt16MacGeneratePublicKeyG1(this.value, params.value));
  }
}

export class BDDT16MacPublicKeyG1 extends BytearrayWrapper {
  isValid(): boolean {
    return bddt16MacIsPublicKeyG1Valid(this.value)
  }
}

export class BDDT16KeypairG1 {
  sk: BDDT16MacSecretKey;
  pk: BDDT16MacPublicKeyG1;

  constructor(sk: BDDT16MacSecretKey, pk: BDDT16MacPublicKeyG1) {
    this.sk = sk;
    this.pk = pk;
  }

  static generate(params: BDDT16MacParams, seed?: Uint8Array): BDDT16KeypairG1 {
    const sk = BDDT16MacSecretKey.generate(seed);
    const pk = sk.generatePublicKeyG1(params);
    return new BDDT16KeypairG1(sk, pk)
  }
}