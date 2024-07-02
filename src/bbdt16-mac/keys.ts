import { BytearrayWrapper } from '../bytearray-wrapper';
import { bddt16MacGenerateSecretKey, bddt16MacGeneratePublicKeyG1, bddt16MacIsPublicKeyG1Valid } from 'crypto-wasm-new';
import { BBDT16MacParams } from './params';

/**
 * BBDT16 MAC secret key. Used to create and verify the MAC
 */
export class BBDT16MacSecretKey extends BytearrayWrapper {
  static generate(seed?: Uint8Array) {
    return new this(bddt16MacGenerateSecretKey(seed));
  }

  generatePublicKeyG1(params: BBDT16MacParams): BBDT16MacPublicKeyG1 {
    return new BBDT16MacPublicKeyG1(bddt16MacGeneratePublicKeyG1(this.value, params.value));
  }
}

/**
 * This public key cannot be used to verify the MAC itself but used in verifying the proof of validity of MAC, i.e. `BBDT16MacProofOfValidity`
 */
export class BBDT16MacPublicKeyG1 extends BytearrayWrapper {
  isValid(): boolean {
    return bddt16MacIsPublicKeyG1Valid(this.value);
  }
}

export class BBDT16KeypairG1 {
  sk: BBDT16MacSecretKey;
  pk: BBDT16MacPublicKeyG1;

  constructor(sk: BBDT16MacSecretKey, pk: BBDT16MacPublicKeyG1) {
    this.sk = sk;
    this.pk = pk;
  }

  static generate(params: BBDT16MacParams, seed?: Uint8Array): BBDT16KeypairG1 {
    const sk = BBDT16MacSecretKey.generate(seed);
    const pk = sk.generatePublicKeyG1(params);
    return new BBDT16KeypairG1(sk, pk);
  }

  get secretKey(): BBDT16MacSecretKey {
    return this.sk;
  }

  get publicKey(): BBDT16MacPublicKeyG1 {
    return this.pk;
  }
}
