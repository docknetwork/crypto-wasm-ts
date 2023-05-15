import { bbsGenerateKeyPair, bbsGeneratePublicKey, bbsGenerateSigningKey } from '@docknetwork/crypto-wasm';
import { BBSPlusPublicKeyG1, BBSPlusPublicKeyG2, BBSPlusSecretKey } from '../bbs-plus';
import { BBSSignatureParams } from './params';

/**
 * `BBS` secret key.
 */
export class BBSSecretKey extends BBSPlusSecretKey {
  generatePublicKeyG1(_): BBSPlusPublicKeyG1 {
    throw new Error('Not supported')
  }

  generatePublicKey(params: BBSSignatureParams): BBSPublicKey {
    return new BBSPlusPublicKeyG2(bbsGeneratePublicKey(this.value, params.value));
  }

  static generate(seed?: Uint8Array) {
    return new this(bbsGenerateSigningKey(seed));
  }
}

/**
 * `BBS` public key.
 */
export class BBSPublicKey extends BBSPlusPublicKeyG2 {}

/**
 * `BBS` keypair.
 */
export class BBSKeypair {
  sk: BBSSecretKey;
  pk: BBSPublicKey;

  constructor(sk: BBSSecretKey, pk: BBSPublicKey) {
    this.sk = sk;
    this.pk = pk;
  }

  get secretKey(): BBSSecretKey {
    return this.sk;
  }

  get publicKey(): BBSPublicKey {
    return this.pk;
  }

  static generate(params: BBSSignatureParams, seed?: Uint8Array): BBSKeypair {
    const keypair = bbsGenerateKeyPair(params.value, seed);
    return new BBSKeypair(new BBSSecretKey(keypair.secret_key), new BBSPublicKey(keypair.public_key));
  }
}
