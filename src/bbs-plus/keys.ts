import {
  bbsPlusGenerateKeyPairG1,
  bbsPlusGenerateKeyPairG2,
  bbsPlusGeneratePublicKeyG2,
  bbsPlusGeneratePublicKeyG1,
  bbsPlusIsPublicKeyG2Valid,
  bbsPlusIsPublicKeyG1Valid
} from '@docknetwork/crypto-wasm';
import { SignatureParamsG1, SignatureParamsG2 } from './params';
import { BytearrayWrapper } from '../bytearray-wrapper';

export abstract class BBSPlusPublicKey extends BytearrayWrapper {
  abstract isValid(): boolean;
}

export class BBSPlusPublicKeyG1 extends BBSPlusPublicKey {
  isValid(): boolean {
    return bbsPlusIsPublicKeyG1Valid(this.value);
  }
}

export class BBSPlusPublicKeyG2 extends BBSPlusPublicKey {
  isValid(): boolean {
    return bbsPlusIsPublicKeyG2Valid(this.value);
  }
}

export class BBSPlusSecretKey extends BytearrayWrapper {
  generatePublicKeyG1(params: SignatureParamsG2): BBSPlusPublicKeyG1 {
    return new BBSPlusPublicKeyG1(bbsPlusGeneratePublicKeyG1(this.value, params.value));
  }

  generatePublicKeyG2(params: SignatureParamsG1): BBSPlusPublicKeyG2 {
    return new BBSPlusPublicKeyG2(bbsPlusGeneratePublicKeyG2(this.value, params.value));
  }
}

export abstract class BBSPlusKeypair {
  sk: BBSPlusSecretKey;
  pk: BBSPlusPublicKey;

  constructor(sk: BBSPlusSecretKey, pk: BBSPlusPublicKey) {
    this.sk = sk;
    this.pk = pk;
  }

  get secretKey(): BBSPlusSecretKey {
    return this.sk;
  }

  get publicKey(): BBSPlusPublicKey {
    return this.pk;
  }
}

export class KeypairG1 extends BBSPlusKeypair {
  static generate(params: SignatureParamsG2, seed?: Uint8Array): KeypairG1 {
    const keypair = bbsPlusGenerateKeyPairG1(params.value, seed);
    return new KeypairG1(new BBSPlusSecretKey(keypair.secret_key), new BBSPlusPublicKeyG1(keypair.public_key));
  }
}

export class KeypairG2 extends BBSPlusKeypair {
  static generate(params: SignatureParamsG1, seed?: Uint8Array): KeypairG2 {
    const keypair = bbsPlusGenerateKeyPairG2(params.value, seed);
    return new KeypairG2(new BBSPlusSecretKey(keypair.secret_key), new BBSPlusPublicKeyG2(keypair.public_key));
  }
}
