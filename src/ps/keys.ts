import {
  psGeneratePublicKey,
  psGenerateSigningKey,
  psIsPublicKeyValid,
} from '@docknetwork/crypto-wasm';
import { PSSignatureParams } from './params';
import { BytearrayWrapper } from '../bytearray-wrapper';

export class PSPublicKey extends BytearrayWrapper {
  isValid(): boolean {
    return psIsPublicKeyValid(this.value)
  }
}

export class PSSecretKey extends BytearrayWrapper {
  static generate(messageCount: number, seed?: Uint8Array) {
    return new this(psGenerateSigningKey(messageCount, seed));
  }

  generatePublicKey(params: PSSignatureParams): PSPublicKey {
    return new PSPublicKey(psGeneratePublicKey(this.value, params.value));
  }
}

export class PSKeypair {
  sk: PSSecretKey;
  pk: PSPublicKey;

  constructor(sk: PSSecretKey, pk: PSPublicKey) {
    this.sk = sk;
    this.pk = pk;
  }

  get secretKey(): PSSecretKey {
    return this.sk;
  }

  get publicKey(): PSPublicKey {
    return this.pk;
  }

  static generate(params: PSSignatureParams, seed?: Uint8Array): PSKeypair {
    const secret = PSSecretKey.generate(params.supportedMessageCount(), seed);
    const pub = secret.generatePublicKey(params);

    return new PSKeypair(secret, pub);
  }
}
