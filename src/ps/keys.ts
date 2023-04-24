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
