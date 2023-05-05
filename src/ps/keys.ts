import { PSSignatureParams } from './params';
import { BytearrayWrapper } from '../bytearray-wrapper';
import {
  psGeneratePublicKey,
  psGenerateSigningKey,
  psIsPublicKeyValid,
  psAdaptSecretKeyForLessMessages,
  psAdaptSecretKeyForMoreMessages,
  psSigningKeyMaxSupportedMsgs,
  psPublicKeyMaxSupportedMsgs,
  psAdaptPublicKeyForLessMessages
} from '@docknetwork/crypto-wasm';
import { psShamirDeal } from '@docknetwork/crypto-wasm';

export class PSPublicKey extends BytearrayWrapper {
  supportedMessageCount(): number {
    return psPublicKeyMaxSupportedMsgs(this.value);
  }

  adaptForLess(messageCount: number) {
    const adapted = psAdaptPublicKeyForLessMessages(this.value, messageCount);

    return adapted != null ? new (this.constructor as typeof PSPublicKey)(adapted): null;
  }

  isValid(): boolean {
    return psIsPublicKeyValid(this.value);
  }
}

export class PSSecretKey extends BytearrayWrapper {
  supportedMessageCount(): number {
    return psSigningKeyMaxSupportedMsgs(this.value);
  }

  adaptForLess(messageCount: number) {
    const adapted = psAdaptSecretKeyForLessMessages(this.value, messageCount);

    return adapted != null ? new (this.constructor as typeof PSSecretKey)(adapted): null;
  }

  adaptForMore(seed: Uint8Array, messageCount: number) {
    const adapted = psAdaptSecretKeyForMoreMessages(this.value, seed, messageCount);
    return adapted != null ? new (this.constructor as typeof PSSecretKey)(adapted): null;
  }

  static generate(messageCount: number, seed?: Uint8Array) {
    return new this(psGenerateSigningKey(messageCount, seed));
  }

  static dealShamirSS(messageCount: number, threshold: number, total: number): [PSSecretKey, PSSecretKey[]] {
    const [thresholdKey, participantKeys] = psShamirDeal(messageCount, threshold, total);

    return [new PSSecretKey(thresholdKey), participantKeys.map(key => new PSSecretKey(key))]
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

  supportedMessageCount(): number {
    return Math.min(this.sk.supportedMessageCount(), this.pk.supportedMessageCount());
  }

  adaptForLess(messageCount: number) {
    const sk = this.sk.adaptForLess(messageCount);
    const pk = this.pk.adaptForLess(messageCount);

    return sk != null && pk != null ? new (this.constructor as typeof PSKeypair)(sk, pk): null;
  }

  static generate(params: PSSignatureParams, seed?: Uint8Array): PSKeypair {
    const secret = PSSecretKey.generate(params.supportedMessageCount(), seed);
    const pub = secret.generatePublicKey(params);

    return new PSKeypair(secret, pub);
  }
}
