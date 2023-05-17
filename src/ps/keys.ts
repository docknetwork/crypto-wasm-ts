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

/**
 * Public key for modified Pointcheval-Sanders signature scheme used in `Coconut`.
 */
export class PSPublicKey extends BytearrayWrapper {
  supportedMessageCount(): number {
    return psPublicKeyMaxSupportedMsgs(this.value);
  }

  adaptForLess(messageCount: number) {
    const adapted = psAdaptPublicKeyForLessMessages(this.value, messageCount);
    if (adapted == null) {
      throw new Error(`Failed to adapt public key ${this} for ${messageCount} messages`)
    }

    return new (this.constructor as typeof PSPublicKey)(adapted);
  }

  isValid(): boolean {
    return psIsPublicKeyValid(this.value);
  }
}

/**
 * Secret key for modified Pointcheval-Sanders signature scheme used in `Coconut`.
 */
export class PSSecretKey extends BytearrayWrapper {
  supportedMessageCount(): number {
    return psSigningKeyMaxSupportedMsgs(this.value);
  }

  adaptForLess(messageCount: number) {
    const adapted = psAdaptSecretKeyForLessMessages(this.value, messageCount);
    if (adapted == null) {
      throw new Error(`Failed to adapt secret key ${this} for ${messageCount} messages`)
    }

    return new PSSecretKey(adapted);
  }

  adaptForMore(seed: Uint8Array, messageCount: number) {
    const adapted = psAdaptSecretKeyForMoreMessages(this.value, seed, messageCount);
    if (adapted == null) {
      throw new Error(`Failed to adapt secret key ${this} for ${messageCount} messages`)
    }

    return new PSSecretKey(adapted);
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

/**
 * Keypair (secret and public keys) for modified Pointcheval-Sanders signature scheme used in `Coconut`.
 */
export class PSKeypair {
  sk: PSSecretKey;
  pk: PSPublicKey;

  constructor(sk: PSSecretKey, pk: PSPublicKey) {
    if (sk.supportedMessageCount() !== pk.supportedMessageCount()) {
      throw new Error(`Incompatible public/secret keys: public key supports ${pk.supportedMessageCount()} messages while ${sk.supportedMessageCount()}`)
    }
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
    return this.sk.supportedMessageCount();
  }

  adaptForLess(messageCount: number): PSKeypair {
    const sk = this.sk.adaptForLess(messageCount);
    const pk = this.pk.adaptForLess(messageCount);

    return new PSKeypair(sk, pk);
  }

  static generate(params: PSSignatureParams, seed?: Uint8Array): PSKeypair {
    const secret = PSSecretKey.generate(params.supportedMessageCount(), seed);
    const pub = secret.generatePublicKey(params);

    return new PSKeypair(secret, pub);
  }
}
