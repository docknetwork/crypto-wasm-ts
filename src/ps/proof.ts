/**
 * Proof of knowledge of signature protocol
 */
import { PSSignature } from './signature';
import { PSSignatureParams } from './params';
import {
  psInitializeSignaturePoK,
  psGenSignaturePoK,
  psChallengeSignaturePoKContributionFromProtocol,
  psChallengeSignaturePoKContributionFromProof,
  psVerifySignaturePoK,
  PSPoKSigProtocol,
  VerifyResult
} from 'crypto-wasm-new';
import { PSPublicKey } from './keys';
import { BytearrayWrapper } from '../bytearray-wrapper';

export class PSPoKSignatureProtocol {
  value: PSPoKSigProtocol;

  constructor(protocol: PSPoKSigProtocol) {
    this.value = protocol;
  }

  static initialize(
    messages: Uint8Array[],
    signature: PSSignature,
    publicKey: PSPublicKey,
    params: PSSignatureParams,
    blindings: Map<number, Uint8Array> = new Map(),
    revealed: Set<number> = new Set()
  ): PSPoKSignatureProtocol {
    if (messages.length !== params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    const protocol = psInitializeSignaturePoK(
      signature.value,
      params.value,
      publicKey.value,
      messages.map((message, idx) => {
        if (revealed.has(idx)) {
          return 'RevealMessage';
        }

        const blinding = blindings.get(idx);
        if (blinding !== void 0) {
          return { BlindMessageWithConcreteBlinding: { message, blinding } };
        } else {
          return { BlindMessageRandomly: message };
        }
      })
    );

    return new PSPoKSignatureProtocol(protocol);
  }

  generateProof(challenge: Uint8Array): PSPoKSigProof {
    return new PSPoKSigProof(psGenSignaturePoK(this.value, challenge));
  }

  challengeContribution(params: PSSignatureParams, publicKey: PSPublicKey): Uint8Array {
    return psChallengeSignaturePoKContributionFromProtocol(this.value, publicKey.value, params.value);
  }
}

export class PSPoKSigProof extends BytearrayWrapper {
  verify(
    challenge: Uint8Array,
    publicKey: PSPublicKey,
    params: PSSignatureParams,
    revealedMsgs: Map<number, Uint8Array> = new Map()
  ): VerifyResult {
    return psVerifySignaturePoK(this.value, revealedMsgs, challenge, publicKey.value, params.value);
  }

  challengeContribution(params: PSSignatureParams, publicKey: PSPublicKey): Uint8Array {
    return psChallengeSignaturePoKContributionFromProof(this.value, publicKey.bytes, params.value);
  }
}
