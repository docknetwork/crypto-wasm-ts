/**
 * Proof of knowledge of signature protocol
 */
import { BBSSignature } from './signature';
import { BBSSignatureParams } from './params';
import {
  bbsInitializeProofOfKnowledgeOfSignature,
  bbsGenProofOfKnowledgeOfSignature,
  bbsChallengeContributionFromProtocol,
  bbsChallengeContributionFromProof,
  bbsVerifyProofOfKnowledgeOfSignature,
  BbsPoKSigProtocol,
  VerifyResult
} from '@docknetwork/crypto-wasm';
import { BBSPublicKey } from './keys';
import { BytearrayWrapper } from '../bytearray-wrapper';

export class BBSPoKSignatureProtocol {
  value: BbsPoKSigProtocol;

  constructor(protocol: BbsPoKSigProtocol) {
    this.value = protocol;
  }

  static initialize(
    messages: Uint8Array[],
    signature: BBSSignature,
    params: BBSSignatureParams,
    encodeMessages: boolean,
    blindings?: Map<number, Uint8Array>,
    revealed?: Set<number>
  ): BBSPoKSignatureProtocol {
    if (messages.length !== params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    const b = blindings === undefined ? new Map<number, Uint8Array>() : blindings;
    const r = revealed === undefined ? new Set<number>() : revealed;
    const protocol = bbsInitializeProofOfKnowledgeOfSignature(
      signature.value,
      params.value,
      messages,
      b,
      r,
      encodeMessages
    );
    return new BBSPoKSignatureProtocol(protocol);
  }

  generateProof(challenge: Uint8Array): BBSPoKSigProof {
    return new BBSPoKSigProof(bbsGenProofOfKnowledgeOfSignature(this.value, challenge));
  }

  challengeContribution(
    params: BBSSignatureParams,
    encodeMessages: boolean,
    revealedMsgs?: Map<number, Uint8Array>
  ): Uint8Array {
    const r = revealedMsgs === undefined ? new Map<number, Uint8Array>() : revealedMsgs;
    return bbsChallengeContributionFromProtocol(this.value, r, params.value, encodeMessages);
  }
}

export class BBSPoKSigProof extends BytearrayWrapper {
  verify(
    challenge: Uint8Array,
    publicKey: BBSPublicKey,
    params: BBSSignatureParams,
    encodeMessages: boolean,
    revealedMsgs?: Map<number, Uint8Array>
  ): VerifyResult {
    const r = revealedMsgs === undefined ? new Map<number, Uint8Array>() : revealedMsgs;
    return bbsVerifyProofOfKnowledgeOfSignature(
      this.value,
      r,
      challenge,
      publicKey.value,
      params.value,
      encodeMessages
    );
  }

  challengeContribution(
    params: BBSSignatureParams,
    encodeMessages: boolean,
    revealedMsgs?: Map<number, Uint8Array>
  ): Uint8Array {
    const r = revealedMsgs === undefined ? new Map<number, Uint8Array>() : revealedMsgs;
    return bbsChallengeContributionFromProof(this.value, r, params.value, encodeMessages);
  }
}
