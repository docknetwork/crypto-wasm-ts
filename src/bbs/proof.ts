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
} from 'crypto-wasm-new';
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
    blindings: Map<number, Uint8Array> = new Map(),
    revealed: Set<number> = new Set()
  ): BBSPoKSignatureProtocol {
    if (messages.length !== params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    const protocol = bbsInitializeProofOfKnowledgeOfSignature(
      signature.value,
      params.value,
      messages,
      blindings,
      revealed,
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
    revealedMsgs: Map<number, Uint8Array> = new Map()
  ): Uint8Array {
    return bbsChallengeContributionFromProtocol(this.value, revealedMsgs, params.value, encodeMessages);
  }
}

export class BBSPoKSigProof extends BytearrayWrapper {
  verify(
    challenge: Uint8Array,
    publicKey: BBSPublicKey,
    params: BBSSignatureParams,
    encodeMessages: boolean,
    revealedMsgs: Map<number, Uint8Array> = new Map()
  ): VerifyResult {
    return bbsVerifyProofOfKnowledgeOfSignature(
      this.value,
      revealedMsgs,
      challenge,
      publicKey.value,
      params.value,
      encodeMessages
    );
  }

  challengeContribution(
    params: BBSSignatureParams,
    encodeMessages: boolean,
    revealedMsgs: Map<number, Uint8Array> = new Map()
  ): Uint8Array {
    return bbsChallengeContributionFromProof(this.value, revealedMsgs, params.value, encodeMessages);
  }
}
