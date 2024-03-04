/**
 * Proof of knowledge of signature protocol
 */
import { BBSPlusSignatureG1 } from './signature';
import { BBSPlusSignatureParamsG1 } from './params';
import {
  bbsPlusInitializeProofOfKnowledgeOfSignature,
  bbsPlusGenProofOfKnowledgeOfSignature,
  bbsPlusChallengeContributionFromProtocol,
  bbsPlusChallengeContributionFromProof,
  bbsPlusVerifyProofOfKnowledgeOfSignature,
  BbsPlusPoKSigProtocol,
  VerifyResult
} from 'crypto-wasm-new';
import { BBSPlusPublicKeyG2 } from './keys';
import { BytearrayWrapper } from '../bytearray-wrapper';

export class BBSPlusPoKSignatureProtocol {
  value: BbsPlusPoKSigProtocol;

  constructor(protocol: BbsPlusPoKSigProtocol) {
    this.value = protocol;
  }

  static initialize(
    messages: Uint8Array[],
    signature: BBSPlusSignatureG1,
    params: BBSPlusSignatureParamsG1,
    encodeMessages: boolean,
    blindings: Map<number, Uint8Array> = new Map(),
    revealed: Set<number> = new Set()
  ): BBSPlusPoKSignatureProtocol {
    if (messages.length !== params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    const protocol = bbsPlusInitializeProofOfKnowledgeOfSignature(
      signature.value,
      params.value,
      messages,
      blindings,
      revealed,
      encodeMessages
    );
    return new BBSPlusPoKSignatureProtocol(protocol);
  }

  generateProof(challenge: Uint8Array): BBSPlusPoKSigProof {
    return new BBSPlusPoKSigProof(bbsPlusGenProofOfKnowledgeOfSignature(this.value, challenge));
  }

  challengeContribution(
    params: BBSPlusSignatureParamsG1,
    encodeMessages: boolean,
    revealedMsgs: Map<number, Uint8Array> = new Map()
  ): Uint8Array {
    return bbsPlusChallengeContributionFromProtocol(this.value, revealedMsgs, params.value, encodeMessages);
  }
}

export class BBSPlusPoKSigProof extends BytearrayWrapper {
  verify(
    challenge: Uint8Array,
    publicKey: BBSPlusPublicKeyG2,
    params: BBSPlusSignatureParamsG1,
    encodeMessages: boolean,
    revealedMsgs: Map<number, Uint8Array> = new Map()
  ): VerifyResult {
    return bbsPlusVerifyProofOfKnowledgeOfSignature(
      this.value,
      revealedMsgs,
      challenge,
      publicKey.value,
      params.value,
      encodeMessages
    );
  }

  challengeContribution(
    params: BBSPlusSignatureParamsG1,
    encodeMessages: boolean,
    revealedMsgs: Map<number, Uint8Array> = new Map()
  ): Uint8Array {
    return bbsPlusChallengeContributionFromProof(this.value, revealedMsgs, params.value, encodeMessages);
  }
}
