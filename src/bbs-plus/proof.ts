/**
 * Proof of knowledge of signature protocol
 */
import { SignatureG1 } from './signature';
import { SignatureParamsG1 } from './params';
import {
  bbsInitializeProofOfKnowledgeOfSignature,
  bbsGenProofOfKnowledgeOfSignature,
  bbsChallengeContributionFromProtocol,
  bbsChallengeContributionFromProof,
  bbsVerifyProofOfKnowledgeOfSignature,
  BbsPoKSigProtocol,
  VerifyResult
} from '@docknetwork/crypto-wasm';
import { BBSPlusPublicKeyG2 } from './keys';
import { BytearrayWrapper } from '../bytearray-wrapper';

export class PoKSigProtocol {
  value: BbsPoKSigProtocol;

  constructor(protocol: BbsPoKSigProtocol) {
    this.value = protocol;
  }

  static initialize(
    messages: Uint8Array[],
    signature: SignatureG1,
    params: SignatureParamsG1,
    encodeMessages: boolean,
    blindings?: Map<number, Uint8Array>,
    revealed?: Set<number>
  ): PoKSigProtocol {
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
    return new PoKSigProtocol(protocol);
  }

  generateProof(challenge: Uint8Array): PoKSigProof {
    return new PoKSigProof(bbsGenProofOfKnowledgeOfSignature(this.value, challenge));
  }

  challengeContribution(
    params: SignatureParamsG1,
    encodeMessages: boolean,
    revealedMsgs?: Map<number, Uint8Array>
  ): Uint8Array {
    const r = revealedMsgs === undefined ? new Map<number, Uint8Array>() : revealedMsgs;
    return bbsChallengeContributionFromProtocol(this.value, r, params.value, encodeMessages);
  }
}

export class PoKSigProof extends BytearrayWrapper {
  verify(
    challenge: Uint8Array,
    publicKey: BBSPlusPublicKeyG2,
    params: SignatureParamsG1,
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
    params: SignatureParamsG1,
    encodeMessages: boolean,
    revealedMsgs?: Map<number, Uint8Array>
  ): Uint8Array {
    const r = revealedMsgs === undefined ? new Map<number, Uint8Array>() : revealedMsgs;
    return bbsChallengeContributionFromProof(this.value, r, params.value, encodeMessages);
  }
}
