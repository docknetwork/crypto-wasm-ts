/**
 * Proof of knowledge of signature protocol
 */
import {SignatureG1} from "./signature";
import {SignatureParamsG1} from "./params";
import {BbsPoKSigProtocol, VerifyResult} from "@docknetwork/crypto-wasm";
import {
    bbsInitializeProofOfKnowledgeOfSignature,
    bbsGenProofOfKnowledgeOfSignature,
    bbsChallengeContributionFromProtocol,
    bbsChallengeContributionFromProof,
    bbsVerifyProofOfKnowledgeOfSignature
} from "@docknetwork/crypto-wasm";

export class PoKSigProtocol {
    value: BbsPoKSigProtocol;

    constructor(protocol: BbsPoKSigProtocol) {
        this.value = protocol;
    }

    static initialize(messages: Uint8Array[], signature: SignatureG1, params: SignatureParamsG1, encodeMessages: boolean, blindings?: Map<number, Uint8Array>, revealed?: Set<number>): PoKSigProtocol {
        const b = blindings === undefined ? new Map<number, Uint8Array>() : blindings;
        const r = revealed === undefined ? new Set<number>() : revealed;
        const protocol = bbsInitializeProofOfKnowledgeOfSignature(signature.value, params.value, messages, b, r, encodeMessages);
        return new PoKSigProtocol(protocol);
    }

    generateProof(challenge: Uint8Array): PoKSigProof {
        return new PoKSigProof(bbsGenProofOfKnowledgeOfSignature(this.value, challenge));
    }

    challengeContribution(params: SignatureParamsG1, encodeMessages: boolean, revealedMsgs?: Map<number, Uint8Array>): Uint8Array {
        const r = revealedMsgs === undefined ? new Map<number, Uint8Array>() : revealedMsgs;
        return bbsChallengeContributionFromProtocol(this.value, r, params.value, encodeMessages);
    }
}

export class PoKSigProof {
    value: Uint8Array;

    constructor(proof: Uint8Array) {
        this.value = proof;
    }

    verify(challenge: Uint8Array, publicKey: Uint8Array, params: SignatureParamsG1, encodeMessages: boolean, revealedMsgs?: Map<number, Uint8Array>): VerifyResult {
        const r = revealedMsgs === undefined ? new Map<number, Uint8Array>() : revealedMsgs;
        return bbsVerifyProofOfKnowledgeOfSignature(this.value, r, challenge, publicKey, params.value, encodeMessages);
    }

    challengeContribution(params: SignatureParamsG1, encodeMessages: boolean, revealedMsgs?: Map<number, Uint8Array>): Uint8Array {
        const r = revealedMsgs === undefined ? new Map<number, Uint8Array>() : revealedMsgs;
        return bbsChallengeContributionFromProof(this.value, r, params.value, encodeMessages);
    }
}
