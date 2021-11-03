import {AccumulatorParams, VerifyResult} from "../../../crypto-wasm/src/js";
import {
    accumulatorChallengeContributionFromNonMembershipProof,
    accumulatorInitializeMembershipProof,
    accumulatorVerifyNonMembershipProof,
    generateRandomFieldElement,
    accumulatorChallengeContributionFromMembershipProof,
    accumulatorChallengeContributionFromMembershipProtocol,
    accumulatorChallengeContributionFromNonMembershipProtocol,
    accumulatorGenMembershipProof,
    accumulatorGenNonMembershipProof,
    accumulatorInitializeNonMembershipProof,
    accumulatorVerifyMembershipProof
} from "../../../crypto-wasm/src/js";
import {MembershipWitness, NonMembershipWitness} from "./accumulatorWitness";

export class MembershipProofProtocol {
    value: Uint8Array;

    constructor(protocol: Uint8Array) {
        this.value = protocol;
    }

    static initialize(member: Uint8Array, witness: MembershipWitness, publicKey: Uint8Array, params: AccumulatorParams, provingKey: Uint8Array, blinding?: Uint8Array): MembershipProofProtocol {
        const b = blinding === undefined ? generateRandomFieldElement() : blinding;
        const protocol = accumulatorInitializeMembershipProof(member, b, witness.value, publicKey, params, provingKey);
        return new MembershipProofProtocol(protocol);
    }

    generateProof(challenge: Uint8Array): MembershipProof {
        const proof = accumulatorGenMembershipProof(this.value, challenge);
        return new MembershipProof(proof);
    }

    challengeContribution(accumulated: Uint8Array, publicKey: Uint8Array, params: AccumulatorParams, provingKey: Uint8Array,): Uint8Array {
        return accumulatorChallengeContributionFromMembershipProtocol(this.value, accumulated, publicKey, params, provingKey);
    }
}

export class NonMembershipProofProtocol {
    value: Uint8Array;

    constructor(protocol: Uint8Array) {
        this.value = protocol;
    }

    static initialize(nonMember: Uint8Array, witness: NonMembershipWitness, publicKey: Uint8Array, params: AccumulatorParams, provingKey: Uint8Array, blinding?: Uint8Array): MembershipProofProtocol {
        const b = blinding === undefined ? generateRandomFieldElement() : blinding;
        const protocol = accumulatorInitializeNonMembershipProof(nonMember, b, witness.value, publicKey, params, provingKey);
        return new MembershipProofProtocol(protocol);
    }

    generateProof(challenge: Uint8Array): NonMembershipProof {
        const proof = accumulatorGenNonMembershipProof(this.value, challenge);
        return new NonMembershipProof(proof);
    }

    challengeContribution(accumulated: Uint8Array, publicKey: Uint8Array, params: AccumulatorParams, provingKey: Uint8Array): Uint8Array {
        return accumulatorChallengeContributionFromNonMembershipProtocol(this.value, accumulated, publicKey, params, provingKey);
    }
}

export class MembershipProof {
    value: Uint8Array;

    constructor(proof: Uint8Array) {
        this.value = proof;
    }

    verify(accumulated: Uint8Array, challenge: Uint8Array, publicKey: Uint8Array, params: AccumulatorParams, provingKey: Uint8Array): VerifyResult {
        return accumulatorVerifyMembershipProof(this.value, accumulated, challenge, publicKey, params, provingKey);
    }

    challengeContribution(accumulated: Uint8Array, publicKey: Uint8Array, params: AccumulatorParams, provingKey: Uint8Array): Uint8Array {
        return accumulatorChallengeContributionFromMembershipProof(this.value, accumulated, publicKey, params, provingKey);
    }
}

export class NonMembershipProof {
    value: Uint8Array;

    constructor(proof: Uint8Array) {
        this.value = proof;
    }

    verify(accumulated: Uint8Array, challenge: Uint8Array, publicKey: Uint8Array, params: AccumulatorParams, provingKey: Uint8Array): VerifyResult {
        return accumulatorVerifyNonMembershipProof(this.value, accumulated, challenge, publicKey, params, provingKey);
    }

    challengeContribution(accumulated: Uint8Array, publicKey: Uint8Array, params: AccumulatorParams, provingKey: Uint8Array): Uint8Array {
        return accumulatorChallengeContributionFromNonMembershipProof(this.value, accumulated, publicKey, params, provingKey);
    }
}
