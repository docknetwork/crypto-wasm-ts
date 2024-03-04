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
  accumulatorVerifyMembershipProof,
  VerifyResult
} from 'crypto-wasm-new';
import { VBMembershipWitness, VBNonMembershipWitness } from './accumulatorWitness';
import {
  AccumulatorParams,
  AccumulatorPublicKey,
  MembershipProvingKey,
  NonMembershipProvingKey
} from './params-and-keys';
import { BytearrayWrapper } from '../bytearray-wrapper';

export class VBMembershipProofProtocol extends BytearrayWrapper {
  static initialize(
    member: Uint8Array,
    witness: VBMembershipWitness,
    publicKey: AccumulatorPublicKey,
    params: AccumulatorParams,
    provingKey: MembershipProvingKey,
    blinding: Uint8Array = generateRandomFieldElement()
  ): VBMembershipProofProtocol {
    const protocol = accumulatorInitializeMembershipProof(
      member,
      blinding,
      witness.value,
      publicKey.value,
      params.value,
      provingKey.value
    );
    return new VBMembershipProofProtocol(protocol);
  }

  generateProof(challenge: Uint8Array): VBMembershipProof {
    const proof = accumulatorGenMembershipProof(this.value, challenge);
    return new VBMembershipProof(proof);
  }

  challengeContribution(
    accumulated: Uint8Array,
    publicKey: AccumulatorPublicKey,
    params: AccumulatorParams,
    provingKey: MembershipProvingKey
  ): Uint8Array {
    return accumulatorChallengeContributionFromMembershipProtocol(
      this.value,
      accumulated,
      publicKey.value,
      params.value,
      provingKey.value
    );
  }
}

export class VBNonMembershipProofProtocol extends BytearrayWrapper {
  static initialize(
    nonMember: Uint8Array,
    witness: VBNonMembershipWitness,
    publicKey: AccumulatorPublicKey,
    params: AccumulatorParams,
    provingKey: NonMembershipProvingKey,
    blinding?: Uint8Array
  ): VBMembershipProofProtocol {
    const b = blinding === undefined ? generateRandomFieldElement() : blinding;
    const protocol = accumulatorInitializeNonMembershipProof(
      nonMember,
      b,
      witness.value,
      publicKey.value,
      params.value,
      provingKey.value
    );
    return new VBMembershipProofProtocol(protocol);
  }

  generateProof(challenge: Uint8Array): VBNonMembershipProof {
    const proof = accumulatorGenNonMembershipProof(this.value, challenge);
    return new VBNonMembershipProof(proof);
  }

  challengeContribution(
    accumulated: Uint8Array,
    publicKey: AccumulatorPublicKey,
    params: AccumulatorParams,
    provingKey: NonMembershipProvingKey
  ): Uint8Array {
    return accumulatorChallengeContributionFromNonMembershipProtocol(
      this.value,
      accumulated,
      publicKey.value,
      params.value,
      provingKey.value
    );
  }
}

export class VBMembershipProof extends BytearrayWrapper {
  verify(
    accumulated: Uint8Array,
    challenge: Uint8Array,
    publicKey: AccumulatorPublicKey,
    params: AccumulatorParams,
    provingKey: MembershipProvingKey
  ): VerifyResult {
    return accumulatorVerifyMembershipProof(
      this.value,
      accumulated,
      challenge,
      publicKey.value,
      params.value,
      provingKey.value
    );
  }

  challengeContribution(
    accumulated: Uint8Array,
    publicKey: AccumulatorPublicKey,
    params: AccumulatorParams,
    provingKey: MembershipProvingKey
  ): Uint8Array {
    return accumulatorChallengeContributionFromMembershipProof(
      this.value,
      accumulated,
      publicKey.value,
      params.value,
      provingKey.value
    );
  }
}

export class VBNonMembershipProof extends BytearrayWrapper {
  verify(
    accumulated: Uint8Array,
    challenge: Uint8Array,
    publicKey: AccumulatorPublicKey,
    params: AccumulatorParams,
    provingKey: NonMembershipProvingKey
  ): VerifyResult {
    return accumulatorVerifyNonMembershipProof(
      this.value,
      accumulated,
      challenge,
      publicKey.value,
      params.value,
      provingKey.value
    );
  }

  challengeContribution(
    accumulated: Uint8Array,
    publicKey: AccumulatorPublicKey,
    params: AccumulatorParams,
    provingKey: NonMembershipProvingKey
  ): Uint8Array {
    return accumulatorChallengeContributionFromNonMembershipProof(
      this.value,
      accumulated,
      publicKey.value,
      params.value,
      provingKey.value
    );
  }
}
