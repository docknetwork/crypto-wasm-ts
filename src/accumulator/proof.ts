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
} from '@docknetwork/crypto-wasm';
import { MembershipWitness, NonMembershipWitness } from './accumulatorWitness';
import {
  AccumulatorParams,
  AccumulatorPublicKey,
  MembershipProvingKey,
  NonMembershipProvingKey
} from './params-and-keys';
import { BytearrayWrapper } from '../bytearray-wrapper';

export class MembershipProofProtocol extends BytearrayWrapper {
  static initialize(
    member: Uint8Array,
    witness: MembershipWitness,
    publicKey: AccumulatorPublicKey,
    params: AccumulatorParams,
    provingKey: MembershipProvingKey,
    blinding: Uint8Array = generateRandomFieldElement()
  ): MembershipProofProtocol {
    const protocol = accumulatorInitializeMembershipProof(
      member,
      blinding,
      witness.value,
      publicKey.value,
      params.value,
      provingKey.value
    );
    return new MembershipProofProtocol(protocol);
  }

  generateProof(challenge: Uint8Array): MembershipProof {
    const proof = accumulatorGenMembershipProof(this.value, challenge);
    return new MembershipProof(proof);
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

export class NonMembershipProofProtocol extends BytearrayWrapper {
  static initialize(
    nonMember: Uint8Array,
    witness: NonMembershipWitness,
    publicKey: AccumulatorPublicKey,
    params: AccumulatorParams,
    provingKey: NonMembershipProvingKey,
    blinding?: Uint8Array
  ): MembershipProofProtocol {
    const b = blinding === undefined ? generateRandomFieldElement() : blinding;
    const protocol = accumulatorInitializeNonMembershipProof(
      nonMember,
      b,
      witness.value,
      publicKey.value,
      params.value,
      provingKey.value
    );
    return new MembershipProofProtocol(protocol);
  }

  generateProof(challenge: Uint8Array): NonMembershipProof {
    const proof = accumulatorGenNonMembershipProof(this.value, challenge);
    return new NonMembershipProof(proof);
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

export class MembershipProof extends BytearrayWrapper {
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

export class NonMembershipProof extends BytearrayWrapper {
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
