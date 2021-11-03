import {
  generatePedersenCommitmentWitness,
  generatePoKBBSSignatureWitness,
  generateAccumulatorMembershipWitness,
  generateAccumulatorNonMembershipWitness
} from '@docknetwork/crypto-wasm';
import { SignatureG1 } from '../bbs-plus';
import { MembershipWitness, NonMembershipWitness } from '../accumulator';

export class Witness {
  static pedersenCommitment(elements: Uint8Array[]): Uint8Array {
    return generatePedersenCommitmentWitness(elements);
  }

  static poKBBSSignature(
    signature: SignatureG1,
    unrevealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSSignatureWitness(signature.value, unrevealedMessages, encodeMessages);
  }

  static accumulatorMembership(member: Uint8Array, accumulatorWitness: MembershipWitness): Uint8Array {
    return generateAccumulatorMembershipWitness(member, accumulatorWitness.value);
  }

  static accumulatorNonMembership(nonMember: Uint8Array, accumulatorWitness: NonMembershipWitness): Uint8Array {
    return generateAccumulatorNonMembershipWitness(nonMember, accumulatorWitness.value);
  }
}

export class Witnesses {
  values: Uint8Array[];

  constructor() {
    this.values = [];
  }

  add(witness: Uint8Array): number {
    this.values.push(witness);
    return this.values.length - 1;
  }
}
