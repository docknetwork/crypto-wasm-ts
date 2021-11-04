import {
  generatePedersenCommitmentWitness,
  generatePoKBBSSignatureWitness,
  generateAccumulatorMembershipWitness,
  generateAccumulatorNonMembershipWitness
} from '@docknetwork/crypto-wasm';
import { SignatureG1 } from '../bbs-plus';
import { MembershipWitness, NonMembershipWitness } from '../accumulator';

/**
 * Private data known only to the prover whose knowledge is being proved in a proof.
 */
export class Witness {
  /**
   * Opening of the Pedersen commitment
   * @param elements
   */
  static pedersenCommitment(elements: Uint8Array[]): Uint8Array {
    return generatePedersenCommitmentWitness(elements);
  }

  /**
   * Signature and messages of BBS+ signature
   * @param signature
   * @param unrevealedMessages
   * @param encodeMessages
   */
  static poKBBSSignature(
    signature: SignatureG1,
    unrevealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSSignatureWitness(signature.value, unrevealedMessages, encodeMessages);
  }

  /**
   * Accumulator member and its witness
   * @param member
   * @param accumulatorWitness
   */
  static accumulatorMembership(member: Uint8Array, accumulatorWitness: MembershipWitness): Uint8Array {
    return generateAccumulatorMembershipWitness(member, accumulatorWitness.value);
  }

  /**
   * Accumulator non-member and its witness
   * @param nonMember
   * @param accumulatorWitness
   */
  static accumulatorNonMembership(nonMember: Uint8Array, accumulatorWitness: NonMembershipWitness): Uint8Array {
    return generateAccumulatorNonMembershipWitness(nonMember, accumulatorWitness.value);
  }
}

/**
 * A collection of witnesses.
 */
export class Witnesses {
  values: Uint8Array[];

  constructor() {
    this.values = [];
  }

  /**
   * Add a new witness. Returns the index (id) of the added witness. This index is part of the witness reference.
   * @param witness
   */
  add(witness: Uint8Array): number {
    this.values.push(witness);
    return this.values.length - 1;
  }
}
