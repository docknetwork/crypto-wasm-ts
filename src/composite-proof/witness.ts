import {
  generatePedersenCommitmentWitness,
  generatePoKBBSSignatureWitness,
  generateAccumulatorMembershipWitness,
  generateAccumulatorNonMembershipWitness,
  generateSaverWitness,
  generateBoundCheckWitness
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
  static bbsSignature(
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

  /**
   * Witness for verifiable encryption using SAVER
   * @param message - Message being encrypted
   */
  static saver(message: Uint8Array): Uint8Array {
    return generateSaverWitness(message);
  }

  /**
   * Witness for bound check using LegoGroth16
   * @param message - Message whose bounds are being proven using LegoGroth16
   */
  static boundCheckLegoGroth16(message: Uint8Array): Uint8Array {
    return generateBoundCheckWitness(message);
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
