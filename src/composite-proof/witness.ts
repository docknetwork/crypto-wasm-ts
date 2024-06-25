import {
  generatePedersenCommitmentWitness,
  generatePoKBBSPlusSignatureWitness,
  generatePoKPSSignatureWitness,
  generatePoKBBSSignatureWitness,
  generateAccumulatorMembershipWitness,
  generateAccumulatorNonMembershipWitness,
  generateSaverWitness,
  generateBoundCheckWitness,
  generateR1CSCircomWitness,
  generateBoundCheckBppWitness,
  generateBoundCheckSmcWitness,
  generateBoundCheckSmcWithKVWitness,
  generatePublicInequalityWitness,
  generatePoKBDDT16MacWitness,
  generateKBUniversalAccumulatorNonMembershipWitness,
  generateKBUniversalAccumulatorMembershipWitness
} from 'crypto-wasm-new';
import { KBUniversalMembershipWitness, KBUniversalNonMembershipWitness } from '../accumulator/kb-acccumulator-witness';
import { BBSPlusSignatureG1 } from '../bbs-plus';
import { VBMembershipWitness, VBNonMembershipWitness } from '../accumulator';
import { CircomInputs } from '../r1cs';
import { PSSignature } from '../ps';
import { BBSSignature } from '../bbs';
import { BDDT16Mac } from '../bddt16-mac';

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
   * Signature and messages of PS signature
   * @param signature
   * @param unrevealedMessages
   */
  static psSignature(signature: PSSignature, unrevealedMessages: Map<number, Uint8Array>): Uint8Array {
    return generatePoKPSSignatureWitness(signature.value, unrevealedMessages);
  }

  /**
   * Signature and messages of BBS signature
   * @param signature
   * @param unrevealedMessages
   * @param encodeMessages
   */
  static bbsSignature(
    signature: BBSSignature,
    unrevealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSSignatureWitness(signature.value, unrevealedMessages, encodeMessages);
  }

  /**
   * Signature and messages of BBS+ signature
   * @param signature
   * @param unrevealedMessages
   * @param encodeMessages
   */
  static bbsPlusSignature(
    signature: BBSPlusSignatureG1,
    unrevealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSPlusSignatureWitness(signature.value, unrevealedMessages, encodeMessages);
  }

  static bddt16Mac(mac: BDDT16Mac, unrevealedMessages: Map<number, Uint8Array>, encodeMessages: boolean): Uint8Array {
    return generatePoKBDDT16MacWitness(mac.value, unrevealedMessages, encodeMessages);
  }

  /**
   * VB Accumulator member and its witness
   * @param member
   * @param accumulatorWitness
   */
  static vbAccumulatorMembership(member: Uint8Array, accumulatorWitness: VBMembershipWitness): Uint8Array {
    return generateAccumulatorMembershipWitness(member, accumulatorWitness.value);
  }

  /**
   * VB Accumulator non-member and its witness
   * @param nonMember
   * @param accumulatorWitness
   */
  static vbAccumulatorNonMembership(nonMember: Uint8Array, accumulatorWitness: VBNonMembershipWitness): Uint8Array {
    return generateAccumulatorNonMembershipWitness(nonMember, accumulatorWitness.value);
  }

  /**
   * KB universal Accumulator member and its witness
   * @param member
   * @param accumulatorWitness
   */
  static kbUniAccumulatorMembership(member: Uint8Array, accumulatorWitness: KBUniversalMembershipWitness): Uint8Array {
    return generateKBUniversalAccumulatorMembershipWitness(member, accumulatorWitness.value);
  }

  /**
   * KB universal Accumulator non-member and its witness
   * @param nonMember
   * @param accumulatorWitness
   */
  static kbUniAccumulatorNonMembership(
    nonMember: Uint8Array,
    accumulatorWitness: KBUniversalNonMembershipWitness
  ): Uint8Array {
    return generateKBUniversalAccumulatorNonMembershipWitness(nonMember, accumulatorWitness.value);
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

  static pseudonym(secretKey: Uint8Array): Uint8Array {
    return Witness.pedersenCommitment([secretKey]);
  }

  static attributeBoundPseudonym(attributes: Uint8Array[], secretKey?: Uint8Array): Uint8Array {
    const a = [...attributes];
    if (secretKey !== undefined) {
      a.push(secretKey);
    }
    return Witness.pedersenCommitment(a);
  }

  static r1csCircomWitness(inputs: CircomInputs): Uint8Array {
    return generateR1CSCircomWitness(inputs.wires, inputs.privates, inputs.publics);
  }

  /**
   * Witness for bound check using Bulletproofs++
   * @param message - Message whose bounds are being proven using Bulletproofs++
   */
  static boundCheckBpp(message: Uint8Array): Uint8Array {
    return generateBoundCheckBppWitness(message);
  }

  /**
   * Witness for bound check using set-membership
   * @param message - Message whose bounds are being proven using set-membership check
   */
  static boundCheckSmc(message: Uint8Array): Uint8Array {
    return generateBoundCheckSmcWitness(message);
  }

  /**
   * Witness for bound check using set-membership and keyed verification
   * @param message - Message whose bounds are being proven using set-membership check
   */
  static boundCheckSmcWithKV(message: Uint8Array): Uint8Array {
    return generateBoundCheckSmcWithKVWitness(message);
  }

  static publicInequality(message: Uint8Array): Uint8Array {
    return generatePublicInequalityWitness(message);
  }
}

/**
 * A collection of witnesses.
 */
export class Witnesses {
  values: Uint8Array[];

  constructor(values: Uint8Array | Uint8Array[] = []) {
    this.values = Array.isArray(values) ? values : [values];
  }

  /**
   * Add a new witness to the end of the list. Returns the index (id) of the added witness. This index is part of the witness reference.
   * @param witness
   */
  add(witness: Uint8Array): number {
    this.values.push(witness);
    return this.values.length - 1;
  }

  /**
   * Add new witnesses to the end of the list. Returns the indices (ids) of the added witnesses. These indices are part of the witness reference.
   * @param witnesses
   */
  append(witnesses: Witnesses | Uint8Array[]): number[] {
    const rawWitnesses = witnesses instanceof Witnesses ? witnesses.values : witnesses;
    const indices = Array.from({ length: rawWitnesses.length }, (_, i) => this.values.length + i);
    this.values = this.values.concat(rawWitnesses);

    return indices;
  }
}
