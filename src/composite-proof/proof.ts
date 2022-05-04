import { MetaStatements, Statements } from './statement';
import {
  generateCompositeProofG1,
  generateCompositeProofG1WithDeconstructedProofSpec,
  saverGetCiphertextFromProof,
  verifyCompositeProofG1,
  verifyCompositeProofG1WithDeconstructedProofSpec,
  VerifyResult
} from '@docknetwork/crypto-wasm';
import { Witnesses } from './witness';
import { SetupParam } from './setup-param';
import { SaverCiphertext } from '../saver';
import { ProofSpecG1, QuasiProofSpecG1 } from './proof-spec';

/**
 * A proof of 1 or more statements and meta statements.
 */
export class CompositeProofG1 {
  value: Uint8Array;

  constructor(proof: Uint8Array) {
    this.value = proof;
  }

  /**
   * Generate the composite proof using a `ProofSpec`
   * @param proofSpec
   * @param witnesses
   * @param nonce
   */
  static generate(proofSpec: ProofSpecG1, witnesses: Witnesses, nonce?: Uint8Array): CompositeProofG1 {
    const proof = generateCompositeProofG1(proofSpec.value, witnesses.values, nonce);
    return new CompositeProofG1(proof);
  }

  /**
   * Generate the composite proof using a `QuasiProofSpecG1`
   * @param proofSpec
   * @param witnesses
   * @param nonce
   */
  static generateUsingQuasiProofSpec(
    proofSpec: QuasiProofSpecG1,
    witnesses: Witnesses,
    nonce?: Uint8Array
  ): CompositeProofG1 {
    return CompositeProofG1.generateWithDeconstructedProofSpec(
      proofSpec.statements,
      proofSpec.metaStatements,
      witnesses,
      proofSpec.setupParams,
      proofSpec.context,
      nonce
    );
  }

  /**
   * Verify this composite proof using a `ProofSpec`
   * @param proofSpec
   * @param nonce
   */
  verify(proofSpec: ProofSpecG1, nonce?: Uint8Array): VerifyResult {
    return verifyCompositeProofG1(this.value, proofSpec.value, nonce);
  }

  /**
   * Verify this composite proof using a `QuasiProofSpecG1`
   * @param proofSpec
   * @param nonce
   */
  verifyUsingQuasiProofSpec(proofSpec: QuasiProofSpecG1, nonce?: Uint8Array): VerifyResult {
    return this.verifyWithDeconstructedProofSpec(
      proofSpec.statements,
      proofSpec.metaStatements,
      proofSpec.setupParams,
      proofSpec.context,
      nonce
    );
  }

  /**
   * Get the ciphertext for the SAVER statement at index `statementIndex`. The proof involving any SAVER statement also
   * contains the ciphertext corresponding to that statement. Will throw an error if it could not find the ciphertext or
   * statement at that index
   * @param statementIndex
   */
  getSaverCiphertext(statementIndex: number): SaverCiphertext {
    return new SaverCiphertext(saverGetCiphertextFromProof(this.value, statementIndex));
  }

  static generateWithDeconstructedProofSpec(
    statements: Statements,
    metaStatements: MetaStatements,
    witnesses: Witnesses,
    setupParams?: SetupParam[],
    context?: Uint8Array,
    nonce?: Uint8Array
  ): CompositeProofG1 {
    const params = (setupParams ?? new Array<SetupParam>()).map((s) => s.value);
    const proof = generateCompositeProofG1WithDeconstructedProofSpec(
      statements.values,
      metaStatements.values,
      params,
      witnesses.values,
      context,
      nonce
    );
    return new CompositeProofG1(proof);
  }

  verifyWithDeconstructedProofSpec(
    statements: Statements,
    metaStatements: MetaStatements,
    setupParams?: SetupParam[],
    context?: Uint8Array,
    nonce?: Uint8Array
  ): VerifyResult {
    const params = (setupParams ?? new Array<SetupParam>()).map((s) => s.value);
    return verifyCompositeProofG1WithDeconstructedProofSpec(
      this.value,
      statements.values,
      metaStatements.values,
      params,
      context,
      nonce
    );
  }
}
