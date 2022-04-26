import { MetaStatements, Statements } from './statement';
import {
  generateCompositeProofG1,
  generateProofSpecG1,
  verifyCompositeProofG1,
  generateCompositeProofG1WithDeconstructedProofSpec,
  verifyCompositeProofG1WithDeconstructedProofSpec,
  VerifyResult,
  saverGetCiphertextFromProof
} from '@docknetwork/crypto-wasm';
import { Witnesses } from './witness';
import { SetupParam } from './setup-param';
import { SaverCiphertext } from '../saver';

/**
 * The specification used to construct the proof. This contains all the statements and the meta statements.
 */
export class ProofSpecG1 {
  value: Uint8Array;

  constructor(
    statements: Statements,
    metaStatements: MetaStatements,
    setupParams?: SetupParam[],
    context?: Uint8Array
  ) {
    /*const params: Uint8Array[] = [];
    if (setupParams !== undefined) {
      setupParams?.forEach((s) => params.push(s.value));
    }*/
    const params = (setupParams ?? new Array<SetupParam>()).map((s) => s.value);
    this.value = generateProofSpecG1(statements.values, metaStatements.values, params, context);
  }
}

/**
 * A proof of 1 or more statements and meta statements.
 */
export class CompositeProofG1 {
  value: Uint8Array;

  constructor(proof: Uint8Array) {
    this.value = proof;
  }

  static generate(proofSpec: ProofSpecG1, witnesses: Witnesses, nonce?: Uint8Array): CompositeProofG1 {
    const proof = generateCompositeProofG1(proofSpec.value, witnesses.values, nonce);
    return new CompositeProofG1(proof);
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

  verify(proofSpec: ProofSpecG1, nonce?: Uint8Array): VerifyResult {
    return verifyCompositeProofG1(this.value, proofSpec.value, nonce);
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

  getSaverCiphertext(statementIndex: number): SaverCiphertext {
    return new SaverCiphertext(saverGetCiphertextFromProof(this.value, statementIndex));
  }
}
