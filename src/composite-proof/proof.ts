import { MetaStatements, Statements } from './statement';
import { VerifyResult } from '@docknetwork/crypto-wasm';
import { generateCompositeProofG1, generateProofSpecG1, verifyCompositeProofG1 } from '@docknetwork/crypto-wasm';
import { Witnesses } from './witness';

/**
 * The specification used to construct the proof. This contains all the statements and the meta statements.
 */
export class ProofSpecG1 {
  value: Uint8Array;

  constructor(statements: Statements, metaStatements: MetaStatements, context?: Uint8Array) {
    this.value = generateProofSpecG1(statements.values, metaStatements.values, context);
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

  verify(proofSpec: ProofSpecG1, nonce?: Uint8Array): VerifyResult {
    return verifyCompositeProofG1(this.value, proofSpec.value, nonce);
  }
}
