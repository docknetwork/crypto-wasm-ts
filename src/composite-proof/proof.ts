import { MetaStatements, Statements } from './statement';
import { VerifyResult } from '@docknetwork/crypto-wasm';
import { generateCompositeProof, generateProofSpec, verifyCompositeProof } from '@docknetwork/crypto-wasm';
import { Witnesses } from './witness';

/**
 * The specification used to construct the proof. This contains all the statements and the meta statements.
 */
export class ProofSpec {
  value: Uint8Array;

  constructor(statements: Statements, metaStatements: MetaStatements, context?: Uint8Array) {
    this.value = generateProofSpec(statements.values, metaStatements.values, context);
  }
}

/**
 * A proof of 1 or more statements and meta statements.
 */
export class CompositeProof {
  value: Uint8Array;

  constructor(proof: Uint8Array) {
    this.value = proof;
  }

  static generate(proofSpec: ProofSpec, witnesses: Witnesses, nonce?: Uint8Array): CompositeProof {
    const proof = generateCompositeProof(proofSpec.value, witnesses.values, nonce);
    return new CompositeProof(proof);
  }

  verify(proofSpec: ProofSpec, nonce?: Uint8Array): VerifyResult {
    return verifyCompositeProof(this.value, proofSpec.value, nonce);
  }
}
