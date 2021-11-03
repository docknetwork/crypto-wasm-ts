import {MetaStatements, Statements} from "./statement";
import {VerifyResult} from "../../../crypto-wasm/src/js";
import {generateCompositeProof, generateProofSpec, verifyCompositeProof} from "../../../crypto-wasm/src/js";
import {Witnesses} from "./witness";

export class ProofSpec {
    value: Uint8Array

    constructor(statements: Statements, metaStatements: MetaStatements, context?: Uint8Array) {
        this.value = generateProofSpec(statements.values, metaStatements.values, context);
    }
}

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
