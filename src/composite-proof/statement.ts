import { AccumulatorParams } from '@docknetwork/crypto-wasm';
import {
  generateAccumulatorMembershipStatement,
  generatePedersenCommitmentG1Statement,
  generatePoKBBSSignatureStatement,
  generateAccumulatorNonMembershipStatement,
  generateWitnessEqualityMetaStatement
} from '@docknetwork/crypto-wasm';
import { SignatureParamsG1 } from '../bbs-plus';

export class Statement {
  static pedersenCommitmentG1(bases: Uint8Array[], commitment: Uint8Array): Uint8Array {
    return generatePedersenCommitmentG1Statement(bases, commitment);
  }

  static poKBBSSignature(
    sigParams: SignatureParamsG1,
    publicKey: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSSignatureStatement(sigParams.value, publicKey, revealedMessages, encodeMessages);
  }

  static accumulatorMembership(
    params: AccumulatorParams,
    publicKey: Uint8Array,
    provingKey: Uint8Array,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateAccumulatorMembershipStatement(params, publicKey, provingKey, accumulated);
  }

  static accumulatorNonMembership(
    params: AccumulatorParams,
    publicKey: Uint8Array,
    provingKey: Uint8Array,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateAccumulatorNonMembershipStatement(params, publicKey, provingKey, accumulated);
  }
}

export class WitnessEqualityMetaStatement {
  witnessRefs: Set<[number, number]>;

  constructor() {
    this.witnessRefs = new Set<[number, number]>();
  }

  addWitnessRef(statementIndex: number, witnessIndex: number) {
    if (!Number.isInteger(statementIndex) || statementIndex < 0) {
      throw new Error(`Statement index should be a positive integer but was ${statementIndex}`);
    }
    if (!Number.isInteger(witnessIndex) || witnessIndex < 0) {
      throw new Error(`Witness index should be a positive integer but was ${witnessIndex}`);
    }
    this.witnessRefs.add([statementIndex, witnessIndex]);
  }
}

export class MetaStatement {
  static witnessEquality(eq: WitnessEqualityMetaStatement): Uint8Array {
    return generateWitnessEqualityMetaStatement(eq.witnessRefs);
  }
}

export class Statements {
  values: Uint8Array[];

  constructor() {
    this.values = [];
  }

  add(statement: Uint8Array): number {
    this.values.push(statement);
    return this.values.length - 1;
  }
}

export class MetaStatements {
  values: Uint8Array[];

  constructor() {
    this.values = [];
  }

  add(metaStatement: Uint8Array): number {
    this.values.push(metaStatement);
    return this.values.length - 1;
  }
}
