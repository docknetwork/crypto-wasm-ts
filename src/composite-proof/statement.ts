import {
  generateAccumulatorMembershipStatement,
  generatePedersenCommitmentG1Statement,
  generatePoKBBSSignatureStatement,
  generateAccumulatorNonMembershipStatement,
  generateWitnessEqualityMetaStatement
} from '@docknetwork/crypto-wasm';
import { SignatureParamsG1 } from '../bbs-plus';

/**
 * Relation which needs to be proven. Contains any public data that needs to be known to both prover and verifier
 */
export class Statement {
  /**
   * Create statement for proving knowledge of opening of Pedersen commitment.
   * @param bases - commitment key (public params)
   * @param commitment
   */
  static pedersenCommitmentG1(bases: Uint8Array[], commitment: Uint8Array): Uint8Array {
    return generatePedersenCommitmentG1Statement(bases, commitment);
  }

  /**
   * Create statement for proving knowledge of BBS+ signature
   * @param sigParams
   * @param publicKey
   * @param revealedMessages
   * @param encodeMessages
   */
  static bbsSignature(
    sigParams: SignatureParamsG1,
    publicKey: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSSignatureStatement(sigParams.value, publicKey, revealedMessages, encodeMessages);
  }

  /**
   * Create statement for proving knowledge of accumulator membership
   * @param params
   * @param publicKey
   * @param provingKey
   * @param accumulated
   */
  static accumulatorMembership(
    params: Uint8Array,
    publicKey: Uint8Array,
    provingKey: Uint8Array,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateAccumulatorMembershipStatement(params, publicKey, provingKey, accumulated);
  }

  /**
   * Create statement for proving knowledge of accumulator non-membership
   * @param params
   * @param publicKey
   * @param provingKey
   * @param accumulated
   */
  static accumulatorNonMembership(
    params: Uint8Array,
    publicKey: Uint8Array,
    provingKey: Uint8Array,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateAccumulatorNonMembershipStatement(params, publicKey, provingKey, accumulated);
  }
}

/**
 * Meta statement used to express equality between witnesses of several statements or of the same statement.
 * Each witness is known by a pair of indices, the first index is the statement index and second is witness index in a particular
 * statement.
 */
export class WitnessEqualityMetaStatement {
  witnessRefs: Set<[number, number]>;

  constructor() {
    this.witnessRefs = new Set<[number, number]>();
  }

  /**
   * Add a witness reference
   * @param statementIndex
   * @param witnessIndex
   */
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

/**
 * A collection of statements
 */
export class Statements {
  values: Uint8Array[];

  constructor() {
    this.values = [];
  }

  /**
   * Add a new statement. Returns the index (id) of the added statement. This index is part of the witness reference.
   * @param statement
   */
  add(statement: Uint8Array): number {
    this.values.push(statement);
    return this.values.length - 1;
  }
}

/**
 * Expresses a relation between 1 or more statement or several witnesses of the same statement
 */
export class MetaStatements {
  values: Uint8Array[];

  constructor() {
    this.values = [];
  }

  /**
   * Add a new meta statement.
   * @param metaStatement
   */
  add(metaStatement: Uint8Array): number {
    this.values.push(metaStatement);
    return this.values.length - 1;
  }
}
