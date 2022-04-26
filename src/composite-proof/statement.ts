import {
  generateAccumulatorMembershipStatement,
  generatePedersenCommitmentG1Statement,
  generatePoKBBSSignatureStatement,
  generateAccumulatorNonMembershipStatement,
  generateWitnessEqualityMetaStatement,
  generatePedersenCommitmentG1StatementFromParamRefs,
  generatePoKBBSSignatureStatementFromParamRefs,
  generateAccumulatorMembershipStatementFromParamRefs,
  generateAccumulatorNonMembershipStatementFromParamRefs,
  generateSaverProverStatement,
  generateSaverProverStatementFromParamRefs,
  generateSaverVerifierStatement,
  generateSaverVerifierStatementFromParamRefs,
  generateBoundCheckLegoProverStatement,
  generateBoundCheckLegoProverStatementFromParamRefs,
  generateBoundCheckLegoVerifierStatement,
  generateBoundCheckLegoVerifierStatementFromParamRefs
} from '@docknetwork/crypto-wasm';
import { SignatureParamsG1 } from '../bbs-plus';
import {
  SaverChunkedCommitmentGens,
  SaverChunkedCommitmentGensUncompressed,
  SaverEncryptionGens,
  SaverEncryptionGensUncompressed,
  SaverEncryptionKey,
  SaverEncryptionKeyUncompressed,
  SaverProvingKey,
  SaverProvingKeyUncompressed,
  SaverVerifyingKey,
  SaverVerifyingKeyUncompressed
} from '../saver';
import {
  LegoProvingKey,
  LegoVerifyingKey,
  LegoProvingKeyUncompressed,
  LegoVerifyingKeyUncompressed
} from '../legosnark';

/**
 * Relation which needs to be proven. Contains any public data that needs to be known to both prover and verifier
 */
export class Statement {
  /**
   * Create statement for proving knowledge of opening of Pedersen commitment with commitment key and commitment in G1
   * @param commitmentKey - commitment key
   * @param commitment
   */
  static pedersenCommitmentG1(commitmentKey: Uint8Array[], commitment: Uint8Array): Uint8Array {
    return generatePedersenCommitmentG1Statement(commitmentKey, commitment);
  }

  static pedersenCommitmentG1FromSetupParamRef(commitmentKeyRef: number, commitment: Uint8Array): Uint8Array {
    return generatePedersenCommitmentG1StatementFromParamRefs(commitmentKeyRef, commitment);
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

  static bbsSignatureFromSetupParamRefs(
    sigParamsRef: number,
    publicKeyRef: number,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSSignatureStatementFromParamRefs(sigParamsRef, publicKeyRef, revealedMessages, encodeMessages);
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

  static accumulatorMembershipFromSetupParamRefs(
    params: number,
    publicKey: number,
    provingKey: number,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateAccumulatorMembershipStatementFromParamRefs(params, publicKey, provingKey, accumulated);
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

  static accumulatorNonMembershipFromSetupParamRefs(
    params: number,
    publicKey: number,
    provingKey: number,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateAccumulatorNonMembershipStatementFromParamRefs(params, publicKey, provingKey, accumulated);
  }

  static saverProver(
    chunkBitSize: number,
    encGens: SaverEncryptionGensUncompressed,
    commGens: SaverChunkedCommitmentGensUncompressed,
    encryptionKey: SaverEncryptionKeyUncompressed,
    snarkPk: SaverProvingKeyUncompressed
  ): Uint8Array {
    return generateSaverProverStatement(
      chunkBitSize,
      encGens.value,
      commGens.value,
      encryptionKey.value,
      snarkPk.value,
      true
    );
  }

  static saverProverFromCompressedParams(
    chunkBitSize: number,
    encGens: SaverEncryptionGens,
    commGens: SaverChunkedCommitmentGens,
    encryptionKey: SaverEncryptionKey,
    snarkPk: SaverProvingKey
  ): Uint8Array {
    return generateSaverProverStatement(
      chunkBitSize,
      encGens.value,
      commGens.value,
      encryptionKey.value,
      snarkPk.value,
      false
    );
  }

  static saverProverFromSetupParamRefs(
    chunkBitSize: number,
    encGens: number,
    commGens: number,
    encryptionKey: number,
    snarkPk: number
  ): Uint8Array {
    return generateSaverProverStatementFromParamRefs(chunkBitSize, encGens, commGens, encryptionKey, snarkPk);
  }

  static saverVerifier(
    chunkBitSize: number,
    encGens: SaverEncryptionGensUncompressed,
    commGens: SaverChunkedCommitmentGensUncompressed,
    encryptionKey: SaverEncryptionKeyUncompressed,
    snarkVk: SaverVerifyingKeyUncompressed
  ): Uint8Array {
    return generateSaverVerifierStatement(
      chunkBitSize,
      encGens.value,
      commGens.value,
      encryptionKey.value,
      snarkVk.value,
      true
    );
  }

  static saverVerifierFromCompressedParams(
    chunkBitSize: number,
    encGens: SaverEncryptionGens,
    commGens: SaverChunkedCommitmentGens,
    encryptionKey: SaverEncryptionKey,
    snarkVk: SaverVerifyingKey
  ): Uint8Array {
    return generateSaverVerifierStatement(
      chunkBitSize,
      encGens.value,
      commGens.value,
      encryptionKey.value,
      snarkVk.value,
      false
    );
  }

  static saverVerifierFromSetupParamRefs(
    chunkBitSize: number,
    encGens: number,
    commGens: number,
    encryptionKey: number,
    snarkVk: number
  ): Uint8Array {
    return generateSaverVerifierStatementFromParamRefs(chunkBitSize, encGens, commGens, encryptionKey, snarkVk);
  }

  static boundCheckProver(min: number, max: number, snarkPk: LegoProvingKeyUncompressed): Uint8Array {
    return generateBoundCheckLegoProverStatement(min, max, snarkPk.value, true);
  }

  static boundCheckProverFromCompressedParams(min: number, max: number, snarkPk: LegoProvingKey): Uint8Array {
    return generateBoundCheckLegoProverStatement(min, max, snarkPk.value, false);
  }

  static boundCheckProverFromSetupParamRefs(min: number, max: number, snarkPkRef: number): Uint8Array {
    return generateBoundCheckLegoProverStatementFromParamRefs(min, max, snarkPkRef);
  }

  static boundCheckVerifier(min: number, max: number, snarkVk: LegoVerifyingKeyUncompressed): Uint8Array {
    return generateBoundCheckLegoVerifierStatement(min, max, snarkVk.value, true);
  }

  static boundCheckVerifierFromCompressedParams(min: number, max: number, snarkVk: LegoVerifyingKey): Uint8Array {
    return generateBoundCheckLegoVerifierStatement(min, max, snarkVk.value, false);
  }

  static boundCheckVerifierFromSetupParamRefs(min: number, max: number, snarkVkRef: number): Uint8Array {
    return generateBoundCheckLegoVerifierStatementFromParamRefs(min, max, snarkVkRef);
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
