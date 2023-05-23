import {
  generateAccumulatorMembershipStatement,
  generatePedersenCommitmentG1Statement,
  generatePoKBBSPlusSignatureStatement,
  generatePoKBBSSignatureStatement,
  generatePoKPSSignatureStatement,
  generateAccumulatorNonMembershipStatement,
  generateWitnessEqualityMetaStatement,
  generatePedersenCommitmentG1StatementFromParamRefs,
  generatePoKBBSPlusSignatureStatementFromParamRefs,
  generatePoKBBSSignatureStatementFromParamRefs,
  generatePoKPSSignatureStatementFromParamRefs,
  generateAccumulatorMembershipStatementFromParamRefs,
  generateAccumulatorNonMembershipStatementFromParamRefs,
  generateSaverProverStatement,
  generateSaverProverStatementFromParamRefs,
  generateSaverVerifierStatement,
  generateSaverVerifierStatementFromParamRefs,
  generateBoundCheckLegoProverStatement,
  generateBoundCheckLegoProverStatementFromParamRefs,
  generateBoundCheckLegoVerifierStatement,
  generateBoundCheckLegoVerifierStatementFromParamRefs,
  generateR1CSCircomProverStatement,
  generateR1CSCircomProverStatementFromParamRefs,
  generateR1CSCircomVerifierStatement,
  generateR1CSCircomVerifierStatementFromParamRefs,
  R1CS
} from '@docknetwork/crypto-wasm';
import { BBSPlusPublicKeyG2, BBSPlusSignatureParamsG1 } from '../bbs-plus';
import {
  getChunkBitSize,
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
import { AccumulatorParams, AccumulatorPublicKey, MembershipProvingKey, NonMembershipProvingKey } from '../accumulator';
import { AttributeBoundPseudonym, Pseudonym } from '../Pseudonym';
import { isPositiveInteger } from '../util';
import { getR1CS, ParsedR1CSFile } from '../r1cs';
import { BBSSignatureParams } from '../bbs';
import { PSPublicKey, PSSignatureParams } from '../ps';

/**
 * Relation which needs to be proven. Contains any public data that needs to be known to both prover and verifier
 */
export class Statement {
  /**
   * Create statement for proving knowledge of opening of Pedersen commitment with commitment key and commitment in G1
   * @param commitmentKey - commitment key used to create the commitment
   * @param commitment
   */
  static pedersenCommitmentG1(commitmentKey: Uint8Array[], commitment: Uint8Array): Uint8Array {
    return generatePedersenCommitmentG1Statement(commitmentKey, commitment);
  }

  /**
   * Same as `Statement.pedersenCommitmentG1` but does not take the commitment key directly but a reference to it
   * @param commitmentKeyRef
   * @param commitment
   */
  static pedersenCommitmentG1FromSetupParamRef(commitmentKeyRef: number, commitment: Uint8Array): Uint8Array {
    return generatePedersenCommitmentG1StatementFromParamRefs(commitmentKeyRef, commitment);
  }

  /**
   * Create statement for proving knowledge of BBS signature
   * @param sigParams
   * @param publicKey
   * @param revealedMessages
   * @param encodeMessages
   */
  static bbsSignature(
    sigParams: BBSSignatureParams,
    publicKey: BBSPlusPublicKeyG2,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSSignatureStatement(sigParams.value, publicKey.value, revealedMessages, encodeMessages);
  }

  /**
   * Create statement for proving knowledge of BBS+ signature
   * @param sigParams
   * @param publicKey
   * @param revealedMessages
   * @param encodeMessages
   */
  static bbsPlusSignature(
    sigParams: BBSPlusSignatureParamsG1,
    publicKey: BBSPlusPublicKeyG2,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSPlusSignatureStatement(sigParams.value, publicKey.value, revealedMessages, encodeMessages);
  }

  /**
   * Create statement for proving knowledge of Pointcheval-Sanders signature
   * @param sigParams
   * @param publicKey
   * @param revealedMessages
   */
  static psSignature(
    sigParams: PSSignatureParams,
    publicKey: PSPublicKey,
    revealedMessages: Map<number, Uint8Array>
  ): Uint8Array {
    if (sigParams.supportedMessageCount() !== publicKey.supportedMessageCount()) {
      throw new Error(
        `Public key is incompatible with signature params: public key supports ${publicKey.supportedMessageCount()} messages while signature params support ${sigParams.supportedMessageCount()}`
      );
    }
    return generatePoKPSSignatureStatement(sigParams.value, publicKey.value, revealedMessages);
  }

  /**
   * Same as `Statement.bbsSignature` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param sigParamsRef
   * @param publicKeyRef
   * @param revealedMessages
   * @param encodeMessages
   */
  static bbsSignatureFromSetupParamRefs(
    sigParamsRef: number,
    publicKeyRef: number,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSSignatureStatementFromParamRefs(sigParamsRef, publicKeyRef, revealedMessages, encodeMessages);
  }

  /**
   * Same as `Statement.bbsPlusSignature` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param sigParamsRef
   * @param publicKeyRef
   * @param revealedMessages
   * @param encodeMessages
   */
  static bbsPlusSignatureFromSetupParamRefs(
    sigParamsRef: number,
    publicKeyRef: number,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSPlusSignatureStatementFromParamRefs(
      sigParamsRef,
      publicKeyRef,
      revealedMessages,
      encodeMessages
    );
  }

  /**
   * Same as `Statement.psSignature` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param sigParamsRef
   * @param publicKeyRef
   * @param revealedMessages
   */
  static psSignatureFromSetupParamRefs(
    sigParamsRef: number,
    publicKeyRef: number,
    revealedMessages: Map<number, Uint8Array>
  ): Uint8Array {
    return generatePoKPSSignatureStatementFromParamRefs(sigParamsRef, publicKeyRef, revealedMessages);
  }

  /**
   * Create statement for proving knowledge of accumulator membership
   * @param params
   * @param publicKey
   * @param provingKey
   * @param accumulated
   */
  static accumulatorMembership(
    params: AccumulatorParams,
    publicKey: AccumulatorPublicKey,
    provingKey: MembershipProvingKey,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateAccumulatorMembershipStatement(params.value, publicKey.value, provingKey.value, accumulated);
  }

  /**
   * Same as `Statement.accumulatorMembership` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param params
   * @param publicKey
   * @param provingKey
   * @param accumulated
   */
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
    params: AccumulatorParams,
    publicKey: AccumulatorPublicKey,
    provingKey: NonMembershipProvingKey,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateAccumulatorNonMembershipStatement(params.value, publicKey.value, provingKey.value, accumulated);
  }

  /**
   * Same as `Statement.accumulatorNonMembership` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param params
   * @param publicKey
   * @param provingKey
   * @param accumulated
   */
  static accumulatorNonMembershipFromSetupParamRefs(
    params: number,
    publicKey: number,
    provingKey: number,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateAccumulatorNonMembershipStatementFromParamRefs(params, publicKey, provingKey, accumulated);
  }

  /**
   * Create statement for verifiable encryption of a message using SAVER, for the prover. Accepts the parameters in uncompressed form.
   * @param encGens
   * @param commGens
   * @param encryptionKey
   * @param snarkPk
   * @param chunkBitSize - Must be same as the one used by the decryptor to create the parameters.
   */
  static saverProver(
    encGens: SaverEncryptionGensUncompressed,
    commGens: SaverChunkedCommitmentGensUncompressed,
    encryptionKey: SaverEncryptionKeyUncompressed,
    snarkPk: SaverProvingKeyUncompressed,
    chunkBitSize: number
  ): Uint8Array {
    return generateSaverProverStatement(
      getChunkBitSize(chunkBitSize),
      encGens.value,
      commGens.value,
      encryptionKey.value,
      snarkPk.value,
      true
    );
  }

  /**
   * Same as `Statement.saverProver` except that it takes compressed parameters.
   * @param encGens
   * @param commGens
   * @param encryptionKey
   * @param snarkPk
   * @param chunkBitSize - Must be same as the one used by the decryptor to create the parameters.
   */
  static saverProverFromCompressedParams(
    encGens: SaverEncryptionGens,
    commGens: SaverChunkedCommitmentGens,
    encryptionKey: SaverEncryptionKey,
    snarkPk: SaverProvingKey,
    chunkBitSize: number
  ): Uint8Array {
    return generateSaverProverStatement(
      getChunkBitSize(chunkBitSize),
      encGens.value,
      commGens.value,
      encryptionKey.value,
      snarkPk.value,
      false
    );
  }

  /**
   * Same as `Statement.saverProver` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param encGensRef
   * @param commGensRef
   * @param encryptionKeyRef
   * @param snarkPkRef
   * @param chunkBitSize - Must be same as the one used by the decryptor to create the parameters.
   */
  static saverProverFromSetupParamRefs(
    encGensRef: number,
    commGensRef: number,
    encryptionKeyRef: number,
    snarkPkRef: number,
    chunkBitSize: number
  ): Uint8Array {
    return generateSaverProverStatementFromParamRefs(
      getChunkBitSize(chunkBitSize),
      encGensRef,
      commGensRef,
      encryptionKeyRef,
      snarkPkRef
    );
  }

  /**
   * Create statement for verifiable encryption of a message using SAVER, for the verifier. Accepts the parameters in uncompressed form.
   * @param encGens
   * @param commGens
   * @param encryptionKey
   * @param snarkVk,
   * @param chunkBitSize - Must be same as the one used by the decryptor to create the parameters
   */
  static saverVerifier(
    encGens: SaverEncryptionGensUncompressed,
    commGens: SaverChunkedCommitmentGensUncompressed,
    encryptionKey: SaverEncryptionKeyUncompressed,
    snarkVk: SaverVerifyingKeyUncompressed,
    chunkBitSize: number
  ): Uint8Array {
    return generateSaverVerifierStatement(
      getChunkBitSize(chunkBitSize),
      encGens.value,
      commGens.value,
      encryptionKey.value,
      snarkVk.value,
      true
    );
  }

  /**
   * Same as `Statement.saverVerifier` except that it takes compressed parameters.
   * @param encGens
   * @param commGens
   * @param encryptionKey
   * @param snarkVk
   * @param chunkBitSize - Must be same as the one used by the decryptor to create the parameters.
   */
  static saverVerifierFromCompressedParams(
    encGens: SaverEncryptionGens,
    commGens: SaverChunkedCommitmentGens,
    encryptionKey: SaverEncryptionKey,
    snarkVk: SaverVerifyingKey,
    chunkBitSize: number
  ): Uint8Array {
    return generateSaverVerifierStatement(
      getChunkBitSize(chunkBitSize),
      encGens.value,
      commGens.value,
      encryptionKey.value,
      snarkVk.value,
      false
    );
  }

  /**
   * Same as `Statement.saverVerifier` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param encGensRef
   * @param commGensRef
   * @param encryptionKeyRef
   * @param snarkVkRef
   * @param chunkBitSize
   */
  static saverVerifierFromSetupParamRefs(
    encGensRef: number,
    commGensRef: number,
    encryptionKeyRef: number,
    snarkVkRef: number,
    chunkBitSize: number
  ): Uint8Array {
    return generateSaverVerifierStatementFromParamRefs(
      getChunkBitSize(chunkBitSize),
      encGensRef,
      commGensRef,
      encryptionKeyRef,
      snarkVkRef
    );
  }

  /**
   * Create statement for proving bounds of a message using LegoGroth 16, for the prover.
   * @param min - Inclusive lower bound on the message, must be a positive integer.
   * @param max - Inclusive upper bound on the message, must be a positive integer.
   * @param snarkPk - Proving key for LegoGroth16
   */
  static boundCheckProver(min: number, max: number, snarkPk: LegoProvingKeyUncompressed): Uint8Array {
    return generateBoundCheckLegoProverStatement(min, max, snarkPk.value, true);
  }

  /**
   * Same as `Statement.boundCheckProver` except that it takes compressed parameters.
   * @param min - Inclusive lower bound on the message.
   * @param max - Inclusive upper bound on the message.
   * @param snarkPk - Proving key for LegoGroth16
   */
  static boundCheckProverFromCompressedParams(min: number, max: number, snarkPk: LegoProvingKey): Uint8Array {
    return generateBoundCheckLegoProverStatement(min, max, snarkPk.value, false);
  }

  /**
   * Same as `Statement.boundCheckProver` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param min - Inclusive lower bound on the message.
   * @param max - Inclusive upper bound on the message.
   * @param snarkPkRef - Index of proving key in array of `SetupParam`
   */
  static boundCheckProverFromSetupParamRefs(min: number, max: number, snarkPkRef: number): Uint8Array {
    return generateBoundCheckLegoProverStatementFromParamRefs(min, max, snarkPkRef);
  }

  /**
   * Create statement for proving bounds of a message using LegoGroth 16, for the verifier.
   * @param min - Inclusive lower bound on the message, must be a positive integer.
   * @param max - Inclusive upper bound on the message, must be a positive integer.
   * @param snarkVk - Verifying key for LegoGroth16
   */
  static boundCheckVerifier(min: number, max: number, snarkVk: LegoVerifyingKeyUncompressed): Uint8Array {
    return generateBoundCheckLegoVerifierStatement(min, max, snarkVk.value, true);
  }

  /**
   * Same as `Statement.boundCheckVerifier` except that it takes compressed parameters.
   * @param min - Inclusive lower bound on the message.
   * @param max - Inclusive upper bound on the message.
   * @param snarkVk - Verifying key for LegoGroth16
   */
  static boundCheckVerifierFromCompressedParams(min: number, max: number, snarkVk: LegoVerifyingKey): Uint8Array {
    return generateBoundCheckLegoVerifierStatement(min, max, snarkVk.value, false);
  }

  /**
   * Same as `Statement.boundCheckVerifier` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param min - Inclusive lower bound on the message.
   * @param max - Inclusive upper bound on the message.
   * @param snarkVkRef - Index of verifying key in array of `SetupParam`
   */
  static boundCheckVerifierFromSetupParamRefs(min: number, max: number, snarkVkRef: number): Uint8Array {
    return generateBoundCheckLegoVerifierStatementFromParamRefs(min, max, snarkVkRef);
  }

  /**
   * Statement for proving knowledge of secret key behind pseudonym
   * @param pseudonym
   * @param base
   */
  static pseudonym(pseudonym: Pseudonym, base: Uint8Array): Uint8Array {
    return Statement.pedersenCommitmentG1([base], pseudonym.value);
  }

  /**
   * Statement for proving knowledge of secret key and attributes behind pseudonym
   * @param pseudonym
   * @param basesForAttributes
   * @param baseForSecretKey
   */
  static attributeBoundPseudonym(
    pseudonym: AttributeBoundPseudonym,
    basesForAttributes: Uint8Array[],
    baseForSecretKey?: Uint8Array
  ): Uint8Array {
    const b = [...basesForAttributes];
    if (baseForSecretKey !== undefined) {
      b.push(baseForSecretKey);
    }
    return Statement.pedersenCommitmentG1(b, pseudonym.value);
  }

  static r1csCircomProver(
    r1cs: R1CS | ParsedR1CSFile,
    wasmBytes: Uint8Array,
    snarkPk: LegoProvingKeyUncompressed
  ): Uint8Array {
    const processedR1cs = getR1CS(r1cs);
    return generateR1CSCircomProverStatement(
      processedR1cs.curveName,
      processedR1cs.numPublic,
      processedR1cs.numPrivate,
      processedR1cs.constraints,
      wasmBytes,
      snarkPk.value,
      true
    );
  }

  static r1csCircomProverFromCompressedParams(
    r1cs: R1CS | ParsedR1CSFile,
    wasmBytes: Uint8Array,
    snarkPk: LegoProvingKey
  ): Uint8Array {
    const processedR1cs = getR1CS(r1cs);
    return generateR1CSCircomProverStatement(
      processedR1cs.curveName,
      processedR1cs.numPublic,
      processedR1cs.numPrivate,
      processedR1cs.constraints,
      wasmBytes,
      snarkPk.value,
      false
    );
  }

  static r1csCircomProverFromSetupParamRefs(processedR1cs: number, wasmBytes: number, snarkPkRef: number): Uint8Array {
    return generateR1CSCircomProverStatementFromParamRefs(processedR1cs, wasmBytes, snarkPkRef);
  }

  static r1csCircomVerifier(publicInputs: Uint8Array[], snarkVk: LegoVerifyingKeyUncompressed): Uint8Array {
    return generateR1CSCircomVerifierStatement(publicInputs, snarkVk.value, true);
  }

  static r1csCircomVerifierFromCompressedParams(publicInputs: Uint8Array[], snarkVk: LegoVerifyingKey): Uint8Array {
    return generateR1CSCircomVerifierStatement(publicInputs, snarkVk.value, false);
  }

  static r1csCircomVerifierFromSetupParamRefs(publicInputsRef: number, snarkVkRef: number): Uint8Array {
    return generateR1CSCircomVerifierStatementFromParamRefs(publicInputsRef, snarkVkRef);
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
    if (!isPositiveInteger(statementIndex)) {
      throw new Error(`Statement index should be a positive integer but was ${statementIndex}`);
    }
    if (!isPositiveInteger(witnessIndex)) {
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

  constructor(statements: Uint8Array | Uint8Array[] = []) {
    this.values = Array.isArray(statements) ? statements : [statements];
  }

  /**
   * Add a new statement to the end of the list. Returns the index (id) of the added statement. This index is part of the witness reference.
   * @param statement
   */
  add(statement: Uint8Array): number {
    return this.values.push(statement) - 1;
  }

  /**
   * Add new statements to the end of the list. Returns the indices (ids) of the added statements. These indices are part of the witness reference.
   * @param statement
   */
  append(statements: Statements | Uint8Array[]): number[] {
    const rawStatements = statements instanceof Statements ? statements.values : statements;
    const indices = Array.from({ length: rawStatements.length }, (_, i) => this.values.length + i);
    this.values = this.values.concat(rawStatements);

    return indices;
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

  addWitnessEquality(wq: WitnessEqualityMetaStatement) {
    this.values.push(MetaStatement.witnessEquality(wq));
    return this.values.length - 1;
  }
}
