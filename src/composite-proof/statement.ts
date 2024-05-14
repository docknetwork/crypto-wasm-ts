import {
  generateAccumulatorMembershipStatement,
  generatePedersenCommitmentG1Statement,
  generatePoKBBSSignatureProverStatement,
  generatePoKBBSSignatureVerifierStatement,
  generatePoKBBSPlusSignatureProverStatement,
  generatePoKBBSPlusSignatureVerifierStatement,
  generatePoKBBSSignatureProverStatementFromParamRefs,
  generatePoKBBSSignatureVerifierStatementFromParamRefs,
  generatePoKBBSPlusSignatureProverStatementFromParamRefs,
  generatePoKBBSPlusSignatureVerifierStatementFromParamRefs,
  generatePoKPSSignatureStatement,
  generateAccumulatorNonMembershipStatement,
  generateWitnessEqualityMetaStatement,
  generatePedersenCommitmentG1StatementFromParamRefs,
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
  R1CS,
  generateBoundCheckBppStatement,
  generateBoundCheckBppStatementFromParamRefs,
  generateBoundCheckSmcStatement,
  generateBoundCheckSmcStatementFromParamRefs,
  generateBoundCheckSmcWithKVProverStatement,
  generateBoundCheckSmcWithKVProverStatementFromParamRefs,
  generateBoundCheckSmcWithKVVerifierStatement,
  generateBoundCheckSmcWithKVVerifierStatementFromParamRefs,
  generatePublicInequalityG1Statement,
  generatePublicInequalityG1StatementFromParamRefs,
  generatePoKBDDT16MacStatementFromParamRefs,
  generatePoKBDDT16MacStatement,
  generatePoKBDDT16MacFullVerifierStatement,
  generatePoKBDDT16MacFullVerifierStatementFromParamRefs,
  generateAccumulatorKVFullVerifierMembershipStatement,
  generateAccumulatorKVMembershipStatement,
  generateKBUniversalAccumulatorKVNonMembershipStatement,
  generateKBUniversalAccumulatorKVFullVerifierNonMembershipStatement,
  generateKBUniversalAccumulatorKVFullVerifierMembershipStatement,
  generateKBUniversalAccumulatorKVMembershipStatement,
  generateKBUniversalAccumulatorMembershipProverStatement,
  generateKBUniversalAccumulatorMembershipVerifierStatement,
  generateKBUniversalAccumulatorMembershipVerifierStatementFromParamRefs,
  generateKBUniversalAccumulatorNonMembershipProverStatement,
  generateKBUniversalAccumulatorNonMembershipVerifierStatement,
  generateKBUniversalAccumulatorNonMembershipVerifierStatementFromParamRefs
} from 'crypto-wasm-new';
import { BBSPlusPublicKeyG2, BBSPlusSignatureParamsG1 } from '../bbs-plus';
import {
  getChunkBitSize,
  SaverChunkedCommitmentKey,
  SaverChunkedCommitmentKeyUncompressed,
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
import {
  AccumulatorParams,
  AccumulatorPublicKey,
  AccumulatorSecretKey,
  MembershipProvingKey,
  NonMembershipProvingKey
} from '../accumulator';
import { AttributeBoundPseudonym, Pseudonym } from '../Pseudonym';
import { isPositiveInteger } from '../util';
import { BBSSignatureParams } from '../bbs';
import { PSPublicKey, PSSignatureParams } from '../ps';
import { getR1CS, ParsedR1CSFile } from '../r1cs/file';
import {
  BoundCheckBppParams,
  BoundCheckBppParamsUncompressed,
  BoundCheckSmcParams,
  BoundCheckSmcParamsUncompressed,
  BoundCheckSmcWithKVProverParams,
  BoundCheckSmcWithKVProverParamsUncompressed,
  BoundCheckSmcWithKVVerifierParams,
  BoundCheckSmcWithKVVerifierParamsUncompressed
} from '../bound-check';
import { PederCommKey, PederCommKeyUncompressed } from '../ped-com';
import { BDDT16MacParams, BDDT16MacSecretKey } from '../bddt16-mac';

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

  static bbsSignatureProver(
    sigParams: BBSSignatureParams,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSSignatureProverStatement(sigParams.value, revealedMessages, encodeMessages);
  }

  /**
   * Create statement for proving knowledge of BBS signature
   * @param sigParams
   * @param publicKey
   * @param revealedMessages
   * @param encodeMessages
   */
  static bbsSignatureVerifier(
    sigParams: BBSSignatureParams,
    publicKey: BBSPlusPublicKeyG2,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSSignatureVerifierStatement(sigParams.value, publicKey.value, revealedMessages, encodeMessages);
  }

  static bbsPlusSignatureProver(
    sigParams: BBSPlusSignatureParamsG1,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSPlusSignatureProverStatement(sigParams.value, revealedMessages, encodeMessages);
  }

  /**
   * Create statement for proving knowledge of BBS+ signature
   * @param sigParams
   * @param publicKey
   * @param revealedMessages
   * @param encodeMessages
   */
  static bbsPlusSignatureVerifier(
    sigParams: BBSPlusSignatureParamsG1,
    publicKey: BBSPlusPublicKeyG2,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSPlusSignatureVerifierStatement(
      sigParams.value,
      publicKey.value,
      revealedMessages,
      encodeMessages
    );
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

  static bbsSignatureProverFromSetupParamRefs(
    sigParamsRef: number,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSSignatureProverStatementFromParamRefs(sigParamsRef, revealedMessages, encodeMessages);
  }

  /**
   * Same as `Statement.bbsSignatureVerifier` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param sigParamsRef
   * @param publicKeyRef
   * @param revealedMessages
   * @param encodeMessages
   */
  static bbsSignatureVerifierFromSetupParamRefs(
    sigParamsRef: number,
    publicKeyRef: number,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSSignatureVerifierStatementFromParamRefs(
      sigParamsRef,
      publicKeyRef,
      revealedMessages,
      encodeMessages
    );
  }


  static bbsPlusSignatureProverFromSetupParamRefs(
    sigParamsRef: number,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSPlusSignatureProverStatementFromParamRefs(sigParamsRef, revealedMessages, encodeMessages);
  }

  /**
   * Same as `Statement.bbsPlusSignatureVerifier` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param sigParamsRef
   * @param publicKeyRef
   * @param revealedMessages
   * @param encodeMessages
   */
  static bbsPlusSignatureVerifierFromSetupParamRefs(
    sigParamsRef: number,
    publicKeyRef: number,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBBSPlusSignatureVerifierStatementFromParamRefs(
      sigParamsRef,
      publicKeyRef,
      revealedMessages,
      encodeMessages
    );
  }

  static bddt16Mac(
    macParams: BDDT16MacParams,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBDDT16MacStatement(macParams.value, revealedMessages, encodeMessages);
  }

  static bddt16MacFullVerifier(
    macParams: BDDT16MacParams,
    secretKey: BDDT16MacSecretKey,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBDDT16MacFullVerifierStatement(
      macParams.value,
      secretKey.value,
      revealedMessages,
      encodeMessages
    );
  }

  static bddt16MacFromSetupParamRefs(
    macParamsRef: number,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBDDT16MacStatementFromParamRefs(macParamsRef, revealedMessages, encodeMessages);
  }

  static bddt16MacFullVerifierFromSetupParamRefs(
    macParamsRef: number,
    secretKey: BDDT16MacSecretKey,
    revealedMessages: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
    return generatePoKBDDT16MacFullVerifierStatementFromParamRefs(
      macParamsRef,
      secretKey.value,
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
   * Create statement for proving knowledge of VB accumulator membership
   * @param params
   * @param publicKey
   * @param provingKey
   * @param accumulated
   */
  static vbAccumulatorMembership(
    params: AccumulatorParams,
    publicKey: AccumulatorPublicKey,
    provingKey: MembershipProvingKey,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateAccumulatorMembershipStatement(params.value, publicKey.value, provingKey.value, accumulated);
  }

  /**
   * Same as `Statement.vbAccumulatorMembership` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param params
   * @param publicKey
   * @param provingKey
   * @param accumulated
   */
  static vbAccumulatorMembershipFromSetupParamRefs(
    params: number,
    publicKey: number,
    provingKey: number,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateAccumulatorMembershipStatementFromParamRefs(params, publicKey, provingKey, accumulated);
  }

  /**
   * Create statement for proving knowledge of VB accumulator non-membership
   * @param params
   * @param publicKey
   * @param provingKey
   * @param accumulated
   */
  static vbAccumulatorNonMembership(
    params: AccumulatorParams,
    publicKey: AccumulatorPublicKey,
    provingKey: NonMembershipProvingKey,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateAccumulatorNonMembershipStatement(params.value, publicKey.value, provingKey.value, accumulated);
  }

  /**
   * Same as `Statement.vbAccumulatorNonMembership` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param params
   * @param publicKey
   * @param provingKey
   * @param accumulated
   */
  static vbAccumulatorNonMembershipFromSetupParamRefs(
    params: number,
    publicKey: number,
    provingKey: number,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateAccumulatorNonMembershipStatementFromParamRefs(params, publicKey, provingKey, accumulated);
  }

  static vbAccumulatorMembershipKV(accumulated: Uint8Array): Uint8Array {
    return generateAccumulatorKVMembershipStatement(accumulated);
  }

  static vbAccumulatorMembershipKVFullVerifier(secretKey: AccumulatorSecretKey, accumulated: Uint8Array): Uint8Array {
    return generateAccumulatorKVFullVerifierMembershipStatement(secretKey.value, accumulated);
  }

  /**
   * Create statement for proving knowledge of KB universal accumulator membership
   * @param accumulated
   */
  static kbUniAccumulatorMembershipProver(accumulated: Uint8Array): Uint8Array {
    return generateKBUniversalAccumulatorMembershipProverStatement(accumulated);
  }

  /**
   * Create statement for verifying knowledge of KB universal accumulator membership
   * @param params
   * @param publicKey
   * @param accumulated
   */
  static kbUniAccumulatorMembershipVerifier(
    params: AccumulatorParams,
    publicKey: AccumulatorPublicKey,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateKBUniversalAccumulatorMembershipVerifierStatement(params.value, publicKey.value, accumulated);
  }

  /**
   * Same as `Statement.kbUniAccumulatorMembershipVerifier` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param params
   * @param publicKey
   * @param accumulated
   */
  static kbUniAccumulatorMembershipVerifierFromSetupParamRefs(
    params: number,
    publicKey: number,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateKBUniversalAccumulatorMembershipVerifierStatementFromParamRefs(params, publicKey, accumulated);
  }

  /**
   * Create statement for proving knowledge of ¸ non-membership
   * @param accumulated
   */
  static kbUniAccumulatorNonMembershipProver(accumulated: Uint8Array): Uint8Array {
    return generateKBUniversalAccumulatorNonMembershipProverStatement(accumulated);
  }

  /**
   * Create statement for verifying knowledge of KB universal accumulator non-membership
   * @param params
   * @param publicKey
   * @param accumulated
   */
  static kbUniAccumulatorNonMembershipVerifier(
    params: AccumulatorParams,
    publicKey: AccumulatorPublicKey,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateKBUniversalAccumulatorNonMembershipVerifierStatement(params.value, publicKey.value, accumulated);
  }

  /**
   * Same as `Statement.kbUniAccumulatorNonMembershipVerifier` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param params
   * @param publicKey
   * @param accumulated
   */
  static kbUniAccumulatorNonMembershipVerifierFromSetupParamRefs(
    params: number,
    publicKey: number,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateKBUniversalAccumulatorNonMembershipVerifierStatementFromParamRefs(params, publicKey, accumulated);
  }

  static kbUniAccumulatorMembershipKV(accumulated: Uint8Array): Uint8Array {
    return generateKBUniversalAccumulatorKVMembershipStatement(accumulated);
  }

  static kbUniAccumulatorMembershipKVFullVerifier(
    secretKey: AccumulatorSecretKey,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateKBUniversalAccumulatorKVFullVerifierMembershipStatement(secretKey.value, accumulated);
  }

  static kbUniAccumulatorNonMembershipKV(accumulated: Uint8Array): Uint8Array {
    return generateKBUniversalAccumulatorKVNonMembershipStatement(accumulated);
  }

  static kbUniAccumulatorNonMembershipKVFullVerifier(
    secretKey: AccumulatorSecretKey,
    accumulated: Uint8Array
  ): Uint8Array {
    return generateKBUniversalAccumulatorKVFullVerifierNonMembershipStatement(secretKey.value, accumulated);
  }

  /**
   * Create statement for verifiable encryption of a message using SAVER, for the prover. Accepts the parameters in uncompressed form.
   * @param encGens
   * @param commKey
   * @param encryptionKey
   * @param snarkPk
   * @param chunkBitSize - Must be same as the one used by the decryptor to create the parameters.
   */
  static saverProver(
    encGens: SaverEncryptionGensUncompressed,
    commKey: SaverChunkedCommitmentKeyUncompressed,
    encryptionKey: SaverEncryptionKeyUncompressed,
    snarkPk: SaverProvingKeyUncompressed,
    chunkBitSize: number
  ): Uint8Array {
    return generateSaverProverStatement(
      getChunkBitSize(chunkBitSize),
      encGens.value,
      commKey.value,
      encryptionKey.value,
      snarkPk.value,
      true
    );
  }

  /**
   * Same as `Statement.saverProver` except that it takes compressed parameters.
   * @param encGens
   * @param commKey
   * @param encryptionKey
   * @param snarkPk
   * @param chunkBitSize - Must be same as the one used by the decryptor to create the parameters.
   */
  static saverProverFromCompressedParams(
    encGens: SaverEncryptionGens,
    commKey: SaverChunkedCommitmentKey,
    encryptionKey: SaverEncryptionKey,
    snarkPk: SaverProvingKey,
    chunkBitSize: number
  ): Uint8Array {
    return generateSaverProverStatement(
      getChunkBitSize(chunkBitSize),
      encGens.value,
      commKey.value,
      encryptionKey.value,
      snarkPk.value,
      false
    );
  }

  /**
   * Same as `Statement.saverProver` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param encGensRef
   * @param commKeyRef
   * @param encryptionKeyRef
   * @param snarkPkRef
   * @param chunkBitSize - Must be same as the one used by the decryptor to create the parameters.
   */
  static saverProverFromSetupParamRefs(
    encGensRef: number,
    commKeyRef: number,
    encryptionKeyRef: number,
    snarkPkRef: number,
    chunkBitSize: number
  ): Uint8Array {
    return generateSaverProverStatementFromParamRefs(
      getChunkBitSize(chunkBitSize),
      encGensRef,
      commKeyRef,
      encryptionKeyRef,
      snarkPkRef
    );
  }

  /**
   * Create statement for verifiable encryption of a message using SAVER, for the verifier. Accepts the parameters in uncompressed form.
   * @param encGens
   * @param commKey
   * @param encryptionKey
   * @param snarkVk
   * @param chunkBitSize - Must be same as the one used by the decryptor to create the parameters
   */
  static saverVerifier(
    encGens: SaverEncryptionGensUncompressed,
    commKey: SaverChunkedCommitmentKeyUncompressed,
    encryptionKey: SaverEncryptionKeyUncompressed,
    snarkVk: SaverVerifyingKeyUncompressed,
    chunkBitSize: number
  ): Uint8Array {
    return generateSaverVerifierStatement(
      getChunkBitSize(chunkBitSize),
      encGens.value,
      commKey.value,
      encryptionKey.value,
      snarkVk.value,
      true
    );
  }

  /**
   * Same as `Statement.saverVerifier` except that it takes compressed parameters.
   * @param encGens
   * @param commKey
   * @param encryptionKey
   * @param snarkVk
   * @param chunkBitSize - Must be same as the one used by the decryptor to create the parameters.
   */
  static saverVerifierFromCompressedParams(
    encGens: SaverEncryptionGens,
    commKey: SaverChunkedCommitmentKey,
    encryptionKey: SaverEncryptionKey,
    snarkVk: SaverVerifyingKey,
    chunkBitSize: number
  ): Uint8Array {
    return generateSaverVerifierStatement(
      getChunkBitSize(chunkBitSize),
      encGens.value,
      commKey.value,
      encryptionKey.value,
      snarkVk.value,
      false
    );
  }

  /**
   * Same as `Statement.saverVerifier` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param encGensRef
   * @param commGensKey
   * @param encryptionKeyRef
   * @param snarkVkRef
   * @param chunkBitSize
   */
  static saverVerifierFromSetupParamRefs(
    encGensRef: number,
    commGensKey: number,
    encryptionKeyRef: number,
    snarkVkRef: number,
    chunkBitSize: number
  ): Uint8Array {
    return generateSaverVerifierStatementFromParamRefs(
      getChunkBitSize(chunkBitSize),
      encGensRef,
      commGensKey,
      encryptionKeyRef,
      snarkVkRef
    );
  }

  /**
   * Create statement for proving bounds [min, max) of a message using LegoGroth16, for the prover.
   * @param min - Inclusive lower bound on the message, must be a positive integer.
   * @param max - Exclusive upper bound on the message, must be a positive integer.
   * @param snarkPk - Proving key for LegoGroth16
   */
  static boundCheckLegoProver(min: number, max: number, snarkPk: LegoProvingKeyUncompressed): Uint8Array {
    return generateBoundCheckLegoProverStatement(min, max, snarkPk.value, true);
  }

  /**
   * Same as `Statement.boundCheckLegoProver` except that it takes compressed parameters.
   * @param min - Inclusive lower bound on the message.
   * @param max - Exclusive upper bound on the message.
   * @param snarkPk - Proving key for LegoGroth16
   */
  static boundCheckLegoProverFromCompressedParams(min: number, max: number, snarkPk: LegoProvingKey): Uint8Array {
    return generateBoundCheckLegoProverStatement(min, max, snarkPk.value, false);
  }

  /**
   * Same as `Statement.boundCheckLegoProver` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param min - Inclusive lower bound on the message.
   * @param max - Exclusive upper bound on the message.
   * @param snarkPkRef - Index of proving key in array of `SetupParam`
   */
  static boundCheckLegoProverFromSetupParamRefs(min: number, max: number, snarkPkRef: number): Uint8Array {
    return generateBoundCheckLegoProverStatementFromParamRefs(min, max, snarkPkRef);
  }

  /**
   * Create statement for verifying bounds [min, max) of a message using LegoGroth16, for the verifier.
   * @param min - Inclusive lower bound on the message, must be a positive integer.
   * @param max - Exclusive upper bound on the message, must be a positive integer.
   * @param snarkVk - Verifying key for LegoGroth16
   */
  static boundCheckLegoVerifier(min: number, max: number, snarkVk: LegoVerifyingKeyUncompressed): Uint8Array {
    return generateBoundCheckLegoVerifierStatement(min, max, snarkVk.value, true);
  }

  /**
   * Same as `Statement.boundCheckLegoVerifier` except that it takes compressed parameters.
   * @param min - Inclusive lower bound on the message.
   * @param max - Exclusive upper bound on the message.
   * @param snarkVk - Verifying key for LegoGroth16
   */
  static boundCheckLegoVerifierFromCompressedParams(min: number, max: number, snarkVk: LegoVerifyingKey): Uint8Array {
    return generateBoundCheckLegoVerifierStatement(min, max, snarkVk.value, false);
  }

  /**
   * Same as `Statement.boundCheckLegoVerifier` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param min - Inclusive lower bound on the message.
   * @param max - Exclusive upper bound on the message.
   * @param snarkVkRef - Index of verifying key in array of `SetupParam`
   */
  static boundCheckLegoVerifierFromSetupParamRefs(min: number, max: number, snarkVkRef: number): Uint8Array {
    return generateBoundCheckLegoVerifierStatementFromParamRefs(min, max, snarkVkRef);
  }

  /**
   * Statement for proving knowledge of secret key behind pseudonym
   * @param pseudonym
   * @param base
   */
  static pseudonym(pseudonym: Pseudonym, base: Uint8Array): Uint8Array {
    return this.pseudonymVerifier(pseudonym.value, base);
  }

  static pseudonymVerifier(pseudonym: Uint8Array, base: Uint8Array): Uint8Array {
    return Statement.pedersenCommitmentG1([base], pseudonym);
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
    return this.attributeBoundPseudonymVerifier(pseudonym.value, basesForAttributes, baseForSecretKey);
  }

  static attributeBoundPseudonymVerifier(
    pseudonym: Uint8Array,
    basesForAttributes: Uint8Array[],
    baseForSecretKey?: Uint8Array
  ): Uint8Array {
    const b = [...basesForAttributes];
    if (baseForSecretKey !== undefined) {
      b.push(baseForSecretKey);
    }
    return Statement.pedersenCommitmentG1(b, pseudonym);
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

  /**
   * Create statement for proving bounds of a message using Bulletproofs++.
   * @param min - Inclusive lower bound on the message, must be a positive integer.
   * @param max - Exclusive upper bound on the message, must be a positive integer.
   * @param params - Setup params for Bulletproofs++
   */
  static boundCheckBpp(min: number, max: number, params: BoundCheckBppParamsUncompressed): Uint8Array {
    return generateBoundCheckBppStatement(min, max, params.value, true);
  }

  /**
   * Same as `Statement.boundCheckBpp` except that it takes compressed parameters.
   * @param min - Inclusive lower bound on the message.
   * @param max - Exclusive upper bound on the message.
   * @param params - Setup params for Bulletproofs++
   */
  static boundCheckBppFromCompressedParams(min: number, max: number, params: BoundCheckBppParams): Uint8Array {
    return generateBoundCheckBppStatement(min, max, params.value, false);
  }

  /**
   * Same as `Statement.boundCheckBpp` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param min - Inclusive lower bound on the message.
   * @param max - Exclusive upper bound on the message.
   * @param params - Index of setup params in array of `SetupParam`
   */
  static boundCheckBppFromSetupParamRefs(min: number, max: number, params: number): Uint8Array {
    return generateBoundCheckBppStatementFromParamRefs(min, max, params);
  }

  /**
   * Create statement for proving bounds of a message using set-membership check based range proof.
   * @param min - Inclusive lower bound on the message, must be a positive integer.
   * @param max - Exclusive upper bound on the message, must be a positive integer.
   * @param params - Setup params for Bulletproofs++
   */
  static boundCheckSmc(min: number, max: number, params: BoundCheckSmcParamsUncompressed): Uint8Array {
    return generateBoundCheckSmcStatement(min, max, params.value, true);
  }

  /**
   * Same as `Statement.boundCheckSmc` except that it takes compressed parameters.
   * @param min - Inclusive lower bound on the message.
   * @param max - Exclusive upper bound on the message.
   * @param params - Setup params for Bulletproofs++
   */
  static boundCheckSmcFromCompressedParams(min: number, max: number, params: BoundCheckSmcParams): Uint8Array {
    return generateBoundCheckSmcStatement(min, max, params.value, false);
  }

  /**
   * Same as `Statement.boundCheckSmc` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param min - Inclusive lower bound on the message.
   * @param max - Exclusive upper bound on the message.
   * @param params - Index of setup params in array of `SetupParam`
   */
  static boundCheckSmcFromSetupParamRefs(min: number, max: number, params: number): Uint8Array {
    return generateBoundCheckSmcStatementFromParamRefs(min, max, params);
  }

  /**
   * Create statement for proving bounds [min, max) of a message using set-membership check based range proof and keyed verification, for the prover.
   * @param min - Inclusive lower bound on the message, must be a positive integer.
   * @param max - Exclusive upper bound on the message, must be a positive integer.
   * @param params
   */
  static boundCheckSmcWithKVProver(
    min: number,
    max: number,
    params: BoundCheckSmcWithKVProverParamsUncompressed
  ): Uint8Array {
    return generateBoundCheckSmcWithKVProverStatement(min, max, params.value, true);
  }

  /**
   * Same as `Statement.boundCheckSmcWithKVProver` except that it takes compressed parameters.
   * @param min - Inclusive lower bound on the message.
   * @param max - Exclusive upper bound on the message.
   * @param params
   */
  static boundCheckSmcWithKVProverFromCompressedParams(
    min: number,
    max: number,
    params: BoundCheckSmcWithKVProverParams
  ): Uint8Array {
    return generateBoundCheckSmcWithKVProverStatement(min, max, params.value, false);
  }

  /**
   * Same as `Statement.boundCheckSmcWithKVProver` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param min - Inclusive lower bound on the message.
   * @param max - Exclusive upper bound on the message.
   * @param paramsRef - Index of params in array of `SetupParam`
   */
  static boundCheckSmcWithKVProverFromSetupParamRefs(min: number, max: number, paramsRef: number): Uint8Array {
    return generateBoundCheckSmcWithKVProverStatementFromParamRefs(min, max, paramsRef);
  }

  /**
   * Create statement for verifying bounds [min, max) of a message using LegoGroth16, for the verifier.
   * @param min - Inclusive lower bound on the message, must be a positive integer.
   * @param max - Exclusive upper bound on the message, must be a positive integer.
   * @param params
   */
  static boundCheckSmcWithKVVerifier(
    min: number,
    max: number,
    params: BoundCheckSmcWithKVVerifierParamsUncompressed
  ): Uint8Array {
    return generateBoundCheckSmcWithKVVerifierStatement(min, max, params.value, true);
  }

  /**
   * Same as `Statement.boundCheckSmcWithKVVerifier` except that it takes compressed parameters.
   * @param min - Inclusive lower bound on the message.
   * @param max - Exclusive upper bound on the message.
   * @param params
   */
  static boundCheckSmcWithKVVerifierFromCompressedParams(
    min: number,
    max: number,
    params: BoundCheckSmcWithKVVerifierParams
  ): Uint8Array {
    return generateBoundCheckSmcWithKVVerifierStatement(min, max, params.value, false);
  }

  /**
   * Same as `Statement.boundCheckSmcWithKVVerifier` but does not take the parameters directly but a reference to them as indices in the
   * array of `SetupParam`
   * @param min - Inclusive lower bound on the message.
   * @param max - Exclusive upper bound on the message.
   * @param params - Index of params in array of `SetupParam`
   */
  static boundCheckSmcWithKVVerifierFromSetupParamRefs(min: number, max: number, params: number): Uint8Array {
    return generateBoundCheckSmcWithKVVerifierStatementFromParamRefs(min, max, params);
  }

  /**
   * Create statement for proving inequality of a credential
   * @param inequalTo
   * @param commKey
   */
  static publicInequalityG1(inequalTo: Uint8Array, commKey: PederCommKeyUncompressed): Uint8Array {
    return generatePublicInequalityG1Statement(inequalTo, commKey.value, true);
  }

  static publicInequalityG1FromCompressedParams(inequalTo: Uint8Array, commKey: PederCommKey): Uint8Array {
    return generatePublicInequalityG1Statement(inequalTo, commKey.value, false);
  }

  static publicInequalityG1FromSetupParamRefs(inequalTo: Uint8Array, commKey: number): Uint8Array {
    return generatePublicInequalityG1StatementFromParamRefs(inequalTo, commKey);
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
   * @param statements
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
