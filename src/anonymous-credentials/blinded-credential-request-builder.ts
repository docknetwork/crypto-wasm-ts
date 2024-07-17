import { generateRandomFieldElement, R1CS } from 'crypto-wasm-new';
import { unflatten } from 'flat';
import { AccumulatorPublicKey } from '../accumulator';
import { BBSSignatureParams } from '../bbs';
import { BBSPlusSignatureParamsG1 } from '../bbs-plus';
import { BBDT16MacParams } from '../bbdt16-mac';
import { BytearrayWrapper } from '../bytearray-wrapper';
import { LegoProvingKey, LegoProvingKeyUncompressed } from '../legosnark';
import { PederCommKey, PederCommKeyUncompressed } from '../ped-com';
import { getR1CS, ParsedR1CSFile } from '../r1cs/file';
import {
  SaverChunkedCommitmentKey,
  SaverChunkedCommitmentKeyUncompressed,
  SaverEncryptionKey,
  SaverEncryptionKeyUncompressed,
  SaverProvingKey,
  SaverProvingKeyUncompressed
} from '../saver';
import {
  BBSBlindedCredentialRequest,
  BBSPlusBlindedCredentialRequest,
  BBDT16BlindedCredentialRequest
} from './blinded-credential-request';
import { BBSCredential, BBSPlusCredential, PSCredential } from './credential';
import { Presentation } from './presentation';
import {
  IProverBoundedPseudonymInBlindedCredReq,
  IProverCircomPredicate,
  PresentationBuilder
} from './presentation-builder';
import {
  IPresentedAttributeBound,
  IPresentedAttributeInequality,
  IPresentedAttributeVE
} from './presentation-specification';
import { CredentialSchema } from './schema';
import {
  AccumulatorWitnessType,
  AttributeEquality,
  BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES,
  BBS_SIGNATURE_PARAMS_LABEL_BYTES,
  BBDT16_MAC_PARAMS_LABEL_BYTES,
  BlindedAttributeEquality,
  BlindSignatureType,
  BoundCheckParamType,
  BoundType,
  ID_STR, MEM_CHECK_KV_STR,
  MEM_CHECK_STR, NON_MEM_CHECK_KV_STR,
  NON_MEM_CHECK_STR,
  PublicKey,
  REV_CHECK_STR,
  REV_ID_STR,
  RevocationStatusProtocol,
  SignatureParams,
  STATUS_STR,
  SUBJECT_STR,
  TYPE_STR
} from './types-and-consts';
import { Versioned } from './versioned';

type Credential = BBSCredential | BBSPlusCredential | PSCredential;

/**
 * Creates a request for a blinded credential, i.e. where some of the attributes are not known to the signer
 */
export abstract class BlindedCredentialRequestBuilder<SigParams> extends Versioned {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.5.0';

  // The schema of the whole (unblinded credential). This should include all attributes, i.e. blinded and unblinded
  _schema?: CredentialSchema;

  // The attributes of the credential subject that will be blinded (hidden from the issuer)
  _subjectToBlind?: object | object[];

  // The credential status if blinded
  _statusToBlind?: object;

  // Any top level attributes to blind
  _topLevelAttributesToBlind: Map<string, unknown>;

  protected sigParams?: SignatureParams;

  // A blinded credential request will contain a presentation that will prove predicates about the credential attributes and blinded attributes.
  presentationBuilder: PresentationBuilder;

  // Equalities between blinded and credential attributes
  attributeEqualities: BlindedAttributeEquality[];

  // Attributes proved inequal to a public value in zero knowledge. An attribute can be proven inequal to any number of values
  attributeInequalities: Map<string, [IPresentedAttributeInequality, Uint8Array][]>;

  // Bounds on blinded attributes
  bounds: Map<string, IPresentedAttributeBound[]>;

  // Encryption of blinded attributes
  verifEnc: Map<string, IPresentedAttributeVE[]>;

  // Circom predicates on blinded attributes
  circomPredicates: IProverCircomPredicate[];

  // Pseudonyms on blinded and credential attributes
  boundedPseudonyms: IProverBoundedPseudonymInBlindedCredReq[];

  constructor() {
    super(BlindedCredentialRequestBuilder.VERSION);
    this.presentationBuilder = new PresentationBuilder();
    this.attributeEqualities = [];
    this.attributeInequalities = new Map();
    this.bounds = new Map();
    this.verifEnc = new Map();
    this.circomPredicates = [];
    this.boundedPseudonyms = [];
    this._topLevelAttributesToBlind = new Map();
  }

  set subjectToBlind(subject: object | object[]) {
    this._subjectToBlind = subject;
  }

  // @ts-ignore
  get subjectToBlind(): object | object[] | undefined {
    return this._subjectToBlind;
  }

  set schema(schema: CredentialSchema) {
    this._schema = schema;
  }

  // @ts-ignore
  get schema(): CredentialSchema | undefined {
    return this._schema;
  }

  /**
   * Blind some of the credential status values
   * @param registryId - this won't be blinded
   * @param revCheck - this won't be blinded
   * @param memberValue - Only this will be blinded.
   * @param revType
   */
  statusToBlind(registryId: string, revCheck: string, memberValue: unknown, revType= RevocationStatusProtocol.Vb22) {
    if (revType === RevocationStatusProtocol.Vb22) {
      if (revCheck !== MEM_CHECK_STR && revCheck !== NON_MEM_CHECK_STR && revCheck !== MEM_CHECK_KV_STR) {
        throw new Error(`Revocation check should be either ${MEM_CHECK_STR} or ${NON_MEM_CHECK_STR} or ${MEM_CHECK_KV_STR} but was ${revCheck}`);
      }
    }
    if (revType == RevocationStatusProtocol.KbUni24) {
      if (
        revCheck !== MEM_CHECK_STR &&
        revCheck !== NON_MEM_CHECK_STR &&
        revCheck !== MEM_CHECK_KV_STR &&
        revCheck !== NON_MEM_CHECK_KV_STR
      ) {
        throw new Error(
          `Revocation check should be either ${MEM_CHECK_STR} or ${NON_MEM_CHECK_STR} or ${MEM_CHECK_KV_STR} or ${NON_MEM_CHECK_KV_STR} but was ${revCheck}`
        );
      }
    }
    this._statusToBlind = {
      [TYPE_STR]: revType,
      [ID_STR]: registryId,
      [REV_CHECK_STR]: revCheck,
      [REV_ID_STR]: memberValue
    };
  }

  /**
   * Blind top level fields. The issuer should not set these blinded fields at all, not even nested.
   * @param name
   * @param value
   */
  topLevelAttributesToBlind(name: string, value: unknown) {
    if (value !== undefined) {
      this._topLevelAttributesToBlind.set(name, value);
    }
  }

  /**
   * Create a commitment to the blinded attributes.
   * @param encodedSubject - The blinded attributes in encoded (as a field element) form. The key of the map is the index
   * of the attributes in the flattened attributes list
   * @param totalAttributes - Total number of attributes (blinded and unblinded) in the credential
   * @param labelOrParams - Signature params or the label to generate them.
   */
  abstract computeCommitment(
    encodedSubject: Map<number, Uint8Array>,
    totalAttributes: number,
    labelOrParams: Uint8Array | SigParams | undefined
  ): Uint8Array;

  abstract getBlinding(): Uint8Array | undefined;

  static getSigType(): BlindSignatureType {
    throw new Error('This method should be implemented by extending class');
  }

  addCredentialToPresentation(credential: Credential, pk?: PublicKey): number {
    return this.presentationBuilder.addCredential(credential, pk);
  }

  /**
   * Reveal attributes of the presented credential
   * @param credIdx
   * @param attributeNames
   */
  markCredentialAttributesRevealed(credIdx: number, attributeNames: Set<string>) {
    this.presentationBuilder.markAttributesRevealed(credIdx, attributeNames);
  }

  /**
   * Enforce equality on attributes of the presented credential
   * @param equality
   */
  enforceCredentialAttributesEqual(...equality: AttributeEquality) {
    this.presentationBuilder.enforceAttributeEquality(...equality);
  }

  addAccumInfoForCredStatus(
    credIdx: number,
    accumWitness: AccumulatorWitnessType,
    accumulated: Uint8Array,
    accumPublicKey: AccumulatorPublicKey,
    extra: object = {}
  ) {
    this.presentationBuilder.addAccumInfoForCredStatus(credIdx, accumWitness, accumulated, accumPublicKey, extra);
  }

  enforceInequalityOnCredentialAttribute(
    credIdx: number,
    attributeName: string,
    inEqualTo: any,
    paramId?: string,
    param?: PederCommKey | PederCommKeyUncompressed
  ) {
    this.presentationBuilder.enforceAttributeInequality(credIdx, attributeName, inEqualTo, paramId, param);
  }

  enforceBoundsOnCredentialAttribute(
    credIdx: number,
    attributeName: string,
    min: BoundType,
    max: BoundType,
    paramId?: string,
    param?: BoundCheckParamType
  ) {
    this.presentationBuilder.enforceBounds(credIdx, attributeName, min, max, paramId, param);
  }

  verifiablyEncryptCredentialAttribute(
    credIdx: number,
    attributeName: string,
    chunkBitSize: number,
    commKeyId: string,
    encryptionKeyId: string,
    snarkPkId: string,
    commKey?: SaverChunkedCommitmentKey | SaverChunkedCommitmentKeyUncompressed,
    encryptionKey?: SaverEncryptionKey | SaverEncryptionKeyUncompressed,
    snarkPk?: SaverProvingKey | SaverProvingKeyUncompressed
  ) {
    this.presentationBuilder.verifiablyEncrypt(
      credIdx,
      attributeName,
      chunkBitSize,
      commKeyId,
      encryptionKeyId,
      snarkPkId,
      commKey,
      encryptionKey,
      snarkPk
    );
  }

  enforceCircomPredicateOnCredentialAttribute(
    credIdx: number,
    // For each circuit private variable name, give its corresponding attribute names
    circuitPrivateVars: [string, string | string[]][],
    // For each circuit public variable name, give its corresponding values
    circuitPublicVars: [string, Uint8Array | Uint8Array[]][],
    circuitId: string,
    provingKeyId: string,
    r1cs?: R1CS | ParsedR1CSFile,
    wasmBytes?: Uint8Array,
    provingKey?: LegoProvingKey | LegoProvingKeyUncompressed
  ) {
    this.presentationBuilder.enforceCircomPredicate(
      credIdx,
      circuitPrivateVars,
      circuitPublicVars,
      circuitId,
      provingKeyId,
      r1cs,
      wasmBytes,
      provingKey
    );
  }

  enforceCircomPredicateAcrossMultipleCredentials(
    // For each circuit private variable name, give its corresponding credential index and attribute name
    circuitPrivateVars: [string, [number, string] | [number, string][]][],
    // For each circuit public variable name, give its corresponding values
    circuitPublicVars: [string, Uint8Array | Uint8Array[]][],
    circuitId: string,
    provingKeyId: string,
    r1cs?: R1CS | ParsedR1CSFile,
    wasmBytes?: Uint8Array,
    provingKey?: LegoProvingKey | LegoProvingKeyUncompressed
  ) {
    this.presentationBuilder.enforceCircomPredicateAcrossMultipleCredentials(
      circuitPrivateVars,
      circuitPublicVars,
      circuitId,
      provingKeyId,
      r1cs,
      wasmBytes,
      provingKey
    );
  }

  addUnboundedPseudonym(baseForSecretKey: Uint8Array, secretKey: Uint8Array): number {
    return this.presentationBuilder.addUnboundedPseudonym(baseForSecretKey, secretKey);
  }

  /**
   * Add a pseudonym to only credential attributes
   * @param basesForAttribute
   * @param attributeNames
   * @param baseForSecretKey
   * @param secretKey
   * @returns
   */
  addPseudonymToCredentialAttributes(
    basesForAttribute: Uint8Array[],
    attributeNames: Map<number, string[]>,
    baseForSecretKey?: Uint8Array,
    secretKey?: Uint8Array
  ): number {
    return this.presentationBuilder.addBoundedPseudonym(basesForAttribute, attributeNames, baseForSecretKey, secretKey);
  }

  /**
   * Enforce that a blinded attribute is equal to one or more credential attributes
   * @param equality
   */
  enforceEqualityOnBlindedAttribute(equality: BlindedAttributeEquality) {
    this.attributeEqualities.push(equality);
  }

  /**
   * Enforce that the blinded attribute `attributeName` is inequal to the public value `inEqualTo`
   * @param attributeName
   * @param inEqualTo
   * @param paramId
   * @param param
   */
  enforceInequalityOnBlindedAttribute(
    attributeName: string,
    inEqualTo: any,
    paramId?: string,
    param?: PederCommKey | PederCommKeyUncompressed
  ) {
    PresentationBuilder.enforceAttributeInequalities(
      this.presentationBuilder,
      this.attributeInequalities,
      attributeName,
      inEqualTo,
      paramId,
      param
    );
  }

  /**
   *
   * @param attributeName - Nested attribute names use the "dot" separator
   * @param min
   * @param max
   * @param paramId
   * @param param
   */
  enforceBoundsOnBlindedAttribute(
    attributeName: string,
    min: BoundType,
    max: BoundType,
    paramId?: string,
    param?: BoundCheckParamType
  ) {
    PresentationBuilder.processBounds(this.presentationBuilder, this.bounds, attributeName, min, max, paramId, param);
  }

  verifiablyEncryptBlindedAttribute(
    attributeName: string,
    chunkBitSize: number,
    commKeyId: string,
    encryptionKeyId: string,
    snarkPkId: string,
    commKey?: SaverChunkedCommitmentKey | SaverChunkedCommitmentKeyUncompressed,
    encryptionKey?: SaverEncryptionKey | SaverEncryptionKeyUncompressed,
    snarkPk?: SaverProvingKey | SaverProvingKeyUncompressed
  ) {
    if (chunkBitSize !== 8 && chunkBitSize !== 16) {
      throw new Error(`Only 8 and 16 supported for chunkBitSize but given ${chunkBitSize}`);
    }
    PresentationBuilder.processVerifiableEncs(
      this.presentationBuilder,
      this.verifEnc,
      attributeName,
      chunkBitSize,
      commKeyId,
      encryptionKeyId,
      snarkPkId,
      commKey,
      encryptionKey,
      snarkPk
    );
  }

  enforceCircomPredicateOnBlindedAttribute(
    // For each circuit private variable name, give its corresponding attribute names
    circuitPrivateVars: [string, string | string[]][],
    // For each circuit public variable name, give its corresponding values
    circuitPublicVars: [string, Uint8Array | Uint8Array[]][],
    circuitId: string,
    provingKeyId: string,
    r1cs?: R1CS | ParsedR1CSFile,
    wasmBytes?: Uint8Array,
    provingKey?: LegoProvingKey | LegoProvingKeyUncompressed
  ) {
    if (circuitPrivateVars.length === 0) {
      throw new Error('Provide at least one private variable mapping');
    }
    this.circomPredicates.push({
      privateVars: circuitPrivateVars,
      publicVars: circuitPublicVars,
      circuitId,
      provingKeyId
    });
    this.presentationBuilder.updatePredicateParams(provingKeyId, provingKey);
    this.presentationBuilder.updatePredicateParams(
      PresentationBuilder.r1csParamId(circuitId),
      r1cs !== undefined ? getR1CS(r1cs) : undefined
    );
    this.presentationBuilder.updatePredicateParams(PresentationBuilder.wasmParamId(circuitId), wasmBytes);
  }

  /**
   * Add a pseudonym which is bound to 0 or more credential attributes and 0 or more blinded attributes
   * @param basesForAttributes - The bases at the beginning of array will be used for credential attributes and then in the end for blinded attributes.
   * @param credentialAttributeNames - Map with key as the credential index and value as an array of attribute to use in pseudonym.
   * @param blindedAttributeNames - Array of blinded attribute to use in pseudonym
   * @param baseForSecretKey
   * @param secretKey
   */
  addPseudonymToCredentialAndBlindedAttributes(
    basesForAttributes: Uint8Array[],
    credentialAttributeNames: Map<number, string[]>,
    blindedAttributeNames: string[],
    baseForSecretKey?: Uint8Array,
    secretKey?: Uint8Array
  ) {
    let numberOfAttributes = blindedAttributeNames.length;
    for (const [_, attributes] of credentialAttributeNames.entries()) {
      numberOfAttributes += attributes.length;
    }
    if (basesForAttributes.length !== numberOfAttributes) {
      throw new Error(
        `basesForAttribute must have the same length (${basesForAttributes.length}) as the total number of attributes (${numberOfAttributes})`
      );
    }
    if (
      (baseForSecretKey === undefined && secretKey !== undefined) ||
      (baseForSecretKey !== undefined && secretKey === undefined)
    ) {
      throw new Error(`baseForSecretKey and secretKey must be undefined at the same time, or not at all`);
    }
    this.boundedPseudonyms.push({
      basesForAttributes,
      baseForSecretKey,
      credentialAttributes: credentialAttributeNames,
      blindedAttributes: blindedAttributeNames,
      secretKey
    });
  }

  protected createPresentation(sigParams?: SigParams | Uint8Array): Presentation {
    if (this.schema === undefined || this.subjectToBlind === undefined) {
      throw new Error('Both schema and subject to be present');
    }
    const schema = this.schema as CredentialSchema;
    const subject = this.subjectToBlind as object | object[];
    const flattenedSchema = schema.flatten();
    const encodedAttributes = new Map<number, Uint8Array>();
    const attrNameToIndex = new Map<string, number>();
    // Will contain the attribute names that are blinded
    const attributesWithoutVals = {};

    // Create an object representing all attributes, from subject and top level
    const attrs = { [SUBJECT_STR]: subject };
    for (const [k, v] of this._topLevelAttributesToBlind.entries()) {
      attrs[k] = v;
    }
    // Encode the blinded attributes
    for (const [name, value] of schema.encoder.encodeMessageObjectAsMapConstantTime(attrs).entries()) {
      const index = flattenedSchema[0].indexOf(name);
      encodedAttributes.set(index, value);
      attrNameToIndex.set(name, index);
      attributesWithoutVals[name] = null;
    }

    let unBlindedAttributes: object | undefined;
    if (this._statusToBlind !== undefined) {
      const name = `${STATUS_STR}.${REV_ID_STR}`;
      const index = flattenedSchema[0].indexOf(name);
      // Keeping the encoding non-constant time to not break older credentials. This needs to be fixed
      encodedAttributes.set(index, schema.encoder.encodeMessage(name, this._statusToBlind[REV_ID_STR]));
      attrNameToIndex.set(name, index);
      attributesWithoutVals[name] = null;
      unBlindedAttributes = {
        [STATUS_STR]: {
          [TYPE_STR]: this._statusToBlind[TYPE_STR],
          [ID_STR]: this._statusToBlind[ID_STR],
          [REV_CHECK_STR]: this._statusToBlind[REV_CHECK_STR],
        }
      }
    }

    const blindedAttributes = unflatten(attributesWithoutVals) as object;
    // Compute commitment (commitments for PS)
    const commitment = this.computeCommitment(encodedAttributes, flattenedSchema[0].length, sigParams);
    this.presentationBuilder.blindCredReq = {
      req: {
        // @ts-ignore
        sigType: this.constructor.getSigType(),
        version: this.version,
        schema,
        blindedAttributes,
        commitment,
        blindedAttributeEqualities: this.attributeEqualities,
        unBlindedAttributes
      },
      sigParams: this.sigParams as SignatureParams,
      encodedAttributes,
      attrNameToIndex,
      flattenedSchema,
      blinding: this.getBlinding(),
      attributeInequalities: this.attributeInequalities,
      bounds: this.bounds,
      verifEnc: this.verifEnc,
      circPred: this.circomPredicates,
      pseudonyms: this.boundedPseudonyms
    };
    return this.presentationBuilder.finalize();
  }
}

export class BBSBlindedCredentialRequestBuilder extends BlindedCredentialRequestBuilder<BBSSignatureParams> {
  computeCommitment(
    encodedSubject: Map<number, Uint8Array>,
    totalAttributes: number,
    labelOrParams: Uint8Array | BBSSignatureParams = BBS_SIGNATURE_PARAMS_LABEL_BYTES
  ): Uint8Array {
    const sigParams = BBSSignatureParams.getSigParamsOfRequiredSize(totalAttributes, labelOrParams);
    this.sigParams = sigParams;
    return sigParams.commitToMessagesConstantTime(encodedSubject, false);
  }

  /**
   * Create the request to be sent to the signer
   * @param sigParams
   * @returns
   */
  finalize(sigParams: Uint8Array | BBSSignatureParams = BBS_SIGNATURE_PARAMS_LABEL_BYTES): BBSBlindedCredentialRequest {
    return new BBSBlindedCredentialRequest(this.version, super.createPresentation(sigParams));
  }

  /**
   * BBS does not use blinding so return undefined
   * @returns
   */
  getBlinding(): undefined {
    return undefined;
  }

  static getSigType(): BlindSignatureType {
    return BlindSignatureType.Bbs;
  }
}

export class BBSPlusBlindedCredentialRequestBuilder extends BlindedCredentialRequestBuilder<BBSPlusSignatureParamsG1> {
  private readonly blinding: Uint8Array;

  constructor() {
    super();
    this.blinding = generateRandomFieldElement();
  }

  /**
   * Create the request to be sent to the signer and the blinding to be kept to later unblind the credential
   * @param sigParams
   * @returns
   */
  finalize(
    sigParams: Uint8Array | BBSPlusSignatureParamsG1 = BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES
  ): [BBSPlusBlindedCredentialRequest, BBSPlusBlinding] {
    return [
      new BBSPlusBlindedCredentialRequest(this.version, super.createPresentation(sigParams)),
      new BBSPlusBlinding(this.blinding)
    ];
  }

  getBlinding(): Uint8Array {
    return this.blinding;
  }

  computeCommitment(
    encodedSubject: Map<number, Uint8Array>,
    totalAttributes: number,
    labelOrParams: Uint8Array | BBSPlusSignatureParamsG1 = BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES
  ): Uint8Array {
    const sigParams = BBSPlusSignatureParamsG1.getSigParamsOfRequiredSize(totalAttributes, labelOrParams);
    this.sigParams = sigParams;
    const [commitment] = sigParams.commitToMessagesConstantTime(encodedSubject, false, this.blinding);
    return commitment;
  }

  static getSigType(): BlindSignatureType {
    return BlindSignatureType.BbsPlus;
  }
}

export class BBDT16BlindedCredentialRequestBuilder extends BlindedCredentialRequestBuilder<BBDT16MacParams> {
  private readonly blinding: Uint8Array;

  constructor() {
    super();
    this.blinding = generateRandomFieldElement();
  }

  /**
   * Create the request to be sent to the signer and the blinding to be kept to later unblind the credential
   * @param sigParams
   * @returns
   */
  finalize(
    sigParams: Uint8Array | BBDT16MacParams = BBDT16_MAC_PARAMS_LABEL_BYTES
  ): [BBDT16BlindedCredentialRequest, BBDT16Blinding] {
    return [
      new BBDT16BlindedCredentialRequest(this.version, super.createPresentation(sigParams)),
      new BBDT16Blinding(this.blinding)
    ];
  }

  getBlinding(): Uint8Array {
    return this.blinding;
  }

  computeCommitment(
    encodedSubject: Map<number, Uint8Array>,
    totalAttributes: number,
    labelOrParams: Uint8Array | BBDT16MacParams = BBDT16_MAC_PARAMS_LABEL_BYTES
  ): Uint8Array {
    const sigParams = BBDT16MacParams.getMacParamsOfRequiredSize(totalAttributes, labelOrParams);
    this.sigParams = sigParams;
    const [commitment] = sigParams.commitToMessagesConstantTime(encodedSubject, false, this.blinding);
    return commitment;
  }

  static getSigType(): BlindSignatureType {
    return BlindSignatureType.Bbdt16;
  }
}

export class BBSPlusBlinding extends BytearrayWrapper {}

export class BBDT16Blinding extends BytearrayWrapper {}

// TODO: Add for PS as well
