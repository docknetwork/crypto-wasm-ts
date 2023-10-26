import { Versioned } from './versioned';
import {
  IProverBoundedPseudonymInBlindedCredReq,
  IProverCircomPredicate,
  PresentationBuilder
} from './presentation-builder';
import { CredentialSchema } from './schema';
import { BBSCredential, BBSPlusCredential, PSCredential } from './credential';
import {
  AttributeEquality,
  BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES,
  BBS_SIGNATURE_PARAMS_LABEL_BYTES,
  BlindedAttributeEquality,
  BlindSignatureTypes,
  BoundCheckParamType,
  BoundType,
  PublicKey,
  SignatureParams,
  SUBJECT_STR,
  VerifiableEncryptionProtocols
} from './types-and-consts';
import { AccumulatorPublicKey, AccumulatorWitness } from '../accumulator';
import { LegoProvingKey, LegoProvingKeyUncompressed } from '../legosnark';
import {
  SaverChunkedCommitmentKey,
  SaverChunkedCommitmentKeyUncompressed,
  SaverEncryptionKey,
  SaverEncryptionKeyUncompressed,
  SaverProvingKey,
  SaverProvingKeyUncompressed
} from '../saver';
import { generateRandomFieldElement, R1CS } from '@docknetwork/crypto-wasm';
import { BBSBlindedCredentialRequest, BBSPlusBlindedCredentialRequest } from './blinded-credential-request';
import { unflatten } from 'flat';
import { BBSSignatureParams } from '../bbs';
import { BBSPlusSignatureParamsG1 } from '../bbs-plus';
import { BytearrayWrapper } from '../bytearray-wrapper';
import {
  IPresentedAttributeBounds,
  IPresentedAttributeInequality,
  IPresentedAttributeVE
} from './presentation-specification';
import { Presentation } from './presentation';
import { getR1CS, ParsedR1CSFile } from '../r1cs/file';
import { PederCommKey, PederCommKeyUncompressed } from '../ped-com';

type Credential = BBSCredential | BBSPlusCredential | PSCredential;

/**
 * Creates a request for a blinded credential, i.e. where some of the attributes are not known to the signer
 */
export abstract class BlindedCredentialRequestBuilder<SigParams> extends Versioned {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.2.0';

  // The schema of the whole (unblinded credential). This should include all attributes, i.e. blinded and unblinded
  _schema?: CredentialSchema;

  // The attributes of the credential subject that will be blinded (hidden from the issuer)
  _subjectToBlind?: object | object[];

  protected sigParams?: SignatureParams;

  // A blinded credential request will contain a presentation that will prove predicates about the credential attributes and blinded attributes.
  presentationBuilder: PresentationBuilder;

  // Equalities between blinded and credential attributes
  attributeEqualities: BlindedAttributeEquality[];

  // Attributes proved inequal to a public value in zero knowledge. An attribute can be proven inequal to any number of values
  attributeInequalities: Map<string, [IPresentedAttributeInequality, Uint8Array][]>;

  // Bounds on blinded attributes
  bounds: Map<string, IPresentedAttributeBounds[]>;

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

  static getSigType(): BlindSignatureTypes {
    throw new Error('This method should be implemented by extending class');
  }

  addCredentialToPresentation(credential: Credential, pk: PublicKey): number {
    return this.presentationBuilder.addCredential(credential, pk);
  }

  markCredentialAttributesRevealed(credIdx: number, attributeNames: Set<string>) {
    this.presentationBuilder.markAttributesRevealed(credIdx, attributeNames);
  }

  markCredentialAttributesEqual(...equality: AttributeEquality) {
    this.presentationBuilder.markAttributesEqual(...equality);
  }

  addAccumInfoForCredStatus(
    credIdx: number,
    accumWitness: AccumulatorWitness,
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
   * Mark a blinded attribute equal to one or more credential attributes
   * @param equality
   */
  markBlindedAttributesEqual(equality: BlindedAttributeEquality) {
    this.attributeEqualities.push(equality);
  }

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
    PresentationBuilder.processVerifiableEncs(this.presentationBuilder, this.verifEnc, attributeName, chunkBitSize, commKeyId, encryptionKeyId, snarkPkId, commKey, encryptionKey, snarkPk);
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
    const encodedSubject = new Map<number, Uint8Array>();
    const attrNameToIndex = new Map<string, number>();
    const subjectWithoutVals = {};
    for (const [name, value] of schema.encoder.encodeMessageObjectAsMap({ [SUBJECT_STR]: subject }).entries()) {
      const index = flattenedSchema[0].indexOf(name);
      encodedSubject.set(index, value);
      attrNameToIndex.set(name, index);
      subjectWithoutVals[name] = null;
    }
    const blindedAttributes = unflatten(subjectWithoutVals) as object;
    // Compute commitment (commitments for PS)
    const commitment = this.computeCommitment(encodedSubject, flattenedSchema[0].length, sigParams);
    this.presentationBuilder.blindCredReq = {
      req: {
        // @ts-ignore
        sigType: this.constructor.getSigType(),
        version: this.version,
        schema,
        blindedAttributes,
        commitment,
        blindedAttributeEqualities: this.attributeEqualities
      },
      sigParams: this.sigParams as SignatureParams,
      encodedSubject,
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
    return sigParams.commitToMessages(encodedSubject, false);
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

  static getSigType(): BlindSignatureTypes {
    return BlindSignatureTypes.Bbs;
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
    const [commitment] = sigParams.commitToMessages(encodedSubject, false, this.blinding);
    return commitment;
  }

  static getSigType(): BlindSignatureTypes {
    return BlindSignatureTypes.BbsPlus;
  }
}

export class BBSPlusBlinding extends BytearrayWrapper {}

// TODO: Add for PS as well
