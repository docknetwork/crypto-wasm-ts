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
  PublicKey,
  SIG_TYPE_BBS,
  SIG_TYPE_BBS_PLUS,
  SignatureParams,
  SUBJECT_STR
} from './types-and-consts';
import { AccumulatorPublicKey, AccumulatorWitness } from '../accumulator';
import { LegoProvingKey, LegoProvingKeyUncompressed } from '../legosnark';
import {
  SaverChunkedCommitmentGens,
  SaverChunkedCommitmentGensUncompressed,
  SaverEncryptionKey,
  SaverEncryptionKeyUncompressed,
  SaverProvingKey,
  SaverProvingKeyUncompressed
} from '../saver';
import { generateRandomFieldElement, R1CS } from '@docknetwork/crypto-wasm';
import { getR1CS, ParsedR1CSFile } from '../r1cs';
import { BBSBlindedCredentialRequest, BBSPlusBlindedCredentialRequest } from './blinded-credential-request';
import { unflatten } from 'flat';
import { BBSSignatureParams } from '../bbs';
import { BBSPlusSignatureParamsG1 } from '../bbs-plus';
import { BytearrayWrapper } from '../bytearray-wrapper';
import { IPresentedAttributeBounds, IPresentedAttributeVE } from './presentation-specification';
import { Presentation } from './presentation';

type Credential = BBSCredential | BBSPlusCredential | PSCredential;

/**
 * Creates a request for a blinded credential, i.e. where some of the attributes are not known to the signer
 */
export abstract class BlindedCredentialRequestBuilder<SigParams> extends Versioned {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.1.0';

  _schema?: CredentialSchema;
  _subjectToBlind?: object | object[];

  protected sigParams?: SignatureParams;

  // A blinded credential request will contain a presentation that will prove predicates about the credential attributes and blinded attributes.
  presentationBuilder: PresentationBuilder;

  // Equalities between blinded and credential attributes
  attributeEqualities: BlindedAttributeEquality[];

  // Bounds on blinded attributes
  bounds: Map<string, IPresentedAttributeBounds>;

  // Encryption of blinded attributes
  verifEnc: Map<string, IPresentedAttributeVE>;

  // Circom predicates on blinded attributes
  circomPredicates: IProverCircomPredicate[];

  // Pseudonyms on blinded and credential attributes
  boundedPseudonyms: IProverBoundedPseudonymInBlindedCredReq[];

  constructor() {
    super(BlindedCredentialRequestBuilder.VERSION);
    this.presentationBuilder = new PresentationBuilder();
    this.attributeEqualities = [];
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

  abstract computeCommitment(
    encodedSubject: Map<number, Uint8Array>,
    totalAttributes: number,
    labelOrParams: Uint8Array | SigParams | undefined
  ): Uint8Array;

  abstract getBlinding(): Uint8Array | undefined;

  abstract getSigType(): string;

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

  enforceBoundsOnCredentialAttribute(
    credIdx: number,
    attributeName: string,
    min: number,
    max: number,
    provingKeyId: string,
    provingKey?: LegoProvingKey | LegoProvingKeyUncompressed
  ) {
    this.presentationBuilder.enforceBounds(credIdx, attributeName, min, max, provingKeyId, provingKey);
  }

  verifiablyEncryptCredentialAttribute(
    credIdx: number,
    attributeName: string,
    chunkBitSize: number,
    commGensId: string,
    encryptionKeyId: string,
    snarkPkId: string,
    commGens?: SaverChunkedCommitmentGens | SaverChunkedCommitmentGensUncompressed,
    encryptionKey?: SaverEncryptionKey | SaverEncryptionKeyUncompressed,
    snarkPk?: SaverProvingKey | SaverProvingKeyUncompressed
  ) {
    this.presentationBuilder.verifiablyEncrypt(
      credIdx,
      attributeName,
      chunkBitSize,
      commGensId,
      encryptionKeyId,
      snarkPkId,
      commGens,
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

  enforceBoundsOnBlindedAttribute(
    attributeName: string,
    min: number,
    max: number,
    provingKeyId: string,
    provingKey?: LegoProvingKey | LegoProvingKeyUncompressed
  ) {
    if (min >= max) {
      throw new Error(`Invalid bounds min=${min}, max=${max}`);
    }
    if (this.bounds.get(attributeName) !== undefined) {
      throw new Error(`Already enforced bounds on attribute ${attributeName}`);
    }
    this.bounds.set(attributeName, { min, max, paramId: provingKeyId });
    this.presentationBuilder.updatePredicateParams(provingKeyId, provingKey);
  }

  verifiablyEncryptBlindedAttribute(
    attributeName: string,
    chunkBitSize: number,
    commGensId: string,
    encryptionKeyId: string,
    snarkPkId: string,
    commGens?: SaverChunkedCommitmentGens | SaverChunkedCommitmentGensUncompressed,
    encryptionKey?: SaverEncryptionKey | SaverEncryptionKeyUncompressed,
    snarkPk?: SaverProvingKey | SaverProvingKeyUncompressed
  ) {
    if (chunkBitSize !== 8 && chunkBitSize !== 16) {
      throw new Error(`Only 8 and 16 supported for chunkBitSize but given ${chunkBitSize}`);
    }
    if (this.verifEnc.get(attributeName) !== undefined) {
      throw new Error(`Already enforced verifiable encryption on attribute ${attributeName}`);
    }
    this.verifEnc.set(attributeName, {
      chunkBitSize,
      commitmentGensId: commGensId,
      encryptionKeyId: encryptionKeyId,
      snarkKeyId: snarkPkId
    });
    this.presentationBuilder.updatePredicateParams(commGensId, commGens);
    this.presentationBuilder.updatePredicateParams(encryptionKeyId, encryptionKey);
    this.presentationBuilder.updatePredicateParams(snarkPkId, snarkPk);
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
        sigType: this.getSigType(),
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

  getSigType(): string {
    return SIG_TYPE_BBS;
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

  getSigType(): string {
    return SIG_TYPE_BBS_PLUS;
  }
}

export class BBSPlusBlinding extends BytearrayWrapper {}

// TODO: Add for PS as well
