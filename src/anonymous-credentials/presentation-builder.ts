import { Versioned } from './versioned';
import { BBSCredential, BBSPlusCredential, PSCredential } from './credential';
import {
  CompositeProofG1,
  MetaStatements,
  QuasiProofSpecG1,
  SetupParam,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../composite-proof';
import { LegoProvingKey, LegoProvingKeyUncompressed } from '../legosnark';
import { CircomInputs } from '../r1cs';
import { R1CS } from '@docknetwork/crypto-wasm';
import { CredentialSchema, getTransformedMinMax, ValueType } from './schema';
import { getRevealedAndUnrevealed } from '../sign-verify-js-objs';
import {
  AttributeEquality,
  CRYPTO_VERSION_STR,
  FlattenedSchema,
  MEM_CHECK_STR,
  NON_MEM_CHECK_STR,
  PredicateParamType,
  ID_STR,
  REV_CHECK_STR,
  REV_ID_STR,
  SCHEMA_STR,
  STATUS_STR,
  TYPE_STR,
  STATUS_TYPE_STR,
  PublicKey,
  SignatureParams
} from './types-and-consts';
import {
  IBlindCredentialRequest,
  ICircomPredicate,
  ICircuitPrivateVars,
  IPresentedAttributeBounds,
  IPresentedAttributeVE,
  IPresentedStatus,
  PresentationSpecification
} from './presentation-specification';
import { buildContextForProof, Presentation } from './presentation';
import { AccumulatorPublicKey, AccumulatorWitness, MembershipWitness, NonMembershipWitness } from '../accumulator';
import {
  accumulatorStatement,
  buildSignatureStatementFromParamsRef,
  buildWitness,
  createWitEq,
  paramsClassBySignature,
  saverStatement,
  getSignatureParamsForMsgCount,
  createWitEqForBlindedCred
} from './util';
import {
  SaverChunkedCommitmentGens,
  SaverChunkedCommitmentGensUncompressed,
  SaverCiphertext,
  SaverEncryptionKey,
  SaverEncryptionKeyUncompressed,
  SaverProvingKey,
  SaverProvingKeyUncompressed
} from '../saver';
import { unflatten } from 'flat';
import { SetupParamsTracker } from './setup-params-tracker';
import { AttributeBoundPseudonym, Pseudonym, PseudonymBases } from '../Pseudonym';
import { BBSSignatureParams } from '../bbs';
import { BBSPlusSignatureParamsG1 } from '../bbs-plus';
import { getR1CS, ParsedR1CSFile } from '../r1cs/file';

/**
 * Arguments required to generate the corresponding AttributeBoundPseudonym
 * */
export interface BoundedPseudonym {
  /** Keys are credential indices, values are the attribute names in that credential*/
  attributeNames: Map<number, string[]>;
  basesForAttributes: Uint8Array[];
  baseForSecretKey?: Uint8Array;
  secretKey?: Uint8Array;
}

/**
 * Arguments required to generate the corresponding Pseudonym
 * */
export interface UnboundedPseudonym {
  baseForSecretKey: Uint8Array;
  secretKey: Uint8Array;
}

type Credential = BBSCredential | BBSPlusCredential | PSCredential;

export class PresentationBuilder extends Versioned {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.1.0';

  _context?: string;
  _nonce?: Uint8Array;
  proof?: CompositeProofG1;
  // Just for debugging
  private _proofSpec?: QuasiProofSpecG1;
  spec: PresentationSpecification;

  // Each credential is referenced by its index in this array
  credentials: [Credential, PublicKey][];

  // Attributes revealed from each credential, key of the map is the credential index
  revealedAttributes: Map<number, Set<string>>;

  // Arguments required to calculate the attribute bound pseudonyms to be presented
  boundedPseudonyms: BoundedPseudonym[];

  // Arguments required to calculate the pseudonyms to be presented
  unboundedPseudonyms: UnboundedPseudonym[];

  // Attributes proved equal in zero knowledge
  attributeEqualities: AttributeEquality[];

  // Each credential has only one accumulator for status
  credStatuses: Map<number, [AccumulatorWitness, Uint8Array, AccumulatorPublicKey, object]>;

  // Bounds on attribute. The key of the map is the credential index and for the inner map is the attribute and value of map
  // denotes min, max, an identifier of the snark proving key which the verifier knows as well to use corresponding verifying key
  bounds: Map<number, Map<string, IPresentedAttributeBounds>>;

  // Verifiable encryption of attributes
  verifEnc: Map<number, Map<string, IPresentedAttributeVE>>;

  // Predicates expressed as Circom programs. For each credential, store a public, private variables, circuit id (used to fetch R1CS, WASM bytes) and attributes used in circuit
  circomPredicates: Map<number, IProverCircomPredicate[]>;

  // Parameters for predicates like snark proving key for bound check, verifiable encryption, Circom program
  predicateParams: Map<string, PredicateParamType>;

  // Blinded credential request. Stores `SignatureParams` as appropriately sized params are created by the request
  // builder already so not creating it again
  blindCredReq?: {
    req: IBlindCredentialRequest;
    sigParams: SignatureParams;
    encodedSubject: Map<number, Uint8Array>;
    attrNameToIndex: Map<string, number>;
    flattenedSchema: FlattenedSchema;
    blinding?: Uint8Array;
    bounds: Map<string, IPresentedAttributeBounds>;
    verifEnc: Map<string, IPresentedAttributeVE>;
    circPred: IProverCircomPredicate[];
    pseudonyms: IProverBoundedPseudonymInBlindedCredReq[];
  };

  constructor() {
    super(PresentationBuilder.VERSION);
    this.credentials = [];
    this.revealedAttributes = new Map();
    this.attributeEqualities = [];
    this.boundedPseudonyms = [];
    this.unboundedPseudonyms = [];
    this.credStatuses = new Map();
    this.bounds = new Map();
    this.verifEnc = new Map();
    this.predicateParams = new Map();
    this.circomPredicates = new Map();
    this.spec = new PresentationSpecification();
  }

  addCredential(credential: Credential, pk: PublicKey): number {
    this.credentials.push([credential, pk]);
    return this.credentials.length - 1;
  }

  // TODO: Since all attr names below will have the full name (incl. top level attrib, check that no predicate on revealed attrs)

  // NOTE: This and several methods below expect nested attributes names with "dot"s as separators. Passing the nested structure is also
  // possible but will need more parsing and thus can be handled later.

  /**
   *
   * @param credIdx
   * @param attributeNames - Nested attribute names using the "dot" separator
   */
  markAttributesRevealed(credIdx: number, attributeNames: Set<string>) {
    this.validateCredIndex(credIdx);
    let revealed = this.revealedAttributes.get(credIdx);
    if (revealed === undefined) {
      revealed = new Set<string>();
    }
    for (const a of attributeNames) {
      revealed.add(a);
    }
    this.revealedAttributes.set(credIdx, revealed);
  }

  /**
   *
   * @param equality - Array of reference to attribute where each reference is a pair with 1st item being credential index
   * and 2nd being attribute index in the flattened attribute list.
   */
  markAttributesEqual(...equality: AttributeEquality) {
    if (equality.length < 2) {
      throw new Error(`Need atleast 2 attribute references but found ${equality.length}`);
    }
    for (const aRef of equality) {
      this.validateCredIndex(aRef[0]);
    }
    this.attributeEqualities.push(equality);
  }

  /**
   * Add accumulator value, witness and public key for proving credential status.
   * @param credIdx
   * @param accumWitness
   * @param accumulated
   * @param accumPublicKey
   * @param extra
   */
  addAccumInfoForCredStatus(
    credIdx: number,
    accumWitness: AccumulatorWitness,
    accumulated: Uint8Array,
    accumPublicKey: AccumulatorPublicKey,
    extra: object = {}
  ) {
    this.validateCredIndex(credIdx);
    this.credStatuses.set(credIdx, [accumWitness, accumulated, accumPublicKey, extra]);
  }

  /**
   *
   * @param credIdx
   * @param attributeName - Nested attribute names use the "dot" separator
   * @param min
   * @param max
   * @param provingKeyId
   * @param provingKey
   */
  enforceBounds(
    credIdx: number,
    attributeName: string,
    min: number,
    max: number,
    provingKeyId: string,
    provingKey?: LegoProvingKey | LegoProvingKeyUncompressed
  ) {
    if (min >= max) {
      throw new Error(`Invalid bounds min=${min}, max=${max}`);
    }
    this.validateCredIndex(credIdx);
    let b = this.bounds.get(credIdx);
    if (b !== undefined) {
      if (b.get(attributeName) !== undefined) {
        throw new Error(`Already enforced bounds on credential index ${credIdx} and attribute name ${attributeName}`);
      }
    } else {
      b = new Map();
    }
    b.set(attributeName, { min, max, paramId: provingKeyId });
    this.bounds.set(credIdx, b);
    this.updatePredicateParams(provingKeyId, provingKey);
  }

  /**
   *
   * @param credIdx
   * @param attributeName - Nested attribute names use the "dot" separator
   * @param chunkBitSize
   * @param commGensId
   * @param encryptionKeyId
   * @param snarkPkId
   * @param commGens
   * @param encryptionKey
   * @param snarkPk
   */
  verifiablyEncrypt(
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
    if (chunkBitSize !== 8 && chunkBitSize !== 16) {
      throw new Error(`Only 8 and 16 supported for chunkBitSize but given ${chunkBitSize}`);
    }
    this.validateCredIndex(credIdx);
    let v = this.verifEnc.get(credIdx);
    if (v !== undefined) {
      if (v.get(attributeName) !== undefined) {
        throw new Error(
          `Already enforced verifiable encryption on credential index ${credIdx} and attribute name ${attributeName}`
        );
      }
    } else {
      v = new Map();
    }

    v.set(attributeName, {
      chunkBitSize,
      commitmentGensId: commGensId,
      encryptionKeyId: encryptionKeyId,
      snarkKeyId: snarkPkId
    });
    this.updatePredicateParams(commGensId, commGens);
    this.updatePredicateParams(encryptionKeyId, encryptionKey);
    this.updatePredicateParams(snarkPkId, snarkPk);
    this.verifEnc.set(credIdx, v);
  }

  enforceCircomPredicate(
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
    if (circuitPrivateVars.length === 0) {
      throw new Error('Provide at least one private variable mapping');
    }
    this.validateCredIndex(credIdx);
    this.updatePredicateParams(provingKeyId, provingKey);
    this.updatePredicateParams(
      PresentationBuilder.r1csParamId(circuitId),
      r1cs !== undefined ? getR1CS(r1cs) : undefined
    );
    this.updatePredicateParams(PresentationBuilder.wasmParamId(circuitId), wasmBytes);
    let predicates = this.circomPredicates.get(credIdx);
    if (predicates === undefined) {
      predicates = [];
    }
    predicates.push({ privateVars: circuitPrivateVars, publicVars: circuitPublicVars, circuitId, provingKeyId });
    this.circomPredicates.set(credIdx, predicates);
  }

  addBoundedPseudonym(
    basesForAttribute: Uint8Array[],
    // Attributes from each credential: keys are credential indexes, values are attribute names
    attributeNames: Map<number, string[]>,
    baseForSecretKey?: Uint8Array,
    secretKey?: Uint8Array
  ): number {
    let numberOfAttributes = 0;
    for (const [credIdx, attributes] of attributeNames.entries()) {
      this.validateCredIndex(credIdx);
      numberOfAttributes += attributes.length;
    }
    if (basesForAttribute.length !== numberOfAttributes) {
      throw new Error(
        `basesForAttribute must have the same length (${basesForAttribute.length}) as the number of attributes (${numberOfAttributes})`
      );
    }
    if (
      (baseForSecretKey === undefined && secretKey !== undefined) ||
      (baseForSecretKey !== undefined && secretKey === undefined)
    ) {
      throw new Error(`baseForSecretKey and secretKey must be undefined at the same time, or not at all`);
    }

    const pseudonym: BoundedPseudonym = {
      attributeNames: attributeNames,
      basesForAttributes: basesForAttribute,
      baseForSecretKey: baseForSecretKey,
      secretKey: secretKey
    };
    this.boundedPseudonyms.push(pseudonym);
    return this.boundedPseudonyms.length - 1;
  }

  addUnboundedPseudonym(baseForSecretKey: Uint8Array, secretKey: Uint8Array): number {
    const pseudonym: UnboundedPseudonym = {
      baseForSecretKey: baseForSecretKey,
      secretKey: secretKey
    };
    this.unboundedPseudonyms.push(pseudonym);
    return this.unboundedPseudonyms.length - 1;
  }

  /**
   * Create a presentation
   */
  finalize(): Presentation {
    const numCreds = this.credentials.length;
    // Tracking maximum attributes across all credentials so that new values for signatures
    // params are only created when the need be. Check definition of `adapt` for more details.

    const statements = new Statements();
    const metaStatements = new MetaStatements();
    const witnesses = new Witnesses();

    // Flattened schemas of all the credentials of this builder
    const flattenedSchemas: FlattenedSchema[] = [];

    // Store only needed encoded values of names and their indices. Maps cred index -> attribute index in schema -> encoded attribute
    const unrevealedMsgsEncoded = new Map<number, Map<number, Uint8Array>>();

    // For credentials with status, i.e. using accumulators, type is [credIndex, revCheckType, encoded (non)member]
    const credStatusAux: [number, string, Uint8Array][] = [];

    const setupParamsTrk = new SetupParamsTracker();
    const sigParamsByScheme = new Map();

    // Create statements and witnesses for proving possession of each credential, i.e. proof of knowledge of the sigs.
    // Also collect encoded attributes used in any predicate
    for (let i = 0; i < numCreds; i++) {
      const cred = this.credentials[i][0];
      const schema = cred.schema;
      const flattenedSchema = schema.flatten();

      const numAttribs = flattenedSchema[0].length;
      let revealedNames = this.revealedAttributes.get(i);
      if (revealedNames === undefined) {
        revealedNames = new Set();
      }
      const paramsClass = paramsClassBySignature(cred.signature);
      if (paramsClass === null) {
        throw new Error(`Invalid signature: ${cred.signature}`);
      }
      const sigParams = getSignatureParamsForMsgCount(sigParamsByScheme, paramsClass, numAttribs);

      // CredentialBuilder version, schema and 2 fields of revocation - registry id (denoting the accumulator) and the check
      // type, i.e. "membership" or "non-membership" are always revealed.
      revealedNames.add(CRYPTO_VERSION_STR);
      revealedNames.add(SCHEMA_STR);
      if (cred.credentialStatus !== undefined) {
        if (
          cred.credentialStatus[ID_STR] === undefined ||
          (cred.credentialStatus[REV_CHECK_STR] !== MEM_CHECK_STR &&
            cred.credentialStatus[REV_CHECK_STR] !== NON_MEM_CHECK_STR)
        ) {
          throw new Error(`Credential for ${i} has invalid status ${cred.credentialStatus}`);
        }
        revealedNames.add(`${STATUS_STR}.${ID_STR}`);
        revealedNames.add(`${STATUS_STR}.${REV_CHECK_STR}`);
      }

      const [revealedAttrsEncoded, unrevealedAttrsEncoded, revealedAtts] = getRevealedAndUnrevealed(
        cred.serializeForSigning(),
        revealedNames,
        schema.encoder
      );
      const statement = buildSignatureStatementFromParamsRef(
        setupParamsTrk,
        sigParams,
        this.credentials[i][1],
        numAttribs,
        revealedAttrsEncoded
      );
      const witness = buildWitness(cred.signature, unrevealedAttrsEncoded);
      statements.add(statement);
      witnesses.add(witness);

      let presentedStatus: IPresentedStatus | undefined;
      if (cred.credentialStatus !== undefined) {
        const s = this.credStatuses.get(i);
        if (s === undefined) {
          throw new Error(`No status details found for credential index ${i}`);
        }
        presentedStatus = {
          [ID_STR]: cred.credentialStatus[ID_STR],
          [TYPE_STR]: STATUS_TYPE_STR,
          [REV_CHECK_STR]: cred.credentialStatus[REV_CHECK_STR],
          accumulated: s[1],
          extra: s[3]
        };
        credStatusAux.push([
          i,
          cred.credentialStatus[REV_CHECK_STR],
          schema.encoder.encodeMessage(`${STATUS_STR}.${REV_ID_STR}`, cred.credentialStatus[REV_ID_STR])
        ]);
      }

      // Update the map of encoded attributes for current credential with the given attribute name
      function updateEncodedAttrs(attrName: string, encodedAttrs: Map<number, Uint8Array>) {
        const nameIdx = flattenedSchema[0].indexOf(attrName);
        if (nameIdx == -1) {
          throw new Error(`Attribute ${attrName} not found in schema`);
        }
        const val = unrevealedAttrsEncoded.get(nameIdx);
        if (val === undefined) {
          throw new Error(`Attribute ${attrName} value not found in unrevealed encoded attributes`);
        }
        encodedAttrs.set(nameIdx, val);
      }

      // Get encoded attributes which are used in bound check
      const bounds = this.bounds.get(i);
      let attributeBounds: { [key: string]: string | IPresentedAttributeBounds } | undefined;
      if (bounds !== undefined && bounds.size > 0) {
        attributeBounds = {};
        const encodedAttrs = unrevealedMsgsEncoded.get(i) || new Map<number, Uint8Array>();
        for (const [name, b] of bounds.entries()) {
          attributeBounds[name] = b;
          updateEncodedAttrs(name, encodedAttrs);
        }
        attributeBounds = unflatten(attributeBounds);
        unrevealedMsgsEncoded.set(i, encodedAttrs);
      }

      // Get encoded attributes which are used in verifiable encryption
      let attributeEncs: { [key: string]: string | IPresentedAttributeVE } | undefined;
      const encs = this.verifEnc.get(i);
      if (encs !== undefined && encs.size > 0) {
        attributeEncs = {};
        const encodedAttrs = unrevealedMsgsEncoded.get(i) || new Map<number, Uint8Array>();
        for (const [name, ve] of encs.entries()) {
          const valTyp = schema.typeOfName(name, flattenedSchema);
          if (valTyp.type !== ValueType.RevStr) {
            throw new Error(
              `Attribute name ${name} of credential index ${i} should be a reversible string type but was ${valTyp}`
            );
          }
          attributeEncs[name] = ve;
          updateEncodedAttrs(name, encodedAttrs);
        }
        attributeEncs = unflatten(attributeEncs);
        unrevealedMsgsEncoded.set(i, encodedAttrs);
      }

      // Get encoded attributes used in predicates expressed as Circom programs
      const predicates = this.circomPredicates.get(i);
      const [encodedAttrs, predicatesForSpec] = this.encodeCircomAttrsAndFormatPredicatesForSpec(
        predicates,
        () => {
          return unrevealedMsgsEncoded.get(i) || new Map<number, Uint8Array>();
        },
        (a: string, m: Map<number, Uint8Array>) => {
          return updateEncodedAttrs(a, m);
        }
      );
      if (encodedAttrs !== undefined) {
        unrevealedMsgsEncoded.set(i, encodedAttrs);
      }

      function updateUnrevealedMsgsEncoded(attributeNames?: string[]) {
        if (attributeNames !== undefined) {
          // this bounded pseudonym does not use any attributes from credential indexed `i`
          const encodedAttrs = unrevealedMsgsEncoded.get(i) || new Map<number, Uint8Array>();
          for (const attributeName of attributeNames) {
            updateEncodedAttrs(attributeName, encodedAttrs);
          }
          unrevealedMsgsEncoded.set(i, encodedAttrs);
        }
      }

      // Get encoded attributes which are used in bounded pseudonyms
      for (let j = 0; j < this.boundedPseudonyms.length; j++) {
        const attributeNames = this.boundedPseudonyms[j].attributeNames.get(i);
        updateUnrevealedMsgsEncoded(attributeNames);
      }

      // Get encoded attributes which are used in bounded pseudonyms for the blinded credential request
      if (this.blindCredReq !== undefined && this.blindCredReq.pseudonyms.length > 0) {
        for (let j = 0; j < this.blindCredReq.pseudonyms.length; j++) {
          const attributeNames = this.blindCredReq.pseudonyms[j].credentialAttributes.get(i);
          updateUnrevealedMsgsEncoded(attributeNames);
        }
      }

      const ver = revealedAtts[CRYPTO_VERSION_STR];
      const sch = revealedAtts[SCHEMA_STR];
      delete revealedAtts[CRYPTO_VERSION_STR];
      delete revealedAtts[SCHEMA_STR];
      delete revealedAtts[STATUS_STR];
      this.spec.addPresentedCredential(
        ver,
        sch,
        revealedAtts,
        presentedStatus,
        attributeBounds,
        attributeEncs,
        predicatesForSpec
      );

      flattenedSchemas.push(flattenedSchema);
    }

    // Create statements and witnesses for accumulators used in credential status
    credStatusAux.forEach(([i, t, value]) => {
      const s = this.credStatuses.get(i);
      if (s === undefined) {
        throw new Error(`No status details found for credential index ${i}`);
      }
      const [wit, acc, pk] = s;
      let witness;
      if (t === MEM_CHECK_STR) {
        if (!(wit instanceof MembershipWitness)) {
          throw new Error(`Expected membership witness but got non-membership witness for credential index ${i}`);
        }
        witness = Witness.accumulatorMembership(value, wit);
      } else {
        if (!(wit instanceof NonMembershipWitness)) {
          throw new Error(`Expected non-membership witness but got membership witness for credential index ${i}`);
        }
        witness = Witness.accumulatorNonMembership(value, wit);
      }
      const statement = accumulatorStatement(t, pk, acc, setupParamsTrk);
      const sIdx = statements.add(statement);
      witnesses.add(witness);

      const witnessEq = new WitnessEqualityMetaStatement();
      witnessEq.addWitnessRef(i, flattenedSchemas[i][0].indexOf(`${STATUS_STR}.${REV_ID_STR}`));
      witnessEq.addWitnessRef(sIdx, 0);
      metaStatements.addWitnessEquality(witnessEq);
    });

    function createWitnessEqualitiesForPseudonyms(
      credentialAttributes: Map<number, string[]>
    ): [[WitnessEqualityMetaStatement, number][], Uint8Array[]] {
      // the second parameter is the corresponding attribute index
      // to do witnessEq.addWitnessRef(sIdx, index);
      // later when sIdx will be known
      const witnessEqs: [WitnessEqualityMetaStatement, number][] = [];
      const attributes: Uint8Array[] = [];
      for (const [credIdx, attributeNames] of credentialAttributes.entries()) {
        const encodedAttrs = unrevealedMsgsEncoded.get(credIdx) as Map<number, Uint8Array>;
        const flattenedSchema = flattenedSchemas[credIdx];
        for (const attributeName of attributeNames) {
          const attributeIndex = flattenedSchema[0].indexOf(attributeName);
          const attribute = encodedAttrs.get(attributeIndex) as Uint8Array;
          attributes.push(attribute);
          const witnessEq = new WitnessEqualityMetaStatement();
          witnessEq.addWitnessRef(credIdx, attributeIndex);
          witnessEqs.push([witnessEq, attributes.length - 1]);
        }
      }
      return [witnessEqs, attributes];
    }

    function createStatementAndWitnessesForPseudonyms(
      attributeBoundPseudonym: BoundedPseudonym | IProverBoundedPseudonymInBlindedCredReq,
      attributes: Uint8Array[],
      witnessEqs: [WitnessEqualityMetaStatement, number][]
    ): [string, string[], string | undefined] {
      const pseudonym = AttributeBoundPseudonym.new(
        attributeBoundPseudonym.basesForAttributes,
        attributes,
        attributeBoundPseudonym.baseForSecretKey,
        attributeBoundPseudonym.secretKey
      );
      const baseForSecretKey = attributeBoundPseudonym.baseForSecretKey;
      const decodedBaseForSecretKey =
        baseForSecretKey !== undefined ? PseudonymBases.decodeBaseForSecretKey(baseForSecretKey) : undefined;
      const decodedBasesForAttributes = PseudonymBases.decodeBasesForAttributes(
        attributeBoundPseudonym.basesForAttributes
      );
      const decodedPseudonym = Pseudonym.decode(pseudonym.value);
      const statement = Statement.attributeBoundPseudonym(
        pseudonym,
        attributeBoundPseudonym.basesForAttributes,
        attributeBoundPseudonym.baseForSecretKey
      );
      const sIdx = statements.add(statement);
      for (const [witnessEq, attributeIndex] of witnessEqs) {
        witnessEq.addWitnessRef(sIdx, attributeIndex);
        metaStatements.addWitnessEquality(witnessEq);
      }
      const witness = Witness.attributeBoundPseudonym(attributes, attributeBoundPseudonym.secretKey);
      witnesses.add(witness);
      return [decodedPseudonym, decodedBasesForAttributes, decodedBaseForSecretKey];
    }

    // Create statements and witnesses for each boundedPseudonyms
    const presentedBoundedPseudonyms = {};
    for (let i = 0; i < this.boundedPseudonyms.length; i++) {
      const attributeBoundPseudonym = this.boundedPseudonyms[i];
      const [witnessEqs, attributes] = createWitnessEqualitiesForPseudonyms(attributeBoundPseudonym.attributeNames);
      const [decodedPseudonym, decodedBasesForAttributes, decodedBaseForSecretKey] =
        createStatementAndWitnessesForPseudonyms(attributeBoundPseudonym, attributes, witnessEqs);
      presentedBoundedPseudonyms[decodedPseudonym] = {
        commitKey: {
          basesForAttributes: decodedBasesForAttributes,
          baseForSecretKey: decodedBaseForSecretKey
        },
        attributes: Object.fromEntries(attributeBoundPseudonym.attributeNames)
      };
    }
    this.spec.boundedPseudonyms = presentedBoundedPseudonyms;

    // Create statements and witnesses for each unboundedPseudonyms
    const presentedUnboundedPseudonyms = {};
    for (let i = 0; i < this.unboundedPseudonyms.length; i++) {
      const unboundedPseudonym = this.unboundedPseudonyms[i];
      const pseudonym = Pseudonym.new(unboundedPseudonym.baseForSecretKey, unboundedPseudonym.secretKey);
      const decodedBaseForSecretKey = PseudonymBases.decodeBaseForSecretKey(unboundedPseudonym.baseForSecretKey);
      const decodedPseudonym = Pseudonym.decode(pseudonym.value);
      presentedUnboundedPseudonyms[decodedPseudonym] = {
        commitKey: {
          baseForSecretKey: decodedBaseForSecretKey
        }
      };
      const statement = Statement.pseudonym(pseudonym, unboundedPseudonym.baseForSecretKey);
      statements.add(statement);
      const witness = Witness.pseudonym(unboundedPseudonym.secretKey);
      witnesses.add(witness);
    }
    this.spec.unboundedPseudonyms = presentedUnboundedPseudonyms;

    // Create meta-statements for enforcing attribute equalities
    for (const eql of this.attributeEqualities) {
      metaStatements.addWitnessEquality(createWitEq(eql, flattenedSchemas));
      this.spec.attributeEqualities.push(eql);
    }

    // For enforcing attribute bounds, add statement and witness
    for (const [cId, bounds] of this.bounds.entries()) {
      this.processBoundChecks(
        cId,
        (n: string) => {
          return flattenedSchemas[cId][0].indexOf(n);
        },
        bounds,
        flattenedSchemas[cId],
        (i: number) => {
          return unrevealedMsgsEncoded.get(cId)?.get(i) as Uint8Array;
        },
        statements,
        witnesses,
        metaStatements,
        setupParamsTrk
      );
    }

    // For adding ciphertexts corresponding to verifiably encrypted attributes in the presentation.
    // The key of the outer map is the credential index, and key of the inner map is the name of the attribute that
    // is encrypted and value is the  index of statement created for encryption
    const credAttrToSId = new Map<number, Map<string, number>>();

    // For enforcing attribute encryption, add statement and witness
    for (const [cId, verEnc] of this.verifEnc.entries()) {
      this.processVerifiableEncs(
        cId,
        (n: string) => {
          return flattenedSchemas[cId][0].indexOf(n);
        },
        verEnc,
        (i: number) => {
          return unrevealedMsgsEncoded.get(cId)?.get(i) as Uint8Array;
        },
        credAttrToSId,
        statements,
        witnesses,
        metaStatements,
        setupParamsTrk
      );
    }

    // For enforcing Circom predicates, add statement and witness
    for (const [cId, predicates] of this.circomPredicates.entries()) {
      this.processCircomPredicates(
        cId,
        (n: string) => {
          return flattenedSchemas[cId][0].indexOf(n);
        },
        predicates,
        (i: number) => {
          return unrevealedMsgsEncoded.get(cId)?.get(i) as Uint8Array;
        },
        statements,
        witnesses,
        metaStatements,
        setupParamsTrk
      );
    }

    // For blinded credential request
    let blindAttrToSId = new Map<string, number>();
    if (this.blindCredReq !== undefined) {
      const sigParams = this.blindCredReq.sigParams;
      const encodedSubject = this.blindCredReq.encodedSubject;
      // Sorted list of subject attribute indices
      const blindedSubjectIndices = Array.from(encodedSubject.keys()).sort((a, b) => a - b);
      // List of subject attribute values corresponding to blindedSubjectIndices
      const blindedSubjectValues = blindedSubjectIndices.map((i) => encodedSubject.get(i) as Uint8Array);
      // Statement index corresponding to the Pedersen commitment of the blinded attributes
      let pedCommStId;
      // Offset of attributes in the Pedersen Commitment, its 0 for BBS and 1 for BBS+ as the commitment in BBS+ is perfectly hiding.
      let pedCommWitnessOffset;

      if (sigParams instanceof BBSSignatureParams || sigParams instanceof BBSPlusSignatureParamsG1) {
        const commKey = sigParams.getParamsForIndices(blindedSubjectIndices);
        pedCommStId = statements.add(Statement.pedersenCommitmentG1(commKey, this.blindCredReq.req.commitment));
      } else {
        throw new Error('Not yet implemented for PS');
      }

      if (sigParams instanceof BBSSignatureParams) {
        witnesses.add(Witness.pedersenCommitment(blindedSubjectValues));
        pedCommWitnessOffset = 0;
      } else if (sigParams instanceof BBSPlusSignatureParamsG1) {
        witnesses.add(Witness.pedersenCommitment([this.blindCredReq.blinding as Uint8Array, ...blindedSubjectValues]));
        pedCommWitnessOffset = 1;
      } else {
        throw new Error('Blind signing not yet implemented for PS');
      }

      // Get the attribute index in the Pedersen commitment witness
      const getAttrIndexInPedComm = (attr: number | string): number => {
        if (typeof attr === 'number') {
          return blindedSubjectIndices.indexOf(attr) + pedCommWitnessOffset;
        } else {
          const index = this.blindCredReq?.attrNameToIndex.get(attr);
          if (index === undefined) {
            throw new Error(`Missing attribute ${attr} in subject to index map`);
          }
          return blindedSubjectIndices.indexOf(index) + pedCommWitnessOffset;
        }
      };

      // Get the attribute value where the given index is in the Pedersen commitment witness
      const getAttrValue = (attrIdx: number): Uint8Array => {
        return blindedSubjectValues[attrIdx - pedCommWitnessOffset];
      };

      // Create meta-statements for enforcing equalities between blinded attributes and other credential attributes
      for (const [name, otherAttributeRefs] of this.blindCredReq.req.blindedAttributeEqualities) {
        const index = getAttrIndexInPedComm(name);
        metaStatements.addWitnessEquality(
          createWitEqForBlindedCred(pedCommStId, index, otherAttributeRefs, flattenedSchemas)
        );
      }

      this.spec.blindCredentialRequest = this.blindCredReq.req;

      // Create statements, witnesses and meta-statements for enforcing bounds on blinded attributes
      if (this.blindCredReq.bounds.size > 0) {
        this.processBoundChecks(
          pedCommStId,
          getAttrIndexInPedComm,
          this.blindCredReq.bounds,
          this.blindCredReq.flattenedSchema,
          getAttrValue,
          statements,
          witnesses,
          metaStatements,
          setupParamsTrk
        );
        this.spec.blindCredentialRequest.bounds = this.formatAttributesForSpec(this.blindCredReq.bounds);
      }

      // Create statements, witnesses and meta-statements for verifiable encryption of blinded attributes
      if (this.blindCredReq.verifEnc.size > 0) {
        const tempMap = new Map();
        this.processVerifiableEncs(
          pedCommStId,
          getAttrIndexInPedComm,
          this.blindCredReq.verifEnc,
          getAttrValue,
          tempMap,
          statements,
          witnesses,
          metaStatements,
          setupParamsTrk
        );
        blindAttrToSId = tempMap.get(pedCommStId);
        this.spec.blindCredentialRequest.verifiableEncryptions = this.formatAttributesForSpec(
          this.blindCredReq.verifEnc
        );
      }

      // Create statements, witnesses and meta-statements for enforcing Circom predicates on blinded attributes
      if (this.blindCredReq.circPred.length > 0) {
        this.processCircomPredicates(
          pedCommStId,
          getAttrIndexInPedComm,
          this.blindCredReq.circPred,
          getAttrValue,
          statements,
          witnesses,
          metaStatements,
          setupParamsTrk
        );
        const [_, predicatesForSpec] = this.encodeCircomAttrsAndFormatPredicatesForSpec(this.blindCredReq.circPred);
        this.spec.blindCredentialRequest.circomPredicates = predicatesForSpec;
      }

      // Create statements, witnesses and meta-statements for pseudonyms bounded to blinded and/or credential attributes
      if (this.blindCredReq.pseudonyms.length > 0) {
        const presentedBoundedPseudonyms = {};
        for (const attributeBoundPseudonym of this.blindCredReq.pseudonyms) {
          const [witnessEqs, attributes] = createWitnessEqualitiesForPseudonyms(
            attributeBoundPseudonym.credentialAttributes
          );
          for (const attributeName of attributeBoundPseudonym.blindedAttributes) {
            const attributeIndex = getAttrIndexInPedComm(attributeName);
            const attribute = getAttrValue(attributeIndex);
            attributes.push(attribute);
            const witnessEq = new WitnessEqualityMetaStatement();
            witnessEq.addWitnessRef(pedCommStId, attributeIndex);
            witnessEqs.push([witnessEq, attributes.length - 1]);
          }

          const [decodedPseudonym, decodedBasesForAttributes, decodedBaseForSecretKey] =
            createStatementAndWitnessesForPseudonyms(attributeBoundPseudonym, attributes, witnessEqs);

          presentedBoundedPseudonyms[decodedPseudonym] = {
            commitKey: {
              basesForAttributes: decodedBasesForAttributes,
              baseForSecretKey: decodedBaseForSecretKey
            },
            credentialAttributes: Object.fromEntries(attributeBoundPseudonym.credentialAttributes),
            blindedAttributes: attributeBoundPseudonym.blindedAttributes
          };
        }
        this.spec.blindCredentialRequest.pseudonyms = presentedBoundedPseudonyms;
      }
    }

    // The version and spec are also added to the proof thus binding these to the proof cryptographically.
    const ctx = buildContextForProof(this.version, this.spec, this._context);
    this._proofSpec = new QuasiProofSpecG1(statements, metaStatements, setupParamsTrk.setupParams, ctx);
    this.proof = CompositeProofG1.generateUsingQuasiProofSpec(this._proofSpec, witnesses, this._nonce);

    // Ciphertexts of credential attributes
    let attributeCiphertexts;
    // Ciphertexts of blinded attributes
    let blindedAttributeCiphertexts;
    // Statements which correspond to encryption of attributes and thus will have corresponding ciphertexts
    const encryptionStatementIndices: number[] = [];
    // Get statement indices which correspond to encryption of credential attributes
    if (credAttrToSId.size > 0) {
      for (const v of credAttrToSId.values()) {
        for (const sId of v.values()) {
          encryptionStatementIndices.push(sId);
        }
      }
    }

    // Get statement indices which correspond to encryption of blinded attributes
    if (blindAttrToSId.size > 0) {
      encryptionStatementIndices.push(...blindAttrToSId.values());
    }

    // Get all encryption statement indices and get their corresponding ciphertexts
    const ciphertexts = this.proof.getSaverCiphertexts(encryptionStatementIndices);

    if (credAttrToSId.size > 0) {
      attributeCiphertexts = new Map();
      for (const [i, v] of credAttrToSId.entries()) {
        attributeCiphertexts.set(i, this.formatAttributeCiphertexts(v, encryptionStatementIndices, ciphertexts));
      }
    }
    if (blindAttrToSId.size > 0) {
      blindedAttributeCiphertexts = this.formatAttributeCiphertexts(
        blindAttrToSId,
        encryptionStatementIndices,
        ciphertexts
      );
    }

    return new Presentation(
      this.version,
      this.spec,
      this.proof,
      attributeCiphertexts,
      this._context,
      this._nonce,
      blindedAttributeCiphertexts
    );
  }

  get context(): string | undefined {
    return this._context;
  }

  set context(context: string | undefined) {
    this._context = context;
  }

  get nonce(): Uint8Array | undefined {
    return this._nonce;
  }

  set nonce(nonce: Uint8Array | undefined) {
    this._nonce = nonce;
  }

  validateCredIndex(credIdx: number) {
    if (credIdx >= this.credentials.length) {
      throw new Error(`Invalid credential index ${credIdx}. Number of credentials is ${this.credentials.length}`);
    }
  }

  updatePredicateParams(id: string, val?: PredicateParamType) {
    if (val !== undefined) {
      if (this.predicateParams.has(id)) {
        throw new Error(`Predicate params already exists for id ${id}`);
      }
      this.predicateParams.set(id, val);
    }
  }

  static r1csParamId(circuitId: string): string {
    return `${circuitId}__r1cs__`;
  }

  static wasmParamId(circuitId: string): string {
    return `${circuitId}__wasm__`;
  }

  private addLegoProvingKeyToTracker(
    paramId: string,
    param: PredicateParamType | undefined,
    setupParamsTrk: SetupParamsTracker,
    statementIdx: number
  ) {
    if (param instanceof LegoProvingKey) {
      if (!setupParamsTrk.isTrackingParam(paramId)) {
        setupParamsTrk.addForParamId(paramId, SetupParam.legosnarkProvingKey(param));
      }
    } else if (param instanceof LegoProvingKeyUncompressed) {
      if (!setupParamsTrk.isTrackingParam(paramId)) {
        setupParamsTrk.addForParamId(paramId, SetupParam.legosnarkProvingKeyUncompressed(param));
      }
    } else {
      throw new Error(
        `Predicate param id ${paramId} (for statement index ${statementIdx}) was expected to be a Legosnark proving key but was ${param}`
      );
    }
  }

  private processBoundChecks(
    statementIdx: number,
    witnessIndexGetter: (string) => number,
    bounds: Map<string, IPresentedAttributeBounds>,
    flattenedSchema: FlattenedSchema,
    encodedAttrGetter: (number) => Uint8Array,
    statements: Statements,
    witnesses: Witnesses,
    metaStatements: MetaStatements,
    setupParamsTrk: SetupParamsTracker
  ) {
    const dataSortedByNameIdx: [number, string, IPresentedAttributeBounds][] = [];
    for (const [name, b] of bounds.entries()) {
      const nameIdx = witnessIndexGetter(name);
      dataSortedByNameIdx.push([nameIdx, name, b]);
    }
    // Sort by attribute index so that both prover and verifier create statements and witnesses in the same order
    dataSortedByNameIdx.sort(function (a, b) {
      return a[0] - b[0];
    });
    dataSortedByNameIdx.forEach(([nameIdx, name, { min, max, paramId }]) => {
      const valTyp = CredentialSchema.typeOfName(name, flattenedSchema);
      const [transformedMin, transformedMax] = getTransformedMinMax(name, valTyp, min, max);

      const param = this.predicateParams.get(paramId);
      this.addLegoProvingKeyToTracker(paramId, param, setupParamsTrk, statementIdx);
      const statement = Statement.boundCheckProverFromSetupParamRefs(
        transformedMin,
        transformedMax,
        setupParamsTrk.indexForParam(paramId)
      );

      const encodedAttrVal = encodedAttrGetter(nameIdx);
      witnesses.add(Witness.boundCheckLegoGroth16(encodedAttrVal));

      const sIdx = statements.add(statement);
      const witnessEq = new WitnessEqualityMetaStatement();
      witnessEq.addWitnessRef(statementIdx, nameIdx);
      witnessEq.addWitnessRef(sIdx, 0);
      metaStatements.addWitnessEquality(witnessEq);
    });
  }

  private processVerifiableEncs(
    statementIdx: number,
    witnessIndexGetter: (string) => number,
    verEnc: Map<string, IPresentedAttributeVE>,
    encodedAttrGetter: (number) => Uint8Array,
    credAttrToSId: Map<number, Map<string, number>>,
    statements: Statements,
    witnesses: Witnesses,
    metaStatements: MetaStatements,
    setupParamsTrk: SetupParamsTracker
  ) {
    const dataSortedByNameIdx: [number, string, IPresentedAttributeVE][] = [];
    for (const [name, ve] of verEnc.entries()) {
      const nameIdx = witnessIndexGetter(name);
      dataSortedByNameIdx.push([nameIdx, name, ve]);
    }
    // Sort by attribute index so that both prover and verifier create statements and witnesses in the same order
    dataSortedByNameIdx.sort(function (a, b) {
      return a[0] - b[0];
    });
    const attrToSid = new Map<string, number>();
    dataSortedByNameIdx.forEach(([nameIdx, name, { chunkBitSize, commitmentGensId, encryptionKeyId, snarkKeyId }]) => {
      const commGens = this.predicateParams.get(commitmentGensId);
      if (commGens === undefined) {
        throw new Error(`Predicate param for id ${commitmentGensId} not found`);
      }
      const encKey = this.predicateParams.get(encryptionKeyId);
      if (encKey === undefined) {
        throw new Error(`Predicate param for id ${encryptionKeyId} not found`);
      }
      const snarkPk = this.predicateParams.get(snarkKeyId);
      if (snarkPk === undefined) {
        throw new Error(`Predicate param for id ${snarkKeyId} not found`);
      }

      const statement = saverStatement(
        true,
        chunkBitSize,
        commitmentGensId,
        encryptionKeyId,
        snarkKeyId,
        commGens,
        encKey,
        snarkPk,
        setupParamsTrk
      );
      const encodedAttrVal = encodedAttrGetter(nameIdx);
      witnesses.add(Witness.saver(encodedAttrVal));

      const sIdx = statements.add(statement);
      const witnessEq = new WitnessEqualityMetaStatement();
      witnessEq.addWitnessRef(statementIdx, nameIdx);
      witnessEq.addWitnessRef(sIdx, 0);
      metaStatements.addWitnessEquality(witnessEq);
      attrToSid.set(name, sIdx);
    });
    if (attrToSid.size > 0) {
      credAttrToSId.set(statementIdx, attrToSid);
    }
  }

  private processCircomPredicates(
    statementIdx: number,
    witnessIndexGetter: (string) => number,
    predicates: IProverCircomPredicate[],
    encodedAttrGetter: (number) => Uint8Array,
    statements: Statements,
    witnesses: Witnesses,
    metaStatements: MetaStatements,
    setupParamsTrk: SetupParamsTracker
  ) {
    predicates.forEach(({ privateVars, publicVars, circuitId, provingKeyId: snarkKeyId }) => {
      const snarkKey = this.predicateParams.get(snarkKeyId);
      const r1csId = PresentationBuilder.r1csParamId(circuitId);
      const r1cs = this.predicateParams.get(r1csId);
      const wasmId = PresentationBuilder.wasmParamId(circuitId);
      const wasm = this.predicateParams.get(wasmId);
      this.addLegoProvingKeyToTracker(snarkKeyId, snarkKey, setupParamsTrk, statementIdx);
      if (r1cs === undefined || wasm === undefined) {
        throw new Error('Both WASM and R1CS should be present');
      }
      if (!setupParamsTrk.isTrackingParam(r1csId)) {
        setupParamsTrk.addForParamId(r1csId, SetupParam.r1cs(r1cs as R1CS));
      }
      if (!setupParamsTrk.isTrackingParam(wasmId)) {
        setupParamsTrk.addForParamId(wasmId, SetupParam.bytes(wasm as Uint8Array));
      }

      const statement = Statement.r1csCircomProverFromSetupParamRefs(
        setupParamsTrk.indexForParam(r1csId),
        setupParamsTrk.indexForParam(wasmId),
        setupParamsTrk.indexForParam(snarkKeyId)
      );
      const sIdx = statements.add(statement);

      function addWitnessEqualityAndReturnEncodedAttr(name: string): Uint8Array {
        const nameIdx = witnessIndexGetter(name);
        const witnessEq = new WitnessEqualityMetaStatement();
        witnessEq.addWitnessRef(statementIdx, nameIdx);
        witnessEq.addWitnessRef(sIdx, predicateWitnessIdx++);
        metaStatements.addWitnessEquality(witnessEq);
        return encodedAttrGetter(nameIdx);
      }

      let predicateWitnessIdx = 0;
      const circuitInputs = new CircomInputs();
      // For each private input, set its value as the corresponding attribute and set the witness equality
      privateVars.forEach(([varName, name]) => {
        if (Array.isArray(name)) {
          circuitInputs.setPrivateArrayInput(
            varName,
            name.map((n) => {
              return addWitnessEqualityAndReturnEncodedAttr(n);
            })
          );
        } else {
          circuitInputs.setPrivateInput(varName, addWitnessEqualityAndReturnEncodedAttr(name));
        }
      });

      publicVars.forEach(([varName, value]) => {
        if (Array.isArray(value)) {
          circuitInputs.setPublicArrayInput(varName, value);
        } else {
          circuitInputs.setPublicInput(varName, value);
        }
      });
      witnesses.add(Witness.r1csCircomWitness(circuitInputs));
    });
  }

  private formatAttributesForSpec<T>(attrMap: Map<string, T>): { [key: string]: string | T } {
    const formatted = {};
    for (const [name, b] of attrMap.entries()) {
      formatted[name] = b;
    }
    return unflatten(formatted);
  }

  private formatAttributeCiphertexts(
    attrToStIdx: Map<string, number>,
    allEncStIds: number[],
    ciphertexts: SaverCiphertext[]
  ): object {
    const m = {};
    for (const [name, sId] of attrToStIdx.entries()) {
      let curM = m;
      // name is a flattened name, like credentialSubject.nesting1.nesting2.name
      const nameParts = name.split('.');
      for (let j = 0; j < nameParts.length - 1; j++) {
        if (curM[nameParts[j]] === undefined) {
          curM[nameParts[j]] = {};
        }
        // `curM` refers to this inner object of `m`
        curM = curM[nameParts[j]];
      }
      curM[nameParts[nameParts.length - 1]] = ciphertexts[allEncStIds.indexOf(sId)];
    }
    return m;
  }

  private encodeCircomAttrsAndFormatPredicatesForSpec<T>(
    predicates?: IProverCircomPredicate[],
    encodedAttrsGetter?: () => Map<number, Uint8Array>,
    encodedAttrsUpdater?: (string, Map) => void
  ): [Map<number, Uint8Array> | undefined, ICircomPredicate[] | undefined] {
    let predicatesForSpec: ICircomPredicate[] | undefined;
    let encodedAttrs: Map<number, Uint8Array> | undefined;
    if (predicates !== undefined && predicates.length > 0) {
      predicatesForSpec = [];
      if (encodedAttrsGetter !== undefined) {
        encodedAttrs = encodedAttrsGetter();
      }
      predicates.forEach((predicate) => {
        const privateVars = predicate.privateVars;
        const privateVarsForSpec: ICircuitPrivateVars[] = [];
        privateVars.forEach(([varName, attrName]) => {
          if (Array.isArray(attrName)) {
            const attributeName = [];
            attrName.forEach((a) => {
              if (encodedAttrsUpdater !== undefined) {
                encodedAttrsUpdater(a, encodedAttrs);
              }
              attributeName.push(unflatten({ [a]: null }));
            });
            privateVarsForSpec.push({
              varName,
              attributeName
            });
          } else {
            if (encodedAttrsUpdater !== undefined) {
              encodedAttrsUpdater(attrName, encodedAttrs);
            }
            privateVarsForSpec.push({
              varName,
              attributeName: unflatten({ [attrName]: null })
            });
          }
        });
        // @ts-ignore
        predicatesForSpec.push({
          privateVars: privateVarsForSpec,
          publicVars: predicate.publicVars.map(([n, v]) => {
            return {
              varName: n,
              value: v
            };
          }),
          circuitId: predicate.circuitId,
          snarkKeyId: predicate.provingKeyId
        });
      });
    }
    return [encodedAttrs, predicatesForSpec];
  }
}

export interface IProverCircomPredicate {
  privateVars: [string, string | string[]][];
  publicVars: [string, Uint8Array | Uint8Array[]][];
  circuitId: string;
  provingKeyId: string;
}

export interface IProverBoundedPseudonymInBlindedCredReq {
  basesForAttributes: Uint8Array[];
  baseForSecretKey?: Uint8Array;
  // key is credIdx, values are attribute names in the credential corresponding to the credIdx
  credentialAttributes: Map<number, string[]>;
  blindedAttributes: string[];
  secretKey?: Uint8Array;
}
