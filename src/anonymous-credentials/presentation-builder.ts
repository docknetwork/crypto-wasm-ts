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
import { CircomInputs, getR1CS, ParsedR1CSFile } from '../r1cs';
import { R1CS } from '@docknetwork/crypto-wasm';
import { CredentialSchema, ValueType } from './schema';
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
  PublicKey
} from './types-and-consts';
import {
  ICircomPredicate,
  ICircuitPrivateVars,
  IPresentedAttributeBounds,
  IPresentedAttributeVE,
  IPresentedStatus,
  PresentationSpecification
} from './presentation-specification';
import { Presentation } from './presentation';
import { AccumulatorPublicKey, AccumulatorWitness, MembershipWitness, NonMembershipWitness } from '../accumulator';
import {
  accumulatorStatement,
  buildContextForProof,
  buildSignatureStatementFromParamsRef,
  buildWitness,
  createWitEq,
  getTransformedMinMax,
  paramsClassBySignature,
  saverStatement,
  getSignatureParamsForMsgCount
} from './util';
import {
  SaverChunkedCommitmentGens,
  SaverChunkedCommitmentGensUncompressed,
  SaverEncryptionKey,
  SaverEncryptionKeyUncompressed,
  SaverProvingKey,
  SaverProvingKeyUncompressed
} from '../saver';
import { unflatten } from 'flat';
import { SetupParamsTracker } from './setup-params-tracker';

type Credential = BBSCredential | BBSPlusCredential | PSCredential;

export class PresentationBuilder extends Versioned {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.1.0';

  _context?: string;
  _nonce?: Uint8Array;
  proof?: CompositeProofG1;
  // Just for debugging
  _proofSpec?: QuasiProofSpecG1;
  spec: PresentationSpecification;

  // Each credential is referenced by its index in this array
  credentials: [Credential, PublicKey][];

  // Attributes revealed from each credential, key of the map is the credential index
  revealedAttributes: Map<number, Set<string>>;

  // Attributes proved equal in zero knowledge
  attributeEqualities: AttributeEquality[];

  // Each credential has only one accumulator for status
  credStatuses: Map<number, [AccumulatorWitness, Uint8Array, AccumulatorPublicKey, object]>;

  // Bounds on attribute. The key of the map is the credential index and for the inner map is the attribute and value of map
  // denotes min, max, an identifier of the snark proving key which the verifier knows as well to use corresponding verifying key
  bounds: Map<number, Map<string, IPresentedAttributeBounds>>;

  // Verifiable encryption of attributes
  verifEnc: Map<number, Map<string, IPresentedAttributeVE>>;

  // Predicates expressed as Circom programs. For each credential, store a tuple of R1CS, WASM bytes and attributes used in circuit
  circomPredicates: Map<
    number,
    [[string, string | string[]][], [string, Uint8Array | Uint8Array[]][], string, string][]
  >;

  // Parameters for predicates like snark proving key for bound check, verifiable encryption, Circom program
  predicateParams: Map<string, PredicateParamType>;

  constructor() {
    super(PresentationBuilder.VERSION);
    this.credentials = [];
    this.revealedAttributes = new Map();
    this.attributeEqualities = [];
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
   * @param attributeNames - Nested attribute names use the "dot" separator
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
    this.updatePredicateParams(provingKeyId, provingKey);
    b.set(attributeName, { min, max, paramId: provingKeyId });
    this.bounds.set(credIdx, b);
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

    this.updatePredicateParams(commGensId, commGens);
    this.updatePredicateParams(encryptionKeyId, encryptionKey);
    this.updatePredicateParams(snarkPkId, snarkPk);
    v.set(attributeName, {
      chunkBitSize,
      commitmentGensId: commGensId,
      encryptionKeyId: encryptionKeyId,
      snarkKeyId: snarkPkId
    });
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
    if (circuitPrivateVars.length == 0) {
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
    predicates.push([circuitPrivateVars, circuitPublicVars, circuitId, provingKeyId]);
    this.circomPredicates.set(credIdx, predicates);
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
    const sigParamsByScheme = Object.create(null);

    // Reset spec state (incase this method is called more than once)
    this.spec.reset();

    // Create statements and witnesses for proving possession of each credential, i.e. proof of knowledge of the sigs.
    // Also collect encoded attributes used in any predicate
    for (let i = 0; i < numCreds; i++) {
      const cred = this.credentials[i][0];
      const schema = cred.schema as CredentialSchema;
      const flattenedSchema = schema.flatten();

      const numAttribs = flattenedSchema[0].length;
      let revealedNames = this.revealedAttributes.get(i);
      if (revealedNames === undefined) {
        revealedNames = new Set();
      }
      const paramsClass = paramsClassBySignature(cred.signature);
      if (paramsClass == null) {
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

      // Get encoded attributes which are used in bound check
      let attributeBounds: { [key: string]: string | IPresentedAttributeBounds } | undefined;
      const bounds = this.bounds.get(i);
      if (bounds !== undefined && bounds.size > 0) {
        attributeBounds = {};
        const encodedAttrs = unrevealedMsgsEncoded.get(i) || new Map<number, Uint8Array>();
        for (const [name, b] of bounds.entries()) {
          attributeBounds[name] = b;
          const nameIdx = flattenedSchema[0].indexOf(name);
          encodedAttrs.set(nameIdx, unrevealedAttrsEncoded.get(nameIdx) as Uint8Array);
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
          const nameIdx = flattenedSchema[0].indexOf(name);
          const valTyp = schema.typeOfName(name, flattenedSchema);
          if (valTyp.type !== ValueType.RevStr) {
            throw new Error(
              `Attribute name ${name} of credential index ${i} should be a reversible string type but was ${valTyp}`
            );
          }
          attributeEncs[name] = ve;
          encodedAttrs.set(nameIdx, unrevealedAttrsEncoded.get(nameIdx) as Uint8Array);
        }
        attributeEncs = unflatten(attributeEncs);
        unrevealedMsgsEncoded.set(i, encodedAttrs);
      }

      function circomAttrForSpec(attrName: string, encodedAttrs: Map<number, Uint8Array>): object {
        const nameIdx = flattenedSchema[0].indexOf(attrName as string);
        encodedAttrs.set(nameIdx, unrevealedAttrsEncoded.get(nameIdx) as Uint8Array);
        return unflatten({ [attrName]: null });
      }

      // Get encoded attributes used in predicates expressed as Circom programs
      let predicatesForSpec: ICircomPredicate[] | undefined;
      const predicates = this.circomPredicates.get(i);
      if (predicates !== undefined && predicates.length > 0) {
        predicatesForSpec = [];
        const encodedAttrs = unrevealedMsgsEncoded.get(i) || new Map<number, Uint8Array>();
        predicates.forEach((predicate) => {
          const privateVars = predicate[0];
          const privateVarsForSpec: ICircuitPrivateVars[] = [];
          privateVars.forEach(([varName, attrName]) => {
            if (Array.isArray(attrName)) {
              const attributeName = [];
              attrName.forEach((a) => {
                // @ts-ignore
                attributeName.push(circomAttrForSpec(a, encodedAttrs));
              });
              privateVarsForSpec.push({
                varName,
                attributeName
              });
            } else {
              privateVarsForSpec.push({
                varName,
                // @ts-ignore
                attributeName: circomAttrForSpec(attrName, encodedAttrs)
              });
            }
          });
          // @ts-ignore
          predicatesForSpec.push({
            privateVars: privateVarsForSpec,
            publicVars: predicate[1].map(([n, v]) => {
              return {
                varName: n,
                value: v
              };
            }),
            circuitId: predicate[2],
            snarkKeyId: predicate[3]
          });
        });
        unrevealedMsgsEncoded.set(i, encodedAttrs);
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

    // Create meta-statements for enforcing attribute equalities
    for (const eql of this.attributeEqualities) {
      metaStatements.addWitnessEquality(createWitEq(eql, flattenedSchemas));
      this.spec.attributeEqualities.push(eql);
    }

    // For enforcing attribute bounds, add statement and witness
    for (const [cId, bounds] of this.bounds.entries()) {
      const dataSortedByNameIdx: [number, string, IPresentedAttributeBounds][] = [];
      for (const [name, b] of bounds.entries()) {
        const nameIdx = flattenedSchemas[cId][0].indexOf(name);
        dataSortedByNameIdx.push([nameIdx, name, b]);
      }
      // Sort by attribute index so that both prover and verifier create statements and witnesses in the same order
      dataSortedByNameIdx.sort(function (a, b) {
        return a[0] - b[0];
      });
      dataSortedByNameIdx.forEach(([nameIdx, name, { min, max, paramId }]) => {
        const valTyp = CredentialSchema.typeOfName(name, flattenedSchemas[cId]);
        const [transformedMin, transformedMax] = getTransformedMinMax(name, valTyp, min, max);

        const param = this.predicateParams.get(paramId);
        this.addLegoProvingKeyToTracker(paramId, param, setupParamsTrk, cId);
        const statement = Statement.boundCheckProverFromSetupParamRefs(
          transformedMin,
          transformedMax,
          setupParamsTrk.indexForParam(paramId)
        );

        const encodedAttrVal = unrevealedMsgsEncoded.get(cId)?.get(nameIdx) as Uint8Array;
        witnesses.add(Witness.boundCheckLegoGroth16(encodedAttrVal));

        const sIdx = statements.add(statement);
        const witnessEq = new WitnessEqualityMetaStatement();
        witnessEq.addWitnessRef(cId, nameIdx);
        witnessEq.addWitnessRef(sIdx, 0);
        metaStatements.addWitnessEquality(witnessEq);
      });
    }

    // For adding ciphertexts corresponding to verifiably encrypted attributes in the presentation
    const credAttrToSId = new Map<number, Map<string, number>>();

    // For enforcing attribute encryption, add statement and witness
    for (const [cId, verEnc] of this.verifEnc.entries()) {
      const dataSortedByNameIdx: [number, string, IPresentedAttributeVE][] = [];
      for (const [name, ve] of verEnc.entries()) {
        const nameIdx = flattenedSchemas[cId][0].indexOf(name);
        dataSortedByNameIdx.push([nameIdx, name, ve]);
      }
      // Sort by attribute index so that both prover and verifier create statements and witnesses in the same order
      dataSortedByNameIdx.sort(function (a, b) {
        return a[0] - b[0];
      });
      const attrToSid = new Map<string, number>();
      dataSortedByNameIdx.forEach(
        ([nameIdx, name, { chunkBitSize, commitmentGensId, encryptionKeyId, snarkKeyId }]) => {
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
          const encodedAttrVal = unrevealedMsgsEncoded.get(cId)?.get(nameIdx) as Uint8Array;
          witnesses.add(Witness.saver(encodedAttrVal));

          const sIdx = statements.add(statement);
          const witnessEq = new WitnessEqualityMetaStatement();
          witnessEq.addWitnessRef(cId, nameIdx);
          witnessEq.addWitnessRef(sIdx, 0);
          metaStatements.addWitnessEquality(witnessEq);
          attrToSid.set(name, sIdx);
        }
      );
      if (attrToSid.size > 0) {
        credAttrToSId.set(cId, attrToSid);
      }
    }

    // For enforcing Circom predicates, add statement and witness
    for (const [cId, predicates] of this.circomPredicates.entries()) {
      predicates.forEach(([privateVars, publicVars, circuitId, snarkKeyId]) => {
        const snarkKey = this.predicateParams.get(snarkKeyId);
        const r1csId = PresentationBuilder.r1csParamId(circuitId);
        const r1cs = this.predicateParams.get(r1csId);
        const wasmId = PresentationBuilder.wasmParamId(circuitId);
        const wasm = this.predicateParams.get(wasmId);
        this.addLegoProvingKeyToTracker(snarkKeyId, snarkKey, setupParamsTrk, cId);
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
          const nameIdx = flattenedSchemas[cId][0].indexOf(name);
          const witnessEq = new WitnessEqualityMetaStatement();
          witnessEq.addWitnessRef(cId, nameIdx);
          witnessEq.addWitnessRef(sIdx, predicateWitnessIdx++);
          metaStatements.addWitnessEquality(witnessEq);
          return unrevealedMsgsEncoded.get(cId)?.get(nameIdx) as Uint8Array;
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

    // The version and spec are also added to the proof thus binding these to the proof cryptographically.
    const ctx = buildContextForProof(this.version, this.spec, this._context);
    this._proofSpec = new QuasiProofSpecG1(statements, metaStatements, setupParamsTrk.setupParams, ctx);
    this.proof = CompositeProofG1.generateUsingQuasiProofSpec(this._proofSpec, witnesses, this._nonce);

    let attributeCiphertexts;
    if (credAttrToSId.size > 0) {
      const allSIds: number[] = [];
      for (const v of credAttrToSId.values()) {
        for (const sId of v.values()) {
          allSIds.push(sId);
        }
      }
      const ciphertexts = this.proof.getSaverCiphertexts(allSIds);
      attributeCiphertexts = new Map();
      for (const [i, v] of credAttrToSId.entries()) {
        const m = {};
        for (const [name, sId] of v.entries()) {
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
          curM[nameParts[nameParts.length - 1]] = ciphertexts[allSIds.indexOf(sId)];
        }
        attributeCiphertexts.set(i, m);
      }
    }

    return new Presentation(this.version, this.spec, this.proof, attributeCiphertexts, this._context, this._nonce);
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

  private updatePredicateParams(id: string, val?: PredicateParamType) {
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
    credentialIdx: number
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
        `Predicate param id ${paramId} (for credential index ${credentialIdx}) was expected to be a Legosnark proving key but was ${param}`
      );
    }
  }
}
