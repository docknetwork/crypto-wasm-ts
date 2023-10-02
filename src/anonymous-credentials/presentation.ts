import { Versioned } from './versioned';
import {
  IBoundedPseudonymCommitKey,
  ICircomPredicate,
  IPresentedAttributeBounds,
  IPresentedAttributeVE,
  IPresentedCredential,
  PresentationSpecification
} from './presentation-specification';
import {
  CompositeProofG1,
  MetaStatements,
  QuasiProofSpecG1,
  SetupParam,
  Statement,
  Statements,
  WitnessEqualityMetaStatement
} from '../composite-proof';
import { CredentialSchema, getTransformedMinMax, ValueType } from './schema';
import { VerifyResult } from '@docknetwork/crypto-wasm';
import { flatten } from 'flat';
import {
  AttributeCiphertexts,
  BBS_BLINDED_CRED_PROOF_TYPE,
  BBS_PLUS_BLINDED_CRED_PROOF_TYPE,
  CRYPTO_VERSION_STR,
  FlattenedSchema,
  ID_STR,
  MEM_CHECK_STR,
  NON_MEM_CHECK_STR,
  BlindSignatureTypes,
  RevocationStatusProtocols,
  SignatureTypes,
  PredicateParamType,
  PublicKey,
  REV_CHECK_STR,
  REV_ID_STR,
  SCHEMA_STR,
  STATUS_STR,
  BoundCheckProtocols,
  VerifiableEncryptionProtocols,
  CircomProtocols
} from './types-and-consts';
import { AccumulatorPublicKey } from '../accumulator';
import {
  accumulatorStatement,
  buildSignatureStatementFromParamsRef,
  createWitEq,
  createWitEqForBlindedCred,
  deepClone,
  flattenTill2ndLastKey,
  getSignatureParamsForMsgCount,
  paramsClassByPublicKey,
  saverStatement
} from './util';
import { LegoVerifyingKey, LegoVerifyingKeyUncompressed } from '../legosnark';
import { SaverCiphertext } from '../saver';
import b58 from 'bs58';
import { SetupParamsTracker } from './setup-params-tracker';
import { flattenObjectToKeyValuesList } from '../util';
import { Pseudonym, PseudonymBases } from '../Pseudonym';
import { BBSSignatureParams } from '../bbs';
import { BBSPlusSignatureParamsG1 } from '../bbs-plus';
import {
  BoundCheckBppParams,
  BoundCheckBppParamsUncompressed,
  BoundCheckSmcParams,
  BoundCheckSmcParamsUncompressed,
  BoundCheckSmcWithKVVerifierParams,
  BoundCheckSmcWithKVVerifierParamsUncompressed
} from '../bound-check';
import semver from 'semver/preload';

/**
 * The context passed to the proof contains the version and the presentation spec as well. This is done to bind the
 * presentation spec and the version cryptographically to the proof.
 * @param version
 * @param presSpec
 * @param context
 */
export function buildContextForProof(
  version: string,
  presSpec: PresentationSpecification,
  context?: string | Uint8Array
): Uint8Array {
  const te = new TextEncoder();
  let ctx = Array.from(te.encode(version));
  if (context !== undefined) {
    if (typeof context === 'string') {
      ctx = ctx.concat(Array.from(te.encode(context)));
    } else {
      ctx = ctx.concat(Array.from(context));
    }
  }
  ctx = ctx.concat(Array.from(te.encode(JSON.stringify(presSpec.toJSON()))));
  return new Uint8Array(ctx);
}

export class Presentation extends Versioned {
  readonly spec: PresentationSpecification;
  readonly proof: CompositeProofG1;
  // Ciphertexts for the verifiable encryption of required attributes. The key of the map is the credential index.
  // This is intentionally not part of presentation specification as this is created as part of the proof generation,
  // not before.
  readonly attributeCiphertexts?: Map<number, AttributeCiphertexts>;
  // Similar to above for blinded attributes
  readonly blindedAttributeCiphertexts?: AttributeCiphertexts;
  // This can specify the reason why the proof was created, or date of the proof, or self-attested attributes (as JSON string), etc
  readonly context?: string;
  // To prevent replay attack
  readonly nonce?: Uint8Array;

  constructor(
    version: string,
    spec: PresentationSpecification,
    proof: CompositeProofG1,
    attributeCiphertexts?: Map<number, AttributeCiphertexts>,
    context?: string,
    nonce?: Uint8Array,
    blindedAttributeCiphertexts?: AttributeCiphertexts
  ) {
    super(version);
    this.spec = spec;
    this.proof = proof;
    this.attributeCiphertexts = attributeCiphertexts;
    this.blindedAttributeCiphertexts = blindedAttributeCiphertexts;
    this.context = context;
    this.nonce = nonce;
  }

  /**
   *
   * @param publicKeys - Array of keys in the order of credentials in the presentation.
   * @param accumulatorPublicKeys - Mapping credential index -> accumulator public key
   * @param predicateParams - Setup params for various predicates
   * @param circomOutputs - Values for the outputs variables of the Circom programs used for predicates
   * @param blindedAttributesCircomOutputs - Outputs for Circom predicates on blinded attributes
   */
  verify(
    publicKeys: PublicKey[],
    accumulatorPublicKeys?: Map<number, AccumulatorPublicKey>,
    predicateParams?: Map<string, PredicateParamType>,
    circomOutputs?: Map<number, Uint8Array[][]>,
    blindedAttributesCircomOutputs?: Uint8Array[][]
  ): VerifyResult {
    const numCreds = this.spec.credentials.length;
    if (publicKeys.length !== numCreds) {
      throw new Error(`Supply same no of public keys as creds. ${publicKeys.length} != ${numCreds}`);
    }

    const statements = new Statements();
    const metaStatements = new MetaStatements();

    const flattenedSchemas: FlattenedSchema[] = [];

    // For the following arrays of pairs, the 1st item of each pair is the credential index

    // For credentials with status, i.e. using accumulators, type is [credIndex, revCheckType, accumulator]
    const credStatusAux: [number, string, Uint8Array][] = [];

    // For bound check on credential attributes
    const boundsAux: [number, { [key: string]: string | IPresentedAttributeBounds }][] = [];

    // For verifiable encryption of credential attributes
    const verEncAux: [number, { [key: string]: string | IPresentedAttributeVE }][] = [];

    // For circom predicates on credential attributes
    const circomAux: [number, ICircomPredicate[]][] = [];

    const setupParamsTrk = new SetupParamsTracker();
    const sigParamsByScheme = new Map();

    for (let i = 0; i < this.spec.credentials.length; i++) {
      const presentedCred = this.spec.credentials[i];
      const presentedCredSchema = CredentialSchema.fromJSON(JSON.parse(presentedCred.schema));
      const flattenedSchema = presentedCredSchema.flatten();
      const numAttribs = flattenedSchema[0].length;

      const revealedEncoded = Presentation.encodeRevealed(i, presentedCred, presentedCredSchema, flattenedSchema[0]);

      const paramsClass = paramsClassByPublicKey(publicKeys[i]);
      if (paramsClass === null) {
        throw new Error(`Invalid public key: ${publicKeys[i]}`);
      }
      const sigParams = getSignatureParamsForMsgCount(sigParamsByScheme, paramsClass, numAttribs);

      const statement = buildSignatureStatementFromParamsRef(
        setupParamsTrk,
        sigParams,
        publicKeys[i],
        numAttribs,
        revealedEncoded
      );
      statements.add(statement);
      flattenedSchemas.push(flattenedSchema);

      if (presentedCred.status !== undefined) {
        // The input validation and security checks for these have been done as part of encoding revealed attributes
        credStatusAux.push([i, presentedCred.status[REV_CHECK_STR], presentedCred.status.accumulated]);
      }

      if (presentedCred.bounds !== undefined) {
        boundsAux.push([i, presentedCred.bounds]);
      }
      if (presentedCred.verifiableEncryptions !== undefined) {
        verEncAux.push([i, presentedCred.verifiableEncryptions]);
      }
      if (presentedCred.circomPredicates !== undefined) {
        circomAux.push([i, presentedCred.circomPredicates]);
      }
    }

    credStatusAux.forEach(([i, t, accum]) => {
      // let statement;
      const pk = accumulatorPublicKeys?.get(i);
      if (pk === undefined) {
        throw new Error(`Accumulator public key wasn't provided for credential index ${i}`);
      }
      const statement = accumulatorStatement(t, pk, accum, setupParamsTrk);
      const sIdx = statements.add(statement);
      const witnessEq = new WitnessEqualityMetaStatement();
      witnessEq.addWitnessRef(i, flattenedSchemas[i][0].indexOf(`${STATUS_STR}.${REV_ID_STR}`));
      witnessEq.addWitnessRef(sIdx, 0);
      metaStatements.addWitnessEquality(witnessEq);
    });

    if (this.spec.attributeEqualities !== undefined) {
      for (const eql of this.spec.attributeEqualities) {
        metaStatements.addWitnessEquality(createWitEq(eql, flattenedSchemas));
      }
    }

    boundsAux.forEach(([i, b]) => {
      this.processBoundChecks(
        i,
        (n: string) => {
          return flattenedSchemas[i][0].indexOf(n);
        },
        b,
        flattenedSchemas[i],
        statements,
        metaStatements,
        setupParamsTrk,
        predicateParams
      );
    });

    verEncAux.forEach(([i, v]) => {
      this.processVerifiableEncs(
        i,
        (n: string) => {
          return flattenedSchemas[i][0].indexOf(n);
        },
        v,
        flattenedSchemas[i],
        statements,
        metaStatements,
        setupParamsTrk,
        predicateParams
      );
    });

    circomAux.forEach(([i, predicates]) => {
      const outputs = circomOutputs?.get(i);
      this.processCircomPredicates(
        i,
        (n: string) => {
          return flattenedSchemas[i][0].indexOf(n);
        },
        predicates,
        statements,
        metaStatements,
        setupParamsTrk,
        predicateParams,
        outputs
      );
    });

    function createPseudonymStatement(pseudonym: string, commitKey: IBoundedPseudonymCommitKey): number {
      const basesForAttributes = PseudonymBases.encodeBasesForAttributes(commitKey.basesForAttributes);
      const decodedBaseForSecretKey = commitKey.baseForSecretKey;
      const baseForSecretKey =
        decodedBaseForSecretKey !== undefined
          ? PseudonymBases.encodeBaseForSecretKey(decodedBaseForSecretKey)
          : undefined;

      const statement = Statement.attributeBoundPseudonymVerifier(
        Pseudonym.encode(pseudonym),
        basesForAttributes,
        baseForSecretKey
      );
      return statements.add(statement);
    }

    function addWitnessEqualitiesForPseudonym(
      attributeNames: string[],
      witnessIndexGetter: (string) => number,
      credStatementIdx: number,
      pseudonymStIdx: number,
      attrIdx: number
    ): number {
      for (const attributeName of attributeNames) {
        const witnessEq = new WitnessEqualityMetaStatement();
        witnessEq.addWitnessRef(credStatementIdx, witnessIndexGetter(attributeName));
        witnessEq.addWitnessRef(pseudonymStIdx, attrIdx++);
        metaStatements.addWitnessEquality(witnessEq);
      }
      return attrIdx;
    }

    // verify boundedPseudonyms
    if (this.spec.boundedPseudonyms !== undefined) {
      for (const [pseudonym, boundedPseudonym] of Object.entries(this.spec.boundedPseudonyms)) {
        const sIdx = createPseudonymStatement(pseudonym, boundedPseudonym.commitKey);

        let attrIdx = 0; // mirroring how it is constructed on the prover side
        for (const [credIdx, attributeNames] of Object.entries(boundedPseudonym.attributes)) {
          attrIdx = addWitnessEqualitiesForPseudonym(
            attributeNames,
            (n: string) => {
              return flattenedSchemas[credIdx][0].indexOf(n);
            },
            parseInt(credIdx),
            sIdx,
            attrIdx
          );
        }
      }
    }

    // verify unboundedPseudonyms
    if (this.spec.unboundedPseudonyms !== undefined) {
      for (const [pseudonym, unboundedPseudonym] of Object.entries(this.spec.unboundedPseudonyms)) {
        const baseForSecretKey = PseudonymBases.encodeBaseForSecretKey(unboundedPseudonym.commitKey.baseForSecretKey);
        const statement = Statement.pseudonymVerifier(Pseudonym.encode(pseudonym), baseForSecretKey);
        statements.add(statement);
      }
    }

    if (this.spec.blindCredentialRequest !== undefined) {
      const flattenedSchema = this.spec.blindCredentialRequest.schema.flatten();
      const flattenedBlindedAttrs = flatten(this.spec.blindCredentialRequest.blindedAttributes) as object;
      let blindedSubjectIndices: number[] = [];
      const blindedSubjectNameToIndex = new Map<string, number>();
      for (const name of Object.keys(flattenedBlindedAttrs)) {
        const index = flattenedSchema[0].indexOf(name);
        blindedSubjectIndices.push(index);
        blindedSubjectNameToIndex.set(name, index);
      }
      blindedSubjectIndices = blindedSubjectIndices.sort((a, b) => a - b);
      const sigType = this.spec.blindCredentialRequest.sigType;
      const numAttribs = flattenedSchema[0].length;
      let sigParams;
      // Offset of attributes in the Pedersen Commitment, its 0 for BBS and 1 for BBS+ as the commitment in BBS+ is perfectly hiding.
      let pedCommWitnessOffset;

      if (sigType === BBS_BLINDED_CRED_PROOF_TYPE) {
        sigParams = getSignatureParamsForMsgCount(sigParamsByScheme, BBSSignatureParams, numAttribs);
        pedCommWitnessOffset = 0;
      } else if (sigType === BBS_PLUS_BLINDED_CRED_PROOF_TYPE) {
        sigParams = getSignatureParamsForMsgCount(sigParamsByScheme, BBSPlusSignatureParamsG1, numAttribs);
        pedCommWitnessOffset = 1;
      } else {
        throw new Error('Blind signing not yet implemented for PS');
      }
      const commKey = sigParams.getParamsForIndices(blindedSubjectIndices);
      const pedCommStId = statements.add(
        Statement.pedersenCommitmentG1(commKey, this.spec.blindCredentialRequest.commitment)
      );

      const getAttrIndexInPedComm = (attr: number | string): number => {
        if (typeof attr === 'number') {
          return blindedSubjectIndices.indexOf(attr) + pedCommWitnessOffset;
        } else {
          const index = blindedSubjectNameToIndex.get(attr);
          if (index === undefined) {
            throw new Error(`Missing attribute ${attr} in subject to index map`);
          }
          return blindedSubjectIndices.indexOf(index) + pedCommWitnessOffset;
        }
      };

      if (this.spec.blindCredentialRequest.blindedAttributeEqualities !== undefined) {
        for (const [name, otherAttributeRefs] of this.spec.blindCredentialRequest.blindedAttributeEqualities) {
          const index = blindedSubjectNameToIndex.get(name);
          if (index === undefined) {
            throw new Error(`Missing attribute ${name} in subject to index map`);
          }
          metaStatements.addWitnessEquality(
            createWitEqForBlindedCred(pedCommStId, getAttrIndexInPedComm(index), otherAttributeRefs, flattenedSchemas)
          );
        }
      }

      if (this.spec.blindCredentialRequest.bounds !== undefined) {
        this.processBoundChecks(
          pedCommStId,
          getAttrIndexInPedComm,
          this.spec.blindCredentialRequest.bounds,
          flattenedSchema,
          statements,
          metaStatements,
          setupParamsTrk,
          predicateParams
        );
      }

      if (this.spec.blindCredentialRequest.verifiableEncryptions !== undefined) {
        this.processVerifiableEncs(
          pedCommStId,
          getAttrIndexInPedComm,
          this.spec.blindCredentialRequest.verifiableEncryptions,
          flattenedSchema,
          statements,
          metaStatements,
          setupParamsTrk,
          predicateParams
        );
      }

      if (this.spec.blindCredentialRequest.circomPredicates !== undefined) {
        this.processCircomPredicates(
          pedCommStId,
          getAttrIndexInPedComm,
          this.spec.blindCredentialRequest.circomPredicates,
          statements,
          metaStatements,
          setupParamsTrk,
          predicateParams,
          blindedAttributesCircomOutputs
        );
      }

      if (this.spec.blindCredentialRequest.pseudonyms !== undefined) {
        for (const [pseudonym, boundedPseudonym] of Object.entries(this.spec.blindCredentialRequest.pseudonyms)) {
          const sIdx = createPseudonymStatement(pseudonym, boundedPseudonym.commitKey);

          let attrIdx = 0; // mirroring how it is constructed on the prover side
          for (const [credIdx, attributeNames] of Object.entries(boundedPseudonym.credentialAttributes)) {
            attrIdx = addWitnessEqualitiesForPseudonym(
              attributeNames,
              (n: string) => {
                return flattenedSchemas[credIdx][0].indexOf(n);
              },
              parseInt(credIdx),
              sIdx,
              attrIdx
            );
          }
          attrIdx = addWitnessEqualitiesForPseudonym(
            boundedPseudonym.blindedAttributes,
            getAttrIndexInPedComm,
            pedCommStId,
            sIdx,
            attrIdx
          );
        }
      }
    }

    const ctx = buildContextForProof(this.version, this.spec, this.context);
    const proofSpec = new QuasiProofSpecG1(statements, metaStatements, setupParamsTrk.setupParams, ctx);
    return this.proof.verifyUsingQuasiProofSpec(proofSpec, this.nonce);
  }

  /**
   * Encode the revealed attributes of the presented credential
   * @param credIdx
   * @param presentedCred
   * @param presentedCredSchema
   * @param flattenedNames
   */
  private static encodeRevealed(
    credIdx: number,
    presentedCred: IPresentedCredential,
    presentedCredSchema: CredentialSchema,
    flattenedNames: string[]
  ): Map<number, Uint8Array> {
    const revealedRaw = deepClone(presentedCred.revealedAttributes) as object;
    revealedRaw[CRYPTO_VERSION_STR] = presentedCred.version;
    revealedRaw[SCHEMA_STR] = presentedCred.schema;
    if (presentedCredSchema.hasStatus()) {
      // To guard against a malicious holder not proving the credential status when required.
      if (presentedCred.status === undefined) {
        throw new Error(`Schema for the credential index ${credIdx} required a status but wasn't provided`);
      }
      if (
        presentedCred.status[ID_STR] === undefined ||
        (presentedCred.status[REV_CHECK_STR] !== MEM_CHECK_STR &&
          presentedCred.status[REV_CHECK_STR] !== NON_MEM_CHECK_STR)
      ) {
        throw new Error(`Presented credential for ${credIdx} has invalid status ${presentedCred.status}`);
      }
      // Following will also ensure that holder (prover) cannot change the registry (accumulator) id or the type of check
      revealedRaw[STATUS_STR] = {
        [ID_STR]: presentedCred.status[ID_STR],
        [REV_CHECK_STR]: presentedCred.status[REV_CHECK_STR]
      };
    }
    const encoded = new Map<number, Uint8Array>();
    Object.entries(flatten(revealedRaw) as object).forEach(([k, v]) => {
      const i = flattenedNames.indexOf(k);
      if (i === -1) {
        throw new Error(`Attribute name ${k} not found in schema`);
      }
      encoded.set(i, presentedCredSchema.encoder.encodeMessage(k, v));
    });
    return encoded;
  }

  private processBoundChecks(
    statementIdx: number,
    witnessIndexGetter: (string) => number,
    b: { [key: string]: string | IPresentedAttributeBounds },
    flattenedSchema: FlattenedSchema,
    statements: Statements,
    metaStatements: MetaStatements,
    setupParamsTrk: SetupParamsTracker,
    predicateParams?: Map<string, PredicateParamType>
  ) {
    const [names, bounds] = flattenTill2ndLastKey(b);
    names.forEach((name, j) => {
      const nameIdx = witnessIndexGetter(name);
      const valTyp = CredentialSchema.typeOfName(name, flattenedSchema);
      const [min, max] = [bounds[j]['min'], bounds[j]['max']];
      const [transformedMin, transformedMax] = getTransformedMinMax(name, valTyp, min, max);

      const paramId = bounds[j]['paramId'];
      let protocol = bounds[j]['protocol'];
      const param = predicateParams?.get(paramId);
      let statement: Uint8Array;

      // Older versions of presentation did not have protocol name specified
      if (semver.lt(this.version, '0.2.0')) {
        protocol = BoundCheckProtocols.Legogroth16;
      }

      switch (protocol) {
        case BoundCheckProtocols.Legogroth16:
          Presentation.addLegoVerifyingKeyToTracker(paramId, param, setupParamsTrk, statementIdx);
          statement = Statement.boundCheckLegoVerifierFromSetupParamRefs(
            transformedMin,
            transformedMax,
            setupParamsTrk.indexForParam(paramId)
          );
          break;
        case BoundCheckProtocols.Bpp:
          Presentation.addBppSetupParamsToTracker(paramId, param, setupParamsTrk, statementIdx);
          statement = Statement.boundCheckBppFromSetupParamRefs(
            transformedMin,
            transformedMax,
            setupParamsTrk.indexForParam(paramId)
          );
          break;
        case BoundCheckProtocols.Smc:
          Presentation.addSmcSetupParamsToTracker(paramId, param, setupParamsTrk, statementIdx);
          statement = Statement.boundCheckSmcFromSetupParamRefs(
            transformedMin,
            transformedMax,
            setupParamsTrk.indexForParam(paramId)
          );
          break;
        case BoundCheckProtocols.SmcKV:
          Presentation.addSmcKVVerifierParamsToTracker(paramId, param, setupParamsTrk, statementIdx);
          statement = Statement.boundCheckSmcWithKVVerifierFromSetupParamRefs(
            transformedMin,
            transformedMax,
            setupParamsTrk.indexForParam(paramId)
          );
          break;
        default:
          throw new Error(`Unknown protocol ${protocol} for bound check`);
      }
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
    v: { [key: string]: string | IPresentedAttributeVE },
    flattenedSchema: FlattenedSchema,
    statements: Statements,
    metaStatements: MetaStatements,
    setupParamsTrk: SetupParamsTracker,
    predicateParams?: Map<string, PredicateParamType>
  ) {
    const [names, verEnc] = flattenTill2ndLastKey(v);
    names.forEach((name, j) => {
      const valTyp = CredentialSchema.typeOfName(name, flattenedSchema);
      if (valTyp.type !== ValueType.RevStr) {
        throw new Error(
          `Attribute name ${name} of credential index ${statementIdx} should be a reversible string type but was ${valTyp}`
        );
      }
      const nameIdx = witnessIndexGetter(name);
      const commKeyId = verEnc[j]['commitmentGensId'];
      if (commKeyId === undefined) {
        throw new Error(`Commitment gens id not found for ${name}`);
      }
      const commKey = predicateParams?.get(commKeyId);
      if (commKey === undefined) {
        throw new Error(`Commitment gens not found for id ${commKeyId}`);
      }
      const encKeyId = verEnc[j]['encryptionKeyId'];
      if (encKeyId === undefined) {
        throw new Error(`Encryption key id not found for ${name}`);
      }
      const encKey = predicateParams?.get(encKeyId);
      if (encKey === undefined) {
        throw new Error(`Encryption key not found for id ${encKey}`);
      }
      const snarkVkId = verEnc[j]['snarkKeyId'];
      if (snarkVkId === undefined) {
        throw new Error(`Snark verification key id not found for ${name}`);
      }
      const snarkVk = predicateParams?.get(snarkVkId);
      if (snarkVk === undefined) {
        throw new Error(`Snark verification key not found for id ${snarkVkId}`);
      }
      const chunkBitSize = verEnc[j]['chunkBitSize'];
      const statement = saverStatement(
        false,
        chunkBitSize,
        commKeyId,
        encKeyId,
        snarkVkId,
        commKey,
        encKey,
        snarkVk,
        setupParamsTrk
      );
      const sIdx = statements.add(statement);
      const witnessEq = new WitnessEqualityMetaStatement();
      witnessEq.addWitnessRef(statementIdx, nameIdx);
      witnessEq.addWitnessRef(sIdx, 0);
      metaStatements.addWitnessEquality(witnessEq);
    });
  }

  private processCircomPredicates(
    statementIdx: number,
    witnessIndexGetter: (string) => number,
    predicates: ICircomPredicate[],
    statements: Statements,
    metaStatements: MetaStatements,
    setupParamsTrk: SetupParamsTracker,
    predicateParams?: Map<string, PredicateParamType>,
    outputs?: Uint8Array[][]
  ) {
    predicates.forEach((pred, j) => {
      const param = predicateParams?.get(pred.snarkKeyId);
      Presentation.addLegoVerifyingKeyToTracker(pred.snarkKeyId, param, setupParamsTrk, statementIdx);

      let publicInputs = pred.publicVars.flatMap((pv) => {
        return pv.value;
      });
      if (outputs !== undefined && outputs.length > j) {
        publicInputs = outputs[j].concat(publicInputs);
      }
      const unqId = `circom-outputs-${statementIdx}__${j}`;
      setupParamsTrk.addForParamId(unqId, SetupParam.fieldElementVec(publicInputs));

      const statement = Statement.r1csCircomVerifierFromSetupParamRefs(
        setupParamsTrk.indexForParam(unqId),
        setupParamsTrk.indexForParam(pred.snarkKeyId)
      );
      const sIdx = statements.add(statement);

      function addWitnessEquality(attributeName: object) {
        const attr = flattenObjectToKeyValuesList(attributeName) as object;
        const nameIdx = witnessIndexGetter(attr[0][0]);
        const witnessEq = new WitnessEqualityMetaStatement();
        witnessEq.addWitnessRef(statementIdx, nameIdx);
        witnessEq.addWitnessRef(sIdx, predicateWitnessIdx++);
        metaStatements.addWitnessEquality(witnessEq);
      }

      let predicateWitnessIdx = 0;
      pred.privateVars.forEach((privateVars) => {
        if (Array.isArray(privateVars.attributeName)) {
          privateVars.attributeName.forEach((a) => {
            addWitnessEquality(a);
          });
        } else {
          addWitnessEquality(privateVars.attributeName);
        }
      });
    });
  }

  toJSON(): object {
    let attributeCiphertexts;
    if (this.attributeCiphertexts !== undefined) {
      attributeCiphertexts = {};
      for (const [i, v] of this.attributeCiphertexts.entries()) {
        attributeCiphertexts[i] = {};
        Presentation.ciphertextToBs58(v, attributeCiphertexts[i]);
      }
    }

    function formatCircomPreds(circomPredicates: ICircomPredicate[]): object {
      return circomPredicates.map((v) => {
        const r = deepClone(v) as object;
        // @ts-ignore
        r.publicVars = v.publicVars.map((pv) => {
          return {
            varName: pv.varName,
            value: Array.isArray(pv.value) ? pv.value.map(b58.encode) : b58.encode(pv.value)
          };
        });
        return r;
      });
    }

    const creds: object[] = [];
    for (const cred of this.spec.credentials) {
      const current = deepClone(cred) as object; // Need this deep cloning because structure of revealed attributes or key `extra` isn't fixed
      if (cred.status !== undefined) {
        // @ts-ignore
        current.status?.accumulated = b58.encode(cred.status.accumulated);
      }
      if (cred.circomPredicates !== undefined) {
        // @ts-ignore
        current.circomPredicates = formatCircomPreds(cred.circomPredicates);
      }
      creds.push(current);
    }

    let blindCredentialRequest, blindedAttributeCiphertexts;
    if (this.spec.blindCredentialRequest !== undefined) {
      blindCredentialRequest = deepClone(this.spec.blindCredentialRequest) as object;
      blindCredentialRequest.schema = JSON.stringify(this.spec.blindCredentialRequest.schema.toJSON());
      blindCredentialRequest.commitment = b58.encode(this.spec.blindCredentialRequest.commitment);
      if (this.blindedAttributeCiphertexts !== undefined) {
        blindedAttributeCiphertexts = {};
        Presentation.ciphertextToBs58(this.blindedAttributeCiphertexts, blindedAttributeCiphertexts);
      }
      if (this.spec.blindCredentialRequest.circomPredicates !== undefined) {
        blindCredentialRequest.circomPredicates = formatCircomPreds(this.spec.blindCredentialRequest.circomPredicates);
      }
      if (this.spec.blindCredentialRequest.pseudonyms !== undefined) {
        blindCredentialRequest.pseudonyms = this.spec.blindCredentialRequest.pseudonyms;
      }
    }

    const spec = {
      credentials: creds
    };
    if (this.spec.attributeEqualities !== undefined) {
      spec['attributeEqualities'] = this.spec.attributeEqualities;
    }
    if (this.spec.boundedPseudonyms !== undefined) {
      spec['boundedPseudonyms'] = this.spec.boundedPseudonyms;
    }
    if (this.spec.unboundedPseudonyms !== undefined) {
      spec['unboundedPseudonyms'] = this.spec.unboundedPseudonyms;
    }
    if (blindCredentialRequest !== undefined) {
      spec['blindCredentialRequest'] = blindCredentialRequest;
    }

    const p = {
      version: this.version,
      context: this.context,
      nonce: this.nonce ? b58.encode(this.nonce) : null,
      spec,
      proof: b58.encode(this.proof.bytes)
    };

    if (attributeCiphertexts !== undefined) {
      p['attributeCiphertexts'] = attributeCiphertexts;
    }
    if (blindedAttributeCiphertexts !== undefined) {
      p['blindedAttributeCiphertexts'] = blindedAttributeCiphertexts;
    }

    return p;
  }

  // Store base58 representation of ciphertexts present in `v` in `ret`
  static ciphertextToBs58(v: object, ret: object) {
    Object.keys(v).forEach((k) => {
      if (v[k] instanceof SaverCiphertext) {
        // @ts-ignore
        ret[k] = b58.encode(v[k].bytes);
      } else {
        ret[k] = {};
        Presentation.ciphertextToBs58(v[k], ret[k]);
      }
    });
  }

  // Convert base58 encoded ciphertexts present in `v` and store in `ret`
  static ciphertextFromBs58(v: object, ret: AttributeCiphertexts) {
    Object.keys(v).forEach((k) => {
      if (typeof v[k] === 'string') {
        ret[k] = new SaverCiphertext(b58.decode(v[k]));
      } else {
        ret[k] = {};
        // @ts-ignore
        Presentation.ciphertextFromBs58(v[k], ret[k]);
      }
    });
  }

  private static addLegoVerifyingKeyToTracker(
    paramId: string,
    param: PredicateParamType | undefined,
    setupParamsTrk: SetupParamsTracker,
    statementIdx: number
  ) {
    if (param instanceof LegoVerifyingKey) {
      if (!setupParamsTrk.isTrackingParam(paramId)) {
        setupParamsTrk.addForParamId(paramId, SetupParam.legosnarkVerifyingKey(param));
      }
    } else if (param instanceof LegoVerifyingKeyUncompressed) {
      if (!setupParamsTrk.isTrackingParam(paramId)) {
        setupParamsTrk.addForParamId(paramId, SetupParam.legosnarkVerifyingKeyUncompressed(param));
      }
    } else {
      throw new Error(
        `Predicate param id ${paramId} (for statement index ${statementIdx}) was expected to be a Legosnark verifying key but was ${param}`
      );
    }
  }

  static addBppSetupParamsToTracker(
    paramId: string,
    param: PredicateParamType | undefined,
    setupParamsTrk: SetupParamsTracker,
    statementIdx: number
  ) {
    if (param instanceof BoundCheckBppParams) {
      if (!setupParamsTrk.isTrackingParam(paramId)) {
        setupParamsTrk.addForParamId(paramId, SetupParam.bppSetupParams(param));
      }
    } else if (param instanceof BoundCheckBppParamsUncompressed) {
      if (!setupParamsTrk.isTrackingParam(paramId)) {
        setupParamsTrk.addForParamId(paramId, SetupParam.bppSetupParamsUncompressed(param));
      }
    } else {
      throw new Error(
        `Predicate param id ${paramId} (for statement index ${statementIdx}) was expected to be Bulletproofs++ setup params but was ${param}`
      );
    }
  }

  static addSmcSetupParamsToTracker(
    paramId: string,
    param: PredicateParamType | undefined,
    setupParamsTrk: SetupParamsTracker,
    statementIdx: number
  ) {
    if (param instanceof BoundCheckSmcParams) {
      if (!setupParamsTrk.isTrackingParam(paramId)) {
        setupParamsTrk.addForParamId(paramId, SetupParam.smcSetupParams(param));
      }
    } else if (param instanceof BoundCheckSmcParamsUncompressed) {
      if (!setupParamsTrk.isTrackingParam(paramId)) {
        setupParamsTrk.addForParamId(paramId, SetupParam.smcSetupParamsUncompressed(param));
      }
    } else {
      throw new Error(
        `Predicate param id ${paramId} (for statement index ${statementIdx}) was expected to be set-membership check setup params but was ${param}`
      );
    }
  }

  private static addSmcKVVerifierParamsToTracker(
    paramId: string,
    param: PredicateParamType | undefined,
    setupParamsTrk: SetupParamsTracker,
    statementIdx: number
  ) {
    if (param instanceof BoundCheckSmcWithKVVerifierParams) {
      if (!setupParamsTrk.isTrackingParam(paramId)) {
        setupParamsTrk.addForParamId(paramId, SetupParam.smcSetupParamsWithSk(param));
      }
    } else if (param instanceof BoundCheckSmcWithKVVerifierParamsUncompressed) {
      if (!setupParamsTrk.isTrackingParam(paramId)) {
        setupParamsTrk.addForParamId(paramId, SetupParam.smcSetupParamsWithSkUncompressed(param));
      }
    } else {
      throw new Error(
        `Predicate param id ${paramId} (for statement index ${statementIdx}) was expected to be a Legosnark verifying key but was ${param}`
      );
    }
  }

  static fromJSON(j: object): Presentation {
    // @ts-ignore
    const { version, context, nonce, spec, attributeCiphertexts, blindedAttributeCiphertexts, proof } = j;
    const nnc = nonce ? b58.decode(nonce) : undefined;

    function formatCircomPreds(pred: object): ICircomPredicate[] {
      const circomPredicates = deepClone(pred) as object[];
      circomPredicates.forEach((cp) => {
        if (cp['protocol'] !== undefined && !Object.values(CircomProtocols).includes(cp['protocol'])) {
          throw new Error(`Unrecognized protocol ${cp['protocol']} for Circom`);
        }
        cp['publicVars'] = cp['publicVars'].map((pv) => {
          return {
            varName: pv['varName'],
            value: Array.isArray(pv['value']) ? pv['value'].map(b58.decode) : b58.decode(pv['value'])
          };
        });
      });
      // @ts-ignore
      return circomPredicates;
    }

    const presSpec = new PresentationSpecification();
    for (const cred of spec['credentials']) {
      if (typeof cred['bounds'] === 'object') {
        const bounds = flattenTill2ndLastKey(cred['bounds']);
        for (let i = 0; i < bounds[0].length; i++) {
          if (
            bounds[1][i]['protocol'] !== undefined &&
            !Object.values(BoundCheckProtocols).includes(bounds[1][i]['protocol'])
          ) {
            throw new Error(
              `Unrecognized protocol ${bounds[1][i]['protocol']} for bound check for attribute ${bounds[0][i]}`
            );
          }
        }
      }

      if (typeof cred['verifiableEncryptions'] === 'object') {
        const vencs = flattenTill2ndLastKey(cred['verifiableEncryptions']);
        for (let i = 0; i < vencs[0].length; i++) {
          if (
            vencs[1][i]['protocol'] !== undefined &&
            !Object.values(VerifiableEncryptionProtocols).includes(vencs[1][i]['protocol'])
          ) {
            throw new Error(
              `Unrecognized protocol ${vencs[1][i]['protocol']} for verifiable encryption for attribute ${vencs[0][i]}`
            );
          }
        }
      }

      let status, circomPredicates, sigType;
      if (cred['status'] !== undefined) {
        if (Object.values(RevocationStatusProtocols).includes(cred['status']['type'])) {
          status = deepClone(cred['status']) as object;
          status['accumulated'] = b58.decode(cred['status']['accumulated']);
        } else {
          throw new Error(
            `status type should be one of ${RevocationStatusProtocols} but was ${cred['status']['type']}`
          );
        }
      }
      if (cred['circomPredicates'] !== undefined) {
        circomPredicates = formatCircomPreds(cred['circomPredicates']);
      }
      if (cred['sigType'] !== undefined) {
        if (Object.values(SignatureTypes).includes(cred['sigType'])) {
          sigType = cred['sigType'];
        } else {
          throw new Error(`sigType should be one of ${SignatureTypes} but was ${cred['sigType']}`);
        }
      }
      presSpec.addPresentedCredential(
        cred['version'],
        cred['schema'],
        cred['revealedAttributes'],
        status,
        cred['bounds'],
        cred['verifiableEncryptions'],
        circomPredicates,
        sigType
      );
    }
    presSpec.attributeEqualities = spec['attributeEqualities'];
    presSpec.boundedPseudonyms = spec['boundedPseudonyms'];
    presSpec.unboundedPseudonyms = spec['unboundedPseudonyms'];

    let atc;
    if (attributeCiphertexts !== undefined) {
      atc = new Map<number, AttributeCiphertexts>();
      Object.keys(attributeCiphertexts).forEach((k) => {
        const c = attributeCiphertexts[k];
        const rc = {};
        Presentation.ciphertextFromBs58(c, rc);
        atc.set(parseInt(k), rc);
      });
    }

    let bac;
    if (spec['blindCredentialRequest'] !== undefined) {
      const req = deepClone(spec['blindCredentialRequest']) as object;
      if (!Object.values(BlindSignatureTypes).includes(req['sigType'])) {
        throw new Error(`sigType should be one of ${BlindSignatureTypes} but was ${req['sigType']}`);
      }
      req['schema'] = CredentialSchema.fromJSON(JSON.parse(req['schema']));
      req['commitment'] = b58.decode(req['commitment']);
      if (blindedAttributeCiphertexts !== undefined) {
        bac = {};
        Presentation.ciphertextFromBs58(blindedAttributeCiphertexts, bac);
      }
      if (spec['blindCredentialRequest']['circomPredicates'] !== undefined) {
        req['circomPredicates'] = formatCircomPreds(spec['blindCredentialRequest']['circomPredicates']);
      }
      if (spec['blindCredentialRequest']['pseudonyms'] !== undefined) {
        req['pseudonyms'] = spec['blindCredentialRequest']['pseudonyms'];
      }
      // @ts-ignore
      presSpec.blindCredentialRequest = req;
    }

    return new Presentation(version, presSpec, new CompositeProofG1(b58.decode(proof)), atc, context, nnc, bac);
  }
}
