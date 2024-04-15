import b58 from 'bs58';
import { VerifyResult } from 'crypto-wasm-new';
import { flatten } from 'flat';
import stringify from 'json-stringify-deterministic';
import semver from 'semver/preload';
import { AccumulatorPublicKey, AccumulatorSecretKey } from '../accumulator';
import { KBUniversalAccumulatorValue } from '../accumulator/kb-universal-accumulator';
import { BBSSignatureParams } from '../bbs';
import { BBSPlusSignatureParamsG1 } from '../bbs-plus';
import { BDDT16MacParams } from '../bddt16-mac';
import {
  BoundCheckBppParams,
  BoundCheckBppParamsUncompressed,
  BoundCheckSmcParams,
  BoundCheckSmcParamsUncompressed,
  BoundCheckSmcWithKVVerifierParams,
  BoundCheckSmcWithKVVerifierParamsUncompressed
} from '../bound-check';
import {
  CompositeProof,
  MetaStatements,
  QuasiProofSpec,
  SetupParam,
  Statement,
  Statements,
  WitnessEqualityMetaStatement
} from '../composite-proof';
import {
  BDDT16DelegatedProof,
  KBUniAccumMembershipDelegatedProof,
  KBUniAccumNonMembershipDelegatedProof,
  VBAccumMembershipDelegatedProof
} from '../delegated-proofs';
import { LegoVerifyingKey, LegoVerifyingKeyUncompressed } from '../legosnark';
import { PederCommKey, PederCommKeyUncompressed } from '../ped-com';
import { PSSignatureParams } from '../ps';
import { Pseudonym, PseudonymBases } from '../Pseudonym';
import { SaverCiphertext } from '../saver';
import { flattenObjectToKeyValuesList } from '../util';
import { DelegatedProof, IDelegatedCredentialProof, IDelegatedCredentialStatusProof } from './delegated-proof';
import {
  IBoundedPseudonymCommitKey,
  ICircomPredicate,
  ICircuitPrivateVar,
  ICircuitPrivateVarMultiCred,
  IPresentedAttributeBound,
  IPresentedAttributeInequality,
  IPresentedAttributeVE,
  IPresentedCredential,
  PresentationSpecification
} from './presentation-specification';
import { CredentialSchema, getTransformedMinMax, ValueType } from './schema';
import { SetupParamsTracker } from './setup-params-tracker';
import {
  AccumulatorValueType,
  AccumulatorVerificationParam,
  AttributeCiphertexts,
  BBS_BLINDED_CRED_PROOF_TYPE,
  BBS_PLUS_BLINDED_CRED_PROOF_TYPE,
  BDDT16_BLINDED_CRED_PROOF_TYPE,
  BlindSignatureType,
  BoundCheckProtocol,
  CircomProtocol,
  CredentialVerificationParam,
  CRYPTO_VERSION_STR,
  FlattenedSchema,
  ID_STR,
  InequalityProtocol,
  MEM_CHECK_KV_STR,
  MEM_CHECK_STR,
  NON_MEM_CHECK_KV_STR,
  NON_MEM_CHECK_STR,
  PredicateParamType,
  PublicKey,
  REV_CHECK_STR,
  REV_ID_STR,
  RevocationStatusProtocol,
  SCHEMA_STR,
  SignatureType,
  STATUS_STR,
  TYPE_STR,
  VerifiableEncryptionProtocol
} from './types-and-consts';
import {
  buildSignatureVerifierStatementFromParamsRef,
  createWitEq,
  createWitEqForBlindedCred,
  deepClone,
  flattenPredicatesInSpec,
  flattenTill2ndLastKey,
  getSignatureParamsForMsgCount,
  paramsClassByPublicKey,
  saverStatement
} from './util';
import { Versioned } from './versioned';

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
  // Old version used JSON.stringify
  const specJsonStr = semver.lt(version, '0.4.0') ? JSON.stringify(presSpec.toJSON()) : stringify(presSpec.toJSON());
  ctx = ctx.concat(Array.from(te.encode(specJsonStr)));
  return new Uint8Array(ctx);
}

export class Presentation extends Versioned {
  readonly spec: PresentationSpecification;
  readonly proof: CompositeProof;
  // Ciphertexts for the verifiable encryption of required attributes. The key of the map is the credential index.
  // This is intentionally not part of presentation specification as this is created as part of the proof generation,
  // not before.
  readonly attributeCiphertexts?: Map<number, AttributeCiphertexts[]>;
  // Similar to above for blinded attributes
  readonly blindedAttributeCiphertexts?: AttributeCiphertexts[];
  readonly context?: string;
  // To prevent replay attack
  readonly nonce?: Uint8Array;

  constructor(
    version: string,
    spec: PresentationSpecification,
    proof: CompositeProof,
    attributeCiphertexts?: Map<number, AttributeCiphertexts[]>,
    context?: string,
    nonce?: Uint8Array,
    blindedAttributeCiphertexts?: AttributeCiphertexts[]
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
   * @param credentialVerifParams - Map of verification parameters for credentials in the presentation. The key of the map
   * is the credential index. Can also take array of keys in the order of credentials in the presentation for supporting old API but this will
   * be removed in future. The verification param could be a public key or secret key. Certain kinds of credentials don't require
   * either for (partial) verification but will require for full verification
   * @param accumulatorPublicKeys - Mapping credential index -> accumulator verification parameters.
   * @param predicateParams - Setup params for various predicates
   * @param circomOutputs - Values for the outputs variables of the Circom programs used for predicates. They key of the map
   * is the credential index
   * @param blindedAttributesCircomOutputs - Outputs for Circom predicates on blinded attributes
   * @param circomOutputsMultiCred - Values for the outputs variables of the Circom programs spanning over multiple credential attributes
   */
  verify(
    // TODO: Accept reference to public keys in case of same key for many credentials
    credentialVerifParams: Map<number, CredentialVerificationParam> | CredentialVerificationParam[],
    accumulatorPublicKeys?: Map<number, AccumulatorVerificationParam>,
    predicateParams?: Map<string, PredicateParamType>,
    circomOutputs?: Map<number, Uint8Array[][]>,
    blindedAttributesCircomOutputs?: Uint8Array[][],
    circomOutputsMultiCred?: Uint8Array[][]
  ): VerifyResult {
    // NOTE: The order of processing predicates should match exactly to the order in presentation builder, eg. if circom predicates
    // are processed at the end in the builder than they should be processed at the end here as well, if verifiable encryption is
    // processed at 2nd last in the builder than they should be processed at 2nd last here as well. By convention credentials are
    // processed first, then their statuses (if present) and then any predicates.

    // Dealing with old API - convert array to map
    let credVerifParams = new Map<number, CredentialVerificationParam | undefined>();
    if (credentialVerifParams instanceof Map) {
      credVerifParams = credentialVerifParams;
    } else {
      credentialVerifParams.forEach((v, i) => {
        credVerifParams.set(i, v);
      });
    }

    const statements = new Statements();
    const metaStatements = new MetaStatements();

    const flattenedSchemas: FlattenedSchema[] = [];

    // For the following arrays of pairs, the 1st item of each pair is the credential index

    // For credentials with status, i.e. using accumulators, type is [credIndex, protocol, revCheckType, accumulator]
    const credStatusAux: [number, string, string, AccumulatorValueType][] = [];

    // For inequality checks on credential attributes
    const ineqsAux: [number, { [key: string]: [IPresentedAttributeInequality, Uint8Array][] }][] = [];

    // For bound check on credential attributes
    const boundsAux: [number, { [key: string]: string | IPresentedAttributeBound | IPresentedAttributeBound[] }][] = [];

    // For verifiable encryption of credential attributes
    const verEncAux: [number, { [key: string]: string | IPresentedAttributeVE | IPresentedAttributeVE[] }][] = [];

    // For circom predicates on credential attributes
    const circomAux: [number, ICircomPredicate<ICircuitPrivateVar>[]][] = [];

    const setupParamsTrk = new SetupParamsTracker();
    const sigParamsByScheme = new Map();

    const versionGt5 = semver.gt(this.version, '0.5.0');
    const versionGt6 = semver.gt(this.version, '0.6.0');

    for (let credIndex = 0; credIndex < this.spec.credentials.length; credIndex++) {
      const presentedCred = this.spec.credentials[credIndex];
      const presentedCredSchema = CredentialSchema.fromJSON(JSON.parse(presentedCred.schema));
      const flattenedSchema = presentedCredSchema.flatten();
      const numAttribs = flattenedSchema[0].length;

      const revealedEncoded = Presentation.encodeRevealed(
        credIndex,
        presentedCred,
        presentedCredSchema,
        flattenedSchema[0],
        versionGt6
      );

      let sigParamsClass;
      switch (presentedCred.sigType) {
        case SignatureType.Bbs:
          sigParamsClass = BBSSignatureParams;
          break;
        case SignatureType.BbsPlus:
          sigParamsClass = BBSPlusSignatureParamsG1;
          break;
        case SignatureType.Ps:
          sigParamsClass = PSSignatureParams;
          break;
        case SignatureType.Bddt16:
          sigParamsClass = BDDT16MacParams;
          break;
        default:
          if (presentedCred.sigType !== undefined) {
            throw new Error(`Invalid signature type ${presentedCred.sigType} for credential index ${credIndex}`);
          } else {
            const pk = credVerifParams.get(credIndex);
            if (pk === undefined) {
              throw new Error(`Public key not given for for credential index ${credIndex}`);
            }
            // KVAC were introduced later and by that time `sigType` is present in presented credentials
            sigParamsClass = paramsClassByPublicKey(pk as PublicKey);
            if (sigParamsClass === null) {
              throw new Error(`Invalid public key: ${pk} for credential index ${credIndex}`);
            }
          }
      }
      const sigParams = getSignatureParamsForMsgCount(sigParamsByScheme, sigParamsClass, numAttribs);

      const statement = buildSignatureVerifierStatementFromParamsRef(
        setupParamsTrk,
        sigParams,
        numAttribs,
        revealedEncoded,
        credVerifParams.get(credIndex),
        versionGt5
      );
      statements.add(statement);
      flattenedSchemas.push(flattenedSchema);

      if (presentedCred.status !== undefined) {
        // The input validation and security checks for these have been done as part of encoding revealed attributes
        credStatusAux.push([
          credIndex,
          presentedCred.status[TYPE_STR],
          presentedCred.status[REV_CHECK_STR],
          presentedCred.status.accumulated
        ]);
      }

      if (presentedCred.attributeInequalities !== undefined) {
        let [names, ineqs] = flattenPredicatesInSpec(presentedCred.attributeInequalities);
        const obj = {};
        for (let j = 0; j < names.length; j++) {
          obj[names[j]] = ineqs[j].map((ineqs_j) => [
            ineqs_j,
            // @ts-ignore
            presentedCredSchema.encoder.encodeMessage(names[j], ineqs_j.inEqualTo)
          ]);
        }
        ineqsAux.push([credIndex, obj]);
      }

      if (presentedCred.bounds !== undefined) {
        boundsAux.push([credIndex, presentedCred.bounds]);
      }
      if (presentedCred.verifiableEncryptions !== undefined) {
        verEncAux.push([credIndex, presentedCred.verifiableEncryptions]);
      }
      if (presentedCred.circomPredicates !== undefined) {
        circomAux.push([credIndex, presentedCred.circomPredicates]);
      }
    }

    credStatusAux.forEach(([i, protocol, checkType, acc]) => {
      let statement;
      const pk = accumulatorPublicKeys?.get(i);
      if (protocol === RevocationStatusProtocol.Vb22) {
        if (!(Array.isArray(acc) || acc instanceof Uint8Array)) {
          throw new Error(`Accumulator value should have been a Uint8Array but was ${acc}`);
        }
        let pkSp;
        if (checkType === MEM_CHECK_STR || checkType === NON_MEM_CHECK_STR) {
          if (!(pk instanceof AccumulatorPublicKey)) {
            throw new Error(`Accumulator public key wasn't provided for credential index ${i}`);
          }
          if (!setupParamsTrk.hasAccumulatorParams()) {
            setupParamsTrk.addAccumulatorParams();
          }
          pkSp = SetupParam.vbAccumulatorPublicKey(pk);
        }

        if (checkType === MEM_CHECK_STR) {
          if (!setupParamsTrk.hasAccumulatorMemProvingKey()) {
            setupParamsTrk.addAccumulatorMemProvingKey();
          }
          statement = Statement.vbAccumulatorMembershipFromSetupParamRefs(
            setupParamsTrk.accumParamsIdx,
            setupParamsTrk.add(pkSp),
            setupParamsTrk.memPrkIdx,
            acc as Uint8Array
          );
        } else if (checkType === NON_MEM_CHECK_STR) {
          if (!setupParamsTrk.hasAccumulatorNonMemProvingKey()) {
            setupParamsTrk.addAccumulatorNonMemProvingKey();
          }
          statement = Statement.vbAccumulatorNonMembershipFromSetupParamRefs(
            setupParamsTrk.accumParamsIdx,
            setupParamsTrk.add(pkSp),
            setupParamsTrk.nonMemPrkIdx,
            acc as Uint8Array
          );
        } else if (checkType === MEM_CHECK_KV_STR) {
          if (pk === undefined) {
            statement = Statement.vbAccumulatorMembershipKV(acc as Uint8Array);
          } else {
            if (pk instanceof AccumulatorSecretKey) {
              statement = Statement.vbAccumulatorMembershipKVFullVerifier(pk, acc as Uint8Array);
            } else {
              throw new Error(
                `Unexpected accumulator verification param ${pk.constructor.name} passed for credential index ${i}`
              );
            }
          }
        } else {
          throw new Error(`Unknown status check type ${checkType} for credential index ${i}`);
        }
      } else if (protocol === RevocationStatusProtocol.KbUni24) {
        if (!(acc instanceof KBUniversalAccumulatorValue)) {
          throw new Error(`Accumulator value should have been a KBUniversalAccumulatorValue object but was ${acc}`);
        }
        let pkSp;
        if (checkType === MEM_CHECK_STR || checkType === NON_MEM_CHECK_STR) {
          if (!(pk instanceof AccumulatorPublicKey)) {
            throw new Error(`Accumulator public key wasn't provided for credential index ${i}`);
          }
          if (!setupParamsTrk.hasAccumulatorParams()) {
            setupParamsTrk.addAccumulatorParams();
          }
          pkSp = SetupParam.vbAccumulatorPublicKey(pk);
        }

        if (checkType === MEM_CHECK_STR) {
          statement = Statement.kbUniAccumulatorMembershipVerifierFromSetupParamRefs(
            setupParamsTrk.accumParamsIdx,
            setupParamsTrk.add(pkSp),
            acc.mem
          );
        } else if (checkType === NON_MEM_CHECK_STR) {
          statement = Statement.kbUniAccumulatorNonMembershipVerifierFromSetupParamRefs(
            setupParamsTrk.accumParamsIdx,
            setupParamsTrk.add(pkSp),
            acc.nonMem
          );
        } else if (checkType === MEM_CHECK_KV_STR) {
          if (pk === undefined) {
            statement = Statement.kbUniAccumulatorMembershipKV(acc.mem);
          } else {
            if (pk instanceof AccumulatorSecretKey) {
              statement = Statement.kbUniAccumulatorMembershipKVFullVerifier(pk, acc.mem);
            } else {
              throw new Error(
                `Unexpected accumulator verification param ${pk.constructor.name} passed for credential index ${i}`
              );
            }
          }
        } else if (checkType === NON_MEM_CHECK_KV_STR) {
          if (pk === undefined) {
            statement = Statement.kbUniAccumulatorNonMembershipKV(acc.nonMem);
          } else {
            if (pk instanceof AccumulatorSecretKey) {
              statement = Statement.kbUniAccumulatorNonMembershipKVFullVerifier(pk, acc.nonMem);
            } else {
              throw new Error(
                `Unexpected accumulator verification param ${pk.constructor.name} passed for credential index ${i}`
              );
            }
          }
        } else {
          throw new Error(`Unknown status check type ${checkType} for credential index ${i}`);
        }
      } else {
        throw new Error(`Unknown status protocol ${protocol} for credential index ${i}`);
      }

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

    ineqsAux.forEach(([i, ineq]) => {
      this.processAttributeInequalities(
        i,
        (n: string) => {
          return flattenedSchemas[i][0].indexOf(n);
        },
        ineq,
        statements,
        metaStatements,
        setupParamsTrk,
        predicateParams
      );
    });

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

    if (this.spec.circomPredicatesMultiCred !== undefined) {
      this.spec.circomPredicatesMultiCred.forEach((pred, j) => {
        const statement = Presentation.createCircomStatement(
          pred,
          j,
          setupParamsTrk,
          predicateParams,
          circomOutputsMultiCred
        );
        const sIdx = statements.add(statement);

        function addWitnessEquality(cId: number, attributeName: object) {
          const attr = flattenObjectToKeyValuesList(attributeName) as object;
          const nameIdx = flattenedSchemas[cId][0].indexOf(attr[0][0]);
          const witnessEq = new WitnessEqualityMetaStatement();
          witnessEq.addWitnessRef(cId, nameIdx);
          witnessEq.addWitnessRef(sIdx, predicateWitnessIdx++);
          metaStatements.addWitnessEquality(witnessEq);
        }

        let predicateWitnessIdx = 0;
        pred.privateVars.forEach((privateVars) => {
          if (Array.isArray(privateVars.attributeRef)) {
            privateVars.attributeRef.forEach((attrRef) => {
              addWitnessEquality(attrRef[0], attrRef[1]);
            });
          } else {
            addWitnessEquality(privateVars.attributeRef[0], privateVars.attributeRef[1]);
          }
        });
      });
    }

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
      } else if (sigType === BDDT16_BLINDED_CRED_PROOF_TYPE) {
        sigParams = getSignatureParamsForMsgCount(sigParamsByScheme, BDDT16MacParams, numAttribs);
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

      if (this.spec.blindCredentialRequest.attributeInequalities !== undefined) {
        let [names, ineqs] = flattenPredicatesInSpec(this.spec.blindCredentialRequest.attributeInequalities);
        const obj = {};
        for (let j = 0; j < names.length; j++) {
          obj[names[j]] = ineqs[j].map((ineqs_j) => [
            ineqs_j,
            // @ts-ignore
            this.spec.blindCredentialRequest.schema.encoder.encodeMessage(names[j], ineqs_j.inEqualTo)
          ]);
        }
        this.processAttributeInequalities(
          pedCommStId,
          getAttrIndexInPedComm,
          obj,
          statements,
          metaStatements,
          setupParamsTrk,
          predicateParams
        );
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
    const proofSpec = new QuasiProofSpec(statements, metaStatements, setupParamsTrk.setupParams, ctx);
    return this.proof.verifyUsingQuasiProofSpec(proofSpec, this.nonce, versionGt5);
  }

  /**
   * Get delegated proofs for credentials and there statuses where applicable.
   * @returns - The key in the returned map is the credential index
   */
  getDelegatedProofs(): Map<number, DelegatedProof> {
    const r = new Map<number, DelegatedProof>();
    const delegatedProofs = this.proof.getDelegatedProofs();
    let nextCredStatusStatementIdx = this.spec.credentials.length;
    for (let i = 0; i < this.spec.credentials.length; i++) {
      const presentedCred = this.spec.credentials[i];
      let credP: IDelegatedCredentialProof | undefined, statusP: IDelegatedCredentialStatusProof | undefined;

      if (presentedCred.sigType === SignatureType.Bddt16) {
        const proof = delegatedProofs.get(i);
        if (proof === undefined) {
          throw new Error(`Could not find delegated credential proof for credential index ${i}`);
        }
        if (!(proof instanceof BDDT16DelegatedProof)) {
          throw new Error(
            `Unexpected delegated credential proof type ${proof.constructor.name} for credential index ${i}`
          );
        }
        credP = {
          sigType: presentedCred.sigType,
          proof
        };
      }

      if (presentedCred.status !== undefined) {
        if (
          presentedCred.status[TYPE_STR] === RevocationStatusProtocol.Vb22 &&
          presentedCred.status[REV_CHECK_STR] === MEM_CHECK_KV_STR
        ) {
          const proof = delegatedProofs.get(nextCredStatusStatementIdx);
          if (proof === undefined) {
            throw new Error(`Could not find delegated credential status proof for credential index ${i}`);
          }
          if (!(proof instanceof VBAccumMembershipDelegatedProof)) {
            throw new Error(
              `Unexpected delegated credential status proof type ${proof.constructor.name} for credential index ${i}`
            );
          }
          statusP = {
            [ID_STR]: presentedCred.status[ID_STR],
            [TYPE_STR]: presentedCred.status[TYPE_STR],
            [REV_CHECK_STR]: presentedCred.status[REV_CHECK_STR],
            proof
          };
        } else if (
          presentedCred.status[TYPE_STR] === RevocationStatusProtocol.KbUni24 &&
          (presentedCred.status[REV_CHECK_STR] === MEM_CHECK_KV_STR ||
            presentedCred.status[REV_CHECK_STR] === NON_MEM_CHECK_KV_STR)
        ) {
          const proof = delegatedProofs.get(nextCredStatusStatementIdx);
          if (proof === undefined) {
            throw new Error(`Could not find delegated credential status proof for credential index ${i}`);
          }
          if (presentedCred.status[REV_CHECK_STR] === MEM_CHECK_KV_STR) {
            if (!(proof instanceof KBUniAccumMembershipDelegatedProof)) {
              throw new Error(
                `Unexpected delegated credential status proof type ${proof.constructor.name} for credential index ${i}`
              );
            }
          }
          if (presentedCred.status[REV_CHECK_STR] === NON_MEM_CHECK_KV_STR) {
            if (!(proof instanceof KBUniAccumNonMembershipDelegatedProof)) {
              throw new Error(
                `Unexpected delegated credential status proof type ${proof.constructor.name} for credential index ${i}`
              );
            }
          }
          statusP = {
            [ID_STR]: presentedCred.status[ID_STR],
            [TYPE_STR]: presentedCred.status[TYPE_STR],
            [REV_CHECK_STR]: presentedCred.status[REV_CHECK_STR],
            // @ts-ignore
            proof
          };
        }
        nextCredStatusStatementIdx++;
      }

      if (credP !== undefined || statusP !== undefined) {
        r.set(i, new DelegatedProof(credP, statusP));
      }
    }
    return r;
  }

  /**
   * Encode the revealed attributes of the presented credential
   * @param credIdx
   * @param presentedCred
   * @param presentedCredSchema
   * @param flattenedNames
   * @param newVersion
   */
  private static encodeRevealed(
    credIdx: number,
    presentedCred: IPresentedCredential,
    presentedCredSchema: CredentialSchema,
    flattenedNames: string[],
    newVersion: boolean
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
          presentedCred.status[REV_CHECK_STR] !== NON_MEM_CHECK_STR &&
          presentedCred.status[REV_CHECK_STR] !== MEM_CHECK_KV_STR &&
          presentedCred.status[REV_CHECK_STR] !== NON_MEM_CHECK_KV_STR)
      ) {
        throw new Error(`Presented credential for ${credIdx} has invalid status ${presentedCred.status}`);
      }
      // Following will also ensure that holder (prover) cannot change the registry (accumulator) id or the type of check
      revealedRaw[STATUS_STR] = {
        [ID_STR]: presentedCred.status[ID_STR],
        [REV_CHECK_STR]: presentedCred.status[REV_CHECK_STR]
      };
      if (newVersion) {
        revealedRaw[STATUS_STR][TYPE_STR] = presentedCred.status[TYPE_STR];
      }
    }
    const encoded = new Map<number, Uint8Array>();
    Object.entries(flatten(revealedRaw) as object).forEach(([k, v]) => {
      const i = flattenedNames.indexOf(k);
      if (i === -1) {
        // Match text of form "<string>.<number>"
        const re = /.+\.\d+/i;
        if (k.match(re) !== null && v !== null) {
          // Was an array item that was not revealed
          throw new Error(`Attribute name ${k} not found in schema`);
        }
      } else {
        encoded.set(i, presentedCredSchema.encoder.encodeMessage(k, v));
      }
    });
    return encoded;
  }

  private processAttributeInequalities(
    statementIdx: number,
    witnessIndexGetter: (string) => number,
    ineqs: { [key: string]: [IPresentedAttributeInequality, Uint8Array][] },
    statements: Statements,
    metaStatements: MetaStatements,
    setupParamsTrk: SetupParamsTracker,
    predicateParams?: Map<string, PredicateParamType>
  ) {
    Object.keys(ineqs).forEach((name) => {
      const nameIdx = witnessIndexGetter(name);
      ineqs[name].forEach(([ineq, inequalTo]) => {
        const paramId = ineq['paramId'];
        const param = paramId !== undefined ? predicateParams?.get(paramId) : undefined;
        const statement = Presentation.publicInequalityStatement(
          inequalTo,
          setupParamsTrk,
          statementIdx,
          paramId,
          param
        );
        const sIdx = statements.add(statement);
        const witnessEq = new WitnessEqualityMetaStatement();
        witnessEq.addWitnessRef(statementIdx, nameIdx);
        witnessEq.addWitnessRef(sIdx, 0);
        metaStatements.addWitnessEquality(witnessEq);
      });
    });
  }

  private processBoundChecks(
    statementIdx: number,
    witnessIndexGetter: (string) => number,
    b: { [key: string]: string | IPresentedAttributeBound | IPresentedAttributeBound[] },
    flattenedSchema: FlattenedSchema,
    statements: Statements,
    metaStatements: MetaStatements,
    setupParamsTrk: SetupParamsTracker,
    predicateParams?: Map<string, PredicateParamType>
  ) {
    let names: string[];
    let bounds: object[][];
    if (semver.lte(this.version, '0.4.0')) {
      let temp: object[];
      [names, temp] = flattenTill2ndLastKey(b);
      bounds = temp.map((t) => [t]);
    } else {
      [names, bounds] = flattenPredicatesInSpec(b);
    }

    names.forEach((name, j) => {
      const nameIdx = witnessIndexGetter(name);
      const valTyp = CredentialSchema.typeOfName(name, flattenedSchema);
      bounds[j].forEach((bound) => {
        const [min, max] = [bound['min'], bound['max']];
        const [transformedMin, transformedMax] = getTransformedMinMax(name, valTyp, min, max);

        const paramId = bound['paramId'];
        let protocol = bound['protocol'];
        const param = predicateParams?.get(paramId);
        let statement: Uint8Array;

        // Older versions of presentation did not have protocol name specified
        if (semver.lt(this.version, '0.2.0')) {
          protocol = BoundCheckProtocol.Legogroth16;
        }

        if (paramId === undefined) {
          // paramId is undefined means no setup param was passed and thus the default setup of Bulletproofs++ can be used.
          if (protocol !== BoundCheckProtocol.Bpp) {
            throw new Error(
              `Hardcoded setup for bound check is only available for Bulletproofs++ but found protocol ${protocol}`
            );
          } else {
            if (!setupParamsTrk.hasBoundCheckBppSetup()) {
              setupParamsTrk.addBoundCheckBppSetup();
            }
            statement = Statement.boundCheckBppFromSetupParamRefs(
              transformedMin,
              transformedMax,
              setupParamsTrk.boundCheckBppSetupIdx
            );
          }
        } else {
          switch (protocol) {
            case BoundCheckProtocol.Legogroth16:
              Presentation.addLegoVerifyingKeyToTracker(paramId, param, setupParamsTrk, statementIdx);
              statement = Statement.boundCheckLegoVerifierFromSetupParamRefs(
                transformedMin,
                transformedMax,
                setupParamsTrk.indexForParam(paramId)
              );
              break;
            case BoundCheckProtocol.Bpp:
              Presentation.addBppSetupParamsToTracker(paramId, param, setupParamsTrk, statementIdx);
              statement = Statement.boundCheckBppFromSetupParamRefs(
                transformedMin,
                transformedMax,
                setupParamsTrk.indexForParam(paramId)
              );
              break;
            case BoundCheckProtocol.Smc:
              Presentation.addSmcSetupParamsToTracker(paramId, param, setupParamsTrk, statementIdx);
              statement = Statement.boundCheckSmcFromSetupParamRefs(
                transformedMin,
                transformedMax,
                setupParamsTrk.indexForParam(paramId)
              );
              break;
            case BoundCheckProtocol.SmcKV:
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
        }

        const sIdx = statements.add(statement);
        const witnessEq = new WitnessEqualityMetaStatement();
        witnessEq.addWitnessRef(statementIdx, nameIdx);
        witnessEq.addWitnessRef(sIdx, 0);
        metaStatements.addWitnessEquality(witnessEq);
      });
    });
  }

  private processVerifiableEncs(
    statementIdx: number,
    witnessIndexGetter: (string) => number,
    v: { [key: string]: string | IPresentedAttributeVE | IPresentedAttributeVE[] },
    flattenedSchema: FlattenedSchema,
    statements: Statements,
    metaStatements: MetaStatements,
    setupParamsTrk: SetupParamsTracker,
    predicateParams?: Map<string, PredicateParamType>
  ) {
    let names: string[];
    let verEncs: object[][];
    if (semver.lte(this.version, '0.4.0')) {
      let temp: object[];
      [names, temp] = flattenTill2ndLastKey(v);
      verEncs = temp.map((t) => [t]);
    } else {
      [names, verEncs] = flattenPredicatesInSpec(v);
    }

    names.forEach((name, j) => {
      const valTyp = CredentialSchema.typeOfName(name, flattenedSchema);
      if (valTyp.type !== ValueType.RevStr) {
        throw new Error(
          `Attribute name ${name} of credential index ${statementIdx} should be a reversible string type but was ${valTyp}`
        );
      }
      const nameIdx = witnessIndexGetter(name);
      verEncs[j].forEach((verEnc) => {
        const commKeyId = verEnc['commitmentGensId'];
        if (commKeyId === undefined) {
          throw new Error(`Commitment gens id not found for ${name}`);
        }
        const commKey = predicateParams?.get(commKeyId);
        if (commKey === undefined) {
          throw new Error(`Commitment gens not found for id ${commKeyId}`);
        }
        const encKeyId = verEnc['encryptionKeyId'];
        if (encKeyId === undefined) {
          throw new Error(`Encryption key id not found for ${name}`);
        }
        const encKey = predicateParams?.get(encKeyId);
        if (encKey === undefined) {
          throw new Error(`Encryption key not found for id ${encKey}`);
        }
        const snarkVkId = verEnc['snarkKeyId'];
        if (snarkVkId === undefined) {
          throw new Error(`Snark verification key id not found for ${name}`);
        }
        const snarkVk = predicateParams?.get(snarkVkId);
        if (snarkVk === undefined) {
          throw new Error(`Snark verification key not found for id ${snarkVkId}`);
        }
        const chunkBitSize = verEnc['chunkBitSize'];
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
    });
  }

  private processCircomPredicates(
    statementIdx: number,
    witnessIndexGetter: (string) => number,
    predicates: ICircomPredicate<ICircuitPrivateVar>[],
    statements: Statements,
    metaStatements: MetaStatements,
    setupParamsTrk: SetupParamsTracker,
    predicateParams?: Map<string, PredicateParamType>,
    outputs?: Uint8Array[][]
  ) {
    predicates.forEach((pred, j) => {
      const statement = Presentation.createCircomStatement(
        pred,
        j,
        setupParamsTrk,
        predicateParams,
        outputs,
        statementIdx
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

  private static createCircomStatement(
    pred: ICircomPredicate<ICircuitPrivateVar | ICircuitPrivateVarMultiCred>,
    predIdx: number,
    setupParamsTrk: SetupParamsTracker,
    predicateParams?: Map<string, PredicateParamType>,
    outputs?: Uint8Array[][],
    statementIdx?: number
  ): Uint8Array {
    const param = predicateParams?.get(pred.snarkKeyId);
    Presentation.addLegoVerifyingKeyToTracker(pred.snarkKeyId, param, setupParamsTrk);

    let publicInputs = pred.publicVars.flatMap((pv) => {
      return pv.value;
    });
    if (outputs !== undefined && outputs.length > predIdx) {
      publicInputs = outputs[predIdx].concat(publicInputs);
    }
    const unqId = `circom-outputs-${statementIdx !== undefined ? statementIdx : null}__${predIdx}`;
    setupParamsTrk.addForParamId(unqId, SetupParam.fieldElementVec(publicInputs));

    return Statement.r1csCircomVerifierFromSetupParamRefs(
      setupParamsTrk.indexForParam(unqId),
      setupParamsTrk.indexForParam(pred.snarkKeyId)
    );
  }

  toJSON(): object {
    let attributeCiphertexts;
    if (this.attributeCiphertexts !== undefined) {
      attributeCiphertexts = {};
      for (const [i, v] of this.attributeCiphertexts.entries()) {
        attributeCiphertexts[i] = {};
        Presentation.ciphertextToBs58(v, attributeCiphertexts[i], this.version);
      }
    }

    function formatCircomPreds(
      circomPredicates: ICircomPredicate<ICircuitPrivateVar | ICircuitPrivateVarMultiCred>[]
    ): object {
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
        if (cred.status[TYPE_STR] === RevocationStatusProtocol.Vb22) {
          // @ts-ignore
          current.status?.accumulated = b58.encode(cred.status.accumulated);
        } else if (cred.status[TYPE_STR] === RevocationStatusProtocol.KbUni24) {
          // @ts-ignore
          current.status?.accumulated = b58.encode((cred.status.accumulated as KBUniversalAccumulatorValue).toBytes());
        }
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
      blindCredentialRequest.schema = this.spec.blindCredentialRequest.schema.toJsonString();
      blindCredentialRequest.commitment = b58.encode(this.spec.blindCredentialRequest.commitment);
      if (this.blindedAttributeCiphertexts !== undefined) {
        blindedAttributeCiphertexts = {};
        Presentation.ciphertextToBs58(this.blindedAttributeCiphertexts, blindedAttributeCiphertexts, this.version);
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
    if (this.spec.circomPredicatesMultiCred !== undefined) {
      spec['circomPredicatesMultiCred'] = formatCircomPreds(this.spec.circomPredicatesMultiCred);
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
  static ciphertextToBs58(v: object, ret: object, version: string) {
    Object.keys(v).forEach((k) => {
      if (semver.lt(version, '0.5.0')) {
        // Old version had only 1 ciphertext for each attribute
        if (v[k] instanceof SaverCiphertext) {
          // @ts-ignore
          ret[k] = b58.encode(v[k].bytes);
        } else {
          ret[k] = {};
          Presentation.ciphertextToBs58(v[k], ret[k], version);
        }
      } else {
        if (Array.isArray(v[k]) && v[k].every((s) => s instanceof SaverCiphertext)) {
          // @ts-ignore
          ret[k] = v[k].map((s) => b58.encode(s.bytes));
        } else {
          ret[k] = {};
          Presentation.ciphertextToBs58(v[k], ret[k], version);
        }
      }
    });
  }

  // Convert base58 encoded ciphertexts present in `v` and store in `ret`
  static ciphertextFromBs58(v: object, ret: AttributeCiphertexts, version: string) {
    Object.keys(v).forEach((k) => {
      if (semver.lt(version, '0.5.0')) {
        // Old version had only 1 ciphertext for each attribute
        if (typeof v[k] === 'string') {
          // Only one ciphertext for this attribute
          ret[k] = new SaverCiphertext(b58.decode(v[k]));
        } else {
          ret[k] = {};
          // @ts-ignore
          Presentation.ciphertextFromBs58(v[k], ret[k], version);
        }
      } else {
        if (Array.isArray(v[k]) && v[k].every((s) => typeof s === 'string')) {
          // Many ciphertexts for this attribute
          ret[k] = v[k].map((s) => new SaverCiphertext(b58.decode(s)));
        } else {
          ret[k] = {};
          // @ts-ignore
          Presentation.ciphertextFromBs58(v[k], ret[k], version);
        }
      }
    });
  }

  private static addLegoVerifyingKeyToTracker(
    paramId: string,
    param: PredicateParamType | undefined,
    setupParamsTrk: SetupParamsTracker,
    statementIdx?: number
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
      let errorMsg: string;
      if (statementIdx !== undefined) {
        errorMsg = `Predicate param id ${paramId} (for statement index ${statementIdx}) was expected to be a Legosnark verifying key but was ${param}`;
      } else {
        errorMsg = `Predicate param id ${paramId} was expected to be a Legosnark verifying key but was ${param}`;
      }
      throw new Error(errorMsg);
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

  static addPedCommG1ToTracker(
    paramId: string,
    param: PredicateParamType | undefined,
    setupParamsTrk: SetupParamsTracker,
    statementIdx: number
  ): number {
    let index: number | undefined;
    if (param instanceof PederCommKey) {
      if (!setupParamsTrk.isTrackingParam(paramId)) {
        index = setupParamsTrk.addForParamId(paramId, SetupParam.pedCommKeyG1(param));
      }
    } else if (param instanceof PederCommKeyUncompressed) {
      if (!setupParamsTrk.isTrackingParam(paramId)) {
        index = setupParamsTrk.addForParamId(paramId, SetupParam.pedCommKeyG1Uncompressed(param));
      }
    } else {
      throw new Error(
        `Predicate param id ${paramId} (for statement index ${statementIdx}) was expected to be a Pedersen commitment key but was ${param}`
      );
    }
    return index === undefined ? setupParamsTrk.indexForParam(paramId) : index;
  }

  static publicInequalityStatement(
    ineq: Uint8Array,
    setupParamsTrk: SetupParamsTracker,
    statementIdx: number,
    paramId?: string,
    param?: PredicateParamType
  ): Uint8Array {
    let commKeyIdx: number;
    if (paramId !== undefined) {
      commKeyIdx = Presentation.addPedCommG1ToTracker(paramId, param, setupParamsTrk, statementIdx);
    } else {
      if (!setupParamsTrk.hasInequalityCommKey()) {
        setupParamsTrk.addInequalityCommKey();
      }
      commKeyIdx = setupParamsTrk.inqlCommKeyIdx;
    }
    return Statement.publicInequalityG1FromSetupParamRefs(ineq, commKeyIdx);
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

    function formatCircomPreds(pred: object): ICircomPredicate<ICircuitPrivateVar | ICircuitPrivateVarMultiCred>[] {
      const circomPredicates = deepClone(pred) as object[];
      circomPredicates.forEach((cp) => {
        if (cp['protocol'] !== undefined && !Object.values(CircomProtocol).includes(cp['protocol'])) {
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
      if (typeof cred['attributeInequalities'] === 'object') {
        const ineqs = flattenPredicatesInSpec(cred['attributeInequalities']);
        for (let i = 0; i < ineqs[0].length; i++) {
          // @ts-ignore
          ineqs[1][i].forEach((ineq) => {
            if (!Object.values(InequalityProtocol).includes(ineq['protocol'])) {
              throw new Error(
                `Unrecognized protocol ${ineq['protocol']} for public inequality for attribute ${ineqs[0][i]} with value ${ineq['inEqualTo']}`
              );
            }
          });
        }
      }

      if (typeof cred['bounds'] === 'object') {
        const bounds = flattenTill2ndLastKey(cred['bounds']);
        for (let i = 0; i < bounds[0].length; i++) {
          if (
            bounds[1][i]['protocol'] !== undefined &&
            !Object.values(BoundCheckProtocol).includes(bounds[1][i]['protocol'])
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
            !Object.values(VerifiableEncryptionProtocol).includes(vencs[1][i]['protocol'])
          ) {
            throw new Error(
              `Unrecognized protocol ${vencs[1][i]['protocol']} for verifiable encryption for attribute ${vencs[0][i]}`
            );
          }
        }
      }

      let status, circomPredicates, sigType;
      if (cred['status'] !== undefined) {
        if (Object.values(RevocationStatusProtocol).includes(cred['status'][TYPE_STR])) {
          status = deepClone(cred['status']) as object;
          if (status[TYPE_STR] === RevocationStatusProtocol.Vb22) {
            status['accumulated'] = b58.decode(cred['status']['accumulated']);
          } else if (status[TYPE_STR] === RevocationStatusProtocol.KbUni24) {
            status['accumulated'] = KBUniversalAccumulatorValue.fromBytes(b58.decode(status['accumulated']));
          }
        } else {
          throw new Error(`status type should be one of ${RevocationStatusProtocol} but was ${cred['status']['type']}`);
        }
      }
      if (cred['circomPredicates'] !== undefined) {
        circomPredicates = formatCircomPreds(cred['circomPredicates']);
      }
      if (cred['sigType'] !== undefined) {
        if (Object.values(SignatureType).includes(cred['sigType'])) {
          sigType = cred['sigType'];
        } else {
          throw new Error(`sigType should be one of ${SignatureType} but was ${cred['sigType']}`);
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
        sigType,
        cred['attributeInequalities']
      );
    }

    if (spec['circomPredicatesMultiCred'] !== undefined) {
      presSpec.circomPredicatesMultiCred = formatCircomPreds(
        spec['circomPredicatesMultiCred']
      ) as ICircomPredicate<ICircuitPrivateVarMultiCred>[];
    }

    presSpec.attributeEqualities = spec['attributeEqualities'];
    presSpec.boundedPseudonyms = spec['boundedPseudonyms'];
    presSpec.unboundedPseudonyms = spec['unboundedPseudonyms'];

    let atc;
    if (attributeCiphertexts !== undefined) {
      atc = new Map<number, AttributeCiphertexts[]>();
      Object.keys(attributeCiphertexts).forEach((k) => {
        const c = attributeCiphertexts[k];
        const rc = {};
        Presentation.ciphertextFromBs58(c, rc, version);
        atc.set(parseInt(k), rc);
      });
    }

    let bac;
    if (spec['blindCredentialRequest'] !== undefined) {
      const req = deepClone(spec['blindCredentialRequest']) as object;
      if (!Object.values(BlindSignatureType).includes(req['sigType'])) {
        throw new Error(`sigType should be one of ${BlindSignatureType} but was ${req['sigType']}`);
      }
      req['schema'] = CredentialSchema.fromJSON(JSON.parse(req['schema']));
      req['commitment'] = b58.decode(req['commitment']);
      if (blindedAttributeCiphertexts !== undefined) {
        bac = {};
        Presentation.ciphertextFromBs58(blindedAttributeCiphertexts, bac, version);
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

    return new Presentation(version, presSpec, new CompositeProof(b58.decode(proof)), atc, context, nnc, bac);
  }
}
