import { Versioned } from './versioned';
import { ICircomPredicate, IPresentedCredential, PresentationSpecification } from './presentation-specification';
import {
  CompositeProofG1,
  MetaStatements,
  QuasiProofSpecG1,
  SetupParam,
  Statement,
  Statements,
  WitnessEqualityMetaStatement
} from '../composite-proof';
import { CredentialSchema, ValueType } from './schema';
import { VerifyResult } from '@docknetwork/crypto-wasm';
import { flatten } from 'flat';
import {
  AttributeCiphertexts,
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
  PublicKey
} from './types-and-consts';
import { AccumulatorPublicKey } from '../accumulator';
import {
  accumulatorStatement,
  buildContextForProof,
  buildSignatureStatementFromParamsRef,
  createWitEq,
  deepClone,
  flattenTill2ndLastKey,
  getTransformedMinMax,
  paramsClassByPublicKey,
  saverStatement,
  getSignatureParamsForMsgCount
} from './util';
import { LegoVerifyingKey, LegoVerifyingKeyUncompressed } from '../legosnark';
import { SaverCiphertext } from '../saver';
import b58 from 'bs58';
import { SetupParamsTracker } from './setup-params-tracker';
import { flattenObjectToKeyValuesList } from '../util';

export class Presentation extends Versioned {
  readonly spec: PresentationSpecification;
  readonly proof: CompositeProofG1;
  // Ciphertexts for the verifiable encryption of required attributes. The key of the map is the credential index.
  // This is intentionally not part of presentation specification as this is created as part of the proof generation,
  // not before.
  readonly attributeCiphertexts?: Map<number, AttributeCiphertexts>;
  readonly context?: string;
  readonly nonce?: Uint8Array;

  constructor(
    version: string,
    spec: PresentationSpecification,
    proof: CompositeProofG1,
    attributeCiphertexts?: Map<number, AttributeCiphertexts>,
    context?: string,
    nonce?: Uint8Array
  ) {
    super(version);
    this.spec = spec;
    this.proof = proof;
    this.attributeCiphertexts = attributeCiphertexts;
    this.context = context;
    this.nonce = nonce;
  }

  /**
   *
   * @param publicKeys - Array of keys in the order of credentials in the presentation.
   * @param accumulatorPublicKeys - Mapping credential index -> accumulator public key
   * @param predicateParams - Setup params for various predicates
   * @param circomOutputs - Values for the outputs variables of the Circom programs used for predicates
   */
  verify(
    publicKeys: PublicKey[],
    accumulatorPublicKeys?: Map<number, AccumulatorPublicKey>,
    predicateParams?: Map<string, PredicateParamType>,
    circomOutputs?: Map<number, Uint8Array[][]>
  ): VerifyResult {
    const numCreds = this.spec.credentials.length;
    if (publicKeys.length !== numCreds) {
      throw new Error(`Supply same no of public keys as creds. ${publicKeys.length} != ${numCreds}`);
    }

    const statements = new Statements();
    const metaStatements = new MetaStatements();

    const flattenedSchemas: FlattenedSchema[] = [];

    // For credentials with status, i.e. using accumulators, type is [credIndex, revCheckType, accumulator]
    const credStatusAux: [number, string, Uint8Array][] = [];

    const boundsAux: [number, object][] = [];
    const verEncAux: [number, object][] = [];
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

    for (const eql of this.spec.attributeEqualities) {
      metaStatements.addWitnessEquality(createWitEq(eql, flattenedSchemas));
    }

    boundsAux.forEach(([i, b]) => {
      const bounds = flattenTill2ndLastKey(b) as object;
      bounds[0].forEach((name, j) => {
        const nameIdx = flattenedSchemas[i][0].indexOf(name);
        const valTyp = CredentialSchema.typeOfName(name, flattenedSchemas[i]);
        const [min, max] = [bounds[1][j]['min'], bounds[1][j]['max']];
        const [transformedMin, transformedMax] = getTransformedMinMax(name, valTyp, min, max);

        const paramId = bounds[1][j]['paramId'];
        const param = predicateParams?.get(paramId);
        Presentation.addLegoVerifyingKeyToTracker(paramId, param, setupParamsTrk);
        const statement = Statement.boundCheckVerifierFromSetupParamRefs(
          transformedMin,
          transformedMax,
          setupParamsTrk.indexForParam(paramId)
        );
        const sIdx = statements.add(statement);
        const witnessEq = new WitnessEqualityMetaStatement();
        witnessEq.addWitnessRef(i, nameIdx);
        witnessEq.addWitnessRef(sIdx, 0);
        metaStatements.addWitnessEquality(witnessEq);
      });
    });

    verEncAux.forEach(([i, v]) => {
      const verEnc = flattenTill2ndLastKey(v) as object;
      verEnc[0].forEach((name, j) => {
        const valTyp = CredentialSchema.typeOfName(name, flattenedSchemas[i]);
        if (valTyp.type !== ValueType.RevStr) {
          throw new Error(
            `Attribute name ${name} of credential index ${i} should be a reversible string type but was ${valTyp}`
          );
        }
        const nameIdx = flattenedSchemas[i][0].indexOf(name);
        const commGensId = verEnc[1][j]['commitmentGensId'];
        if (commGensId === undefined) {
          throw new Error(`Commitment gens id not found for ${name}`);
        }
        const commGens = predicateParams?.get(commGensId);
        if (commGens === undefined) {
          throw new Error(`Commitment gens not found for id ${commGensId}`);
        }
        const encKeyId = verEnc[1][j]['encryptionKeyId'];
        if (encKeyId === undefined) {
          throw new Error(`Encryption key id not found for ${name}`);
        }
        const encKey = predicateParams?.get(encKeyId);
        if (encKey === undefined) {
          throw new Error(`Encryption key not found for id ${encKey}`);
        }
        const snarkVkId = verEnc[1][j]['snarkKeyId'];
        if (snarkVkId === undefined) {
          throw new Error(`Snark verification key id not found for ${name}`);
        }
        const snarkVk = predicateParams?.get(snarkVkId);
        if (snarkVk === undefined) {
          throw new Error(`Snark verification key not found for id ${snarkVkId}`);
        }
        const chunkBitSize = verEnc[1][j]['chunkBitSize'];
        const statement = saverStatement(
          false,
          chunkBitSize,
          commGensId,
          encKeyId,
          snarkVkId,
          commGens,
          encKey,
          snarkVk,
          setupParamsTrk
        );
        const sIdx = statements.add(statement);
        const witnessEq = new WitnessEqualityMetaStatement();
        witnessEq.addWitnessRef(i, nameIdx);
        witnessEq.addWitnessRef(sIdx, 0);
        metaStatements.addWitnessEquality(witnessEq);
      });
    });

    circomAux.forEach(([i, predicates]) => {
      const outputs = circomOutputs?.get(i);
      predicates.forEach((pred, j) => {
        const param = predicateParams?.get(pred.snarkKeyId);
        Presentation.addLegoVerifyingKeyToTracker(pred.snarkKeyId, param, setupParamsTrk);

        let publicInputs = pred.publicVars.flatMap((pv) => {
          return pv.value;
        });
        if (outputs !== undefined && outputs.length > j) {
          publicInputs = outputs[j].concat(publicInputs);
        }
        const unqId = `circom-outputs-${i}__${j}`;
        setupParamsTrk.addForParamId(unqId, SetupParam.fieldElementVec(publicInputs));

        const statement = Statement.r1csCircomVerifierFromSetupParamRefs(
          setupParamsTrk.indexForParam(unqId),
          setupParamsTrk.indexForParam(pred.snarkKeyId)
        );
        const sIdx = statements.add(statement);

        function addWitnessEquality(attributeName: object) {
          const attr = flattenObjectToKeyValuesList(attributeName) as object;
          const nameIdx = flattenedSchemas[i][0].indexOf(attr[0][0]);
          const witnessEq = new WitnessEqualityMetaStatement();
          witnessEq.addWitnessRef(i, nameIdx);
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
    });

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

  toJSON(): object {
    const attributeCiphertexts = {};
    if (this.attributeCiphertexts !== undefined) {
      for (const [i, v] of this.attributeCiphertexts.entries()) {
        attributeCiphertexts[i] = {};
        Presentation.toBs58(v, attributeCiphertexts[i]);
      }
    }

    const creds: object[] = [];
    for (const cred of this.spec.credentials) {
      const current = deepClone(cred) as object; // Need this deep cloning because structure of revealed attributes or key `extra` isn't fixed
      if (cred.status !== undefined) {
        // @ts-ignore
        current.status?.accumulated = b58.encode(cred.status.accumulated);
      }
      creds.push(current);
    }

    return {
      version: this.version,
      context: this.context,
      nonce: this.nonce ? b58.encode(this.nonce) : null,
      spec: {
        credentials: creds,
        attributeEqualities: this.spec.attributeEqualities
      },
      attributeCiphertexts,
      proof: b58.encode(this.proof.bytes)
    };
  }

  static toBs58(v: object, ret: object) {
    Object.keys(v).forEach((k) => {
      if (v[k] instanceof SaverCiphertext) {
        // @ts-ignore
        ret[k] = b58.encode(v[k].bytes);
      } else {
        ret[k] = {};
        Presentation.toBs58(v[k], ret[k]);
      }
    });
  }

  static fromBs58(v: object, ret: AttributeCiphertexts) {
    Object.keys(v).forEach((k) => {
      if (typeof v[k] === 'string') {
        ret[k] = new SaverCiphertext(b58.decode(v[k]));
      } else {
        ret[k] = {};
        // @ts-ignore
        Presentation.fromBs58(v[k], ret[k]);
      }
    });
  }

  private static addLegoVerifyingKeyToTracker(
    paramId: string,
    param: PredicateParamType | undefined,
    setupParamsTrk: SetupParamsTracker
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
      throw new Error(`Predicate param id ${paramId} was expected to be a Legosnark verifying key but was ${param}`);
    }
  }

  static fromJSON(j: object): Presentation {
    // @ts-ignore
    const { version, context, nonce, spec, attributeCiphertexts, proof } = j;
    const nnc = nonce ? b58.decode(nonce) : undefined;

    const presSpec = new PresentationSpecification();
    for (const cred of spec['credentials']) {
      let status;
      if (cred['status'] !== undefined) {
        status = deepClone(cred['status']) as object;
        status['accumulated'] = b58.decode(cred['status']['accumulated']);
      }
      presSpec.addPresentedCredential(
        cred['version'],
        cred['schema'],
        cred['revealedAttributes'],
        status,
        cred['bounds'],
        cred['verifiableEncryptions'],
        cred['circomPredicates']
      );
    }
    presSpec.attributeEqualities = spec['attributeEqualities'];

    const atc = new Map<number, AttributeCiphertexts>();
    if (attributeCiphertexts !== undefined) {
      Object.keys(attributeCiphertexts).forEach((k) => {
        const c = attributeCiphertexts[k];
        const rc = {};
        Presentation.fromBs58(c, rc);
        atc.set(parseInt(k), rc);
      });
    }

    return new Presentation(version, presSpec, new CompositeProofG1(b58.decode(proof)), atc, context, nnc);
  }
}
