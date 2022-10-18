import { Versioned } from './versioned';
import { IPresentedCredential, PresentationSpecification } from './presentation-specification';
import {
  CompositeProofG1,
  MetaStatements,
  QuasiProofSpecG1,
  Statement,
  Statements,
  WitnessEqualityMetaStatement
} from '../composite-proof';
import { BBSPlusPublicKeyG2, Encoder, SignatureParamsG1 } from '../bbs-plus';
import { CredentialSchema, ValueType } from './schema';
import { VerifyResult } from '@docknetwork/crypto-wasm';
import { flatten } from 'flat';
import {
  AttributeCiphertexts,
  CRED_VERSION_STR,
  FlattenedSchema,
  MEM_CHECK_STR,
  PredicateParamType,
  REGISTRY_ID_STR,
  REV_CHECK_STR,
  REV_ID_STR,
  SCHEMA_STR,
  SIGNATURE_PARAMS_LABEL_BYTES,
  STATUS_STR,
  SUBJECT_STR
} from './types-and-consts';
import { AccumulatorPublicKey } from '../accumulator';
import {
  dockAccumulatorMemProvingKey,
  dockAccumulatorNonMemProvingKey,
  dockAccumulatorParams,
  dockSaverEncryptionGens,
  dockSaverEncryptionGensUncompressed,
  flattenTill2ndLastKey
} from './util';
import { LegoVerifyingKey, LegoVerifyingKeyUncompressed } from '../legosnark';
import {
  SaverChunkedCommitmentGens,
  SaverChunkedCommitmentGensUncompressed,
  SaverEncryptionKey,
  SaverEncryptionKeyUncompressed,
  SaverVerifyingKey,
  SaverVerifyingKeyUncompressed
} from '../saver';

export class Presentation extends Versioned {
  spec: PresentationSpecification;
  proof: CompositeProofG1;
  // Ciphertexts for the verifiable encryption of required attributes. The key of the map is the credential index.
  // This is intentionally not part of presentation specification as this is created as part of the proof generation,
  // not before.
  attributeCiphertexts?: Map<number, AttributeCiphertexts>;
  context?: Uint8Array;
  nonce?: Uint8Array;

  constructor(
    version: string,
    spec: PresentationSpecification,
    proof: CompositeProofG1,
    attributeCiphertexts?: Map<number, AttributeCiphertexts>,
    context?: Uint8Array,
    nonce?: Uint8Array
  ) {
    super(version);
    this.spec = spec;
    this.proof = proof;
    this.attributeCiphertexts = attributeCiphertexts;
    this.context = context;
    this.nonce = nonce;
  }

  // TODO: This can be improved, figure out to use `SetupParams`
  /**
   *
   * @param publicKeys - Array of keys in the order of credentials in the presentation.
   * @param accumulatorValueAndPublicKeys - Mapping credential index -> (accumulator value, accumulator public key)
   * @param predicateParams
   */
  verify(
    publicKeys: BBSPlusPublicKeyG2[],
    accumulatorValueAndPublicKeys?: Map<number, [Uint8Array, AccumulatorPublicKey]>,
    predicateParams?: Map<string, PredicateParamType>
  ): VerifyResult {
    const numCreds = this.spec.credentials.length;
    if (publicKeys.length != numCreds) {
      throw new Error(`Supply same no of public keys as creds. ${publicKeys.length} != ${numCreds}`);
    }

    let maxAttribs = 2; // version and schema
    let sigParams = SignatureParamsG1.generate(maxAttribs, SIGNATURE_PARAMS_LABEL_BYTES);

    const statements = new Statements();
    const metaStatements = new MetaStatements();

    const flattenedSchemas: FlattenedSchema[] = [];

    // For credentials with status, i.e. using accumulators, type is [credIndex, revCheckType, accumulator]
    const credStatusAux: [number, string, Uint8Array][] = [];

    const boundsAux: [number, object][] = [];
    const verEncAux: [number, object][] = [];

    for (let i = 0; i < this.spec.credentials.length; i++) {
      const presentedCred = this.spec.credentials[i];
      const presentedCredSchema = CredentialSchema.fromJSON(presentedCred.schema);
      const flattenedSchema = presentedCredSchema.flatten();
      const numAttribs = flattenedSchema[0].length;

      const revealedEncoded = Presentation.encodeRevealed(presentedCred, presentedCredSchema, flattenedSchema[0]);

      if (maxAttribs < numAttribs) {
        maxAttribs = numAttribs;
      }
      const statement = Statement.bbsSignature(sigParams.adapt(numAttribs), publicKeys[i], revealedEncoded, false);
      statements.add(statement);
      flattenedSchemas.push(flattenedSchema);

      if (presentedCred.status !== undefined) {
        // TODO: Input validation
        credStatusAux.push([i, presentedCred.status[REV_CHECK_STR], presentedCred.status['accumulated']]);
      }

      if (presentedCred.bounds !== undefined) {
        boundsAux.push([i, presentedCred.bounds]);
      }
      if (presentedCred.verifiableEncryptions !== undefined) {
        verEncAux.push([i, presentedCred.verifiableEncryptions]);
      }
    }

    credStatusAux.forEach(([i, t, name]) => {
      let statement;
      const a = accumulatorValueAndPublicKeys?.get(i);
      if (a === undefined) {
        throw new Error(`Accumulator wasn't provided for credential index ${i}`);
      }
      const [acc, pk] = a;
      if (t === MEM_CHECK_STR) {
        statement = Statement.accumulatorMembership(dockAccumulatorParams(), pk, dockAccumulatorMemProvingKey(), acc);
      } else {
        statement = Statement.accumulatorNonMembership(
          dockAccumulatorParams(),
          pk,
          dockAccumulatorNonMemProvingKey(),
          acc
        );
      }
      const sIdx = statements.add(statement);
      const witnessEq = new WitnessEqualityMetaStatement();
      witnessEq.addWitnessRef(i, flattenedSchemas[i][0].indexOf(`${STATUS_STR}.${REV_ID_STR}`));
      witnessEq.addWitnessRef(sIdx, 0);
      metaStatements.addWitnessEquality(witnessEq);
    });

    for (const eql of this.spec.attributeEqualities) {
      const witnessEq = new WitnessEqualityMetaStatement();
      for (const [cIdx, name] of eql) {
        const i = flattenedSchemas[cIdx][0].indexOf(name);
        if (i === -1) {
          throw new Error(`Attribute name ${name} was not found`);
        }
        witnessEq.addWitnessRef(cIdx, i);
      }
      metaStatements.addWitnessEquality(witnessEq);
    }

    boundsAux.forEach(([i, b]) => {
      const bounds = flattenTill2ndLastKey(b) as object;
      bounds[0].forEach((name, j) => {
        const nameIdx = flattenedSchemas[i][0].indexOf(name);
        const valTyp = CredentialSchema.typeOfName(name, flattenedSchemas[i]);
        let statement, transformedMin, transformedMax;
        // TODO: Duplicate code
        const [min, max] = [bounds[1][j]['min'], bounds[1][j]['max']];
        switch (valTyp.type) {
          case ValueType.PositiveInteger:
            transformedMin = min;
            transformedMax = max;
            break;
          case ValueType.Integer:
            transformedMin = Encoder.integerToPositiveInt(valTyp.minimum)(min);
            transformedMax = Encoder.integerToPositiveInt(valTyp.minimum)(max);
            break;
          case ValueType.PositiveNumber:
            transformedMin = Encoder.positiveDecimalNumberToPositiveInt(valTyp.decimalPlaces)(min);
            transformedMax = Encoder.positiveDecimalNumberToPositiveInt(valTyp.decimalPlaces)(max);
            break;
          case ValueType.Number:
            transformedMin = Encoder.decimalNumberToPositiveInt(valTyp.minimum, valTyp.decimalPlaces)(min);
            transformedMax = Encoder.decimalNumberToPositiveInt(valTyp.minimum, valTyp.decimalPlaces)(max);
            break;
          default:
            throw new Error(`${name} should be of numeric type as per schema but was ${valTyp}`);
        }

        const paramId = bounds[1][j]['paramId'];
        const param = predicateParams?.get(paramId);
        if (param instanceof LegoVerifyingKey) {
          statement = Statement.boundCheckVerifierFromCompressedParams(transformedMin, transformedMax, param);
        } else if (param instanceof LegoVerifyingKeyUncompressed) {
          statement = Statement.boundCheckVerifier(transformedMin, transformedMax, param);
        } else {
          throw new Error(
            `Predicate param id ${paramId} was expected to be a Legosnark verifying key but was ${param}`
          );
        }
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
        const encKeyId = verEnc[1][j]['encryptionKeyId'];
        if (encKeyId === undefined) {
          throw new Error(`Encryption key id not found for ${name}`);
        }
        const encKey = predicateParams?.get(encKeyId);
        const snarkVkId = verEnc[1][j]['snarkKeyId'];
        if (snarkVkId === undefined) {
          throw new Error(`Snark verification key id not found for ${name}`);
        }
        const snarkVk = predicateParams?.get(snarkVkId);
        const chunkBitSize = verEnc[1][j]['chunkBitSize'];
        let statement;
        if (
          commGens instanceof SaverChunkedCommitmentGensUncompressed &&
          encKey instanceof SaverEncryptionKeyUncompressed &&
          snarkVk instanceof SaverVerifyingKeyUncompressed
        ) {
          statement = Statement.saverVerifier(
            dockSaverEncryptionGensUncompressed(),
            commGens,
            encKey,
            snarkVk,
            chunkBitSize
          );
        } else if (
          commGens instanceof SaverChunkedCommitmentGens &&
          encKey instanceof SaverEncryptionKey &&
          snarkVk instanceof SaverVerifyingKey
        ) {
          statement = Statement.saverVerifierFromCompressedParams(
            dockSaverEncryptionGens(),
            commGens,
            encKey,
            snarkVk,
            chunkBitSize
          );
        } else {
          throw new Error('All SAVER parameters should either be compressed in uncompressed');
        }
        const sIdx = statements.add(statement);
        const witnessEq = new WitnessEqualityMetaStatement();
        witnessEq.addWitnessRef(i, nameIdx);
        witnessEq.addWitnessRef(sIdx, 0);
        metaStatements.addWitnessEquality(witnessEq);
      });
    });

    // TODO: Fix context calc.
    const proofSpec = new QuasiProofSpecG1(statements, metaStatements, [], this.context);
    return this.proof.verifyUsingQuasiProofSpec(proofSpec, this.nonce);
  }

  /**
   * Encode the revealed attributes of the presented credential
   * @param presentedCred
   * @param presentedCredSchema
   * @param flattenedNames
   */
  private static encodeRevealed(
    presentedCred: IPresentedCredential,
    presentedCredSchema: CredentialSchema,
    flattenedNames: string[]
  ): Map<number, Uint8Array> {
    const revealedRaw = presentedCred.revealedAttributes;
    revealedRaw[CRED_VERSION_STR] = presentedCred.version;
    revealedRaw[SCHEMA_STR] = presentedCred.schema;
    if (presentedCred.status !== undefined) {
      // TODO: Check that keys present in `presentedCred`
      revealedRaw[STATUS_STR] = {};
      revealedRaw[STATUS_STR][REGISTRY_ID_STR] = presentedCred.status[REGISTRY_ID_STR];
      revealedRaw[STATUS_STR][REV_CHECK_STR] = presentedCred.status[REV_CHECK_STR];
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

  // TODO: Add to/from JSON
}
