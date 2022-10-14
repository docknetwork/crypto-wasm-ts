import { Versioned } from './versioned';
import { Credential } from './credential';
import { BBSPlusPublicKeyG2, Encoder, SignatureG1, SignatureParamsG1 } from '../bbs-plus';
import {
  CompositeProofG1,
  MetaStatements,
  QuasiProofSpecG1,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../composite-proof';
import { LegoProvingKey, LegoProvingKeyUncompressed } from '../legosnark';
import { CredentialSchema } from './schema';
import { getRevealedAndUnrevealed } from '../sign-verify-js-objs';
import {
  AttributeEquality,
  CRED_VERSION_STR,
  MEM_CHECK_STR, PredicateParamType,
  REGISTRY_ID_STR,
  REV_CHECK_STR,
  REV_ID_STR,
  SCHEMA_STR,
  SIGNATURE_PARAMS_LABEL_BYTES,
  STATUS_STR,
  StringOrObject,
  SUBJECT_STR
} from './types-and-consts';
import { PresentationSpecification } from './presentation-specification';
import b58 from 'bs58';
import { Presentation } from './presentation';
import { AccumulatorPublicKey, AccumulatorWitness, MembershipWitness, NonMembershipWitness } from '../accumulator';
import { dockAccumulatorMemProvingKey, dockAccumulatorNonMemProvingKey, dockAccumulatorParams } from './util';
import {
  SaverChunkedCommitmentGens,
  SaverChunkedCommitmentGensUncompressed,
  SaverEncryptionKey, SaverEncryptionKeyUncompressed,
  SaverProvingKey,
  SaverProvingKeyUncompressed
} from '../saver';
import { unflatten } from 'flat';

export class PresentationBuilder extends Versioned {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.0.1';

  _context?: Uint8Array;
  _nonce?: Uint8Array;
  proof?: CompositeProofG1;
  // Just for debugging
  _proofSpec?: QuasiProofSpecG1;
  spec: PresentationSpecification;

  credentials: [Credential, BBSPlusPublicKeyG2][];

  // Attributes revealed from each credential, key of the map is the credential index
  revealedAttributes: Map<number, Set<string>>;

  // Attributes proved equal in zero knowledge
  attributeEqualities: AttributeEquality[];

  // Each credential has only one accumulator for status
  credStatuses: Map<number, [AccumulatorWitness, Uint8Array, AccumulatorPublicKey, object]>;

  // Bounds on attribute. The key of the map is the credential index and for the inner map is the attribute and value of map denotes [min, max, an identifier of the snark proving key which the verifier knows as well to use corresponding verifying key]
  bounds: Map<number, Map<string, [number, number, string]>>;

  verifEnc: Map<number, Map<string, [number, string, string, string]>>;

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
    this.spec = new PresentationSpecification();
  }

  addCredential(credential: Credential, pk: BBSPlusPublicKeyG2): number {
    this.credentials.push([credential, pk]);
    return this.credentials.length - 1;
  }

  // NOTE: This and several methods below expect nested attributes names with "dot"s as separators. Passing the nested structure is also
  // possible but will need more parsing and thus can be handled later.
  markAttributesRevealed(credIdx: number, attributeNames: Set<string>) {
    this.validateCredIndex(credIdx);
    let revealed = this.revealedAttributes.get(credIdx);
    if (revealed === undefined) {
      revealed = new Set<string>();
    }
    for (const a of attributeNames) {
      revealed.add(`${SUBJECT_STR}.${a}`);
    }
    this.revealedAttributes.set(credIdx, revealed);
  }

  markAttributesEqual(...equality: AttributeEquality) {
    for (const aRef of equality) {
      this.validateCredIndex(aRef[0]);
    }
    this.attributeEqualities.push(equality);
  }

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
    b.set(attributeName, [min, max, provingKeyId])
    this.bounds.set(credIdx, b);
  }

  // TODO: Should check if all compressed or all uncompressed
  verifiablyEncrypt(credIdx: number, attributeName: string, chunkBitSize: number, commGensId: string, encryptionKeyId: string, snarkPkId: string, commGens?: SaverChunkedCommitmentGens | SaverChunkedCommitmentGensUncompressed, encryptionKey?: SaverEncryptionKey | SaverEncryptionKeyUncompressed, snarkPk?: SaverProvingKey | SaverProvingKeyUncompressed) {
    if ((chunkBitSize !== 8) && (chunkBitSize !== 16)) {
      throw new Error(`Only 8 and 16 supported for chunkBitSize but given ${chunkBitSize}`);
    }
    this.validateCredIndex(credIdx);
    let v = this.verifEnc.get(credIdx);
    if (v !== undefined) {
      if (v.get(attributeName) !== undefined) {
        throw new Error(`Already enforced verifiable encryption on credential index ${credIdx} and attribute name ${attributeName}`);
      }
    } else {
      v = new Map();
    }

    this.updatePredicateParams(commGensId, commGens);
    this.updatePredicateParams(encryptionKeyId, encryptionKey);
    this.updatePredicateParams(snarkPkId, snarkPk);
    v.set(attributeName, [chunkBitSize, commGensId, encryptionKeyId, snarkPkId]);
    this.verifEnc.set(credIdx, v);
  }

  finalize(): Presentation {
    const numCreds = this.credentials.length;
    let maxAttribs = 2; // version and schema
    let sigParams = SignatureParamsG1.generate(maxAttribs, SIGNATURE_PARAMS_LABEL_BYTES);

    const statements = new Statements();
    const metaStatements = new MetaStatements();
    const witnesses = new Witnesses();

    const flattenedSchemas: [string[], unknown[]][] = [];

    // Store only needed encoded values of names and their indices. Maps cred index -> attribute index in schema -> attr value
    const unrevealedMsgsEncoded = new Map<number, Map<number, Uint8Array>>();

    // For credentials with status, i.e. using accumulators, type is [credIndex, revCheckType, encoded (non)member]
    const credStatusAux: [number, string, Uint8Array][] = [];

    // Create statements and witnesses for proving possession of each credential, i.e. proof of knowledge of BBS+ sigs
    for (let i = 0; i < numCreds; i++) {
      const cred = this.credentials[i][0];
      const schema = cred.schema as CredentialSchema;
      const flattenedSchema = schema.flatten();
      const numAttribs = flattenedSchema[0].length;
      if (maxAttribs < numAttribs) {
        sigParams.adapt(numAttribs);
        maxAttribs = numAttribs;
      }
      let revealedNames = this.revealedAttributes.get(i);
      if (revealedNames === undefined) {
        revealedNames = new Set();
      }

      // Credential version, schema and 2 fields of revocation - registry id (denoting the accumulator) and the check
      // type, i.e. "membership" or "non-membership" are always revealed.
      revealedNames.add(CRED_VERSION_STR);
      revealedNames.add(SCHEMA_STR);
      if (cred.credStatus !== undefined) {
        // TODO: Input validation
        revealedNames.add(`${STATUS_STR}.${REGISTRY_ID_STR}`);
        revealedNames.add(`${STATUS_STR}.${REV_CHECK_STR}`);
      }

      const [revealedMsgs, unrevealedMsgs, revealedMsgsRaw] = getRevealedAndUnrevealed(
        cred.serializeForSigning(),
        revealedNames,
        schema.encoder
      );
      const statement = Statement.bbsSignature(
        sigParams.adapt(numAttribs),
        this.credentials[i][1],
        revealedMsgs,
        false
      );
      const witness = Witness.bbsSignature(cred.signature as SignatureG1, unrevealedMsgs, false);
      statements.add(statement);
      witnesses.add(witness);

      let presentedStatus: object | undefined;
      if (cred.credStatus !== undefined) {
        presentedStatus = {};
        presentedStatus[REGISTRY_ID_STR] = cred.credStatus[REGISTRY_ID_STR];
        presentedStatus[REV_CHECK_STR] = cred.credStatus[REV_CHECK_STR];
        const s = this.credStatuses.get(i);
        if (s === undefined) {
          throw new Error(`No status details found for credential index ${i}`);
        }
        presentedStatus['accumulated'] = s[1];
        presentedStatus['extra'] = s[3];
        credStatusAux.push([
          i,
          cred.credStatus[REV_CHECK_STR],
          schema.encoder.encodeMessage(`${STATUS_STR}.${REV_ID_STR}`, cred.credStatus[REV_ID_STR])
        ]);
      }

      let attributeBounds: object | undefined;
      const bounds = this.bounds.get(i);
      if (bounds !== undefined && bounds.size > 0) {
        attributeBounds = {};
        const encodedAttrs = new Map<number, Uint8Array>();
        for (const [name, [min, max, paramId]] of bounds.entries()) {
          attributeBounds[name] = {min, max, paramId};
          const nameIdx = flattenedSchema[0].indexOf(`${SUBJECT_STR}.${name}`);
          encodedAttrs.set(nameIdx, unrevealedMsgs.get(nameIdx) as Uint8Array);
        }
        attributeBounds = unflatten(attributeBounds);
        unrevealedMsgsEncoded.set(i, encodedAttrs)
      }

      this.spec.addPresentedCredential(
        revealedMsgsRaw[CRED_VERSION_STR],
        revealedMsgsRaw[SCHEMA_STR],
        cred.issuerPubKey as StringOrObject,
        revealedMsgsRaw[SUBJECT_STR],
        presentedStatus,
        attributeBounds
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
      let statement, witness;
      if (t === MEM_CHECK_STR) {
        if (!(wit instanceof MembershipWitness)) {
          throw new Error(`Expected membership witness but got non-membership witness for credential index ${i}`);
        }
        statement = Statement.accumulatorMembership(dockAccumulatorParams(), pk, dockAccumulatorMemProvingKey(), acc);
        witness = Witness.accumulatorMembership(value, wit);
      } else {
        if (!(wit instanceof NonMembershipWitness)) {
          throw new Error(`Expected non-membership witness but got membership witness for credential index ${i}`);
        }
        statement = Statement.accumulatorNonMembership(
          dockAccumulatorParams(),
          pk,
          dockAccumulatorNonMemProvingKey(),
          acc
        );
        witness = Witness.accumulatorNonMembership(value, wit);
      }
      const sIdx = statements.add(statement);
      witnesses.add(witness);

      const witnessEq = new WitnessEqualityMetaStatement();
      witnessEq.addWitnessRef(i, flattenedSchemas[i][0].indexOf(`${STATUS_STR}.${REV_ID_STR}`));
      witnessEq.addWitnessRef(sIdx, 0);
      metaStatements.addWitnessEquality(witnessEq);
    });

    // For enforcing attribute equalities
    for (const eql of this.attributeEqualities) {
      const witnessEq = new WitnessEqualityMetaStatement();
      for (const [cIdx, name] of eql) {
        const i = flattenedSchemas[cIdx][0].indexOf(`${SUBJECT_STR}.${name}`);
        if (i === -1) {
          throw new Error(`Attribute name ${name} was not found`);
        }
        witnessEq.addWitnessRef(cIdx, i);
      }
      metaStatements.addWitnessEquality(witnessEq);
      this.spec.attributeEqualities.push(eql);
    }

    // For enforcing attribute bounds
    for (const [cId, bounds] of this.bounds.entries()) {
      const dataSortedByNameIdx: [number, string, number, number, string][] = [];
      for (const [name, [min, max, paramId]] of bounds.entries()) {
        const qualifiedName = `${SUBJECT_STR}.${name}`;
        const nameIdx = flattenedSchemas[cId][0].indexOf(qualifiedName);
        dataSortedByNameIdx.push([nameIdx, name, min, max, paramId]);
      }
      dataSortedByNameIdx.sort(function(a, b) {
        return a[0] - b[0];
      });
      dataSortedByNameIdx.forEach(([nameIdx, name, min, max, paramId]) => {
        const param = this.predicateParams.get(paramId);
        const typ = flattenedSchemas[cId][1][nameIdx] as object;
        let statement, transformedMin, transformedMax;
        switch (typ['type']) {
          case CredentialSchema.POSITIVE_INT_TYPE:
            transformedMin = min;
            transformedMax = max;
            break;
          case CredentialSchema.INT_TYPE:
            transformedMin = Encoder.integerToPositiveInt(typ['minimum'])(min);
            transformedMax = Encoder.integerToPositiveInt(typ['minimum'])(max);
            break;
          case CredentialSchema.POSITIVE_NUM_TYPE:
            transformedMin = Encoder.positiveDecimalNumberToPositiveInt(typ['decimalPlaces'])(min);
            transformedMax = Encoder.positiveDecimalNumberToPositiveInt(typ['decimalPlaces'])(max);
            break;
          case CredentialSchema.NUM_TYPE:
            transformedMin = Encoder.decimalNumberToPositiveInt(typ['minimum'], typ['decimalPlaces'])(min);
            transformedMax = Encoder.decimalNumberToPositiveInt(typ['minimum'], typ['decimalPlaces'])(max);
            break;
          default:
            throw new Error(`${name} should be of numeric type as per schema but was ${flattenedSchemas[cId][1][nameIdx]}`)
        }

        if (param instanceof LegoProvingKey) {
          statement = Statement.boundCheckProverFromCompressedParams(transformedMin, transformedMax, param);
        } else if (param instanceof LegoProvingKeyUncompressed) {
          statement = Statement.boundCheckProver(transformedMin, transformedMax, param);
        } else {
          throw new Error(`Predicate param id ${paramId} was expected to be a Legosnark proving key but was ${param}`);
        }

        const encodedAttrVal = unrevealedMsgsEncoded.get(cId)?.get(nameIdx) as Uint8Array;
        witnesses.add(Witness.boundCheckLegoGroth16(encodedAttrVal));

        const sIdx = statements.add(statement);
        const witnessEq = new WitnessEqualityMetaStatement();
        witnessEq.addWitnessRef(cId, nameIdx);
        witnessEq.addWitnessRef(sIdx, 0);
        metaStatements.addWitnessEquality(witnessEq);
      });
    }

    // TODO: Include version and spec in context
    this._proofSpec = new QuasiProofSpecG1(statements, metaStatements, [], this._context);
    this.proof = CompositeProofG1.generateUsingQuasiProofSpec(this._proofSpec, witnesses, this._nonce);
    return new Presentation(this.version, this.spec, this.proof, this._context, this._nonce);
  }

  get context(): Uint8Array | undefined {
    return this._context;
  }

  // TODO: Context can be string as well.
  set context(context: Uint8Array | undefined) {
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

  toJSON(): string {
    // TODO:
    return JSON.stringify({
      version: this.version,
      context: this._context ? b58.encode(this._context) : null,
      nonce: this._nonce ? b58.encode(this._nonce) : null,
      spec: this.spec.forPresentation(),
      proof: b58.encode((this.proof as CompositeProofG1).bytes)
    });
  }

  private updatePredicateParams(id: string, val?: PredicateParamType) {
    if (val !== undefined) {
      if (this.predicateParams.has(id)) {
        throw new Error(`Predicate params already exists for id ${id}`)
      }
      this.predicateParams.set(id, val);
    }
  }
}
