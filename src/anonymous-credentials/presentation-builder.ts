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
import { CredentialSchema, ValueType } from './schema';
import { getRevealedAndUnrevealed } from '../sign-verify-js-objs';
import {
  AttributeEquality,
  CRED_VERSION_STR,
  FlattenedSchema,
  MEM_CHECK_STR, NON_MEM_CHECK_STR,
  PredicateParamType,
  REGISTRY_ID_STR,
  REV_CHECK_STR,
  REV_ID_STR,
  SCHEMA_STR,
  SIGNATURE_PARAMS_LABEL_BYTES,
  STATUS_STR,
  StringOrObject
} from './types-and-consts';
import {
  IPresentedAttributeBounds,
  IPresentedAttributeVE,
  IPresentedStatus,
  PresentationSpecification
} from './presentation-specification';
import b58 from 'bs58';
import { Presentation } from './presentation';
import { AccumulatorPublicKey, AccumulatorWitness, MembershipWitness, NonMembershipWitness } from '../accumulator';
import {
  buildContextForProof, createWitEq,
  dockAccumulatorMemProvingKey,
  dockAccumulatorNonMemProvingKey,
  dockAccumulatorParams,
  dockSaverEncryptionGens,
  dockSaverEncryptionGensUncompressed, getTransformedMinMax
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

export class PresentationBuilder extends Versioned {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.0.1';

  _context?: string | Uint8Array;
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

  // TODO: Since all attr names below will have the full name (incl. top level attrib, check that no predicate on revealed attrs)

  // NOTE: This and several methods below expect nested attributes names with "dot"s as separators. Passing the nested structure is also
  // possible but will need more parsing and thus can be handled later.
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
    b.set(attributeName, [min, max, provingKeyId]);
    this.bounds.set(credIdx, b);
  }

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
    v.set(attributeName, [chunkBitSize, commGensId, encryptionKeyId, snarkPkId]);
    this.verifEnc.set(credIdx, v);
  }

  // TODO: This can be made more efficient (mostly saving serialization cost) by using `SetupParams`s. Repeated use of the
  //  same param id can be detected and then finally `SetupParams`s can be created for them.
  /**
   * Create a presentation
   */
  finalize(): Presentation {
    const numCreds = this.credentials.length;
    let maxAttribs = 2; // version and schema
    let sigParams = SignatureParamsG1.generate(maxAttribs, SIGNATURE_PARAMS_LABEL_BYTES);

    const statements = new Statements();
    const metaStatements = new MetaStatements();
    const witnesses = new Witnesses();

    const flattenedSchemas: FlattenedSchema[] = [];

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
        sigParams = sigParams.adapt(numAttribs);
        maxAttribs = numAttribs;
      }
      let revealedNames = this.revealedAttributes.get(i);
      if (revealedNames === undefined) {
        revealedNames = new Set();
      }

      // CredentialBuilder version, schema and 2 fields of revocation - registry id (denoting the accumulator) and the check
      // type, i.e. "membership" or "non-membership" are always revealed.
      revealedNames.add(CRED_VERSION_STR);
      revealedNames.add(SCHEMA_STR);
      if (cred.credentialStatus !== undefined) {
        if (cred.credentialStatus[REGISTRY_ID_STR] === undefined || (cred.credentialStatus[REV_CHECK_STR] !== MEM_CHECK_STR && cred.credentialStatus[REV_CHECK_STR] !== NON_MEM_CHECK_STR)) {
          throw new Error(`Credential for ${i} has invalid status ${cred.credentialStatus}`)
        }
        revealedNames.add(`${STATUS_STR}.${REGISTRY_ID_STR}`);
        revealedNames.add(`${STATUS_STR}.${REV_CHECK_STR}`);
      }

      const [revealedAttrsEncoded, unrevealedAttrsEncoded, revealedAtts] = getRevealedAndUnrevealed(
        cred.serializeForSigning(),
        revealedNames,
        schema.encoder
      );
      const statement = Statement.bbsSignature(
        sigParams.adapt(numAttribs),
        this.credentials[i][1],
        revealedAttrsEncoded,
        false
      );
      const witness = Witness.bbsSignature(cred.signature as SignatureG1, unrevealedAttrsEncoded, false);
      statements.add(statement);
      witnesses.add(witness);

      let presentedStatus: IPresentedStatus | undefined;
      if (cred.credentialStatus !== undefined) {
        const s = this.credStatuses.get(i);
        if (s === undefined) {
          throw new Error(`No status details found for credential index ${i}`);
        }
        presentedStatus = {
          [REGISTRY_ID_STR]: cred.credentialStatus[REGISTRY_ID_STR],
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

      let attributeBounds: { [key: string]: string | IPresentedAttributeBounds } | undefined;
      const bounds = this.bounds.get(i);
      if (bounds !== undefined && bounds.size > 0) {
        attributeBounds = {};
        const encodedAttrs = unrevealedMsgsEncoded.get(i) || new Map<number, Uint8Array>();
        for (const [name, [min, max, paramId]] of bounds.entries()) {
          attributeBounds[name] = { min, max, paramId };
          const nameIdx = flattenedSchema[0].indexOf(name);
          encodedAttrs.set(nameIdx, unrevealedAttrsEncoded.get(nameIdx) as Uint8Array);
        }
        attributeBounds = unflatten(attributeBounds);
        unrevealedMsgsEncoded.set(i, encodedAttrs);
      }

      let attributeEncs: { [key: string]: string | IPresentedAttributeVE } | undefined;
      const encs = this.verifEnc.get(i);
      if (encs !== undefined && encs.size > 0) {
        attributeEncs = {};
        const encodedAttrs = unrevealedMsgsEncoded.get(i) || new Map<number, Uint8Array>();
        for (const [name, [chunkBitSize, commGenId, encId, pkId]] of encs.entries()) {
          const nameIdx = flattenedSchema[0].indexOf(name);
          const valTyp = schema.typeOfName(name, flattenedSchema);
          if (valTyp.type !== ValueType.RevStr) {
            throw new Error(
              `Attribute name ${name} of credential index ${i} should be a reversible string type but was ${valTyp}`
            );
          }
          attributeEncs[name] = { chunkBitSize, commitmentGensId: commGenId, encryptionKeyId: encId, snarkKeyId: pkId };
          encodedAttrs.set(nameIdx, unrevealedAttrsEncoded.get(nameIdx) as Uint8Array);
        }
        attributeEncs = unflatten(attributeEncs);
        unrevealedMsgsEncoded.set(i, encodedAttrs);
      }

      const ver = revealedAtts[CRED_VERSION_STR];
      const sch = revealedAtts[SCHEMA_STR];
      delete revealedAtts[CRED_VERSION_STR];
      delete revealedAtts[SCHEMA_STR];
      delete revealedAtts[STATUS_STR];
      this.spec.addPresentedCredential(
        ver,
        sch,
        revealedAtts,
        presentedStatus,
        attributeBounds,
        attributeEncs
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
      metaStatements.addWitnessEquality(createWitEq(eql, flattenedSchemas));
      this.spec.attributeEqualities.push(eql);
    }

    // For enforcing attribute bounds
    for (const [cId, bounds] of this.bounds.entries()) {
      const dataSortedByNameIdx: [number, string, number, number, string][] = [];
      for (const [name, [min, max, paramId]] of bounds.entries()) {
        const nameIdx = flattenedSchemas[cId][0].indexOf(name);
        dataSortedByNameIdx.push([nameIdx, name, min, max, paramId]);
      }
      dataSortedByNameIdx.sort(function (a, b) {
        return a[0] - b[0];
      });
      dataSortedByNameIdx.forEach(([nameIdx, name, min, max, paramId]) => {
        let statement;
        const valTyp = CredentialSchema.typeOfName(name, flattenedSchemas[cId]);
        const [transformedMin, transformedMax] = getTransformedMinMax(valTyp, min, max);

        const param = this.predicateParams.get(paramId);
        if (param instanceof LegoProvingKey) {
          statement = Statement.boundCheckProverFromCompressedParams(transformedMin, transformedMax, param);
        } else if (param instanceof LegoProvingKeyUncompressed) {
          statement = Statement.boundCheckProver(transformedMin, transformedMax, param);
        } else {
          throw new Error(
            `Predicate param id ${paramId} (for credential index ${cId}) was expected to be a Legosnark proving key but was ${param}`
          );
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

    // For adding ciphertexts corresponding to verifiably encrypted attributes in the presentation
    const credAttrToSId = new Map<number, Map<string, number>>();

    // For enforcing attribute encryption
    for (const [cId, verEnc] of this.verifEnc.entries()) {
      const dataSortedByNameIdx: [number, string, number, string, string, string][] = [];
      for (const [name, [chunkBitSize, commGensId, encKeyId, snarkPkId]] of verEnc.entries()) {
        const nameIdx = flattenedSchemas[cId][0].indexOf(name);
        dataSortedByNameIdx.push([nameIdx, name, chunkBitSize, commGensId, encKeyId, snarkPkId]);
      }
      dataSortedByNameIdx.sort(function (a, b) {
        return a[0] - b[0];
      });
      const attrToSid = new Map<string, number>();
      dataSortedByNameIdx.forEach(([nameIdx, name, chunkBitSize, commGensId, encKeyId, snarkPkId]) => {
        const commGens = this.predicateParams.get(commGensId);
        if (commGens === undefined) {
          throw new Error(`Predicate param id ${commGensId} not found`);
        }
        const encKey = this.predicateParams.get(encKeyId);
        if (encKey === undefined) {
          throw new Error(`Predicate param id ${encKeyId} not found`);
        }
        const snarkPk = this.predicateParams.get(snarkPkId);
        if (snarkPk === undefined) {
          throw new Error(`Predicate param id ${snarkPkId} not found`);
        }
        let statement;
        if (
          commGens instanceof SaverChunkedCommitmentGensUncompressed &&
          encKey instanceof SaverEncryptionKeyUncompressed &&
          snarkPk instanceof SaverProvingKeyUncompressed
        ) {
          statement = Statement.saverProver(
            dockSaverEncryptionGensUncompressed(),
            commGens,
            encKey,
            snarkPk,
            chunkBitSize
          );
        } else if (
          commGens instanceof SaverChunkedCommitmentGens &&
          encKey instanceof SaverEncryptionKey &&
          snarkPk instanceof SaverProvingKey
        ) {
          statement = Statement.saverProverFromCompressedParams(
            dockSaverEncryptionGens(),
            commGens,
            encKey,
            snarkPk,
            chunkBitSize
          );
        } else {
          throw new Error('All SAVER parameters should either be compressed in uncompressed');
        }

        const encodedAttrVal = unrevealedMsgsEncoded.get(cId)?.get(nameIdx) as Uint8Array;
        witnesses.add(Witness.saver(encodedAttrVal));

        const sIdx = statements.add(statement);
        const witnessEq = new WitnessEqualityMetaStatement();
        witnessEq.addWitnessRef(cId, nameIdx);
        witnessEq.addWitnessRef(sIdx, 0);
        metaStatements.addWitnessEquality(witnessEq);
        attrToSid.set(name, sIdx);
      });
      if (attrToSid.size > 0) {
        credAttrToSId.set(cId, attrToSid);
      }
    }

    // The version and spec are also added to the proof thus binding these to the proof cryptographically.
    const ctx = buildContextForProof(this.version, this.spec, this._context);
    this._proofSpec = new QuasiProofSpecG1(statements, metaStatements, [], ctx);
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

  get context(): string | Uint8Array | undefined {
    return this._context;
  }

  set context(context: string | Uint8Array | undefined) {
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
      context: this._context ? (typeof this._context === 'string' ? this._context : b58.encode(this._context)) : null,
      nonce: this._nonce ? b58.encode(this._nonce) : null,
      spec: {
        credentials: this.spec.credentials,
        attributeEqualities: this.spec.attributeEqualities
      },
      proof: b58.encode((this.proof as CompositeProofG1).bytes)
    });
  }

  private updatePredicateParams(id: string, val?: PredicateParamType) {
    if (val !== undefined) {
      if (this.predicateParams.has(id)) {
        throw new Error(`Predicate params already exists for id ${id}`);
      }
      this.predicateParams.set(id, val);
    }
  }
}
