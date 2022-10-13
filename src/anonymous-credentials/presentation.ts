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
import { BBSPlusPublicKeyG2, SignatureParamsG1 } from '../bbs-plus';
import { CredentialSchema } from './schema';
import { VerifyResult } from '@docknetwork/crypto-wasm';
import { flatten } from 'flat';
import {
  CRED_VERSION_STR,
  MEM_CHECK_STR,
  REGISTRY_ID_STR,
  REV_CHECK_STR,
  REV_ID_STR,
  SCHEMA_STR,
  SIGNATURE_PARAMS_LABEL_BYTES,
  STATUS_STR,
  SUBJECT_STR
} from './types-and-consts';
import { AccumulatorPublicKey } from '../accumulator';
import { dockAccumulatorMemProvingKey, dockAccumulatorNonMemProvingKey, dockAccumulatorParams } from './util';

export class Presentation extends Versioned {
  spec: PresentationSpecification;
  proof: CompositeProofG1;
  context?: Uint8Array;
  nonce?: Uint8Array;

  constructor(
    version: string,
    spec: PresentationSpecification,
    proof: CompositeProofG1,
    context?: Uint8Array,
    nonce?: Uint8Array
  ) {
    super(version);
    this.spec = spec;
    this.proof = proof;
    this.context = context;
    this.nonce = nonce;
  }

  // TODO: This can be improved, figure out to use `SetupParams`
  verify(
    publicKeys: BBSPlusPublicKeyG2[],
    accumulatorValueAndPublicKeys?: Map<number, [Uint8Array, AccumulatorPublicKey]>
  ): VerifyResult {
    const numCreds = this.spec.credentials.length;
    if (publicKeys.length != numCreds) {
      throw new Error(`Supply same no of public keys as creds. ${publicKeys.length} != ${numCreds}`);
    }

    let maxAttribs = 2; // version and schema
    let sigParams = SignatureParamsG1.generate(maxAttribs, SIGNATURE_PARAMS_LABEL_BYTES);

    const statements = new Statements();
    const metaStatements = new MetaStatements();

    const flattenedSchemas: [string[], unknown[]][] = [];

    // For credentials with status, i.e. using accumulators, type is [credIndex, revCheckType, accumulator]
    const credStatusAux: [number, string, Uint8Array][] = [];

    for (let i = 0; i < this.spec.credentials.length; i++) {
      const presentedCred = this.spec.credentials[i];
      const presentedCredSchema = CredentialSchema.fromJSON(presentedCred.schema);
      const flattenedSchema = presentedCredSchema.flatten();
      const numAttribs = flattenedSchema[0].length;

      const revealedEncoded = Presentation.encodeRevealed(presentedCred, presentedCredSchema, flattenedSchema[0]);

      if (maxAttribs < numAttribs) {
        sigParams.adapt(numAttribs);
        maxAttribs = numAttribs;
      }
      const statement = Statement.bbsSignature(sigParams.adapt(numAttribs), publicKeys[i], revealedEncoded, false);
      statements.add(statement);
      flattenedSchemas.push(flattenedSchema);
      if (presentedCred.status !== undefined) {
        // TODO: Input validation
        credStatusAux.push([i, presentedCred.status[REV_CHECK_STR], presentedCred.status['accumulated']]);
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
        const i = flattenedSchemas[cIdx][0].indexOf(`${SUBJECT_STR}.${name}`);
        if (i === -1) {
          throw new Error(`Attribute name ${name} was not found`);
        }
        witnessEq.addWitnessRef(cIdx, i);
      }
      metaStatements.addWitnessEquality(witnessEq);
    }

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
    const revealedRaw = {};
    revealedRaw[CRED_VERSION_STR] = presentedCred.version;
    revealedRaw[SCHEMA_STR] = presentedCred.schema;
    revealedRaw[SUBJECT_STR] = presentedCred.revealedAttributes;
    if (presentedCred.status !== undefined) {
      // TODO: Check that keys present in `presentedCred`
      revealedRaw[`${STATUS_STR}.${REGISTRY_ID_STR}`] = presentedCred.status[REGISTRY_ID_STR];
      revealedRaw[`${STATUS_STR}.${REV_CHECK_STR}`] = presentedCred.status[REV_CHECK_STR];
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
