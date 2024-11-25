import semver from 'semver/preload';
import { Versioned } from './versioned';
import { CredentialSchema } from './schema';
import { PROOF_STR, SCHEMA_STR, STATUS_STR, SUBJECT_STR } from './types-and-consts';
import b58 from 'bs58';
import { isEmptyObject } from '../util';

/**
 * Common fields and methods of Credential and BlindedCredential
 */
export abstract class CredentialCommon<Sig> extends Versioned {
  /** Each credential references the schema which is included as an attribute */
  readonly schema: CredentialSchema;
  readonly subject: object | object[];
  readonly credentialStatus?: object;
  readonly topLevelFields: Map<string, unknown>;
  readonly signature: Sig;

  constructor(
    version: string,
    schema: CredentialSchema,
    subject: object,
    topLevelFields: Map<string, unknown>,
    sig: Sig,
    credStatus?: object
  ) {
    super(version);
    this.schema = schema;
    this.subject = subject;
    this.topLevelFields = topLevelFields;
    this.signature = sig;
    this.credentialStatus = credStatus;
  }

  getTopLevelField(name: string): unknown {
    const v = this.topLevelFields.get(name);
    if (v === undefined) {
      throw new Error(`Top level field ${name} is absent`);
    }
    return v;
  }

  toJSON(): object {
    const j = {};
    const schema = semver.gte(this.version, '0.6.0') ? this.schema.toJSON() : this.schema.toJsonString();
    j['cryptoVersion'] = this.version;
    j[SCHEMA_STR] = schema;
    j[SUBJECT_STR] = this.subject;
    if (this.credentialStatus !== undefined) {
      j[STATUS_STR] = this.credentialStatus;
    }
    for (const [k, v] of this.topLevelFields.entries()) {
      j[k] = v;
    }

    (this.constructor as typeof CredentialCommon).applyDefaultProofMetadataIfNeeded(j);
    j[PROOF_STR]['proofValue'] = b58.encode((this.signature as any).bytes);
    return j;
  }

  protected static parseJSON(
    j: object,
    proofValue?: string
  ): [string, CredentialSchema, object, Map<string, unknown>, Uint8Array, object] {
    // @ts-ignore
    const { cryptoVersion, credentialSchema, credentialSubject, credentialStatus, proof, ...custom } = j;

    // Ensure proof is present
    if (!proof) {
      throw new Error(`Expects proof to be defined in object`);
    }

    this.validateProofType(proof['type']);

    // Ensure we trim off proofValue as that isn't signed
    const trimmedProof = { ...proof };
    if (!proofValue) {
      if (trimmedProof && trimmedProof.proofValue) {
        proofValue = trimmedProof.proofValue;
        delete trimmedProof.proofValue;
      } else {
        throw new Error('A proofValue was neither provided nor was provided');
      }
    }

    const sig = b58.decode(proofValue as string);
    const topLevelFields = new Map<string, unknown>();
    Object.keys(custom).forEach((k) => {
      topLevelFields.set(k, custom[k]);
    });

    // Note: There is some inconsistency here. While serialization "proof" doesn't exist in `topLevelFields` but during
    // deserialization, it is. This doesn't break anything for now but can cause unexpected errors in future as the
    // deserialized object won't be exactly same as the object that was serialized.
    if (!isEmptyObject(trimmedProof)) {
      topLevelFields.set(PROOF_STR, trimmedProof);
    }

    return [
      cryptoVersion,
      CredentialSchema.fromJSON(typeof credentialSchema === 'string' ? JSON.parse(credentialSchema) : credentialSchema),
      credentialSubject,
      topLevelFields,
      sig,
      credentialStatus
    ];
  }

  /**
   * A credential will have at least some proof metadata like the type or purpose. This adds those defaults to the
   * given object.
   * @param _s
   */
  static applyDefaultProofMetadataIfNeeded(_s: object) {}

  protected static validateProofType(_typ: string) {}
}
