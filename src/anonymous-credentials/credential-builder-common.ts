import { Versioned } from './versioned';
import { CredentialSchema } from './schema';
import {
  CRYPTO_VERSION_STR,
  ID_STR,
  MEM_CHECK_STR,
  NON_MEM_CHECK_STR,
  RevocationStatusProtocols,
  REV_CHECK_STR,
  REV_ID_STR,
  SCHEMA_STR,
  STATUS_STR,
  SUBJECT_STR,
  TYPE_STR
} from './types-and-consts';

/**
 * Common fields and methods of `CredentialBuilder` and `BlindedCredentialBuilder`
 */
export abstract class CredentialBuilderCommon extends Versioned {
  // Each credential references the schema which is included as an attribute
  _schema?: CredentialSchema;
  _subject?: object | object[];
  _credStatus?: object;
  _topLevelFields: Map<string, unknown>;

  constructor(version: string) {
    super(version);
    this._topLevelFields = new Map();
  }

  set schema(schema: CredentialSchema) {
    this._schema = schema;
  }

  // @ts-ignore
  get schema(): CredentialSchema | undefined {
    return this._schema;
  }

  /**
   * Add single or an array of subjects.
   * @param subject
   */
  set subject(subject: object | object[]) {
    this._subject = subject;
  }

  // @ts-ignore
  get subject(): object | object[] | undefined {
    return this._subject;
  }

  set credStatus(subject: object | undefined) {
    this._credStatus = subject;
  }

  get credStatus(): object | undefined {
    return this._credStatus;
  }

  setCredentialStatus(registryId: string, revCheck: string, memberValue: unknown) {
    if (revCheck !== MEM_CHECK_STR && revCheck !== NON_MEM_CHECK_STR) {
      throw new Error(`Revocation check should be either ${MEM_CHECK_STR} or ${NON_MEM_CHECK_STR} but was ${revCheck}`);
    }
    this._credStatus = {
      [TYPE_STR]: RevocationStatusProtocols.Vb22,
      [ID_STR]: registryId,
      [REV_CHECK_STR]: revCheck,
      [REV_ID_STR]: memberValue
    };
  }

  setTopLevelField(name: string, value: unknown) {
    if (value !== undefined) {
      this._topLevelFields.set(name, value);
    }
  }

  getTopLevelField(name: string): unknown {
    const v = this._topLevelFields.get(name);
    if (v === undefined) {
      throw new Error(`Top level field ${name} is absent`);
    }
    return v;
  }

  serializeForSigning(): object {
    // Schema should be part of the credential signature to prevent the credential holder from convincing a verifier of a manipulated schema
    const s = {
      [CRYPTO_VERSION_STR]: this._version,
      [SCHEMA_STR]: this.schema?.toJsonString(),
      [SUBJECT_STR]: this._subject
    };
    for (const [k, v] of this._topLevelFields.entries()) {
      s[k] = v;
    }
    if (this._credStatus !== undefined) {
      s[STATUS_STR] = this._credStatus;
    }

    this.applyDefaultProofMetadataIfNeeded(s);
    return s;
  }

  /**
   * Update given object with proof metadata
   * @param s - the object that be updated with the proof metadata
   * @protected
   */
  protected abstract applyDefaultProofMetadataIfNeeded(s: object);
}
