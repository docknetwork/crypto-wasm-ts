import { BBSPlusPublicKeyG2, BBSPlusSecretKey, SignatureG1 } from '../bbs-plus';
import { signMessageObject, verifyMessageObject } from '../sign-verify-js-objs';
import { VerifyResult } from '@docknetwork/crypto-wasm';
import { Versioned } from './versioned';
import { CredentialSchema } from './schema';
import {
  CRED_VERSION_STR,
  MEM_CHECK_STR,
  NON_MEM_CHECK_STR,
  REGISTRY_ID_STR,
  REV_CHECK_STR,
  REV_ID_STR,
  SCHEMA_STR,
  SIGNATURE_PARAMS_LABEL_BYTES,
  STATUS_STR,
  StringOrObject,
  SUBJECT_STR
} from './types-and-consts';
import { Credential } from './credential';

export class CredentialBuilder extends Versioned {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.0.1';

  // Each credential references the schema which is included as an attribute
  _schema?: CredentialSchema;
  _subject?: object | object[];
  _credStatus?: object;
  // TODO: Remove
  _issuerPubKey?: StringOrObject;
  _encodedAttributes?: { [key: string]: Uint8Array };
  _topLevelFields: Map<string, unknown>;
  _sig?: SignatureG1;

  constructor() {
    super(CredentialBuilder.VERSION);
    this._topLevelFields = new Map();
  }

  /**
   * Currently supports only 1 subject. Nothing tricky in supporting more but more parsing and serialization work
   * @param subject
   */
  set subject(subject: object | object[]) {
    this._subject = subject;
  }

  // @ts-ignore
  get subject(): object | object[] | undefined {
    return this._subject;
  }

  set schema(schema: CredentialSchema) {
    this._schema = schema;
  }

  // @ts-ignore
  get schema(): CredentialSchema | undefined {
    return this._schema;
  }

  set issuerPubKey(issuer: StringOrObject) {
    this._issuerPubKey = issuer;
  }

  // @ts-ignore
  get issuerPubKey(): StringOrObject | undefined {
    return this._issuerPubKey;
  }

  get credStatus(): object | undefined {
    return this._credStatus;
  }

  setCredentialStatus(registryId: string, revCheck: string, memberValue: unknown) {
    if (revCheck !== MEM_CHECK_STR && revCheck !== NON_MEM_CHECK_STR) {
      throw new Error(`Revocation check should be either ${MEM_CHECK_STR} or ${NON_MEM_CHECK_STR} but was ${revCheck}`);
    }
    this._credStatus = {
      [REGISTRY_ID_STR]: registryId,
      [REV_CHECK_STR]: revCheck,
      [REV_ID_STR]: memberValue
    };
  }

  get signature(): SignatureG1 | undefined {
    return this._sig;
  }

  setTopLevelField(name: string, value: unknown) {
    this._topLevelFields.set(name, value);
  }

  getTopLevelField(name: string): unknown {
    const v = this._topLevelFields.get(name);
    if (v === undefined) {
      throw new Error(`Top level field ${name} is absent`);
    }
    return v;
  }

  sign(secretKey: BBSPlusSecretKey): Credential {
    const cred = this.serializeForSigning();
    const schema = this._schema as CredentialSchema;
    const signed = signMessageObject(cred, secretKey, SIGNATURE_PARAMS_LABEL_BYTES, schema.encoder);
    this._encodedAttributes = signed.encodedMessages;
    this._sig = signed.signature;
    return new Credential(
      this._version,
      schema,
      // @ts-ignore
      this._subject,
      this.issuerPubKey,
      this._topLevelFields,
      this._sig,
      this._credStatus
    );
  }

  // TODO: Set schema and validate that no reserved names are used, subject, status is as per schema, revocation check is either membership or non-membership, etc

  serializeForSigning() {
    // Schema should be part of the credential signature to prevent the credential holder from convincing a verifier of a manipulated schema
    const s = {
      [CRED_VERSION_STR]: this._version,
      [SCHEMA_STR]: this._schema?.toJSON(),
      [SUBJECT_STR]: this._subject
    };
    for (const [k, v] of this._topLevelFields.entries()) {
      s[k] = v;
    }
    if (this._credStatus !== undefined) {
      s[STATUS_STR] = this._credStatus;
    }
    return s;
  }
}
