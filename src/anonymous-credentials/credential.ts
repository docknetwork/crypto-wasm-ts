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
  SCHEMA_STR, SIGNATURE_PARAMS_LABEL_BYTES,
  STATUS_STR,
  StringOrObject,
  SUBJECT_STR
} from './types-and-consts';
import b58 from 'bs58';

export class Credential extends Versioned {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.0.1';

  // Each credential references the schema which is included as an attribute
  _schema?: CredentialSchema;
  _subject?: object;
  _credStatus?: object;
  _issuerPubKey?: StringOrObject;
  _encodedSubject?: { [key: string]: Uint8Array };
  _sig?: SignatureG1;

  constructor() {
    super(Credential.VERSION);
  }

  /**
   * Currently supports only 1 subject. Nothing tricky in supporting more but more parsing and serialization work
   * @param subject
   */
  set subject(subject: object) {
    this._subject = subject;
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

  setCredentialStatus(registryId: string, revCheck: string, memberName: string, memberValue: unknown) {
    if (revCheck !== MEM_CHECK_STR && revCheck !== NON_MEM_CHECK_STR) {
      throw new Error(`Revocation check should be either ${MEM_CHECK_STR} or ${NON_MEM_CHECK_STR} but was ${revCheck}`);
    }
    this._credStatus = {};
    this._credStatus[REGISTRY_ID_STR] = registryId;
    this._credStatus[REV_CHECK_STR] = revCheck;
    this._credStatus[memberName] = memberValue;
  }

  get signature(): SignatureG1 | undefined {
    return this._sig;
  }

  sign(secretKey: BBSPlusSecretKey) {
    const cred = this.serializeForSigning();
    const signed = signMessageObject(
      cred,
      secretKey,
      SIGNATURE_PARAMS_LABEL_BYTES,
      (this._schema as CredentialSchema).encoder
    );
    this._encodedSubject = signed.encodedMessages;
    this._sig = signed.signature;
  }

  // TODO: Set schema and validate that no reserved names are used, subject, status is as per schema, revocation check is either membership or non-membership, etc

  serializeForSigning() {
    const s = {};
    s[CRED_VERSION_STR] = this._version;
    s[SCHEMA_STR] = this._schema?.toJSON();
    s[SUBJECT_STR] = this._subject;
    if (this._credStatus !== undefined) {
      s[STATUS_STR] = this._credStatus;
    }
    return s;
  }

  verify(publicKey: BBSPlusPublicKeyG2): VerifyResult {
    const cred = this.serializeForSigning();
    return verifyMessageObject(
      cred,
      this._sig as SignatureG1,
      publicKey,
      SIGNATURE_PARAMS_LABEL_BYTES,
      (this._schema as CredentialSchema).encoder
    );
  }

  // TODO: Add checks isReady, isSigned which check if necessary attributes are there.
  toJSON(): string {
    const j = {};
    j['version'] = this._version;
    j['schema'] = this._schema?.forCredential();
    j['credentialSubject'] = this._subject;
    if (this._credStatus !== undefined) {
      j['credentialStatus'] = this._credStatus;
    }
    j['issuerPubKey'] = this._issuerPubKey;
    j['proof'] = {
      type: 'Bls12381BBS+SignatureDock2022',
      proofValue: b58.encode((this._sig as SignatureG1).bytes)
    };
    // This is for debugging only and can be omitted
    j['encodedCredentialSubject'] = Object.fromEntries(
      Object.entries(this._encodedSubject as object).map(([k, v]) => [k, b58.encode(v)])
    );
    return JSON.stringify(j);
  }

  static fromJSON(json: string): Credential {
    // TODO
    return new Credential();
  }
}
