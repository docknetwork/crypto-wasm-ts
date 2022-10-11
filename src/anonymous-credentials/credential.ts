import { BBSPlusPublicKeyG2, BBSPlusSecretKey, SignatureG1 } from '../bbs-plus';
import { signMessageObject, verifyMessageObject } from '../sign-verify-js-objs';
import { VerifyResult } from '@docknetwork/crypto-wasm';
import { Versioned } from './versioned';
import { CredentialSchema } from './schema';
import { CRED_VERSION_STR, SCHEMA_STR, STATUS_STR, StringOrObject, SUBJECT_STR, VERSION_STR } from './globals';
import b58 from 'bs58';

export class Credential extends Versioned {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.0.1';

  // Label used for generating signature parameters
  static SIGNATURE_PARAMS_LABEL = 'DockBBS+Signature2022';

  // Each credential references the schema which is included as an attribute
  _schema?: CredentialSchema;
  _subject?: object;
  _credStatus?: object;
  _issuer?: StringOrObject;
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

  set issuer(issuer: StringOrObject) {
    this._issuer = issuer;
  }

  sign(secretKey: BBSPlusSecretKey) {
    const cred = this.serializeForSigning();
    const signed = signMessageObject(cred, secretKey, Credential.getLabelBytes(), (this._schema as CredentialSchema).encoder);
    this._encodedSubject = signed.encodedMessages;
    this._sig = signed.signature;
  }

  // TODO: Set schema and validate that no reserved names are used, subject, status is as per schema, etc

  serializeForSigning() {
    const s = {};
    s[CRED_VERSION_STR] = this._version;
    s[SCHEMA_STR] = this._schema?.toJSON();
    s[SUBJECT_STR] = this._subject;
    if (this._credStatus !== undefined) {
      s[STATUS_STR] = this._credStatus;
    }
    return s
  }

  verify(publicKey: BBSPlusPublicKeyG2): VerifyResult {
    const cred = this.serializeForSigning();
    return verifyMessageObject(cred, this._sig as SignatureG1, publicKey, Credential.getLabelBytes(), (this._schema as CredentialSchema).encoder)
  }

  // TODO: Add checks isReady, isSigned which check if necessary attributes are there.
  toJSON(): string {
    const j = {};
    j['version'] = this._version;
    j['schema'] = this._schema?.toJSON();
    j['credentialSubject'] = this._subject;
    if (this._credStatus !== undefined) {
      j['credentialStatus'] = this._credStatus;
    }
    j['encodedCredentialSubject'] = Object.fromEntries(
      Object.entries(this._encodedSubject as object).map(
        ([k, v]) => [k, b58.encode(v)]
      )
    );
    j['proof'] = {
      type: 'Bls12381BBS+SignatureDock2022',
      proofValue: b58.encode(this._sig?.bytes as Uint8Array)
    }
    return JSON.stringify(j);
  }

  static fromJSON(json: string): Credential {
    // TODO
    return new Credential()
  }

  static getLabelBytes(): Uint8Array {
    return (new TextEncoder()).encode(this.SIGNATURE_PARAMS_LABEL)
  }
}
