import { Versioned } from './versioned';
import { CredentialSchema } from './schema';
import {
  CRED_VERSION_STR,
  SCHEMA_STR,
  SIGNATURE_PARAMS_LABEL_BYTES,
  STATUS_STR,
  StringOrObject,
  SUBJECT_STR
} from './types-and-consts';
import { BBSPlusPublicKeyG2, SignatureG1 } from '../bbs-plus';
import { VerifyResult } from '@docknetwork/crypto-wasm';
import { verifyMessageObject } from '../sign-verify-js-objs';
import b58 from 'bs58';

export class Credential extends Versioned {
  // Each credential references the schema which is included as an attribute
  schema: CredentialSchema;
  subject: object | object[];
  credStatus?: object;
  // TODO: Remove
  issuerPubKey: StringOrObject;
  topLevelFields: Map<string, unknown>;
  signature: SignatureG1;

  constructor(
    version: string,
    schema: CredentialSchema,
    subject: object,
    issuerPubKey: StringOrObject,
    topLevelFields: Map<string, unknown>,
    sig: SignatureG1,
    credStatus?: object
  ) {
    super(version);
    this.schema = schema;
    this.subject = subject;
    this.issuerPubKey = issuerPubKey;
    this.topLevelFields = topLevelFields;
    this.signature = sig;
    this.credStatus = credStatus;
  }

  verify(publicKey: BBSPlusPublicKeyG2): VerifyResult {
    const cred = this.serializeForSigning();
    return verifyMessageObject(cred, this.signature, publicKey, SIGNATURE_PARAMS_LABEL_BYTES, this.schema.encoder);
  }

  getTopLevelField(name: string): unknown {
    const v = this.topLevelFields.get(name);
    if (v === undefined) {
      throw new Error(`Top level field ${name} is absent`);
    }
    return v;
  }

  serializeForSigning() {
    // Schema should be part of the credential signature to prevent the credential holder from convincing a verifier of a manipulated schema
    const s = {
      [CRED_VERSION_STR]: this.version,
      [SCHEMA_STR]: this.schema.toJSON(),
      [SUBJECT_STR]: this.subject
    };
    for (const [k, v] of this.topLevelFields.entries()) {
      s[k] = v;
    }
    if (this.credStatus !== undefined) {
      s[STATUS_STR] = this.credStatus;
    }
    return s;
  }

  toJSON(): string {
    const j = {};
    j['version'] = this._version;
    j['schema'] = this.schema.forCredential();
    j['credentialSubject'] = this.subject;
    if (this.credStatus !== undefined) {
      j['credentialStatus'] = this.credStatus;
    }
    for (const [k, v] of this.topLevelFields.entries()) {
      j[k] = v;
    }
    j['issuerPubKey'] = this.issuerPubKey;
    j['proof'] = {
      type: 'Bls12381BBS+SignatureDock2022',
      proofValue: b58.encode(this.signature.bytes)
    };
    return JSON.stringify(j);
  }

  static fromJSON(json: string): Credential {
    // TODO
    // @ts-ignore
    return new Credential();
  }
}
