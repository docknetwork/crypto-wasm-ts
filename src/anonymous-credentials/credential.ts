import { Versioned } from './versioned';
import { CredentialSchema } from './schema';
import {
  CRED_VERSION_STR,
  SCHEMA_STR,
  SIGNATURE_PARAMS_LABEL_BYTES,
  STATUS_STR,
  SUBJECT_STR
} from './types-and-consts';
import { BBSPlusPublicKeyG2, SignatureG1, SignatureParamsG1 } from '../bbs-plus';
import { VerifyResult } from '@docknetwork/crypto-wasm';
import { verifyMessageObject } from '../sign-verify-js-objs';
import b58 from 'bs58';

export class Credential extends Versioned {
  // Each credential references the schema which is included as an attribute
  schema: CredentialSchema;
  subject: object | object[];
  credentialStatus?: object;
  topLevelFields: Map<string, unknown>;
  signature: SignatureG1;

  constructor(
    version: string,
    schema: CredentialSchema,
    subject: object,
    topLevelFields: Map<string, unknown>,
    sig: SignatureG1,
    credStatus?: object
  ) {
    super(version);
    this.schema = schema;
    this.subject = subject;
    this.topLevelFields = topLevelFields;
    this.signature = sig;
    this.credentialStatus = credStatus;
  }

  verify(publicKey: BBSPlusPublicKeyG2, signatureParams?: SignatureParamsG1): VerifyResult {
    const cred = this.serializeForSigning();
    return verifyMessageObject(
      cred,
      this.signature,
      publicKey,
      signatureParams !== undefined ? signatureParams : SIGNATURE_PARAMS_LABEL_BYTES,
      this.schema.encoder
    );
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
    if (this.credentialStatus !== undefined) {
      s[STATUS_STR] = this.credentialStatus;
    }
    return s;
  }

  prepareForJson(): object {
    const j = {};
    j['credentialVersion'] = this._version;
    j['credentialSchema'] = this.schema.toJSON();
    j['credentialSubject'] = this.subject;
    if (this.credentialStatus !== undefined) {
      j['credentialStatus'] = this.credentialStatus;
    }
    for (const [k, v] of this.topLevelFields.entries()) {
      j[k] = v;
    }
    j['proof'] = {
      type: 'Bls12381BBS+SignatureDock2022',
      proofValue: b58.encode(this.signature.bytes)
    };
    return j;
  }

  prepareForJsonLd(): object {
    let j = this.prepareForJson();
    const jctx = this.schema.getJsonLdContext();
    // TODO: Uncomment me. The correct context should be "something like" below. See comments over the commented function `getJsonLdContext` for details
    // jctx['@context'][1]['proof'] = {
    //   type: 'schema:Text',
    //   proofValue: 'schema:Text',
    // };
    jctx['@context'][1]['proof'] = CredentialSchema.getDummyContextValue('proof');
    jctx['@context'][1]['type'] = CredentialSchema.getDummyContextValue('type');
    jctx['@context'][1]['proofValue'] = CredentialSchema.getDummyContextValue('proofValue');
    j = { ...j, ...jctx };
    return j;
  }

  toJSON(): string {
    return JSON.stringify(this.prepareForJson());
  }

  toJSONWithJsonLdContext(): string {
    return JSON.stringify(this.prepareForJsonLd());
  }

  static fromJSON(json: string): Credential {
    const { credentialVersion, credentialSchema, credentialSubject, credentialStatus, proof, ...custom } =
      JSON.parse(json);
    if (proof['type'] !== 'Bls12381BBS+SignatureDock2022') {
      throw new Error(`Invalid proof type ${proof['type']}`);
    }
    const sig = new SignatureG1(b58.decode(proof['proofValue']));
    const topLevelFields = new Map<string, unknown>();
    Object.keys(custom).forEach((k) => {
      topLevelFields.set(k, custom[k]);
    });
    return new Credential(
      credentialVersion,
      CredentialSchema.fromJSON(credentialSchema),
      credentialSubject,
      topLevelFields,
      sig,
      credentialStatus
    );
  }
}
