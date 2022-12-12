import { Versioned } from './versioned';
import { CredentialSchema } from './schema';
import {
  CRYPTO_VERSION_STR,
  SCHEMA_STR,
  SIGNATURE_PARAMS_LABEL_BYTES,
  STATUS_STR,
  SUBJECT_STR
} from './types-and-consts';
import { BBSPlusPublicKeyG2, SignatureG1, SignatureParamsG1 } from '../bbs-plus';
import { VerifyResult } from '@docknetwork/crypto-wasm';
import { verifyMessageObject } from '../sign-verify-js-objs';
import { isEmptyObject } from '../util';
import b58 from 'bs58';

export class Credential extends Versioned {
  // Each credential references the schema which is included as an attribute
  readonly schema: CredentialSchema;
  readonly subject: object | object[];
  readonly credentialStatus?: object;
  readonly topLevelFields: Map<string, unknown>;
  readonly signature: SignatureG1;

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

  static applyProof(s: object) {
    if (!s['proof']) {
      s['proof'] = {
        type: 'Bls12381BBS+SignatureDock2022',
      };
    }
    return s;
  }

  serializeForSigning(): object {
    // Schema should be part of the credential signature to prevent the credential holder from convincing a verifier of a manipulated schema
    const s = {
      [CRYPTO_VERSION_STR]: this.version,
      // Converting the schema to a JSON string rather than keeping it JSO object to avoid creating extra fields while
      // signing which makes the implementation more expensive as one sig param is needed for each field.
      [SCHEMA_STR]: JSON.stringify(this.schema?.toJSON()),
      [SUBJECT_STR]: this.subject
    };
    for (const [k, v] of this.topLevelFields.entries()) {
      s[k] = v;
    }
    if (this.credentialStatus !== undefined) {
      s[STATUS_STR] = this.credentialStatus;
    }

    Credential.applyProof(s);
    delete s['proof']['proofValue'];

    return s;
  }

  toJSON(): object {
    const j = {};
    j['cryptoVersion'] = this._version;
    j['credentialSchema'] = JSON.stringify(this.schema.toJSON());
    j['credentialSubject'] = this.subject;
    if (this.credentialStatus !== undefined) {
      j['credentialStatus'] = this.credentialStatus;
    }
    for (const [k, v] of this.topLevelFields.entries()) {
      j[k] = v;
    }

    Credential.applyProof(j);
    j['proof']['proofValue'] = b58.encode(this.signature.bytes);
    return j;
  }

  toJSONWithJsonLdContext(): object {
    let j = this.toJSON();
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

  static fromJSON(j: object, proofValue: string = ''): Credential {
    // @ts-ignore
    const { cryptoVersion, credentialSchema, credentialSubject, credentialStatus, proof, ...custom } = j;

    // Ensure proof is present
    if (!proof) {
      throw new Error(`Credential.fromJSON expects proof to be defined in object`);
    }

    // Ensure proof type is correct
    if (proof['type'] !== 'Bls12381BBS+SignatureDock2022') {
      throw new Error(`Invalid proof type ${proof['type']}`);
    }

    // Ensure we trim off proofValue as that isnt signed
    const trimmedProof = { ...proof };
    if (!proofValue && trimmedProof && trimmedProof.proofValue) {
      proofValue = trimmedProof.proofValue;
      delete trimmedProof.proofValue;
    }

    const sig = new SignatureG1(b58.decode(proofValue));
    const topLevelFields = new Map<string, unknown>();
    Object.keys(custom).forEach((k) => {
      topLevelFields.set(k, custom[k]);
    });

    if (!isEmptyObject(trimmedProof)) {
      topLevelFields.set('proof', trimmedProof);
    }

    return new Credential(
      cryptoVersion,
      CredentialSchema.fromJSON(typeof credentialSchema === 'string' ? JSON.parse(credentialSchema) : credentialSchema),
      credentialSubject,
      topLevelFields,
      sig,
      credentialStatus
    );
  }
}
