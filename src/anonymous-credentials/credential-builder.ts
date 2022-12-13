import { BBSPlusSecretKey, SignatureG1, SignatureParamsG1 } from '../bbs-plus';
import { signMessageObject } from '../sign-verify-js-objs';
import { Versioned } from './versioned';
import { CredentialSchema } from './schema';
import {
  CRYPTO_VERSION_STR,
  MEM_CHECK_STR,
  NON_MEM_CHECK_STR,
  ID_STR,
  REV_CHECK_STR,
  REV_ID_STR,
  SCHEMA_STR,
  SIGNATURE_PARAMS_LABEL_BYTES,
  STATUS_STR,
  STATUS_TYPE_STR,
  SUBJECT_STR,
  TYPE_STR
} from './types-and-consts';
import { Credential } from './credential';
import { flatten } from 'flat';
import { areArraysEqual } from '../util';

export interface ISigningOpts {
  // Whether the credential should contain exactly the same fields (object keys, array items, literals) as the
  // schema. Providing false for it will result in generation of a new schema to match the credential and that schema
  // will be embedded in the signed credential.
  requireSameFieldsAsSchema: boolean;
}

export const DefaultSigningOpts: ISigningOpts = {
  requireSameFieldsAsSchema: true,
};

/**
 * Create a credential
 */
export class CredentialBuilder extends Versioned {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.1.0';

  // Each credential references the schema which is included as an attribute
  _schema?: CredentialSchema;
  _subject?: object | object[];
  _credStatus?: object;
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
      [TYPE_STR]: STATUS_TYPE_STR,
      [ID_STR]: registryId,
      [REV_CHECK_STR]: revCheck,
      [REV_ID_STR]: memberValue
    };
  }

  get signature(): SignatureG1 | undefined {
    return this._sig;
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

  /**
   * Serializes and signs creating a credential.
   * Expects the credential to have the same fields as schema. This is intentional to always communicate to the
   * verifier the full structure of the credential.
   *
   * @param secretKey
   * @param signatureParams - This makes bulk issuance of credentials with same number of attributes faster because the
   * signature params don't have to be generated.
   * @param signingOpts
   */
  sign(
    secretKey: BBSPlusSecretKey,
    signatureParams?: SignatureParamsG1,
    signingOpts?: Partial<ISigningOpts>
  ): Credential {
    if (signingOpts === undefined) {
      signingOpts = DefaultSigningOpts;
    }

    const cred = this.updateSchemaIfNeeded(signingOpts);
    const schema = this.schema as CredentialSchema;

    const signed = signMessageObject(
      cred,
      secretKey,
      signatureParams !== undefined ? signatureParams : SIGNATURE_PARAMS_LABEL_BYTES,
      schema.encoder
    );

    this._encodedAttributes = signed.encodedMessages;
    this._sig = signed.signature;

    return new Credential(
      this._version,
      schema,
      // @ts-ignore
      this._subject,
      this._topLevelFields,
      this._sig,
      this._credStatus
    );
  }

  serializeForSigning(): object {
    // Schema should be part of the credential signature to prevent the credential holder from convincing a verifier of a manipulated schema
    const s = {
      [CRYPTO_VERSION_STR]: this._version,
      [SCHEMA_STR]: JSON.stringify(this.schema?.toJSON()),
      [SUBJECT_STR]: this._subject
    };
    for (const [k, v] of this._topLevelFields.entries()) {
      s[k] = v;
    }
    if (this._credStatus !== undefined) {
      s[STATUS_STR] = this._credStatus;
    }

    Credential.applyDefaultProofMetadataIfNeeded(s);
    return s;
  }

  /**
   * When schema doesn't match the credential, create a new appropriate schema and update the credential. Returns the
   * serialized credential
   * @param signingOpts
   */
  updateSchemaIfNeeded(signingOpts?: Partial<ISigningOpts>): object {
    const cred = this.serializeForSigning();
    const schema = this.schema as CredentialSchema;
    if (signingOpts && !CredentialBuilder.hasSameFieldsAsSchema(cred, schema)) {
      if (signingOpts.requireSameFieldsAsSchema) {
        throw new Error('Credential does not have the fields as schema');
      } else {
        // Generate new schema
        this.schema = CredentialSchema.generateAppropriateSchema(cred, schema);
        cred[SCHEMA_STR] = JSON.stringify(this.schema?.toJSON());
      }
    }
    return cred;
  }

  static hasSameFieldsAsSchema(cred: object, schema: CredentialSchema): boolean {
    return areArraysEqual(schema.flatten()[0], Object.keys(flatten(cred) as object).sort());
  }
}
