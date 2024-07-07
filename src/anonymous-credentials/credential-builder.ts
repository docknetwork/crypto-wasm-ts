import { CredentialSchema } from './schema';
import {
  SCHEMA_STR,
  BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES,
  BBS_SIGNATURE_PARAMS_LABEL_BYTES,
  PS_SIGNATURE_PARAMS_LABEL_BYTES,
  BBDT16_MAC_PARAMS_LABEL_BYTES, CRYPTO_VERSION_STR, SUBJECT_STR, STATUS_STR
} from './types-and-consts';
import { BBSCredential, BBSPlusCredential, BBDT16Credential, Credential, PSCredential } from './credential';
import { flatten } from 'flat';
import { areArraysEqual } from '../util';
import { BBSPublicKey, BBSSecretKey, BBSSignature, BBSSignatureParams } from '../bbs';
import {
  BBSPlusPublicKeyG2,
  BBSPlusSecretKey,
  BBSPlusSignatureG1,
  BBSPlusSignatureParamsG1,
  Encoder
} from '../bbs-plus';
import { PSPublicKey, PSSecretKey, PSSignature, PSSignatureParams } from '../ps';
import { SignedMessages } from '../types';
import { CredentialBuilderCommon } from './credential-builder-common';
import { BBDT16Mac, BBDT16MacParams, BBDT16MacSecretKey } from '../bbdt16-mac';

export interface ISigningOpts {
  // Whether the credential should contain exactly the same fields (object keys, array items, literals) as the
  // schema. Providing false for it will result in generation of a new schema to match the credential and that schema
  // will be embedded in the signed credential.
  requireSameFieldsAsSchema: boolean;
}

export const DefaultSigningOpts: ISigningOpts = {
  requireSameFieldsAsSchema: true
};

/**
 * Create a credential
 */
export abstract class CredentialBuilder<
  SecretKey,
  PublicKey,
  Signature,
  SignatureParams
> extends CredentialBuilderCommon {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.7.0';

  _encodedAttributes?: { [key: string]: Uint8Array };
  _sig?: Signature;

  constructor() {
    super(CredentialBuilder.VERSION);
  }

  get signature(): Signature | undefined {
    return this._sig;
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
    secretKey: SecretKey,
    signatureParams?: SignatureParams,
    signingOpts?: Partial<ISigningOpts>
  ): Credential<PublicKey, Signature, SignatureParams> {
    if (signingOpts === undefined) {
      signingOpts = DefaultSigningOpts;
    }

    const cred = this.updateSchemaIfNeeded(signingOpts);
    const schema = this.schema as CredentialSchema;

    const signed = this.signMessageObject(cred, secretKey, signatureParams, schema.encoder);

    this._encodedAttributes = signed.encodedMessages;
    this._sig = signed.signature;

    return this.newCredential(
      this._version,
      schema,
      // @ts-ignore
      this._subject,
      this._topLevelFields,
      this._sig,
      this._credStatus
    );
  }

  /**
   * When schema doesn't match the credential, create a new appropriate schema and update the credential. Returns the
   * serialized credential. Legacy version. Used by SDK for some older credential versions
   * @param signingOpts
   */
  updateSchemaIfNeededLegacy(signingOpts?: Partial<ISigningOpts>): object {
    const cred = {
      [CRYPTO_VERSION_STR]: this._version,
      [SCHEMA_STR]: this.schema?.toJsonString(),
      [SUBJECT_STR]: this._subject
    };
    for (const [k, v] of this._topLevelFields.entries()) {
      cred[k] = v;
    }
    if (this._credStatus !== undefined) {
      cred[STATUS_STR] = this._credStatus;
    }

    this.applyDefaultProofMetadataIfNeeded(cred);
    const schema = this.schema as CredentialSchema;
    if (signingOpts && !CredentialBuilder.hasSameFieldsAsSchema(cred, schema)) {
      if (signingOpts.requireSameFieldsAsSchema) {
        throw new Error('Credential does not have the fields as schema');
      } else {
        // Generate new schema
        this.schema = CredentialSchema.generateAppropriateSchema(cred, schema);
        // @ts-ignore
        cred[SCHEMA_STR] = this.schema?.toJsonString();
      }
    }
    return cred;
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
        cred[SCHEMA_STR] = this.schema?.toJSON();
      }
    }
    return cred;
  }

  static hasSameFieldsAsSchema(cred: object, schema: CredentialSchema): boolean {
    return areArraysEqual(schema.flatten()[0], Object.keys(flatten(cred)).sort());
  }

  protected abstract signMessageObject(
    messages: Object,
    secretKey: SecretKey,
    labelOrParams: Uint8Array | SignatureParams | undefined,
    encoder: Encoder
  ): SignedMessages<Signature>;

  protected abstract newCredential(
    version: string,
    schema: CredentialSchema,
    subject: object,
    topLevelFields: Map<string, unknown>,
    sig: Signature,
    credStatus?: object
  ): Credential<PublicKey, Signature, SignatureParams>;
}

/**
 * Create a `BBS` credential
 */
export class BBSCredentialBuilder extends CredentialBuilder<
  BBSSecretKey,
  BBSPublicKey,
  BBSSignature,
  BBSSignatureParams
> {
  protected signMessageObject(
    messages: Object,
    secretKey: BBSSecretKey,
    labelOrParams: Uint8Array | BBSSignatureParams = BBS_SIGNATURE_PARAMS_LABEL_BYTES,
    encoder: Encoder
  ): SignedMessages<BBSSignature> {
    return BBSSignature.signMessageObject(messages, secretKey, labelOrParams, encoder);
  }

  protected newCredential(
    version: string,
    schema: CredentialSchema,
    subject: object,
    topLevelFields: Map<string, unknown>,
    sig: BBSSignature,
    credStatus?: object
  ): BBSCredential {
    return new BBSCredential(version, schema, subject, topLevelFields, sig, credStatus);
  }

  protected applyDefaultProofMetadataIfNeeded(s: object) {
    BBSCredential.applyDefaultProofMetadataIfNeeded(s);
  }
}

/**
 * Create a `BBS+` credential
 */
export class BBSPlusCredentialBuilder extends CredentialBuilder<
  BBSPlusSecretKey,
  BBSPlusPublicKeyG2,
  BBSPlusSignatureG1,
  BBSPlusSignatureParamsG1
> {
  protected signMessageObject(
    messages: Object,
    secretKey: BBSPlusSecretKey,
    labelOrParams: Uint8Array | BBSPlusSignatureParamsG1 = BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES,
    encoder: Encoder
  ): SignedMessages<BBSPlusSignatureG1> {
    return BBSPlusSignatureG1.signMessageObject(messages, secretKey, labelOrParams, encoder);
  }

  protected newCredential(
    version: string,
    schema: CredentialSchema,
    subject: object,
    topLevelFields: Map<string, unknown>,
    sig: BBSPlusSignatureG1,
    credStatus?: object
  ): BBSPlusCredential {
    return new BBSPlusCredential(version, schema, subject, topLevelFields, sig, credStatus);
  }

  protected applyDefaultProofMetadataIfNeeded(s: object) {
    BBSPlusCredential.applyDefaultProofMetadataIfNeeded(s);
  }
}

/**
 * Create a `Pointcheval-Sanders` credential
 */

export class PSCredentialBuilder extends CredentialBuilder<PSSecretKey, PSPublicKey, PSSignature, PSSignatureParams> {
  protected signMessageObject(
    messages: Object,
    secretKey: PSSecretKey,
    labelOrParams: Uint8Array | PSSignatureParams = PS_SIGNATURE_PARAMS_LABEL_BYTES,
    encoder: Encoder
  ): SignedMessages<PSSignature> {
    return PSSignature.signMessageObject(messages, secretKey, labelOrParams, encoder);
  }

  protected newCredential(
    version: string,
    schema: CredentialSchema,
    subject: object,
    topLevelFields: Map<string, unknown>,
    sig: PSSignature,
    credStatus?: object
  ): PSCredential {
    return new PSCredential(version, schema, subject, topLevelFields, sig, credStatus);
  }

  protected applyDefaultProofMetadataIfNeeded(s: object) {
    PSCredential.applyDefaultProofMetadataIfNeeded(s);
  }
}

export class BBDT16CredentialBuilder extends CredentialBuilder<
  BBDT16MacSecretKey,
  undefined,
  BBDT16Mac,
  BBDT16MacParams
> {
  protected signMessageObject(
    messages: Object,
    secretKey: BBDT16MacSecretKey,
    labelOrParams: Uint8Array | BBDT16MacParams = BBDT16_MAC_PARAMS_LABEL_BYTES,
    encoder: Encoder
  ): SignedMessages<BBDT16Mac> {
    return BBDT16Mac.signMessageObject(messages, secretKey, labelOrParams, encoder);
  }

  protected newCredential(
    version: string,
    schema: CredentialSchema,
    subject: object,
    topLevelFields: Map<string, unknown>,
    sig: BBDT16Mac,
    credStatus?: object
  ): BBDT16Credential {
    return new BBDT16Credential(version, schema, subject, topLevelFields, sig, credStatus);
  }

  protected applyDefaultProofMetadataIfNeeded(s: object) {
    BBDT16Credential.applyDefaultProofMetadataIfNeeded(s);
  }
}
