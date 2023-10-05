import { CredentialSchema } from './schema';
import {
  SCHEMA_STR,
  BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES,
  BBS_SIGNATURE_PARAMS_LABEL_BYTES,
  PS_SIGNATURE_PARAMS_LABEL_BYTES
} from './types-and-consts';
import { BBSCredential, BBSPlusCredential, Credential, PSCredential } from './credential';
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
  static VERSION = '0.3.0';

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
