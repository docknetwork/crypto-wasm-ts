import { CredentialSchema } from './schema';
import {
  BBS_CRED_PROOF_TYPE,
  BBS_PLUS_CRED_PROOF_TYPE,
  CRYPTO_VERSION_STR,
  PS_CRED_PROOF_TYPE,
  SCHEMA_STR,
  BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES,
  BBS_SIGNATURE_PARAMS_LABEL_BYTES,
  PS_SIGNATURE_PARAMS_LABEL_BYTES,
  STATUS_STR,
  SUBJECT_STR,
  PROOF_STR
} from './types-and-consts';
import { VerifyResult } from '@docknetwork/crypto-wasm';
import { BBSPublicKey, BBSSignature, BBSSignatureParams } from '../bbs';
import { PSPublicKey, PSSignature, PSSignatureParams } from '../ps';
import { BBSPlusPublicKeyG2, BBSPlusSignatureG1, BBSPlusSignatureParamsG1 } from '../bbs-plus';
import { CredentialCommon } from './credential-common';

export abstract class Credential<PublicKey, Signature, SignatureParams> extends CredentialCommon<Signature> {
  abstract verify(publicKey: PublicKey, signatureParams?: SignatureParams): VerifyResult;

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

    (this.constructor as typeof Credential).applyDefaultProofMetadataIfNeeded(s);
    delete s[PROOF_STR]['proofValue'];

    return s;
  }

  toJSONWithJsonLdContext(): object {
    let j = this.toJSON();
    const jctx = this.schema.getJsonLdContext();
    // TODO: Uncomment me. The correct context should be "something like" below. See comments over the commented function `getJsonLdContext` for details
    // jctx['@context'][1]['proof'] = {
    //   type: 'schema:Text',
    //   proofValue: 'schema:Text',
    // };
    jctx['@context'][1][PROOF_STR] = CredentialSchema.getDummyContextValue(PROOF_STR);
    jctx['@context'][1]['type'] = CredentialSchema.getDummyContextValue('type');
    jctx['@context'][1]['proofValue'] = CredentialSchema.getDummyContextValue('proofValue');
    j = { ...j, ...jctx };
    return j;
  }

  /**
   * Ensure proof type is correct
   * @param typ
   * @protected
   */
  protected static validateProofType(typ: string) {
    if (![BBS_CRED_PROOF_TYPE, BBS_PLUS_CRED_PROOF_TYPE, PS_CRED_PROOF_TYPE].includes(typ)) {
      throw new Error(`Invalid proof type ${typ}`);
    }
  }
}

export class BBSCredential extends Credential<BBSPublicKey, BBSSignature, BBSSignatureParams> {
  verify(publicKey: BBSPublicKey, signatureParams?: BBSSignatureParams): VerifyResult {
    const cred = this.serializeForSigning();
    return BBSSignatureParams.verifyMessageObject(
      cred,
      this.signature,
      publicKey,
      signatureParams ?? BBS_SIGNATURE_PARAMS_LABEL_BYTES,
      this.schema.encoder
    );
  }

  /**
   * A credential will have at least some proof metadata like the type or purpose. This adds those defaults to the
   * given object.
   * @param s
   */
  static applyDefaultProofMetadataIfNeeded(s: object) {
    if (!s[PROOF_STR]) {
      s[PROOF_STR] = {
        type: BBS_CRED_PROOF_TYPE
      };
    }
  }

  static fromJSON(j: object, proofValue?: string): BBSCredential {
    const [cryptoVersion, credentialSchema, credentialSubject, topLevelFields, sig, credentialStatus] = this.parseJSON(
      j,
      proofValue
    );

    return new this(
      cryptoVersion,
      credentialSchema,
      credentialSubject,
      topLevelFields,
      new BBSSignature(sig),
      credentialStatus
    );
  }
}

export class BBSPlusCredential extends Credential<BBSPlusPublicKeyG2, BBSPlusSignatureG1, BBSPlusSignatureParamsG1> {
  verify(publicKey: BBSPlusPublicKeyG2, signatureParams?: BBSPlusSignatureParamsG1): VerifyResult {
    const cred = this.serializeForSigning();
    return BBSPlusSignatureParamsG1.verifyMessageObject(
      cred,
      this.signature,
      publicKey,
      signatureParams ?? BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES,
      this.schema.encoder
    );
  }

  /**
   * A credential will have at least some proof metadata like the type or purpose. This adds those defaults to the
   * given object.
   * @param s
   */
  static applyDefaultProofMetadataIfNeeded(s: object) {
    if (!s[PROOF_STR]) {
      s[PROOF_STR] = {
        type: BBS_PLUS_CRED_PROOF_TYPE
      };
    }
  }

  static fromJSON(j: object, proofValue?: string): BBSPlusCredential {
    const [cryptoVersion, credentialSchema, credentialSubject, topLevelFields, sig, credentialStatus] = this.parseJSON(
      j,
      proofValue
    );

    return new this(
      cryptoVersion,
      credentialSchema,
      credentialSubject,
      topLevelFields,
      new BBSPlusSignatureG1(sig),
      credentialStatus
    );
  }
}

export class PSCredential extends Credential<PSPublicKey, PSSignature, PSSignatureParams> {
  verify(publicKey: PSPublicKey, signatureParams?: PSSignatureParams): VerifyResult {
    const cred = this.serializeForSigning();
    return PSSignatureParams.verifyMessageObject(
      cred,
      this.signature,
      publicKey,
      signatureParams ?? PS_SIGNATURE_PARAMS_LABEL_BYTES,
      this.schema.encoder
    );
  }

  /**
   * A credential will have at least some proof metadata like the type or purpose. This adds those defaults to the
   * given object.
   * @param s
   */
  static applyDefaultProofMetadataIfNeeded(s: object) {
    if (!s[PROOF_STR]) {
      s[PROOF_STR] = {
        type: PS_CRED_PROOF_TYPE
      };
    }
  }

  static fromJSON(j: object, proofValue?: string): PSCredential {
    const [cryptoVersion, credentialSchema, credentialSubject, topLevelFields, sig, credentialStatus] = this.parseJSON(
      j,
      proofValue
    );

    return new this(
      cryptoVersion,
      credentialSchema,
      credentialSubject,
      topLevelFields,
      new PSSignature(sig),
      credentialStatus
    );
  }
}
