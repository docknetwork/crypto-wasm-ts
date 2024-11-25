import semver from 'semver/preload';
import { CredentialSchema } from './schema';
import {
  BBS_CRED_PROOF_TYPE,
  BBS_PLUS_CRED_PROOF_TYPE,
  BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES,
  BBS_SIGNATURE_PARAMS_LABEL_BYTES,
  CRYPTO_VERSION_STR,
  SignatureType,
  PROOF_STR,
  PS_CRED_PROOF_TYPE,
  PS_SIGNATURE_PARAMS_LABEL_BYTES,
  SCHEMA_STR,
  STATUS_STR,
  SUBJECT_STR,
  BBDT16_CRED_PROOF_TYPE,
  BBDT16_MAC_PARAMS_LABEL_BYTES
} from './types-and-consts';
import { VerifyResult } from 'crypto-wasm-new';
import { BBSPublicKey, BBSSignature, BBSSignatureParams } from '../bbs';
import { PSPublicKey, PSSignature, PSSignatureParams } from '../ps';
import { BBSPlusPublicKeyG2, BBSPlusSignatureG1, BBSPlusSignatureParamsG1 } from '../bbs-plus';
import { CredentialCommon } from './credential-common';
import {
  BBDT16Mac,
  BBDT16MacParams,
  BBDT16MacProofOfValidity,
  BBDT16MacPublicKeyG1,
  BBDT16MacSecretKey
} from '../bbdt16-mac';

export abstract class Credential<PublicKey, Signature, SignatureParams> extends CredentialCommon<Signature> {
  abstract verify(publicKey: PublicKey, signatureParams?: SignatureParams): VerifyResult;

  serializeForSigning(): object {
    const schema = semver.gte(this.version, '0.6.0') ? this.schema?.toJSON() : this.schema?.toJsonString();
    // Schema should be part of the credential signature to prevent the credential holder from convincing a verifier of a manipulated schema
    const s = {
      [CRYPTO_VERSION_STR]: this.version,
      // Converting the schema to a JSON string rather than keeping it JSON object to avoid creating extra fields while
      // signing which makes the implementation more expensive as one sig param is needed for each field.
      [SCHEMA_STR]: schema,
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
    const expectedTyp = this.getSigType();
    if (typ !== expectedTyp) {
      throw new Error(`Expected proof type to be ${expectedTyp} but found ${typ}`);
    }
  }

  static getSigType(): SignatureType {
    throw new Error('This method should be implemented by extending class');
  }
}

export class BBSCredential extends Credential<BBSPublicKey, BBSSignature, BBSSignatureParams> {
  verify(publicKey: BBSPublicKey, signatureParams?: BBSSignatureParams): VerifyResult {
    const cred = this.serializeForSigning();
    return this.signature.verifyMessageObject(
      cred,
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

  static getSigType(): SignatureType {
    return SignatureType.Bbs;
  }
}

export class BBSPlusCredential extends Credential<BBSPlusPublicKeyG2, BBSPlusSignatureG1, BBSPlusSignatureParamsG1> {
  verify(publicKey: BBSPlusPublicKeyG2, signatureParams?: BBSPlusSignatureParamsG1): VerifyResult {
    const cred = this.serializeForSigning();
    return this.signature.verifyMessageObject(
      cred,
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

  static getSigType(): SignatureType {
    return SignatureType.BbsPlus;
  }
}

export class PSCredential extends Credential<PSPublicKey, PSSignature, PSSignatureParams> {
  verify(publicKey: PSPublicKey, signatureParams?: PSSignatureParams): VerifyResult {
    const cred = this.serializeForSigning();
    return this.signature.verifyMessageObject(
      cred,
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

  static getSigType(): SignatureType {
    return SignatureType.Ps;
  }
}

export class BBDT16Credential extends Credential<undefined, BBDT16Mac, BBDT16MacParams> {
  verify(publicKey: undefined, signatureParams?: BBDT16MacParams): VerifyResult {
    throw new Error(`Not applicable`);
  }

  /**
   * Since these cannot be directly verified using the public key, issuer creates a proof of validity and
   * gives to the holder who can then verify it without using the secret key
   * @param secretKey
   * @param publicKey
   * @param signatureParams
   */
  proofOfValidity(
    secretKey: BBDT16MacSecretKey,
    publicKey: BBDT16MacPublicKeyG1,
    signatureParams?: BBDT16MacParams
  ): BBDT16MacProofOfValidity {
    const p = signatureParams ?? BBDT16MacParams.getMacParamsOfRequiredSize(1, BBDT16_MAC_PARAMS_LABEL_BYTES);
    return new BBDT16MacProofOfValidity(this.signature, secretKey, publicKey, p);
  }

  /**
   * This is just done for testing. In practice a credential holder will never have the secret key
   * @param secretKey
   * @param signatureParams
   */
  verifyUsingSecretKey(secretKey: BBDT16MacSecretKey, signatureParams?: BBDT16MacParams): VerifyResult {
    const cred = this.serializeForSigning();
    return this.signature.verifyMessageObject(
      cred,
      secretKey,
      signatureParams ?? BBDT16_MAC_PARAMS_LABEL_BYTES,
      this.schema.encoder
    );
  }

  verifyUsingValidityProof(
    proof: BBDT16MacProofOfValidity,
    publicKey: BBDT16MacPublicKeyG1,
    signatureParams?: BBDT16MacParams
  ): VerifyResult {
    const cred = this.serializeForSigning();
    return proof.verifyWithMessageObject(
      this.signature,
      cred,
      publicKey,
      signatureParams ?? BBDT16_MAC_PARAMS_LABEL_BYTES,
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
        type: BBDT16_CRED_PROOF_TYPE
      };
    }
  }

  static fromJSON(j: object, proofValue?: string): BBDT16Credential {
    const [cryptoVersion, credentialSchema, credentialSubject, topLevelFields, sig, credentialStatus] = this.parseJSON(
      j,
      proofValue
    );

    return new this(
      cryptoVersion,
      credentialSchema,
      credentialSubject,
      topLevelFields,
      new BBDT16Mac(sig),
      credentialStatus
    );
  }

  static getSigType(): SignatureType {
    return SignatureType.Bbdt16;
  }
}
