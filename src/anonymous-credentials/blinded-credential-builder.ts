import { CredentialBuilderCommon } from './credential-builder-common';
import { IBlindCredentialRequest } from './presentation-specification';
import {
  BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES,
  BBS_SIGNATURE_PARAMS_LABEL_BYTES,
  SUBJECT_STR
} from './types-and-consts';
import { BBSCredential, BBSPlusCredential } from './credential';
import { BBSBlindSignature, BBSSecretKey, BBSSignatureParams } from '../bbs';
import { BBSPlusBlindSignatureG1, BBSPlusSecretKey, BBSPlusSignatureParamsG1 } from '../bbs-plus';
import { CredentialSchema } from './schema';
import { BBSBlindedCredential, BBSPlusBlindedCredential } from './blinded-credential';

/**
 * Used by the signer to create a blinded credential. The signer will know only the unblinded attributes
 */
export abstract class BlindedCredentialBuilder extends CredentialBuilderCommon {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.2.0';

  blindedCredReq: IBlindCredentialRequest;

  constructor(blindedCredReq: IBlindCredentialRequest) {
    super(BlindedCredentialBuilder.VERSION);
    this.blindedCredReq = blindedCredReq;
    this.schema = blindedCredReq.schema;
  }

  protected getTotalAttributesAndEncodedKnownAttributes(): [number, Map<number, Uint8Array>] {
    const schema = this.schema as CredentialSchema;
    const flattenedSchema = schema.flatten();
    const knownAttributes = this.serializeForSigning();
    const encodedAttributes = new Map<number, Uint8Array>();
    Object.entries(schema.encoder.encodeMessageObjectAsObject(knownAttributes)).forEach(([name, value]) => {
      encodedAttributes.set(flattenedSchema[0].indexOf(name), value);
    });
    return [flattenedSchema[0].length, encodedAttributes];
  }
}

export class BBSBlindedCredentialBuilder extends BlindedCredentialBuilder {
  protected applyDefaultProofMetadataIfNeeded(s: object) {
    BBSCredential.applyDefaultProofMetadataIfNeeded(s);
  }

  /**
   * Blind sign a credential
   * @param secretKey
   * @param sigParams
   * @returns
   */
  sign(
    secretKey: BBSSecretKey,
    sigParams: Uint8Array | BBSSignatureParams = BBS_SIGNATURE_PARAMS_LABEL_BYTES
  ): BBSBlindedCredential {
    const [totalAttrs, encodedAttrs] = this.getTotalAttributesAndEncodedKnownAttributes();
    const params = BBSSignatureParams.getSigParamsOfRequiredSize(totalAttrs, sigParams);
    const sig = BBSBlindSignature.generate(this.blindedCredReq.commitment, encodedAttrs, secretKey, params, false);
    return new BBSBlindedCredential(
      this.version,
      this.schema as CredentialSchema,
      // @ts-ignore
      this.subject,
      this._topLevelFields,
      sig,
      this.credStatus
    );
  }
}

export class BBSPlusBlindedCredentialBuilder extends BlindedCredentialBuilder {
  protected applyDefaultProofMetadataIfNeeded(s: object) {
    BBSPlusCredential.applyDefaultProofMetadataIfNeeded(s);
  }

  /**
   * Blind sign a credential
   * @param secretKey
   * @param sigParams
   * @returns
   */
  sign(
    secretKey: BBSPlusSecretKey,
    sigParams: Uint8Array | BBSPlusSignatureParamsG1 = BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES
  ): BBSPlusBlindedCredential {
    const [totalAttrs, encodedAttrs] = this.getTotalAttributesAndEncodedKnownAttributes();
    const params = BBSPlusSignatureParamsG1.getSigParamsOfRequiredSize(totalAttrs, sigParams);
    const sig = BBSPlusBlindSignatureG1.generate(
      this.blindedCredReq.commitment,
      encodedAttrs,
      secretKey,
      params,
      false
    );
    return new BBSPlusBlindedCredential(
      this.version,
      this.schema as CredentialSchema,
      // @ts-ignore
      this.subject,
      this._topLevelFields,
      sig,
      this.credStatus
    );
  }
}
