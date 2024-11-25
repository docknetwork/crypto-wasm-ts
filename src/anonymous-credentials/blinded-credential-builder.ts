import { CredentialBuilder } from './credential-builder';
import { CredentialBuilderCommon } from './credential-builder-common';
import { IBlindCredentialRequest } from './presentation-specification';
import {
  BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES,
  BBS_SIGNATURE_PARAMS_LABEL_BYTES,
  STATUS_STR,
  BBDT16_MAC_PARAMS_LABEL_BYTES
} from './types-and-consts';
import { BBSCredential, BBSPlusCredential, BBDT16Credential } from './credential';
import { BBSBlindSignature, BBSSecretKey, BBSSignatureParams } from '../bbs';
import { BBSPlusBlindSignatureG1, BBSPlusSecretKey, BBSPlusSignatureParamsG1 } from '../bbs-plus';
import { CredentialSchema } from './schema';
import { BBSBlindedCredential, BBSPlusBlindedCredential, BBDT16BlindedCredential } from './blinded-credential';
import { BBDT16BlindMac, BBDT16MacParams, BBDT16MacSecretKey } from '../bbdt16-mac';

/**
 * Used by the signer to create a blinded credential. The signer will know only the unblinded attributes
 */
export abstract class BlindedCredentialBuilder extends CredentialBuilderCommon {
  /** NOTE: This should match `CredentialBuilder.VERSION` exactly else backward compatibility code won't always work.
  This is because `BlindedCredential.toCredential` outputs a `Credential` which should be same as the one output
  by `CredentialBuilder.sign` */
  static VERSION = CredentialBuilder.VERSION;

  blindedCredReq: IBlindCredentialRequest;

  constructor(blindedCredReq: IBlindCredentialRequest) {
    super(BlindedCredentialBuilder.VERSION);
    this.blindedCredReq = blindedCredReq;
    this.schema = blindedCredReq.schema;
  }

  protected getTotalAttributesAndEncodedKnownAttributes(): [number, Map<number, Uint8Array>] {
    const schema = this.schema as CredentialSchema;
    const flattenedSchema = schema.flatten();
    let knownAttributes = this.serializeForSigning();
    if (this.blindedCredReq.unBlindedAttributes !== undefined) {
      if (typeof this.blindedCredReq.unBlindedAttributes !== 'object') {
        throw new Error(
          `Unblinded attributes were supposed to an object but found ${this.blindedCredReq.unBlindedAttributes}`
        );
      }
      knownAttributes = { ...knownAttributes, ...this.blindedCredReq.unBlindedAttributes };
    }
    const encodedAttributes = new Map<number, Uint8Array>();
    Object.entries(schema.encoder.encodeMessageObjectAsObjectConstantTime(knownAttributes)).forEach(([name, value]) => {
      encodedAttributes.set(flattenedSchema[0].indexOf(name), value);
    });
    return [flattenedSchema[0].length, encodedAttributes];
  }

  protected processUnBlindedAttributes() {
    if (this.blindedCredReq.unBlindedAttributes !== undefined) {
      if (typeof this.blindedCredReq.unBlindedAttributes !== 'object') {
        throw new Error(
          `Unblinded attributes were supposed to an object but found ${this.blindedCredReq.unBlindedAttributes}`
        );
      }
      for (const [name, value] of Object.entries(this.blindedCredReq.unBlindedAttributes)) {
        if (name === STATUS_STR) {
          if (this.credStatus !== undefined) {
            throw new Error('credStatus was set by the signer when it was provided in request as well');
          }
          this.credStatus = value;
        } else {
          throw new Error(`Unsupported for blinded attribute ${name}`);
        }
      }
    }
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
    this.processUnBlindedAttributes();
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
    this.processUnBlindedAttributes();
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

export class BBDT16BlindedCredentialBuilder extends BlindedCredentialBuilder {
  protected applyDefaultProofMetadataIfNeeded(s: object) {
    BBDT16Credential.applyDefaultProofMetadataIfNeeded(s);
  }

  /**
   * Blind sign a credential
   * @param secretKey
   * @param sigParams
   * @returns
   */
  sign(
    secretKey: BBDT16MacSecretKey,
    sigParams: Uint8Array | BBDT16MacParams = BBDT16_MAC_PARAMS_LABEL_BYTES
  ): BBDT16BlindedCredential {
    const [totalAttrs, encodedAttrs] = this.getTotalAttributesAndEncodedKnownAttributes();
    const params = BBDT16MacParams.getMacParamsOfRequiredSize(totalAttrs, sigParams);
    const sig = BBDT16BlindMac.generate(this.blindedCredReq.commitment, encodedAttrs, secretKey, params, false);
    this.processUnBlindedAttributes();
    return new BBDT16BlindedCredential(
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
