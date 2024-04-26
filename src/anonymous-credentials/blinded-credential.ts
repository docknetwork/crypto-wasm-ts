import { BBSPlusBlindSignatureG1 } from '../bbs-plus';
import { BBSBlindSignature, BBSSignature } from '../bbs';
import { BBSCredential, BBSPlusCredential, BDDT16Credential } from './credential';
import { BBSPlusBlinding, BDDT16Blinding } from './blinded-credential-request-builder';
import * as _ from 'lodash';
import { CredentialCommon } from './credential-common';
import {
  BBS_BLINDED_CRED_PROOF_TYPE,
  BBS_CRED_PROOF_TYPE,
  BBS_PLUS_BLINDED_CRED_PROOF_TYPE,
  BBS_PLUS_CRED_PROOF_TYPE,
  BDDT16_BLINDED_CRED_PROOF_TYPE,
  BDDT16_CRED_PROOF_TYPE,
  PROOF_STR,
  TYPE_STR
} from './types-and-consts';
import { BDDT16BlindMac } from '../bddt16-mac';

/**
 * A blinded credential created by the signer. Has to be converted to a (unblinded) credential
 */
export abstract class BlindedCredential<BlindSig> extends CredentialCommon<BlindSig> {
  /**
   * Merge blinded and unblinded subject to create the subject of the final credential
   * @param blindedSubject
   * @returns
   */
  protected getUpdatedSubject(blindedSubject: object | object[]): object | object[] {
    const subject = _.cloneDeep(this.subject);
    if (Array.isArray(subject)) {
      if (!Array.isArray(blindedSubject)) {
        throw new Error('Both blinded and unblinded subjects should be array');
      }
      if (subject.length !== blindedSubject.length) {
        throw new Error(
          `Both blinded and unblinded subjects should be array of same length but subject length = ${subject.length} and blinded subject length = ${blindedSubject.length}`
        );
      }
      const updatedSubject = [];
      for (let i = 0; i < subject.length; i++) {
        // @ts-ignore
        updatedSubject.push(_.merge(subject[i], blindedSubject[i]));
      }
      return updatedSubject;
    } else {
      if (Array.isArray(blindedSubject)) {
        throw new Error('Both blinded and unblinded subjects should be objects');
      }
      return _.merge(subject, blindedSubject);
    }
  }

  protected getUpdatedStatus(blindedStatus?: object): object | undefined {
    let credStatus = this.credentialStatus ? _.cloneDeep(this.credentialStatus) as object : undefined;
    if (blindedStatus && credStatus) {
      credStatus = _.merge(credStatus, blindedStatus);
    }
    return credStatus;
  }

  protected getUpdatedAttributes(proofType: string, blindedSubject: object | object[], blindedStatus?: object, blindedTopLevelFields?: Map<string, unknown>): [object | object[], object | undefined, Map<string, unknown>] {
    const updatedSubject = this.getUpdatedSubject(blindedSubject);
    const credStatus = this.getUpdatedStatus(blindedStatus);
    const topLevelFields = this.updateProofType(proofType);
    if (blindedTopLevelFields) {
      for (const [k, v] of blindedTopLevelFields.entries()) {
        // This will overwrite any top-level fields set by issuer.
        topLevelFields.set(k, v);
      }
    }
    return [updatedSubject, credStatus, topLevelFields]
  }

  protected static validateProofType(typ: string) {
    if (
      ![BBS_BLINDED_CRED_PROOF_TYPE, BBS_PLUS_BLINDED_CRED_PROOF_TYPE, BDDT16_BLINDED_CRED_PROOF_TYPE].includes(typ)
    ) {
      throw new Error(`Invalid proof type ${typ}`);
    }
  }

  /**
   * Change the proof type from "blinded" to "unblinded"
   * @param newProofType
   * @protected
   */
  protected updateProofType(newProofType): Map<string, unknown> {
    let topLevelFields;
    if (this.topLevelFields.has(PROOF_STR)) {
      topLevelFields = _.cloneDeep(this.topLevelFields);
      const pVal = topLevelFields.get(PROOF_STR);
      pVal[TYPE_STR] = newProofType;
      topLevelFields.set(PROOF_STR, pVal);
    } else {
      topLevelFields = this.topLevelFields;
    }
    return topLevelFields;
  }
}

export class BBSBlindedCredential extends BlindedCredential<BBSBlindSignature> {
  /**
   * Convert to unblinded credential which can be verified with the public key
   * @param blindedSubject
   * @param blindedStatus
   * @param blindedTopLevelFields - Any top level fields that are blinded. Ensure that these are not set by the issuer.
   * @returns
   */
  toCredential(blindedSubject: object | object[], blindedStatus?: object, blindedTopLevelFields?: Map<string, unknown>): BBSCredential {
    const [updatedSubject, credStatus, topLevelFields] = this.getUpdatedAttributes(BBS_CRED_PROOF_TYPE, blindedSubject, blindedStatus, blindedTopLevelFields);
    return new BBSCredential(
      this.version,
      this.schema,
      updatedSubject,
      topLevelFields,
      new BBSSignature(this.signature.value),
      credStatus
    );
  }

  static fromJSON(j: object, proofValue?: string): BBSBlindedCredential {
    const [cryptoVersion, credentialSchema, credentialSubject, topLevelFields, sig, credentialStatus] = this.parseJSON(
      j,
      proofValue
    );

    return new this(
      cryptoVersion,
      credentialSchema,
      credentialSubject,
      topLevelFields,
      new BBSBlindSignature(sig),
      credentialStatus
    );
  }

  static applyDefaultProofMetadataIfNeeded(s: object) {
    if (!s[PROOF_STR]) {
      s[PROOF_STR] = {
        type: BBS_BLINDED_CRED_PROOF_TYPE
      };
    }
  }
}

export class BBSPlusBlindedCredential extends BlindedCredential<BBSPlusBlindSignatureG1> {
  /**
   * Convert to unblinded credential which can be verified with the public key
   * @param blindedSubject
   * @param blinding - blinding used while creating the request
   * @param blindedStatus
   * @param blindedTopLevelFields - Any top level fields that are blinded. Ensure that these are not set by the issuer.
   * @returns
   */
  toCredential(blindedSubject: object | object[], blinding: BBSPlusBlinding, blindedStatus?: object, blindedTopLevelFields?: Map<string, unknown>): BBSPlusCredential {
    const [updatedSubject, credStatus, topLevelFields] = this.getUpdatedAttributes(BBS_PLUS_CRED_PROOF_TYPE, blindedSubject, blindedStatus, blindedTopLevelFields);
    const unblindedSig = this.signature.unblind(blinding.value);
    return new BBSPlusCredential(
      this.version,
      this.schema,
      updatedSubject,
      topLevelFields,
      unblindedSig,
      credStatus
    );
  }

  static fromJSON(j: object, proofValue?: string): BBSPlusBlindedCredential {
    const [cryptoVersion, credentialSchema, credentialSubject, topLevelFields, sig, credentialStatus] = this.parseJSON(
      j,
      proofValue
    );

    return new this(
      cryptoVersion,
      credentialSchema,
      credentialSubject,
      topLevelFields,
      new BBSPlusBlindSignatureG1(sig),
      credentialStatus
    );
  }

  static applyDefaultProofMetadataIfNeeded(s: object) {
    if (!s[PROOF_STR]) {
      s[PROOF_STR] = {
        type: BBS_PLUS_BLINDED_CRED_PROOF_TYPE
      };
    }
  }
}

export class BDDT16BlindedCredential extends BlindedCredential<BDDT16BlindMac> {
  /**
   * Convert to unblinded credential which can be verified with the secret key
   * @param blindedSubject
   * @param blinding - blinding used while creating the request
   * @param blindedStatus
   * @param blindedTopLevelFields - Any top level fields that are blinded. Ensure that these are not set by the issuer.
   * @returns
   */
  toCredential(blindedSubject: object | object[], blinding: BDDT16Blinding, blindedStatus?: object, blindedTopLevelFields?: Map<string, unknown>): BDDT16Credential {
    const [updatedSubject, credStatus, topLevelFields] = this.getUpdatedAttributes(BDDT16_CRED_PROOF_TYPE, blindedSubject, blindedStatus, blindedTopLevelFields);
    const unblindedSig = this.signature.unblind(blinding.value);
    return new BDDT16Credential(
      this.version,
      this.schema,
      updatedSubject,
      topLevelFields,
      unblindedSig,
      credStatus
    );
  }

  static fromJSON(j: object, proofValue?: string): BDDT16BlindedCredential {
    const [cryptoVersion, credentialSchema, credentialSubject, topLevelFields, sig, credentialStatus] = this.parseJSON(
      j,
      proofValue
    );

    return new this(
      cryptoVersion,
      credentialSchema,
      credentialSubject,
      topLevelFields,
      new BDDT16BlindMac(sig),
      credentialStatus
    );
  }

  static applyDefaultProofMetadataIfNeeded(s: object) {
    if (!s[PROOF_STR]) {
      s[PROOF_STR] = {
        type: BDDT16_BLINDED_CRED_PROOF_TYPE
      };
    }
  }
}
