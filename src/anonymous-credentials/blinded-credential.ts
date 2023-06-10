import { BBSPlusBlindSignatureG1 } from '../bbs-plus';
import { BBSBlindSignature, BBSSignature } from '../bbs';
import { BBSCredential, BBSPlusCredential } from './credential';
import { BBSPlusBlinding } from './blinded-credential-request-builder';
import * as _ from 'lodash';
import { CredentialCommon } from './credential-common';
import {
  BBS_BLINDED_CRED_PROOF_TYPE,
  BBS_CRED_PROOF_TYPE,
  BBS_PLUS_BLINDED_CRED_PROOF_TYPE,
  BBS_PLUS_CRED_PROOF_TYPE,
  PROOF_STR,
  TYPE_STR
} from './types-and-consts';

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
    const subject = this.subject;
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

  protected static validateProofType(typ: string) {
    if (![BBS_BLINDED_CRED_PROOF_TYPE, BBS_PLUS_BLINDED_CRED_PROOF_TYPE].includes(typ)) {
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
   * @returns
   */
  toCredential(blindedSubject: object | object[]): BBSCredential {
    const updatedSubject = this.getUpdatedSubject(blindedSubject);
    const topLevelFields = this.updateProofType(BBS_CRED_PROOF_TYPE);
    return new BBSCredential(
      this.version,
      this.schema,
      updatedSubject,
      topLevelFields,
      new BBSSignature(this.signature.value),
      this.credentialStatus
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
   * @returns
   */
  toCredential(blindedSubject: object | object[], blinding: BBSPlusBlinding): BBSPlusCredential {
    const updatedSubject = this.getUpdatedSubject(blindedSubject);
    const unblindedSig = this.signature.unblind(blinding.value);
    const topLevelFields = this.updateProofType(BBS_PLUS_CRED_PROOF_TYPE);
    return new BBSPlusCredential(
      this.version,
      this.schema,
      updatedSubject,
      topLevelFields,
      unblindedSig,
      this.credentialStatus
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
