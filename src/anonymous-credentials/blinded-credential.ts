import { Versioned } from './versioned';
import { CredentialSchema } from './schema';
import { BBSPlusBlindSignatureG1 } from '../bbs-plus';
import { BBSBlindSignature, BBSSignature } from '../bbs';
import { BBSCredential, BBSPlusCredential } from './credential';
import { BBSPlusBlinding } from './blinded-credential-request-builder';
import * as _ from 'lodash';

/**
 * A blinded credential created by the signer. Has to be converted to a (unblinded) credential
 */
export abstract class BlindedCredential<BlindSig> extends Versioned {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.1.0';

  readonly schema: CredentialSchema;
  readonly subject: object | object[];
  readonly credentialStatus?: object;
  readonly topLevelFields: Map<string, unknown>;
  readonly signature: BlindSig;
  readonly blindedAttributes: object;

  constructor(
    version: string,
    schema: CredentialSchema,
    subject: object,
    topLevelFields: Map<string, unknown>,
    blindedAttributes: object,
    sig: BlindSig,
    credStatus?: object
  ) {
    super(version);
    this.schema = schema;
    this.subject = subject;
    this.topLevelFields = topLevelFields;
    this.blindedAttributes = blindedAttributes;
    this.signature = sig;
    this.credentialStatus = credStatus;
  }

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
}

export class BBSBlindedCredential extends BlindedCredential<BBSBlindSignature> {
  /**
   * Convert to unblinded credential which can be verified with the public key
   * @param blindedSubject 
   * @returns 
   */
  toCredential(blindedSubject: object | object[]): BBSCredential {
    const updatedSubject = this.getUpdatedSubject(blindedSubject);
    return new BBSCredential(
      this.version,
      this.schema,
      updatedSubject,
      this.topLevelFields,
      new BBSSignature(this.signature.value),
      this.credentialStatus
    );
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
    return new BBSPlusCredential(
      this.version,
      this.schema,
      updatedSubject,
      this.topLevelFields,
      unblindedSig,
      this.credentialStatus
    );
  }
}
