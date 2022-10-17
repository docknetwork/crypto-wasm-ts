import { AttributeEquality, StringOrObject } from './types-and-consts';

export interface IPresentedCredential {
  version: string;
  schema: string;
  issuer: StringOrObject;
  revealedAttributes: object;
  status?: object;
  // Bounds proved of any attribute(s)
  // {min, max, paramsId}
  bounds?: object;
  // Verifiable encryption of any attributes
  // {commGensId, ekId, pkId, ciphertext}
  verifiableEncryptions?: object;
}

/**
 * Specifies what the presentation is proving like what credentials, what's being revealed, which attributes are being proven
 * equal, bounds being enforced, etc
 */
export class PresentationSpecification {
  credentials: IPresentedCredential[];
  attributeEqualities: AttributeEquality[];

  constructor() {
    this.credentials = [];
    this.attributeEqualities = [];
  }

  addPresentedCredential(
    version: string,
    schema: string,
    issuer: StringOrObject,
    revealedAttributes: object,
    status?: object,
    bounds?: object,
    verifiableEncryptions?: object
  ) {
    const ps = {
      version,
      schema,
      issuer,
      revealedAttributes
    };
    if (status !== undefined) {
      ps['status'] = status;
    }
    if (bounds !== undefined) {
      ps['bounds'] = bounds;
    }
    if (verifiableEncryptions !== undefined) {
      ps['verifiableEncryptions'] = verifiableEncryptions;
    }
    this.credentials.push(ps);
  }

  forPresentation(): object {
    return {
      credentials: this.credentials
    };
  }
}
