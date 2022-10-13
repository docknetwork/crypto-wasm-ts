import { AttributeEquality, StringOrObject } from './types-and-consts';

export interface IPresentedCredential {
  version: string;
  schema: string;
  issuer: StringOrObject;
  revealedAttributes: object;
  status?: object;
  // Bounds proved of any attribute
  bounds?: object;
}

/**
 * Specifies what the presentation is proving like what credentials, whats being revealed, which attributes are being proven
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
    status?: object
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
    this.credentials.push(ps);
  }

  forPresentation(): object {
    return {
      credentials: this.credentials
    };
  }
}
