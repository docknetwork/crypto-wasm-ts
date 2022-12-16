import { AttributeEquality, ID_STR, REV_CHECK_STR, TYPE_STR } from './types-and-consts';
import b58 from 'bs58';

export interface IPresentedStatus {
  [ID_STR]: string;
  [TYPE_STR]: string;
  [REV_CHECK_STR]: string;
  accumulated: Uint8Array;
  extra: object;
}

export interface IPresentedAttributeBounds {
  min: number;
  max: number;
  paramId: string;
}

export interface IPresentedAttributeVE {
  chunkBitSize: number;
  commitmentGensId: string;
  encryptionKeyId: string;
  snarkKeyId: string;
}

export interface IPresentedCredential {
  version: string;
  schema: string;
  revealedAttributes: object;
  status?: IPresentedStatus;
  // Bounds proved of any attribute(s)
  bounds?: { [key: string]: string | IPresentedAttributeBounds };
  // Verifiable encryption of any attributes
  verifiableEncryptions?: { [key: string]: string | IPresentedAttributeVE };
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

  reset() {
    this.credentials = [];
    this.attributeEqualities = [];
  }

  addPresentedCredential(
    version: string,
    schema: string,
    revealedAttributes: object,
    status?: IPresentedStatus,
    bounds?: { [key: string]: string | IPresentedAttributeBounds },
    verifiableEncryptions?: { [key: string]: string | IPresentedAttributeVE }
  ) {
    const ps = {
      version,
      schema,
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

  getStatus(credIndex: number): IPresentedStatus | undefined {
    if (credIndex >= this.credentials.length) {
      throw new Error(`Invalid credential index ${credIndex}`);
    }
    return this.credentials[credIndex].status;
  }

  toJSON(): string {
    const j = {
      credentials: [],
      attributeEqualities: this.attributeEqualities
    };

    for (const pc of this.credentials) {
      const curJ = {
        version: pc.version,
        schema: pc.schema,
        revealedAttributes: pc.revealedAttributes
      };
      if (pc.status !== undefined) {
        curJ['status'] = { ...pc.status };
        curJ['status'].accumulated = b58.encode(pc.status.accumulated);
      }
      if (pc.bounds !== undefined) {
        curJ['bounds'] = pc.bounds;
      }
      if (pc.verifiableEncryptions !== undefined) {
        curJ['verifiableEncryptions'] = pc.verifiableEncryptions;
      }
      // @ts-ignore
      j.credentials.push(curJ);
    }
    return JSON.stringify(j);
  }
}
