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

/**
 * A mapping of one private variable of the Circom circuit to one or more attributes
 */
export interface ICircuitPrivateVars {
  varName: string;
  // A circuit variable can be a single value or an array and thus map to one or more attributes
  attributeName: { [key: string]: null | object } | { [key: string]: null | object }[];
}

/**
 * A mapping of one public variable of the Circom circuit to one or more values
 */
export interface ICircuitPublicVars {
  varName: string;
  // A circuit variable can be a single value or an array and thus map to one or more values
  value: Uint8Array | Uint8Array[];
}

/**
 * R1CS public inputs, private attribute names involved in circuit.
 */
export interface ICircomPredicate {
  privateVars: ICircuitPrivateVars[];
  publicVars: ICircuitPublicVars[];
  // Used to identify the circuit and associated R1CS and WASM files
  circuitId: string;
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
  // Predicates proved using Circom. Can be over any number of attributes
  circomPredicates?: ICircomPredicate[];
}

export interface IBoundedPseudonymCommitKey {
  basesForAttributes: string[];
  baseForSecretKey?: string;
}

export interface IPresentedBoundedPseudonym {
  commitKey: IBoundedPseudonymCommitKey;
  // key is credIdx, values are attribute names in the credential corresponding to the credIdx
  attributes: Map<number, Set<string>>;
}

export interface IUnboundedPseudonymCommitKey {
  baseForSecretKey: string;
}

export interface IPresentedUnboundedPseudonym {
  commitKey: IUnboundedPseudonymCommitKey;
}

/**
 * Specifies what the presentation is proving like what credentials, what's being revealed, which attributes are being proven
 * equal, bounds being enforced, etc
 */
export class PresentationSpecification {
  credentials: IPresentedCredential[];
  attributeEqualities: AttributeEquality[];
  // key == pseudonym
  boundedPseudonyms: Map<string, IPresentedBoundedPseudonym>;
  // key == pseudonym
  unboundedPseudonyms: Map<string, IPresentedUnboundedPseudonym>;

  constructor() {
    this.credentials = [];
    this.attributeEqualities = [];
    this.boundedPseudonyms = new Map();
    this.unboundedPseudonyms = new Map();
  }

  reset() {
    this.credentials = [];
    this.attributeEqualities = [];
    this.boundedPseudonyms = new Map();
    this.unboundedPseudonyms = new Map();
  }

  addPresentedCredential(
    version: string,
    schema: string,
    revealedAttributes: object,
    status?: IPresentedStatus,
    bounds?: { [key: string]: string | IPresentedAttributeBounds },
    verifiableEncryptions?: { [key: string]: string | IPresentedAttributeVE },
    circomPredicates?: ICircomPredicate[]
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
    if (circomPredicates !== undefined) {
      ps['circomPredicates'] = circomPredicates;
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
      attributeEqualities: this.attributeEqualities,
      boundedPseudonyms: this.boundedPseudonyms,
      unboundedPseudonyms: this.unboundedPseudonyms
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
      if (pc.circomPredicates !== undefined) {
        curJ['circomPredicates'] = pc.circomPredicates;
      }
      // @ts-ignore
      j.credentials.push(curJ);
    }
    return JSON.stringify(j);
  }
}
