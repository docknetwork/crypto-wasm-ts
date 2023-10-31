import {
  AttributeEquality,
  BlindedAttributeEquality,
  ID_STR,
  BlindSignatureType,
  BoundCheckProtocol,
  CircomProtocol,
  RevocationStatusProtocol,
  SignatureType,
  VerifiableEncryptionProtocol,
  REV_CHECK_STR,
  TYPE_STR,
  InequalityProtocol
} from './types-and-consts';
import b58 from 'bs58';
import { CredentialSchema } from './schema';

export interface IPresentedStatus {
  [ID_STR]: string;
  [TYPE_STR]: RevocationStatusProtocol;
  [REV_CHECK_STR]: string;
  accumulated: Uint8Array;
  extra: object;
}

export interface IPresentedAttributeBound {
  min: number;
  max: number;
  // paramId will be absent when Bulletproofs++ with default setup is used
  paramId?: string;
  protocol: BoundCheckProtocol;
}

export interface IPresentedAttributeVE {
  chunkBitSize: number;
  commitmentGensId: string;
  encryptionKeyId: string;
  snarkKeyId: string;
  protocol: VerifiableEncryptionProtocol;
}

/**
 * A mapping of one private variable of the Circom circuit to one or more attributes
 */
export interface ICircuitPrivateVar {
  varName: string;
  // A circuit variable can be a single value or an array and thus map to one or more attributes
  attributeName: { [key: string]: null | object } | { [key: string]: null | object }[];
}

/**
 * A mapping of one private variable of the Circom circuit to one or more (credential, attribute) pairs
 */
export interface ICircuitPrivateVarMultiCred {
  varName: string;
  // A circuit variable can be reference to a single attribute or an array and thus map to one
  // or more attribute references. Each attribute reference is a pair with 1st item is the credential
  // index and 2nd is the attribute name
  attributeRef: [number, { [key: string]: null | object }] | [number, { [key: string]: null | object }][];
}

/**
 * A mapping of one public variable of the Circom circuit to one or more values
 */
export interface ICircuitPublicVar {
  varName: string;
  // A circuit variable can be a single value or an array and thus map to one or more values
  value: Uint8Array | Uint8Array[];
}

/**
 * R1CS public inputs, private attribute names involved in circuit.
 */
export interface ICircomPredicate<PV> {
  privateVars: PV[];
  publicVars: ICircuitPublicVar[];
  // Used to identify the circuit and associated R1CS and WASM files
  circuitId: string;
  snarkKeyId: string;
  protocol: CircomProtocol;
}

export interface IPresentedAttributeInequality {
  inEqualTo: any;
  // paramId will be absent when default commitment key is used
  paramId?: string;
  protocol: InequalityProtocol;
}

export interface IPresentedCredential {
  sigType?: SignatureType;
  version: string;
  schema: string;
  // Attributes being revealed to the verifier
  revealedAttributes: object;
  // Credential status used for checking revocation
  status?: IPresentedStatus;
  // Bounds proved of any attribute(s)
  bounds?: { [key: string]: string | IPresentedAttributeBound | IPresentedAttributeBound[] };
  // Verifiable encryption of any attributes
  verifiableEncryptions?: { [key: string]: string | IPresentedAttributeVE | IPresentedAttributeVE[] };
  // Predicates proved using Circom. Can be over any number of attributes
  circomPredicates?: ICircomPredicate<ICircuitPrivateVar>[];
  attributeInequalities?: { [key: string]: string | IPresentedAttributeInequality[] };
}

export interface IBoundedPseudonymCommitKey {
  basesForAttributes: string[];
  baseForSecretKey?: string;
}

export interface IPresentedBoundedPseudonym {
  commitKey: IBoundedPseudonymCommitKey;
  // key is credIdx, values are attribute names in the credential corresponding to the credIdx
  attributes: { [key: number]: string[] };
}

export interface IUnboundedPseudonymCommitKey {
  baseForSecretKey: string;
}

export interface IPresentedUnboundedPseudonym {
  commitKey: IUnboundedPseudonymCommitKey;
}

// Pseudonym bounded to credential as well as blinded attributes. Used when requesting blinded credential.
export interface IPresentedBoundedPseudonymInBlindedCredReq {
  commitKey: IBoundedPseudonymCommitKey;
  // key is credIdx, values are attribute names in the credential corresponding to the credIdx
  credentialAttributes: { [key: number]: string[] };
  blindedAttributes: string[];
}

export interface IBlindCredentialRequest {
  // Type of the signature requested, like BBS, BBS+
  sigType: BlindSignatureType;
  version: string;
  // The schema of the whole (unblinded credential). This should include all attributes, i.e. blinded and unblinded
  schema: CredentialSchema;
  blindedAttributes: object;
  // Commitment to the blinded attributes
  commitment: Uint8Array;
  attributeInequalities?: { [key: string]: string | IPresentedAttributeInequality[] };
  // Bounds proved of any attribute(s)
  bounds?: { [key: string]: string | IPresentedAttributeBound[] };
  // Verifiable encryption of any blinded attributes
  verifiableEncryptions?: { [key: string]: string | IPresentedAttributeVE[] };
  // Predicates proved using Circom. Can be over any number of blinded attributes
  circomPredicates?: ICircomPredicate<ICircuitPrivateVar>[];
  // Equalities between the blinded attributes and credential attributes
  blindedAttributeEqualities?: BlindedAttributeEquality[];
  pseudonyms?: { [key: string]: IPresentedBoundedPseudonymInBlindedCredReq };
}

/**
 * Specifies what the presentation is proving like what credentials, what's being revealed, which attributes are being proven
 * equal, bounds being enforced, etc
 */
export class PresentationSpecification {
  // The credentials used in the presentation
  credentials: IPresentedCredential[];
  // The attributes being proved equal
  attributeEqualities?: AttributeEquality[];
  // key == pseudonym
  boundedPseudonyms?: { [key: string]: IPresentedBoundedPseudonym };
  // key == pseudonym
  unboundedPseudonyms?: { [key: string]: IPresentedUnboundedPseudonym };
  blindCredentialRequest?: IBlindCredentialRequest;
  circomPredicatesMultiCred?: ICircomPredicate<ICircuitPrivateVarMultiCred>[]

  constructor() {
    this.credentials = [];
    this.attributeEqualities = [];
    this.boundedPseudonyms = {};
    this.unboundedPseudonyms = {};
  }

  addPresentedCredential(
    version: string,
    schema: string,
    revealedAttributes: object,
    status?: IPresentedStatus,
    bounds?: { [key: string]: string | IPresentedAttributeBound[] },
    verifiableEncryptions?: { [key: string]: string | IPresentedAttributeVE[] },
    circomPredicates?: ICircomPredicate<ICircuitPrivateVar>[],
    sigType?: SignatureType,
    attributeInequalities?: { [key: string]: string | IPresentedAttributeInequality[] }
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
    if (sigType !== undefined) {
      ps['sigType'] = sigType;
    }
    if (attributeInequalities !== undefined) {
      ps['attributeInequalities'] = attributeInequalities;
    }
    this.credentials.push(ps);
  }

  addAttributeEquality(eql: AttributeEquality) {
    if (this.attributeEqualities === undefined) {
      this.attributeEqualities = [];
    }
    this.attributeEqualities.push(eql);
  }

  getStatus(credIndex: number): IPresentedStatus | undefined {
    if (credIndex >= this.credentials.length) {
      throw new Error(`Invalid credential index ${credIndex}`);
    }
    return this.credentials[credIndex].status;
  }

  toJSON(): object {
    const j = {
      credentials: [],
      attributeEqualities: this.attributeEqualities,
      boundedPseudonyms: this.boundedPseudonyms,
      unboundedPseudonyms: this.unboundedPseudonyms,
      blindCredentialRequest: this.blindCredentialRequest,
      circomPredicatesMultiCred: this.circomPredicatesMultiCred
    };

    for (const pc of this.credentials) {
      const curJ = {
        version: pc.version,
        schema: pc.schema,
        revealedAttributes: pc.revealedAttributes
      };
      if (pc.sigType !== undefined) {
        curJ['sigType'] = pc.sigType;
      }
      if (pc.status !== undefined) {
        curJ['status'] = { ...pc.status };
        curJ['status'].accumulated = b58.encode(pc.status.accumulated);
      }
      if (pc.attributeInequalities !== undefined) {
        curJ['attributeInequalities'] = pc.attributeInequalities;
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

    return j;
  }
}
