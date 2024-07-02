import b58 from 'bs58';
import { VerifyResult } from 'crypto-wasm-new';
import { AccumulatorSecretKey } from '../accumulator';
import { BBDT16MacSecretKey } from '../bbdt16-mac';
import {
  BBDT16KeyedProof,
  KBUniAccumMembershipKeyedProof,
  KBUniAccumNonMembershipKeyedProof,
  VBAccumMembershipKeyedProof
} from '../keyed-proofs';
import {
  ID_STR,
  MEM_CHECK_KV_STR,
  NON_MEM_CHECK_KV_STR,
  REV_CHECK_STR,
  RevocationStatusProtocol,
  SignatureType,
  TYPE_STR
} from './types-and-consts';
import { Versioned } from './versioned';

export interface IKeyedCredentialProof {
  sigType: SignatureType;
  proof: BBDT16KeyedProof;
}

export interface IKeyedCredentialStatusProof {
  [ID_STR]: string;
  [TYPE_STR]: RevocationStatusProtocol;
  [REV_CHECK_STR]: string;
  proof: VBAccumMembershipKeyedProof | KBUniAccumMembershipKeyedProof | KBUniAccumNonMembershipKeyedProof;
}

/**
 * Keyed proof for a KVAC. It can contain proof for either the credential or the status or both. A keyed proof
 * is (usually) part of a larger proof and validating it requires the knowledge of secret key.
 */
export class KeyedProof extends Versioned {
  static VERSION = '0.1.0';

  readonly credential?: IKeyedCredentialProof;
  readonly status?: IKeyedCredentialStatusProof;

  constructor(credential?: IKeyedCredentialProof, status?: IKeyedCredentialStatusProof) {
    if (credential === undefined && status === undefined) {
      throw new Error(`At least one of credential or status must be defined`);
    }
    super(KeyedProof.VERSION);
    this.credential = credential;
    this.status = status;
  }

  verify(credentialSecretKey?: BBDT16MacSecretKey, accumSecretKey?: AccumulatorSecretKey): VerifyResult {
    const r = { verified: true, error: '' };

    if (this.credential !== undefined) {
      if (credentialSecretKey === undefined) {
        throw new Error('Secret key not provided for credential');
      }
      const rc = this.credential.proof.verify(credentialSecretKey);
      if (!rc.verified) {
        return rc;
      }
    }

    if (this.status !== undefined) {
      if (accumSecretKey === undefined) {
        throw new Error('Secret key not provided for accumulator');
      }
      if (this.status[ID_STR] === undefined) {
        throw new Error(`${ID_STR} field is required in the keyed proof`);
      }
      if (this.status[TYPE_STR] === RevocationStatusProtocol.Vb22) {
        if (this.status[REV_CHECK_STR] !== MEM_CHECK_KV_STR) {
          throw new Error(
            `Unexpected values for ${TYPE_STR} and ${REV_CHECK_STR}: ${this.status[TYPE_STR]}, ${this.status[REV_CHECK_STR]}`
          );
        }
      } else if (this.status[TYPE_STR] === RevocationStatusProtocol.KbUni24) {
        if (this.status[REV_CHECK_STR] !== MEM_CHECK_KV_STR && this.status[REV_CHECK_STR] !== NON_MEM_CHECK_KV_STR) {
          throw new Error(
            `Unexpected values for ${TYPE_STR} and ${REV_CHECK_STR}: ${this.status[TYPE_STR]}, ${this.status[REV_CHECK_STR]}`
          );
        }
      } else {
        throw new Error(`Unexpected value for ${TYPE_STR}: ${this.status[TYPE_STR]}`);
      }
      const rc = this.status.proof.verify(accumSecretKey);
      if (!rc.verified) {
        return rc;
      }
    }
    return r;
  }

  toJSON(): object {
    let d = {};
    if (this.credential !== undefined) {
      d['credential'] = {
        sigType: this.credential.sigType,
        proof: b58.encode(this.credential.proof.bytes)
      };
    }
    if (this.status !== undefined) {
      d['status'] = {
        [ID_STR]: this.status[ID_STR],
        [TYPE_STR]: this.status[TYPE_STR],
        [REV_CHECK_STR]: this.status[REV_CHECK_STR],
        proof: b58.encode(this.status.proof.bytes)
      };
    }
    return d;
  }

  static fromJSON(j: object): KeyedProof {
    let credential, status;
    if (j['credential'] !== undefined) {
      if (j['credential'].sigType === undefined || j['credential'].proof === undefined) {
        throw new Error(`Expected fields sigType and proof but found the credential object to be ${j['credential']}`);
      }
      credential = {
        sigType: j['credential'].sigType,
        proof: new BBDT16KeyedProof(b58.decode(j['credential'].proof))
      };
    }
    if (j['status'] !== undefined) {
      if (
        j['status'][ID_STR] === undefined ||
        j['status'][TYPE_STR] === undefined ||
        j['status'][REV_CHECK_STR] === undefined ||
        j['status'].proof === undefined
      ) {
        throw new Error(
          `Expected fields ${ID_STR}, ${TYPE_STR}, ${REV_CHECK_STR} and proof but found the status object to be ${j['status']}`
        );
      }
      let cls;
      if (j['status'][TYPE_STR] === RevocationStatusProtocol.Vb22) {
        cls = VBAccumMembershipKeyedProof;
      } else if (j['status'][TYPE_STR] === RevocationStatusProtocol.KbUni24) {
        if (j['status'][REV_CHECK_STR] === MEM_CHECK_KV_STR) {
          cls = KBUniAccumMembershipKeyedProof;
        } else if (j['status'][REV_CHECK_STR] === NON_MEM_CHECK_KV_STR) {
          cls = KBUniAccumNonMembershipKeyedProof;
        }
      }
      status = {
        [ID_STR]: j['status'][ID_STR],
        [TYPE_STR]: j['status'][TYPE_STR],
        [REV_CHECK_STR]: j['status'][REV_CHECK_STR],
        proof: new cls(b58.decode(j['status'].proof))
      };
    }
    return new KeyedProof(credential, status);
  }
}
