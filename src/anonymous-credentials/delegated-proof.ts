import { VerifyResult } from 'crypto-wasm-new';
import { AccumulatorSecretKey } from '../accumulator';
import { BDDT16MacSecretKey } from '../bddt16-mac';
import { BDDT16DelegatedProof, VBAccumMembershipDelegatedProof } from '../delegated-proofs';
import { ID_STR, REV_CHECK_STR, RevocationStatusProtocol, SignatureType, TYPE_STR } from './types-and-consts';
import { Versioned } from './versioned';

export interface IDelegatedCredentialProof {
  sigType: SignatureType,
  proof: BDDT16DelegatedProof
}

export interface IDelegatedCredentialStatusProof {
  [ID_STR]: string;
  [TYPE_STR]: RevocationStatusProtocol;
  [REV_CHECK_STR]: string;
  proof: VBAccumMembershipDelegatedProof
}

export class DelegatedProof extends Versioned {
  static VERSION = '0.1.0';

  readonly credential?: IDelegatedCredentialProof;
  readonly status?: IDelegatedCredentialStatusProof;

  constructor(credential?: IDelegatedCredentialProof, status?: IDelegatedCredentialStatusProof) {
    super(DelegatedProof.VERSION);
    this.credential = credential;
    this.status = status;
  }

  verify(credentialSecretKey?: BDDT16MacSecretKey, accumSecretKey?: AccumulatorSecretKey): VerifyResult {
    const r = {verified: true, error: ""}
    if (this.credential !== undefined) {
      if (credentialSecretKey === undefined) {
        throw new Error('Secret key not provided for credential')
      }
      const rc = this.credential.proof.verify(credentialSecretKey);
      if (!rc.verified) {
        return rc;
      }
    }
    if (this.status !== undefined) {
      if (accumSecretKey === undefined) {
        throw new Error('Secret key not provided for accumulator')
      }
      const rc = this.status.proof.verify(accumSecretKey);
      if (!rc.verified) {
        return rc;
      }
    }
    return r;
  }
}