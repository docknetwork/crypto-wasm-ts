import { BBSPublicKey, BBSSignature, BBSSignatureParams } from '../bbs';
import { LegoProvingKey, LegoProvingKeyUncompressed } from '../legosnark';
import {
  SaverChunkedCommitmentGens,
  SaverCiphertext,
  SaverEncryptionKey,
  SaverProvingKey,
  SaverProvingKeyUncompressed
} from '../saver';
import { R1CS } from '@docknetwork/crypto-wasm';
import { BBSPlusPublicKeyG2, BBSPlusSignatureG1, BBSPlusSignatureParamsG1 } from '../bbs-plus';
import { PSPublicKey, PSSignature, PSSignatureParams } from '../ps';

export type StringOrObject = string | object;
// Reference to an attribute of a credential. The first item of the pair is the credential index in the presentation.
export type AttributeRef = [number, string];
// Array of references to attributes that are equal
export type AttributeEquality = AttributeRef[];
export type PredicateParamType =
  | LegoProvingKey
  | LegoProvingKeyUncompressed
  | SaverProvingKey
  | SaverProvingKeyUncompressed
  | SaverEncryptionKey
  | SaverChunkedCommitmentGens
  | R1CS
  | Uint8Array;

export type FlattenedSchema = [string[], object[]];
export type AttributeCiphertexts = { [key: string]: object | SaverCiphertext };

export type PublicKey = BBSPublicKey | BBSPlusPublicKeyG2 | PSPublicKey;
export type Signature = BBSSignature | BBSPlusSignatureG1 | PSSignature;
export type SignatureParams = BBSSignatureParams | BBSPlusSignatureParamsG1 | PSSignatureParams;
export type SignatureParamsClass =
  | typeof BBSSignatureParams
  | typeof BBSPlusSignatureParamsG1
  | typeof PSSignatureParams;

export const VERSION_STR = 'version';
export const CRYPTO_VERSION_STR = 'cryptoVersion';
export const SCHEMA_STR = 'credentialSchema';
export const SCHEMA_TYPE_STR = 'JsonSchemaValidator2018';
export const SUBJECT_STR = 'credentialSubject';
export const STATUS_STR = 'credentialStatus';
export const TYPE_STR = 'type';
export const STATUS_TYPE_STR = 'DockVBAccumulator2022';
export const ID_STR = 'id';
export const REV_CHECK_STR = 'revocationCheck';
export const REV_ID_STR = 'revocationId';
export const MEM_CHECK_STR = 'membership';
export const NON_MEM_CHECK_STR = 'non-membership';
export const BBS_CRED_PROOF_TYPE = 'Bls12381BBSSignatureDock2023';
export const BBS_PLUS_CRED_PROOF_TYPE = 'Bls12381BBS+SignatureDock2022';
export const PS_CRED_PROOF_TYPE = 'Bls12381PSSignatureDock2023';

const te = new TextEncoder();
// Label used for generating BBS+ signature parameters
export const BBS_SIGNATURE_PARAMS_LABEL = 'DockBBSSignature2023';
export const BBS_SIGNATURE_PARAMS_LABEL_BYTES = te.encode(BBS_SIGNATURE_PARAMS_LABEL);

// Label used for generating BBS+ signature parameters
export const BBS_PLUS_SIGNATURE_PARAMS_LABEL = 'DockBBS+Signature2022';
export const BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES = te.encode(BBS_PLUS_SIGNATURE_PARAMS_LABEL);

// Label used for generating PS signature parameters
export const PS_SIGNATURE_PARAMS_LABEL = 'DockPSSignature2023';
export const PS_SIGNATURE_PARAMS_LABEL_BYTES = te.encode(PS_SIGNATURE_PARAMS_LABEL);

// Label used for generating accumulator parameters
export const ACCUMULATOR_PARAMS_LABEL = 'DockVBAccumulator2022';
export const ACCUMULATOR_PARAMS_LABEL_BYTES = te.encode(ACCUMULATOR_PARAMS_LABEL);

// Label used for generating accumulator proving key
export const ACCUMULATOR_PROVING_KEY_LABEL = 'DockVBAccumulatorProvingKey2022';
export const ACCUMULATOR_PROVING_KEY_LABEL_BYTES = te.encode(ACCUMULATOR_PROVING_KEY_LABEL);

// Label used for generating SAVER encryption generators
export const SAVER_ENCRYPTION_GENS_LABEL = 'DockSAVEREncryptionGens2022';
export const SAVER_ENCRYPTION_GENS_BYTES = te.encode(SAVER_ENCRYPTION_GENS_LABEL);
