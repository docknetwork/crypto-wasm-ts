import { BBSPublicKey, BBSSignature, BBSSignatureParams } from '../bbs';
import { LegoProvingKey, LegoProvingKeyUncompressed } from '../legosnark';
import {
  SaverChunkedCommitmentKey,
  SaverCiphertext,
  SaverEncryptionGens,
  SaverEncryptionGensUncompressed,
  SaverEncryptionKey,
  SaverProvingKey,
  SaverProvingKeyUncompressed
} from '../saver';
import { R1CS } from '@docknetwork/crypto-wasm';
import { BBSPlusPublicKeyG2, BBSPlusSignatureG1, BBSPlusSignatureParamsG1 } from '../bbs-plus';
import { PSPublicKey, PSSignature, PSSignatureParams } from '../ps';
import { Accumulator, AccumulatorParams, MembershipProvingKey, NonMembershipProvingKey } from '../accumulator';
import {
  BoundCheckBppParams,
  BoundCheckBppParamsUncompressed,
  BoundCheckSmcParams,
  BoundCheckSmcParamsUncompressed,
  BoundCheckSmcWithKVProverParams,
  BoundCheckSmcWithKVProverParamsUncompressed,
  BoundCheckSmcWithKVVerifierParams,
  BoundCheckSmcWithKVVerifierParamsUncompressed
} from '../bound-check';

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
  | SaverChunkedCommitmentKey
  | R1CS
  | Uint8Array
  | BoundCheckBppParams
  | BoundCheckBppParamsUncompressed
  | BoundCheckSmcParams
  | BoundCheckSmcParamsUncompressed
  | BoundCheckSmcWithKVProverParams
  | BoundCheckSmcWithKVProverParamsUncompressed
  | BoundCheckSmcWithKVVerifierParams
  | BoundCheckSmcWithKVVerifierParamsUncompressed;

export type BoundCheckParamType =
  | LegoProvingKey
  | LegoProvingKeyUncompressed
  | BoundCheckBppParams
  | BoundCheckBppParamsUncompressed
  | BoundCheckSmcParams
  | BoundCheckSmcParamsUncompressed
  | BoundCheckSmcWithKVProverParams
  | BoundCheckSmcWithKVProverParamsUncompressed
  | BoundCheckSmcWithKVVerifierParams
  | BoundCheckSmcWithKVVerifierParamsUncompressed;

export type BlindedAttributeEquality = [string, AttributeRef[]];

export type DateType = Date | string;
export type BoundType = number | DateType;

// The 1st element is an array of all attribute names as flattened and sorted and 2nd element is an array of types of those attributes
// in the same order
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
export const VB_ACCUMULATOR_22 = 'DockVBAccumulator2022';
export const ID_STR = 'id';
export const REV_CHECK_STR = 'revocationCheck';
export const REV_ID_STR = 'revocationId';
export const MEM_CHECK_STR = 'membership';
export const PROOF_STR = 'proof';
export const NON_MEM_CHECK_STR = 'non-membership';
export const BBS_CRED_PROOF_TYPE = 'Bls12381BBSSignatureDock2023';
export const BBS_BLINDED_CRED_PROOF_TYPE = 'Bls12381BlindedBBSSignatureDock2023';
export const BBS_PLUS_CRED_PROOF_TYPE = 'Bls12381BBS+SignatureDock2022';
export const BBS_PLUS_BLINDED_CRED_PROOF_TYPE = 'Bls12381BlindedBBS+SignatureDock2023';
export const PS_CRED_PROOF_TYPE = 'Bls12381PSSignatureDock2023';

export const LEGOGROTH16 = 'LegoGroth16';
export const SAVER = 'SAVER';

export const BPP = 'Bulletproofs++';
export const SMC = 'Set-membership-check';
export const SMC_KV = 'Set-membership-check-with-keyed-verification';

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

export function dockAccumulatorParams(): AccumulatorParams {
  return Accumulator.generateParams(ACCUMULATOR_PARAMS_LABEL_BYTES);
}

export function dockAccumulatorMemProvingKey(): MembershipProvingKey {
  return MembershipProvingKey.generate(ACCUMULATOR_PROVING_KEY_LABEL_BYTES);
}

export function dockAccumulatorNonMemProvingKey(): NonMembershipProvingKey {
  return NonMembershipProvingKey.generate(ACCUMULATOR_PROVING_KEY_LABEL_BYTES);
}

export function dockSaverEncryptionGens(): SaverEncryptionGens {
  return SaverEncryptionGens.generate(SAVER_ENCRYPTION_GENS_BYTES);
}

export function dockSaverEncryptionGensUncompressed(): SaverEncryptionGensUncompressed {
  return SaverEncryptionGens.generate(SAVER_ENCRYPTION_GENS_BYTES).decompress();
}

export enum SignatureTypes {
  Bbs = BBS_CRED_PROOF_TYPE,
  BbsPlus = BBS_PLUS_CRED_PROOF_TYPE,
  Ps = PS_CRED_PROOF_TYPE
}

export enum BlindSignatureTypes {
  Bbs = BBS_BLINDED_CRED_PROOF_TYPE,
  BbsPlus = BBS_PLUS_BLINDED_CRED_PROOF_TYPE
}

export enum RevocationStatusProtocols {
  Vb22 = VB_ACCUMULATOR_22
}

export enum BoundCheckProtocols {
  Legogroth16 = LEGOGROTH16,
  Bpp = BPP,
  Smc = SMC,
  SmcKV = SMC_KV
}

export enum VerifiableEncryptionProtocols {
  Saver = SAVER
}

export enum CircomProtocols {
  Legogroth16 = LEGOGROTH16
}
