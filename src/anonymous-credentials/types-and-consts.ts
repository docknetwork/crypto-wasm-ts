import { KBUniversalMembershipWitness, KBUniversalNonMembershipWitness } from '../accumulator/kb-acccumulator-witness';
import { KBUniversalAccumulatorValue } from '../accumulator/kb-universal-accumulator';
import { BBSPublicKey, BBSSecretKey, BBSSignature, BBSSignatureParams } from '../bbs';
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
import { R1CS } from 'crypto-wasm-new';
import { BBSPlusPublicKeyG2, BBSPlusSecretKey, BBSPlusSignatureG1, BBSPlusSignatureParamsG1 } from '../bbs-plus';
import { PSPublicKey, PSSecretKey, PSSignature, PSSignatureParams } from '../ps';
import {
  Accumulator,
  AccumulatorParams,
  AccumulatorPublicKey,
  AccumulatorSecretKey,
  MembershipProvingKey,
  NonMembershipProvingKey,
  VBMembershipWitness,
  VBNonMembershipWitness
} from '../accumulator';
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
import { PederCommKey, PederCommKeyUncompressed } from '../ped-com';
import { BDDT16Mac, BDDT16MacParams, BDDT16MacSecretKey } from '../bddt16-mac';

export type StringOrObject = string | object;
// Reference to an attribute of a credential. The first item of the pair is the credential index in the presentation and the
// second item is the fully qualified attribute name.
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

// The first item is the fully qualified attribute name
export type BlindedAttributeEquality = [string, AttributeRef[]];

export type DateType = Date | string;
export type BoundType = number | DateType;

// The 1st element is an array of all attribute names as flattened and sorted and 2nd element is an array of types of those attributes
// in the same order
export type FlattenedSchema = [string[], object[]];
export type AttributeCiphertexts = { [key: string]: object | SaverCiphertext | SaverCiphertext[] };

export type SecretKey = BBSSecretKey | BBSPlusSecretKey | PSSecretKey | BDDT16MacSecretKey;
export type PublicKey = BBSPublicKey | BBSPlusPublicKeyG2 | PSPublicKey;
export type Signature = BBSSignature | BBSPlusSignatureG1 | PSSignature | BDDT16Mac;
export type SignatureParams = BBSSignatureParams | BBSPlusSignatureParamsG1 | PSSignatureParams | BDDT16MacParams;
export type SignatureParamsClass =
  | typeof BBSSignatureParams
  | typeof BBSPlusSignatureParamsG1
  | typeof PSSignatureParams
  | typeof BDDT16MacParams;

// A parameter to verify the credential. This could be a public key or the secret key. Secret key is used to verify credentials
// in situations where the issuer and verifier are the same entity (or share the secret key). Thus, such credentials are not
// publicly verifiable
export type CredentialVerificationParam = PublicKey | BDDT16MacSecretKey;
// A parameter to verify the proof of accumulator (non)membership in zero-knowledge. This could be a public key or the secret key.
// Secret key is used to verify the proof in situations where the revocation authority and verifier are the same entity (or share the secret key).
// Thus, such proofs are not publicly verifiable
export type AccumulatorVerificationParam = AccumulatorPublicKey | AccumulatorSecretKey;

export type AccumulatorWitnessType =
  | VBMembershipWitness
  | VBNonMembershipWitness
  | KBUniversalMembershipWitness
  | KBUniversalNonMembershipWitness;
export type AccumulatorValueType = Uint8Array | KBUniversalAccumulatorValue;

export const VERSION_STR = 'version';
export const CRYPTO_VERSION_STR = 'cryptoVersion';
export const SCHEMA_STR = 'credentialSchema';

export const JSON_SCHEMA_STR = 'jsonSchema';
export const FULL_SCHEMA_STR = 'fullJsonSchema';
export const SCHEMA_TYPE_STR = 'JsonSchemaValidator2018';

export const SCHEMA_PROPS_STR = 'properties';
export const SCHEMA_DETAILS_STR = 'details';

export const SUBJECT_STR = 'credentialSubject';
export const STATUS_STR = 'credentialStatus';
export const TYPE_STR = 'type';
export const VB_ACCUMULATOR_22 = 'DockVBAccumulator2022';
export const KB_UNI_ACCUMULATOR_24 = 'DockKBUniversalAccumulator2024';
export const ID_STR = 'id';
export const REV_CHECK_STR = 'revocationCheck';
export const REV_ID_STR = 'revocationId';
export const MEM_CHECK_STR = 'membership';
export const NON_MEM_CHECK_STR = 'non-membership';
export const MEM_CHECK_KV_STR = 'membership-kv';
export const NON_MEM_CHECK_KV_STR = 'non-membership-kv';
export const PROOF_STR = 'proof';
export const BBS_CRED_PROOF_TYPE = 'Bls12381BBSSignatureDock2023';
export const BBS_BLINDED_CRED_PROOF_TYPE = 'Bls12381BlindedBBSSignatureDock2023';
export const BBS_PLUS_CRED_PROOF_TYPE = 'Bls12381BBS+SignatureDock2022';
export const BBS_PLUS_BLINDED_CRED_PROOF_TYPE = 'Bls12381BlindedBBS+SignatureDock2023';
export const PS_CRED_PROOF_TYPE = 'Bls12381PSSignatureDock2023';
export const BDDT16_CRED_PROOF_TYPE = 'Bls12381BDDT16MACDock2024';
export const BDDT16_BLINDED_CRED_PROOF_TYPE = 'Bls12381BlindedBDDT16MACDock2024';
export const LEGOGROTH16 = 'LegoGroth16';
export const SAVER = 'SAVER';

export const BPP = 'Bulletproofs++';
export const SMC = 'Set-membership-check';
export const SMC_KV = 'Set-membership-check-with-keyed-verification';

export const UPROVE = 'UProve';

const te = new TextEncoder();
// Label used for generating BBS+ signature parameters
export const BBS_SIGNATURE_PARAMS_LABEL = 'DockBBSSignature2023';
export const BBS_SIGNATURE_PARAMS_LABEL_BYTES = te.encode(BBS_SIGNATURE_PARAMS_LABEL);

// Label used for generating BBS+ signature parameters
export const BBS_PLUS_SIGNATURE_PARAMS_LABEL = 'DockBBS+Signature2022';
export const BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES = te.encode(BBS_PLUS_SIGNATURE_PARAMS_LABEL);

// Label used for generating BDDT16 MAC parameters
export const BDDT16_MAC_PARAMS_LABEL = 'DockBDDT16MAC';
export const BDDT16_MAC_PARAMS_LABEL_BYTES = te.encode(BDDT16_MAC_PARAMS_LABEL);

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
export const SAVER_ENCRYPTION_GENS_LABEL_BYTES = te.encode(SAVER_ENCRYPTION_GENS_LABEL);

// Label used for generating Bulletproofs++ generators
export const BPP_GENS_LABEL = 'DockBulletproofs++2023';
export const BPP_GENS_LABEL_BYTES = te.encode(BPP_GENS_LABEL);

// Label used for generating commitment key for proving inequality
export const INEQUALITY_COMM_KEY_LABEL = 'DockInequalityDiscreteLog2023';
export const INEQUALITY_COMM_KEY_LABEL_BYTES = te.encode(INEQUALITY_COMM_KEY_LABEL);

export const EMPTY_SCHEMA_ID = 'data:application/json;charset=utf-8,';

export const SCHEMA_FIELDS = [`${SCHEMA_STR}.${SCHEMA_DETAILS_STR}`, `${SCHEMA_STR}.${ID_STR}`, `${SCHEMA_STR}.${TYPE_STR}`, `${SCHEMA_STR}.${VERSION_STR}`];

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
  return SaverEncryptionGens.generate(SAVER_ENCRYPTION_GENS_LABEL_BYTES);
}

export function dockSaverEncryptionGensUncompressed(): SaverEncryptionGensUncompressed {
  return SaverEncryptionGens.generate(SAVER_ENCRYPTION_GENS_LABEL_BYTES).decompress();
}

export function dockBoundCheckBppSetup(): BoundCheckBppParams {
  return new BoundCheckBppParams(BPP_GENS_LABEL_BYTES);
}

export function dockBoundCheckBppSetupUncompressed(): BoundCheckBppParamsUncompressed {
  return new BoundCheckBppParams(BPP_GENS_LABEL_BYTES).decompress();
}

export function dockInequalityCommKey(): PederCommKey {
  return new PederCommKey(INEQUALITY_COMM_KEY_LABEL_BYTES);
}

export function dockInequalityCommKeyUncompressed(): PederCommKeyUncompressed {
  return new PederCommKey(INEQUALITY_COMM_KEY_LABEL_BYTES).decompress();
}

export enum SignatureType {
  Bbs = BBS_CRED_PROOF_TYPE,
  BbsPlus = BBS_PLUS_CRED_PROOF_TYPE,
  Ps = PS_CRED_PROOF_TYPE,
  Bddt16 = BDDT16_CRED_PROOF_TYPE
}

export enum BlindSignatureType {
  Bbs = BBS_BLINDED_CRED_PROOF_TYPE,
  BbsPlus = BBS_PLUS_BLINDED_CRED_PROOF_TYPE,
  Bddt16 = BDDT16_BLINDED_CRED_PROOF_TYPE
}

export enum RevocationStatusProtocol {
  Vb22 = VB_ACCUMULATOR_22,
  KbUni24 = KB_UNI_ACCUMULATOR_24
}

export enum BoundCheckProtocol {
  Legogroth16 = LEGOGROTH16,
  Bpp = BPP,
  Smc = SMC,
  SmcKV = SMC_KV
}

export enum VerifiableEncryptionProtocol {
  Saver = SAVER
}

export enum CircomProtocol {
  Legogroth16 = LEGOGROTH16
}

export enum InequalityProtocol {
  Uprove = UPROVE
}
