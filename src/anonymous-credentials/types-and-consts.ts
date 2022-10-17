import { LegoProvingKey, LegoProvingKeyUncompressed } from '../legosnark';
import {
  SaverChunkedCommitmentGens,
  SaverCiphertext,
  SaverEncryptionKey,
  SaverProvingKey,
  SaverProvingKeyUncompressed
} from '../saver';

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
  | SaverChunkedCommitmentGens;

export type FlattenedSchema = [string[], object[]];
export type AttributeCiphertexts = { [key: string]: object | SaverCiphertext };

export const VERSION_STR = '$version';
export const CRED_VERSION_STR = '$credentialVersion';
export const SCHEMA_STR = '$credentialSchema';
export const SUBJECT_STR = '$credentialSubject';
export const STATUS_STR = '$credentialStatus';
export const REGISTRY_ID_STR = '$registryId';
export const REV_CHECK_STR = '$revocationCheck';
export const REV_ID_STR = '$revocationId';
export const MEM_CHECK_STR = 'membership';
export const NON_MEM_CHECK_STR = 'non-membership';

const te = new TextEncoder();
// Label used for generating signature parameters
export const SIGNATURE_PARAMS_LABEL = 'DockBBS+Signature2022';
export const SIGNATURE_PARAMS_LABEL_BYTES = te.encode(SIGNATURE_PARAMS_LABEL);

// Label used for generating accumulator parameters
export const ACCUMULATOR_PARAMS_LABEL = 'DockVBAccumulator2022';
export const ACCUMULATOR_PARAMS_LABEL_BYTES = te.encode(ACCUMULATOR_PARAMS_LABEL);

// Label used for generating accumulator proving key
export const ACCUMULATOR_PROVING_KEY_LABEL = 'DockVBAccumulatorProvingKey2022';
export const ACCUMULATOR_PROVING_KEY_LABEL_BYTES = te.encode(ACCUMULATOR_PROVING_KEY_LABEL);

// Label used for generating SAVER encryption generators
export const SAVER_ENCRYPTION_GENS_LABEL = 'DockSAVEREncryptionGens2022';
export const SAVER_ENCRYPTION_GENS_BYTES = te.encode(SAVER_ENCRYPTION_GENS_LABEL);
