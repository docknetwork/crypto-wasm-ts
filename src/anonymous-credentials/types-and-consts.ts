export type StringOrObject = string | object;
export type AttributeRef = [number, string];
export type AttributeEquality = AttributeRef[];

export const VERSION_STR = '$version';
export const CRED_VERSION_STR = '$credentialVersion';
export const SCHEMA_STR = '$credentialSchema';
export const SUBJECT_STR = '$credentialSubject';
export const STATUS_STR = '$credentialStatus';
export const REGISTRY_ID_STR = '$registryId';
export const REV_CHECK_STR = '$revocationCheck';
export const MEM_CHECK_STR = 'membership';
export const NON_MEM_CHECK_STR = 'non-membership';

const te = new TextEncoder();
// Label used for generating signature parameters
export const SIGNATURE_PARAMS_LABEL = 'DockBBS+Signature2022';
export const SIGNATURE_PARAMS_LABEL_BYTES = te.encode(SIGNATURE_PARAMS_LABEL);

// Label used for generating accumulator parameters
export const ACCUMULATOR_PARAMS_LABEL = 'DockVBAccumulator2022';
export const ACCUMULATOR_PARAMS_LABEL_BYTES = te.encode(ACCUMULATOR_PARAMS_LABEL);

export const ACCUMULATOR_PROVING_KEY_LABEL = 'DockVBAccumulatorProvingKey2022';
export const ACCUMULATOR_PROVING_KEY_LABEL_BYTES = te.encode(ACCUMULATOR_PROVING_KEY_LABEL);
