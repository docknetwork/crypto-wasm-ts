/**
 * Expects JSON object with field `value` as a bytearray and returns the bytearray
 * @param json
 * @returns
 */
import { generateFieldElementFromBytes, generateRandomFieldElement } from '@docknetwork/crypto-wasm';
import { flatten } from 'flat';

export function jsonObjToUint8Array(json: string): Uint8Array {
  const obj = JSON.parse(json);
  const arr = getUint8ArraysFromObject(obj, ['value']);
  return arr[0];
}

export function getUint8ArraysFromObject(obj: Record<string, unknown>, keys: string[]): Uint8Array[] {
  const values: Uint8Array[] = [];
  for (const k of keys) {
    if (obj[k] === undefined) {
      throw new Error(`Missing field "${k}"`);
    }
    if (obj[k] instanceof Uint8Array) {
      values.push(obj[k] as Uint8Array);
      continue;
    }
    if (!(obj[k] instanceof Array)) {
      throw new Error(`value of key "${k}" should be Array`);
    }
    values.push(obj[k] as Uint8Array);
  }

  return values;
}

export function bytesToChallenge(bytes: Uint8Array): Uint8Array {
  return generateFieldElementFromBytes(bytes);
}

export function isNumberBiggerThanNBits(num: number, bits: number): boolean {
  // Following can be done using bit shifts, but they only work for small number of shifts. Checked in Chrome and FF
  return num.toString(2).length > bits;
}

/**
 * Throws an error if the given number takes more bits than expected.
 * @param num
 * @param size - expected size in bits
 */
export function ensurePositiveIntegerOfSize(num: number, size: number) {
  if (!(Number.isSafeInteger(num) && num > 0)) {
    throw new Error(`{num} should be safe positive integer`);
  }
  if (isNumberBiggerThanNBits(num, size)) {
    throw new Error(`{num} was found to be bigger than {size} bits`);
  }
}

export function randomFieldElement(seed?: Uint8Array): Uint8Array {
  return generateRandomFieldElement(seed);
}

/**
 * Takes an object, nested or otherwise and flattens it to list. Returns 2 arrays, 1st array contains keys in alphabetical
 * sorted order and 2nd contains the values in the order of the keys. Both arrays have same size. Nested keys have their
 * parent key name prefixed with a dot, eg for key `lat` in `{location: {lat: 25.01, long: 30.02} }`, it becomes `location.lat`
 * @param obj
 * @param flattenOptions
 */
export function flattenObjectToKeyValuesList(obj: object, flattenOptions = undefined): [string[], unknown[]] {
  const flattened = flatten(obj, flattenOptions) as object;
  const keys = Object.keys(flattened).sort();
  // @ts-ignore
  const values = keys.map((k) => flattened[k]);
  return [keys, values];
}

export function isPositiveInteger(n: unknown): boolean {
  // @ts-ignore
  return Number.isInteger(n) && n >= 0;
}

export function bytearrayToHex(b: Uint8Array): string {
  const alphabet = '0123456789abcdef';
  let hex = '';
  b.forEach((v) => {
    hex += alphabet[v >> 4] + alphabet[v & 15];
  });
  return hex;
}
