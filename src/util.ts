/**
 * Expects JSON object with field `value` as a bytearray and returns the bytearray
 * @param json
 * @returns
 */
import { generateFieldElementFromBytes, generateRandomFieldElement } from '@docknetwork/crypto-wasm';

export function jsonObjToUint8Array(json: string): Uint8Array {
  const obj = JSON.parse(json);
  if (obj.value === undefined) {
    throw new Error('Missing field `value`');
  }
  if (obj.value instanceof Uint8Array) {
    throw new Error('`value` should be Uint8Array');
  }
  return obj.value;
}

export function getUint8ArraysFromObject(obj: Record<string, any>, keys: string[]): Uint8Array[] {
  const values: Uint8Array[] = [];
  keys.forEach((k) => {
    if (obj[k] === undefined) {
      throw new Error(`Missing field "${k}"`);
    }
    if (obj[k] instanceof Uint8Array) {
      throw new Error(`value of key "${k}" should be Uint8Array`);
    }
    values.push(new Uint8Array(obj[k]));
  });

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
