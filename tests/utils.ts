import * as r1csf from 'r1csfile';
import * as fs from 'fs';
import * as path from 'path';
import {
  LegoProvingKey,
  LegoProvingKeyUncompressed,
  LegoVerifyingKey,
  LegoVerifyingKeyUncompressed,
  ParsedR1CSFile
} from '../src';
import { VerifyResult } from '@docknetwork/crypto-wasm';

/**
 * Converts a UTF-8 Encoded string to a byte array
 * @param string
 */
export const stringToBytes = (string: string): Uint8Array => Uint8Array.from(Buffer.from(string, 'utf-8'));

export function areUint8ArraysEqual(arr1: Uint8Array, arr2: Uint8Array): boolean {
  if (arr1.length !== arr2.length) {
    return false;
  }

  for (let i = 0; i < arr1.length; i++) {
    if (arr1[i] !== arr2[i]) {
      return false;
    }
  }

  return true;
}

/**
 * Given messages and indices to reveal, returns 2 maps, one for revealed messages and one for unrevealed
 * @param messages
 * @param revealedIndices
 */
export function getRevealedUnrevealed(
  messages: Uint8Array[],
  revealedIndices: Set<number>
): [Map<number, Uint8Array>, Map<number, Uint8Array>] {
  const revealedMsgs = new Map();
  const unrevealedMsgs = new Map();
  for (let i = 0; i < messages.length; i++) {
    if (revealedIndices.has(i)) {
      revealedMsgs.set(i, messages[i]);
    } else {
      unrevealedMsgs.set(i, messages[i]);
    }
  }

  return [revealedMsgs, unrevealedMsgs];
}

/**
 * Convert little-endian bytearray to BigInt
 * @param arr
 * @returns
 */
export function fromLeToBigInt(arr: Uint8Array): BigInt {
  let r = BigInt(0);
  let m = BigInt(1);
  for (let i = 0; i < arr.length; i++) {
    r += m * BigInt(arr[i]);
    m <<= BigInt(8);
  }
  return r;
}

export function circomArtifactPath(fileName: string): string {
  return `${path.resolve('./')}/tests/circom/${fileName}`;
}

export async function parseR1CSFile(r1csName: string): Promise<ParsedR1CSFile> {
  const parsed = await r1csf.readR1cs(circomArtifactPath(r1csName));
  await parsed.curve.terminate();
  return parsed;
}

export function getWasmBytes(fileName: string): Uint8Array {
  const content = fs.readFileSync(circomArtifactPath(fileName));
  return new Uint8Array(content);
}

export function checkLegoProvingKey(provingKey: unknown) {
  expect(provingKey instanceof LegoProvingKey).toBe(true);

  const pk: LegoProvingKey = provingKey as LegoProvingKey;

  const pkUncompressed = pk.decompress();
  expect(pkUncompressed instanceof LegoProvingKeyUncompressed).toBe(true);

  const vk = pk.getVerifyingKey();
  const vkUncompressed = pk.getVerifyingKeyUncompressed();

  expect(vk instanceof LegoVerifyingKey).toBe(true);
  expect(vkUncompressed instanceof LegoVerifyingKeyUncompressed).toBe(true);

  const vkUncompressed1 = vk.decompress();
  expect(vkUncompressed1 instanceof LegoVerifyingKeyUncompressed).toBe(true);

  expect(vkUncompressed1.value).toEqual(vkUncompressed.value);
}

export function checkResult(result: VerifyResult) {
  const verified = result.verified;
  if (!verified) {
    console.log(result.error);
  }
  expect(verified).toEqual(true);
}
