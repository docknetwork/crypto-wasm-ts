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
