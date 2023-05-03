import { BBSPlusSignatureG1, bytearrayToHex, SignedMessages } from '../../../src';

export function signedToHex(signed: SignedMessages<BBSPlusSignatureG1>): object {
  const sig = signed.signature.hex;
  const enc = {};
  Object.keys(signed.encodedMessages).forEach((k) => {
    // @ts-ignore
    enc[k] = bytearrayToHex(signed.encodedMessages[k]);
  });
  return { encodedMessages: enc, signature: sig };
}

export function checkMapsEqual(mapA: Map<unknown, unknown>, mapB: Map<unknown, unknown>) {
  expect(mapA.size).toEqual(mapB.size);
  for (const key of mapA.keys()) {
    expect(mapA.get(key)).toEqual(mapB.get(key));
  }
}
