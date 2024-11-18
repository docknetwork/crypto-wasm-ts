import { error } from 'console';
import { VerifyResult } from 'crypto-wasm-new';
import * as fs from 'fs';
import * as path from 'path';
import * as r1csf from 'r1csfile';
import {
  BoundCheckSnarkSetup,
  LegoProvingKey,
  LegoProvingKeyUncompressed,
  LegoVerifyingKey,
  LegoVerifyingKeyUncompressed,
  ParsedR1CSFile,
  PublicKeyBase
} from '../src';
import { FrostDkgParticipant, Round1Msg, Share } from '../src/frost-dkg';
import {
  buildProverStatement,
  buildVerifierStatement,
  isBBSPlus,
  isKvac,
  isPS,
  PublicKey,
  SecretKey,
  Signature,
  SignatureParams
} from './scheme';

/**
 * Converts a UTF-8 Encoded string to a byte array
 * @param string
 */
export const stringToBytes = (string: string): Uint8Array => Uint8Array.from(Buffer.from(string, 'utf-8'));

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
    error(result);
  }
  expect(verified).toEqual(true);
}

/**
 * Convert relative path from `tests` folder to absolute path.
 * @param relativePath - Path relative to tests folder
 */
function relPathToAbsPath(relativePath: string): string {
  let p = relativePath;
  if (relativePath.startsWith('/')) {
    p = p.slice(1);
  }
  return `${path.resolve('./')}/tests/${p}`;
}
/**
 *
 * @param bytes
 * @param relativePath - Path relative to `tests` folder
 */
export function writeByteArrayToFile(bytes: Uint8Array, relativePath: string) {
  fs.writeFileSync(relPathToAbsPath(relativePath), bytes);
}

/**
 *
 * @param relativePath - Path relative to tests folder
 */
export function readByteArrayFromFile(relativePath: string): Uint8Array {
  return fs.readFileSync(relPathToAbsPath(relativePath));
}

export function getBoundCheckSnarkKeys(
  loadSnarkSetupFromFiles: boolean
): [LegoProvingKeyUncompressed, LegoVerifyingKeyUncompressed] {
  let snarkProvingKey: LegoProvingKeyUncompressed, snarkVerifyingKey: LegoVerifyingKeyUncompressed;
  if (loadSnarkSetupFromFiles) {
    snarkProvingKey = new LegoProvingKeyUncompressed(
      readByteArrayFromFile('snark-setups/bound-check-proving-key-uncompressed.bin')
    );
    snarkVerifyingKey = new LegoVerifyingKeyUncompressed(
      readByteArrayFromFile('snark-setups/bound-check-verifying-key-uncompressed.bin')
    );
  } else {
    const pk = BoundCheckSnarkSetup();
    snarkProvingKey = pk.decompress();
    snarkVerifyingKey = pk.getVerifyingKeyUncompressed();
  }
  return [snarkProvingKey, snarkVerifyingKey];
}

export function runFrostKeygen(participants: FrostDkgParticipant[], pkBase: PublicKeyBase): [Uint8Array[], Uint8Array[], Uint8Array] {
  const msgs = new Map<number, Round1Msg>();
  for (let i = 0; i < participants.length; i++) {
    expect(participants[i].hasStarted()).toEqual(false);
    const msg = participants[i].startRound1(pkBase);
    expect(participants[i].hasStarted()).toEqual(true);
    msgs.set(participants[i].id, msg);
  }

  for (const [senderId, msg] of msgs) {
    for (let i = 0; i < participants.length; i++) {
      if (participants[i].id != senderId) {
        participants[i].processReceivedMessageInRound1(msg, pkBase);
      }
    }
  }

  const shares = new Map<number, Share[]>();
  for (let i = 0; i < participants.length; i++) {
    expect(participants[i].hasFinishedRound1()).toEqual(false);
    const s = participants[i].finishRound1();
    expect(participants[i].hasFinishedRound1()).toEqual(true);
    shares.set(participants[i].id, s);
  }

  for (const [senderId, s] of shares) {
    for (let i = 0; i < participants.length; i++) {
      if (participants[i].id != senderId) {
        participants[i].processReceivedSharesInRound2(senderId, s[participants[i].id - 1], pkBase);
      }
    }
  }

  const sks: Uint8Array[] = [];
  const pks: Uint8Array[] = [];
  const pkWithIds: [number, Uint8Array][] = [];
  let expectedTpk: Uint8Array;
  for (let i = 0; i < participants.length; i++) {
    expect(participants[i].hasFinishedRound2()).toEqual(false);
    const [s, p, t] = participants[i].finishRound2(pkBase);
    expect(participants[i].hasFinishedRound2()).toEqual(true);
    sks.push(s);
    pks.push(p);
    pkWithIds.push([participants[i].id, p]);
    if (i === 0) {
      expectedTpk = t;
    } else {
      // @ts-ignore
      expect(expectedTpk).toEqual(t);
    }
  }

  // @ts-ignore
  expect(expectedTpk as Uint8Array).toEqual(participants[0].generateThresholdPublicKeyFromPublicKeys(pkWithIds).value);
  // @ts-ignore
  return [sks, pks, expectedTpk];
}

export function getParamsAndKeys(messageCount: number, label?: Uint8Array): [SignatureParams, SecretKey, PublicKey] {
  const params = SignatureParams.generate(messageCount, label);

  const sk = SecretKey.generate(isPS() ? messageCount : void 0);
  const pk = isKvac() ? undefined : isBBSPlus() ? sk.generatePublicKeyG2(params) : sk.generatePublicKey(params);
  return [params, sk, pk];
}

export function signAndVerify(messages, params, sk, pk, encode = false): [Signature, VerifyResult] {
  const sig = isPS() ? Signature.generate(messages, sk, params) : Signature.generate(messages, sk, params, encode);
  const result = isKvac() ? sig.verify(messages, sk, params, encode) : isPS() ? sig.verify(messages, pk, params) : sig.verify(messages, pk, params, encode);
  return [sig, result];
}

export function proverStmt(params: SignatureParams, revealedMsgs: Map<number, Uint8Array>, pk?: PublicKey, encode = false) {
  return isPS() ? buildProverStatement(params, pk, revealedMsgs, encode) : buildProverStatement(params, revealedMsgs, encode)
}

export function verifierStmt(params: SignatureParams, revealedMsgs: Map<number, Uint8Array>, pk?: PublicKey, encode = false) {
  return isKvac() ? buildVerifierStatement(params, revealedMsgs, encode) : buildVerifierStatement(params, pk, revealedMsgs, encode);
}

export function logObject(obj) {
  console.dir(obj, {depth: null})
}