// Utilities for signing and proving when working with messages as JS objects.

import { flatten, unflatten } from 'flat';
import {
  BBSPlusPublicKeyG2,
  BBSPlusSecretKey,
  Encoder,
  getIndicesForMsgNames,
  SignatureG1,
  SignatureParamsG1,
  WitnessEqualityMetaStatement
} from './index';

export function getAdaptedSignatureParamsForMessages(
  params: SignatureParamsG1,
  msgStructure: object
): SignatureParamsG1 {
  const flattened = flatten(msgStructure);
  // @ts-ignore
  return params.adapt(Object.keys(flattened).length);
}

export class SigParamsGetter {
  defaultLabel?: Uint8Array;

  constructor(defaultLabel?: Uint8Array) {
    this.defaultLabel = defaultLabel;
  }

  getSigParamsOfRequiredSize(msgCount: number, labelOrParams: Uint8Array | SignatureParamsG1): SignatureParamsG1 {
    let sigParams: SignatureParamsG1;
    if (labelOrParams instanceof SignatureParamsG1) {
      if (labelOrParams.supportedMessageCount() !== msgCount) {
        if (labelOrParams.label === undefined) {
          throw new Error(
            `Signature params mismatch, needed ${msgCount}, got ${labelOrParams.supportedMessageCount()}`
          );
        } else {
          sigParams = labelOrParams.adapt(msgCount);
        }
      } else {
        sigParams = labelOrParams;
      }
    } else if (labelOrParams instanceof Uint8Array) {
      sigParams = SignatureParamsG1.generate(msgCount, labelOrParams);
    } else if (this.defaultLabel !== undefined) {
      sigParams = SignatureParamsG1.generate(msgCount, this.defaultLabel);
    } else {
      throw new Error(`Could not get SignatureParamsG1 of size ${msgCount}`);
    }
    return sigParams;
  }
}

/**
 * Gives `SignatureParamsG1` that can sign `msgCount` number of messages.
 * @param msgCount
 * @param labelOrParams
 */
export function getSigParamsOfRequiredSize(
  msgCount: number,
  labelOrParams: Uint8Array | SignatureParamsG1
): SignatureParamsG1 {
  let sigParams: SignatureParamsG1;
  if (labelOrParams instanceof SignatureParamsG1) {
    if (labelOrParams.supportedMessageCount() !== msgCount) {
      if (labelOrParams.label === undefined) {
        throw new Error(`Signature params mismatch, needed ${msgCount}, got ${labelOrParams.supportedMessageCount()}`);
      } else {
        sigParams = labelOrParams.adapt(msgCount);
      }
    } else {
      sigParams = labelOrParams;
    }
  } else {
    sigParams = SignatureParamsG1.generate(msgCount, labelOrParams);
  }
  return sigParams;
}

interface SignedMessages {
  encodedMessages: { [key: string]: Uint8Array };
  signature: SignatureG1;
}

/**
 * Takes messages as a JS object, flattens it, encodes the values and creates a BBS+ signature in group G1. Returns the
 * encoded messages and the signature.
 * @param messages
 * @param secretKey
 * @param labelOrParams
 * @param encoder
 */
export function signMessageObject(
  messages: object,
  secretKey: BBSPlusSecretKey,
  labelOrParams: Uint8Array | SignatureParamsG1,
  encoder: Encoder
): SignedMessages {
  const [names, encodedValues] = encoder.encodeMessageObject(messages);
  const msgCount = names.length;

  const sigParams = getSigParamsOfRequiredSize(msgCount, labelOrParams);

  const signature = SignatureG1.generate(encodedValues, secretKey, sigParams, false);

  // Encoded message as an object with key as the flattened name
  const encodedMessages: { [key: string]: Uint8Array } = {};
  for (let i = 0; i < msgCount; i++) {
    encodedMessages[names[i]] = encodedValues[i];
  }

  return {
    encodedMessages,
    signature
  };
}

/**
 * Verifies the signature on the given messages. Takes the messages as a JS object, flattens it, encodes the values similar
 * to signing and then verifies the sigature.
 * @param messages
 * @param signature
 * @param publicKey
 * @param labelOrParams
 * @param encoder
 */
export function verifyMessageObject(
  messages: object,
  signature: SignatureG1,
  publicKey: BBSPlusPublicKeyG2,
  labelOrParams: Uint8Array | SignatureParamsG1,
  encoder: Encoder
): boolean {
  const [_, encodedValues] = encoder.encodeMessageObject(messages);
  const msgCount = encodedValues.length;

  const sigParams = getSigParamsOfRequiredSize(msgCount, labelOrParams);
  const result = signature.verify(encodedValues, publicKey, sigParams, false);
  return result.verified;
}

/**
 * Given the messages as a JS object and the names (use "." for nested property names) of the messages to reveal, returns
 * the encoded messages to reveal and hide as separate maps with the key being the index of the message when the object is
 * flattened.
 * @param messages
 * @param revealedMsgNames
 * @param encoder
 */
export function getRevealedAndUnrevealed(
  messages: object,
  revealedMsgNames: Set<string>,
  encoder: Encoder
): [Map<number, Uint8Array>, Map<number, Uint8Array>, object] {
  const [names, encodedValues] = encoder.encodeMessageObject(messages);
  const revealedMsgs = new Map<number, Uint8Array>();
  const unrevealedMsgs = new Map<number, Uint8Array>();
  for (let i = 0; i < names.length; i++) {
    if (revealedMsgNames.has(names[i]) === true) {
      revealedMsgs.set(i, encodedValues[i]);
    } else {
      unrevealedMsgs.set(i, encodedValues[i]);
    }
  }

  // This will be given to the verifier to encode independently.
  const revealedMsgsRaw: { [key: string]: unknown } = {};
  const flattened = flatten(messages);
  // @ts-ignore
  revealedMsgNames.forEach((n: string) => (revealedMsgsRaw[n] = flattened[n]));
  return [revealedMsgs, unrevealedMsgs, unflatten(revealedMsgsRaw)];
}

/**
 * Used by the verifier to encode the revealed messages given by the prover.
 * @param revealedMsgsRaw - Revealed messages given by the prover.
 * @param msgStructure - Message structure, i.e. the structure of JS object with key names but values redacted.
 * @param encoder
 */
export function encodeRevealedMsgs(
  revealedMsgsRaw: object,
  msgStructure: object,
  encoder: Encoder
): Map<number, Uint8Array> {
  const revealed = new Map<number, Uint8Array>();
  // @ts-ignore
  const names = Object.keys(flatten(msgStructure)).sort();
  const flattenedRevealed = flatten(revealedMsgsRaw);
  // @ts-ignore
  Object.entries(flattenedRevealed).forEach(([n, v]) => {
    const i = names.indexOf(n);
    if (i === -1) {
      throw new Error(`Message name ${n} was not found`);
    }
    revealed.set(i, encoder.encodeMessage(n, v));
  });
  return revealed;
}

/**
 * Takes an equality of messages across statements and returns the `MetaStatement` to be used in the proof.
 * @param equality - Map with key as the statement index and value as the message names of that statement
 * that are to be proved equal and the message structure.
 */
export function createWitnessEqualityMetaStatement(
  equality: Map<number, [msgNames: string[], msgStructure: object]>
): WitnessEqualityMetaStatement {
  const ms = new WitnessEqualityMetaStatement();
  for (const [sIdx, [names, struct]] of equality.entries()) {
    const indices = getIndicesForMsgNames(names, struct);
    indices.forEach((i) => ms.addWitnessRef(sIdx, i));
  }
  return ms;
}
