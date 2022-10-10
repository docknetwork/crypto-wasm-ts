// Utilities for signing and proving when working with messages as JS objects.

import { flatten, unflatten } from 'flat';
import {
  BBSPlusPublicKeyG2,
  BBSPlusSecretKey,
  BlindSignatureG1,
  BlindSignatureRequest,
  Encoder,
  getIndicesForMsgNames,
  SignatureG1,
  SignatureParamsG1,
  Statement,
  Witness,
  WitnessEqualityMetaStatement
} from './index';

// The following `ts-ignore` shouldn't be necessary as per https://github.com/microsoft/TypeScript/pull/33050 but it still is (on TS 4.8)
// @ts-ignore
export type MessageStructure = Record<string, null | MessageStructure>;

export function flattenMessageStructure(msgStructure: MessageStructure): object {
  return flatten(msgStructure);
}

export function getAdaptedSignatureParamsForMessages(
  params: SignatureParamsG1,
  msgStructure: MessageStructure
): SignatureParamsG1 {
  const flattened = flattenMessageStructure(msgStructure);
  return params.adapt(Object.keys(flattened).length);
}

export class SigParamsGetter {
  defaultLabel?: Uint8Array;

  constructor(defaultLabel?: Uint8Array) {
    this.defaultLabel = defaultLabel;
  }

  getSigParamsOfRequiredSize(msgCount: number, labelOrParams?: Uint8Array | SignatureParamsG1): SignatureParamsG1 {
    if (labelOrParams === undefined && this.defaultLabel === undefined) {
      throw new Error(`No default label or argument to create signature params of size of size ${msgCount}`);
    }
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
    } else if (labelOrParams !== undefined) {
      sigParams = SignatureParamsG1.generate(msgCount, labelOrParams);
    } else {
      sigParams = SignatureParamsG1.generate(msgCount, this.defaultLabel);
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

export function getSigParamsForMsgStructure(
  msgStructure: MessageStructure,
  labelOrParams: Uint8Array | SignatureParamsG1
): SignatureParamsG1 {
  const msgCount = Object.keys(flattenMessageStructure(msgStructure)).length;
  return getSigParamsOfRequiredSize(msgCount, labelOrParams);
}

export interface SignedMessages {
  encodedMessages: { [key: string]: Uint8Array };
  signature: SignatureG1;
}

export interface BlindSignedMessages {
  encodedMessages: { [key: string]: Uint8Array };
  signature: BlindSignatureG1;
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
 * to signing and then verifies the signature.
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
  let found = 0;
  for (let i = 0; i < names.length; i++) {
    if (revealedMsgNames.has(names[i])) {
      revealedMsgs.set(i, encodedValues[i]);
      found++;
    } else {
      unrevealedMsgs.set(i, encodedValues[i]);
    }
  }

  if (revealedMsgNames.size !== found) {
    throw new Error(
      `Some of the revealed message names were not found in the given messages object, ${
        revealedMsgNames.size - found
      } extra names found`
    );
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
  msgStructure: MessageStructure,
  encoder: Encoder
): Map<number, Uint8Array> {
  const revealed = new Map<number, Uint8Array>();
  const names = Object.keys(flattenMessageStructure(msgStructure)).sort();
  const flattenedRevealed = flatten(revealedMsgsRaw) as object;
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
 * Generate a request for getting a blind signature from a signer, i.e. some messages are hidden from signer.
 * Returns the blinding, the request to be sent to the signer and the witness to be used in the proof
 * @param hiddenMsgNames - The names of messages being hidden from signer
 * @param messages - All the message, i.e. known + hidden.
 * @param labelOrParams
 * @param encoder
 * @param blinding - Optional, if not provided, its generated randomly
 */
export function genBlindSigRequestAndWitness(
  hiddenMsgNames: Set<string>,
  messages: object,
  labelOrParams: Uint8Array | SignatureParamsG1,
  encoder: Encoder,
  blinding?: Uint8Array
): [Uint8Array, BlindSignatureRequest, Uint8Array] {
  const [names, encodedValues] = encoder.encodeMessageObject(messages);
  const hiddenMsgs = new Map<number, Uint8Array>();
  let found = 0;
  hiddenMsgNames.forEach((n) => {
    const i = names.indexOf(n);
    if (i !== -1) {
      hiddenMsgs.set(i, encodedValues[i]);
      found++;
    }
  });
  if (hiddenMsgNames.size !== found) {
    throw new Error(
      `Some of the hidden message names were not found in the given messages object, ${
        hiddenMsgNames.size - found
      } missing names`
    );
  }
  const sigParams = getSigParamsOfRequiredSize(names.length, labelOrParams);
  const [blinding_, request] = BlindSignatureG1.generateRequest(hiddenMsgs, sigParams, false, blinding);
  const committeds = [blinding_];
  for (const i of request.blindedIndices) {
    committeds.push(hiddenMsgs.get(i) as Uint8Array);
  }
  const witness = Witness.pedersenCommitment(committeds);
  return [blinding_, request, witness];
}

/**
 * Get the statement to be used in composite proof for the blind signature request
 * @param request
 * @param sigParams
 */
export function getStatementForBlindSigRequest(
  request: BlindSignatureRequest,
  sigParams: SignatureParamsG1
): Uint8Array {
  const commKey = sigParams.getParamsForIndices(request.blindedIndices);
  return Statement.pedersenCommitmentG1(commKey, request.commitment);
}

/**
 * Used by the signer to create a blind signature
 * @param blindSigRequest - The blind sig request sent by user.
 * @param knownMessages - The messages known to the signer
 * @param secretKey
 * @param msgStructure
 * @param labelOrParams
 * @param encoder
 */
export function blindSignMessageObject(
  blindSigRequest: BlindSignatureRequest,
  knownMessages: object,
  secretKey: BBSPlusSecretKey,
  msgStructure: MessageStructure,
  labelOrParams: Uint8Array | SignatureParamsG1,
  encoder: Encoder
): BlindSignedMessages {
  const flattenedAllNames = Object.keys(flattenMessageStructure(msgStructure)).sort();
  const [flattenedUnblindedNames, encodedValues] = encoder.encodeMessageObject(knownMessages);

  const knownMessagesEncoded = new Map<number, Uint8Array>();
  const encodedMessages: { [key: string]: Uint8Array } = {};
  flattenedAllNames.forEach((n, i) => {
    const j = flattenedUnblindedNames.indexOf(n);
    if (j > -1) {
      knownMessagesEncoded.set(i, encodedValues[j]);
      encodedMessages[n] = encodedValues[j];
    }
  });

  if (flattenedUnblindedNames.length !== knownMessagesEncoded.size) {
    throw new Error(
      `Message structure incompatible with knownMessages. Got ${flattenedUnblindedNames.length} to encode but encoded only ${knownMessagesEncoded.size}`
    );
  }
  if (flattenedAllNames.length !== knownMessagesEncoded.size + blindSigRequest.blindedIndices.length) {
    throw new Error(
      `Message structure likely incompatible with knownMessages and blindSigRequest. ${flattenedAllNames.length} != (${knownMessagesEncoded.size} + ${blindSigRequest.blindedIndices.length})`
    );
  }

  const sigParams = getSigParamsOfRequiredSize(flattenedAllNames.length, labelOrParams);
  const blindSig = BlindSignatureG1.generate(
    blindSigRequest.commitment,
    knownMessagesEncoded,
    secretKey,
    sigParams,
    false
  );
  return {
    encodedMessages: encodedMessages,
    signature: blindSig
  };
}

/**
 * Takes an equality of messages across statements and returns the `MetaStatement` to be used in the proof.
 * @param equality - Map with key as the statement index and value as the message names of that statement
 * that are to be proved equal and the message structure.
 */
export function createWitnessEqualityMetaStatement(
  equality: Map<number, [msgNames: string[], msgStructure: MessageStructure]>
): WitnessEqualityMetaStatement {
  const ms = new WitnessEqualityMetaStatement();
  for (const [sIdx, [names, struct]] of equality.entries()) {
    const indices = getIndicesForMsgNames(names, struct);
    indices.forEach((i) => ms.addWitnessRef(sIdx, i));
  }
  return ms;
}
