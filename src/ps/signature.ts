import { PSSignatureParams } from './params';
import {
  psBlindSign,
  psSign,
  psUnblindSignature,
  psVerify,
  generateRandomFieldElement,
  VerifyResult,
  psMessageCommitment,
  PSCommitmentOrMessage
} from 'crypto-wasm-new';
import { PSPublicKey, PSSecretKey } from './keys';
import { BytearrayWrapper } from '../bytearray-wrapper';
import { encodeRevealedMessageObject } from '../sign-verify-js-objs';
import { Encoder, MessageEncoder } from '../encoder';
import { psAggregateSignatures } from 'crypto-wasm-new';
import { MessageStructure, SignedMessages } from '../types';

/**
 *  Modified Pointcheval-Sanders signature used in `Coconut`.
 */
export class PSSignature extends MessageEncoder {
  /**
   * Signer creates a new signature
   * @param messages - Ordered list of messages. Order and contents should be kept same for both signer and verifier
   * @param secretKey
   * @param params
   */
  static generate(messages: Uint8Array[], secretKey: PSSecretKey, params: PSSignatureParams): PSSignature {
    if (messages.length !== params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    if (messages.length !== secretKey.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${secretKey.supportedMessageCount()} supported by the secret key`
      );
    }
    const sig = psSign(messages, secretKey.value, params.value);
    return new PSSignature(sig);
  }

  /**
   * Verify the signature
   * @param messages - Ordered list of messages. Order and contents should be kept same for both signer and verifier
   * @param publicKey
   * @param params
   */
  verify(messages: Uint8Array[], publicKey: PSPublicKey, params: PSSignatureParams): VerifyResult {
    if (messages.length !== params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    if (messages.length !== publicKey.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${publicKey.supportedMessageCount()} supported by the public key`
      );
    }
    return psVerify(messages, this.value, publicKey.value, params.value);
  }

  /**
   * Aggregates signatures received from participants.
   * @param signatures
   * @param h
   * @returns
   */
  static aggregate(signatures: Map<number, PSSignature>, h: Uint8Array): PSSignature {
    const rawSignatures = new Map([...signatures.entries()].map(([participant, sig]) => [participant, sig.value]));

    return new PSSignature(psAggregateSignatures(rawSignatures, h));
  }

  static signMessageObject(
    messages: Object,
    secretKey: PSSecretKey,
    labelOrParams: Uint8Array | PSSignatureParams,
    encoder: Encoder
  ): SignedMessages<PSSignature> {
    const encodedMessages = encoder.encodeMessageObjectAsObjectConstantTime(messages);
    const encodedMessageList = Object.values(encodedMessages);
    const msgCount = encodedMessageList.length;

    const sigParams = PSSignatureParams.getSigParamsOfRequiredSize(msgCount, labelOrParams);
    const supportedMsgCount = secretKey.supportedMessageCount();
    if (supportedMsgCount < msgCount) {
      throw new Error(`Unsupported message count - supported up to ${supportedMsgCount}, received: ${msgCount}`);
    } else if (supportedMsgCount > msgCount) {
      secretKey = secretKey.adaptForLess(msgCount);
    }
    const signature = PSSignature.generate(encodedMessageList, secretKey, sigParams);

    return {
      encodedMessages,
      signature
    };
  }

  /**
   * Verifies the signature on the given messages. Takes the messages as a JS object, flattens it, encodes the values similar
   * to signing and then verifies the signature.
   * @param messages
   * @param publicKey
   * @param labelOrParams
   * @param encoder
   * @param useConstantTimeEncoding
   */
  verifyMessageObject(
    messages: object,
    publicKey: PSPublicKey,
    labelOrParams: Uint8Array | PSSignatureParams,
    encoder: Encoder,
    useConstantTimeEncoding = true,
  ): VerifyResult {
    const [_, encodedValues] = useConstantTimeEncoding ? encoder.encodeMessageObjectConstantTime(messages) : encoder.encodeMessageObject(messages);
    const msgCount = encodedValues.length;

    const sigParams = PSSignatureParams.getSigParamsOfRequiredSize(msgCount, labelOrParams);
    const supportedMsgCount = publicKey.supportedMessageCount();
    if (supportedMsgCount < msgCount) {
      throw new Error(`Unsupported message count - supported up to ${supportedMsgCount}, received: ${msgCount}`);
    } else if (supportedMsgCount > msgCount) {
      publicKey = publicKey.adaptForLess(msgCount);
    }
    return this.verify(encodedValues, publicKey, sigParams);
  }
}

/**
 * Modified Pointcheval-Sanders blind signature used in `Coconut`.
 */
export class PSBlindSignature extends BytearrayWrapper {
  /**
   * Generate blinding for creating the commitment used in the request for blind signature
   * @param seed - Optional seed to serve as entropy for the blinding.
   */
  static generateBlinding(seed?: Uint8Array): Uint8Array {
    return generateRandomFieldElement(seed);
  }

  /**
   * Generates a blind signature over the commitment of unrevealed messages and revealed messages
   * @param messages - Iterator producing blinded messages (commitments) or revealed messages
   * @param secretKey
   * @param h
   */
  static generate(messages: Iterable<PSCommitmentOrMessage>, secretKey: PSSecretKey, h: Uint8Array): PSBlindSignature {
    return new PSBlindSignature(psBlindSign(messages, secretKey.value, h));
  }

  /**
   * Unblind the blind signature to get a regular signature that can be verified
   * @param indexedBlindings
   * @param pk
   */
  unblind(indexedBlindings: Map<number, Uint8Array>, pk: PSPublicKey, h: Uint8Array): PSSignature {
    return new PSSignature(psUnblindSignature(this.value, indexedBlindings, pk.value, h));
  }

  /**
   * Generate a request for a blind signature
   * @param messagesToBlind - messages the requester wants to hide from the signer. The key of the map is the index of the
   * message as per the params.
   * @param params
   * @param h
   * @param blindings - If no blinding is provided for a message, a random blinding will be generated for each message and written to this map
   * @param blinding
   * @param revealedMessages - Any messages that the requester wishes to inform the signer about. This is for informational
   * purpose only and has no cryptographic use.
   */
  static generateRequest(
    messagesToBlind: Map<number, Uint8Array>,
    params: PSSignatureParams,
    h: Uint8Array,
    blindings: Map<number, Uint8Array>,
    blinding: Uint8Array = generateRandomFieldElement(),
    revealedMessages: Map<number, Uint8Array> = new Map()
  ): [Uint8Array, PSBlindSignatureRequest] {
    const hArr = params.getParamsForIndices([...messagesToBlind.keys()]);
    const commitment = params.multiMessageCommitment([...messagesToBlind.values()], hArr, blinding);
    const commitments: Map<number, Uint8Array> = new Map(
      [...messagesToBlind.entries()].map(([idx, message]) => {
        if (revealedMessages.has(idx)) {
          throw new Error(`Invalid revealed message with index ${idx} - this index is already committed`);
        }
        let msgBlinding = blindings.get(idx);
        if (msgBlinding === void 0) {
          msgBlinding = this.generateBlinding();
          blindings.set(idx, msgBlinding);
        }

        return [idx, psMessageCommitment(message, msgBlinding, h, params.value.g)];
      })
    );

    return [blinding, { commitment, commitments, revealedMessages }];
  }

  /**
   * Generate a blind signature from request
   * @param request
   * @param secretKey
   * @param h
   * @returns {PSBlindSignature}
   */
  static fromRequest(
    { commitments, revealedMessages }: PSBlindSignatureRequest,
    secretKey: PSSecretKey,
    h: Uint8Array
  ): PSBlindSignature {
    const msgIter = this.combineRevealedAndBlindedMessages(revealedMessages, commitments);

    return this.generate([...msgIter], secretKey, h);
  }

  /**
   * Used by the signer to create a blind signature
   * @param blindSigRequest - The blind sig request sent by user.
   * @param revealedMessages - The messages known to the signer
   * @param secretKey
   * @param msgStructure
   * @param h
   * @param encoder
   */
  static blindSignMessageObject(
    blindSigRequest: PSBlindSignatureRequest,
    revealedMessages: object,
    secretKey: PSSecretKey,
    msgStructure: MessageStructure,
    h: Uint8Array,
    encoder: Encoder
  ): SignedMessages<PSBlindSignature> {
    const { encodedByName: encodedMessages, encodedByIndex: revealedMessagesEncoded } = encodeRevealedMessageObject(
      revealedMessages,
      blindSigRequest.commitments.size,
      msgStructure,
      encoder
    );
    const msgIter = this.combineRevealedAndBlindedMessages(revealedMessagesEncoded, blindSigRequest.commitments);
    const signature = this.generate([...msgIter], secretKey, h);

    return {
      encodedMessages,
      signature
    };
  }

  private static combineRevealedAndBlindedMessages(
    revealedMessages: Map<number, Uint8Array>,
    blindedMessages: Map<number, Uint8Array>
  ): Iterable<PSCommitmentOrMessage> {
    return {
      [Symbol.iterator]() {
        let lastIdx = 0;

        return {
          next() {
            const idx = lastIdx++;

            const revealedMessage = revealedMessages.get(idx);
            const commitment = blindedMessages.get(idx);

            if (revealedMessage !== void 0 && commitment !== void 0) {
              throw new Error(`Found both revealed message and commitment for ${idx}`);
            } else if (revealedMessage !== void 0) {
              return { value: { RevealedMessage: revealedMessage }, done: false };
            } else if (commitment !== void 0) {
              return { value: { BlindedMessage: commitment }, done: false };
            } else if (revealedMessages.size + blindedMessages.size !== idx) {
              const missedCommitments = [...blindedMessages.entries()].filter(([key]) => key > idx);
              const missedRevealed = [...revealedMessages.entries()].filter(([key]) => key > idx);

              throw new Error(
                `Some revealed messages or/and commitments were not included because of invalid indices: not included commitments = ${JSON.stringify(
                  missedCommitments
                )}, not included revealed = ${JSON.stringify(missedRevealed)}`
              );
            }

            return { value: undefined as any, done: true };
          }
        };
      }
    };
  }
}

/**
 * Structure to send to the signer to request a blind signature for `Pointcheval-Sanders` scheme.
 */
export interface PSBlindSignatureRequest {
  /**
   * The commitment for the blinded messages
   */
  commitment: Uint8Array;
  /**
   * The commitments for the blinded messages
   */
  commitments: Map<number, Uint8Array>;
  /**
   * The messages which are known to the signer. Here the key is message index (as per the `SignatureParams`). This is not
   * mandatory as the signer might already know the messages to sign. This is used when the requester wants to inform the
   * signer of some or all of the messages
   */
  revealedMessages: Map<number, Uint8Array>;
}
