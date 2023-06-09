import { BBSPlusSignatureParamsG1 } from './params';
import {
  bbsPlusBlindSignG1,
  bbsPlusSignG1,
  bbsPlusUnblindSigG1,
  bbsPlusVerifyG1,
  generateRandomFieldElement,
  VerifyResult
} from '@docknetwork/crypto-wasm';
import { BBSPlusPublicKeyG2, BBSPlusSecretKey } from './keys';
import { BytearrayWrapper } from '../bytearray-wrapper';
import { encodeRevealedMessageObject, getBlindedIndicesAndRevealedMessages } from '../sign-verify-js-objs';
import { Encoder, MessageEncoder } from '../encoder';
import { MessageStructure, SignedMessages } from '../types';

export class BBSPlusSignatureG1 extends MessageEncoder {
  /**
   * Signer creates a new signature
   * @param messages - Ordered list of messages. Order and contents should be kept same for both signer and verifier
   * @param secretKey
   * @param params
   * @param encodeMessages - If true, the messages are encoded as field elements otherwise they are assumed to be already encoded.
   */
  static generate(
    messages: Uint8Array[],
    secretKey: BBSPlusSecretKey,
    params: BBSPlusSignatureParamsG1,
    encodeMessages: boolean
  ): BBSPlusSignatureG1 {
    if (messages.length !== params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    const sig = bbsPlusSignG1(messages, secretKey.value, params.value, encodeMessages);
    return new BBSPlusSignatureG1(sig);
  }

  /**
   * Verify the signature
   * @param messages - Ordered list of messages. Order and contents should be kept same for both signer and verifier
   * @param publicKey
   * @param params
   * @param encodeMessages - If true, the messages are encoded as field elements otherwise they are assumed to be already encoded.
   */
  verify(
    messages: Uint8Array[],
    publicKey: BBSPlusPublicKeyG2,
    params: BBSPlusSignatureParamsG1,
    encodeMessages: boolean
  ): VerifyResult {
    if (messages.length !== params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    return bbsPlusVerifyG1(messages, this.value, publicKey.value, params.value, encodeMessages);
  }
}

export abstract class BBSPlusBlindSignature extends BytearrayWrapper {
  /**
   * Generate blinding for creating the commitment used in the request for blind signature
   * @param seed - Optional seed to serve as entropy for the blinding.
   */
  static generateBlinding(seed?: Uint8Array): Uint8Array {
    return generateRandomFieldElement(seed);
  }
}

export class BBSPlusBlindSignatureG1 extends MessageEncoder {
  /**
   * Generates a blind signature over the commitment of unrevealed messages and revealed messages
   * @param commitment - Commitment over unrevealed messages sent by the requester of the blind signature. Its assumed that
   * the signers has verified the knowledge of committed messages
   * @param revealedMessages
   * @param secretKey
   * @param params
   * @param encodeMessages
   */
  static generate(
    commitment: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    secretKey: BBSPlusSecretKey,
    params: BBSPlusSignatureParamsG1,
    encodeMessages: boolean
  ): BBSPlusBlindSignatureG1 {
    if (revealedMessages.size >= params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          revealedMessages.size
        } must be less than ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    const sig = bbsPlusBlindSignG1(commitment, revealedMessages, secretKey.value, params.value, encodeMessages);
    return new BBSPlusBlindSignatureG1(sig);
  }

  /**
   * Generate a blind signature from request
   * @param request
   * @param secretKey
   * @param params
   * @returns {BBSPlusBlindSignatureG1}
   */
  static fromRequest(
    { commitment, revealedMessages }: BBSPlusBlindSignatureRequest,
    secretKey: BBSPlusSecretKey,
    params: BBSPlusSignatureParamsG1
  ): BBSPlusBlindSignatureG1 {
    return this.generate(commitment, revealedMessages ?? new Map(), secretKey, params, false);
  }

  /**
   * Unblind the blind signature to get a regular signature that can be verified
   * @param blinding
   */
  unblind(blinding: Uint8Array): BBSPlusSignatureG1 {
    const sig = bbsPlusUnblindSigG1(this.value, blinding);
    return new BBSPlusSignatureG1(sig);
  }

  /**
   * Generate a request for a blind signature
   * @param messagesToBlind - messages the requester wants to hide from the signer. The key of the map is the index of the
   * message as per the params.
   * @param params
   * @param encodeMessages
   * @param blinding - If not provided, a random blinding is generated
   * @param revealedMessages - Any messages that the requester wishes to inform the signer about. This is for informational
   * purpose only and has no cryptographic use.
   */
  static generateRequest(
    messagesToBlind: Map<number, Uint8Array>,
    params: BBSPlusSignatureParamsG1,
    encodeMessages: boolean,
    blinding?: Uint8Array,
    revealedMessages?: Map<number, Uint8Array>
  ): [Uint8Array, BBSPlusBlindSignatureRequest] {
    const [commitment, b] = params.commitToMessages(messagesToBlind, encodeMessages, blinding);
    const [blindedIndices, encodedRevealedMessages] = getBlindedIndicesAndRevealedMessages(
      messagesToBlind,
      encodeMessages,
      revealedMessages
    );
    return [b, { commitment, blindedIndices, revealedMessages: encodedRevealedMessages }];
  }

  /**
   * Used by the signer to create a blind signature
   * @param blindSigRequest - The blind sig request sent by user.
   * @param revealedMessages - The messages known to the signer
   * @param secretKey
   * @param msgStructure
   * @param labelOrParams
   * @param encoder
   */
  static blindSignMessageObject(
    blindSigRequest: BBSPlusBlindSignatureRequest,
    revealedMessages: object,
    secretKey: BBSPlusSecretKey,
    msgStructure: MessageStructure,
    labelOrParams: Uint8Array | BBSPlusSignatureParamsG1,
    encoder: Encoder
  ): SignedMessages<BBSPlusBlindSignatureG1> {
    const {
      encodedByName: encodedMessages,
      encodedByIndex: revealedMessagesEncoded,
      total
    } = encodeRevealedMessageObject(revealedMessages, blindSigRequest.blindedIndices.length, msgStructure, encoder);

    const sigParams = BBSPlusSignatureParamsG1.getSigParamsOfRequiredSize(total, labelOrParams);
    const signature = this.generate(blindSigRequest.commitment, revealedMessagesEncoded, secretKey, sigParams, false);

    return {
      encodedMessages,
      signature
    };
  }
}

/**
 * Structure to send to the signer to request a blind signature for `BBS+` scheme.
 */
export interface BBSPlusBlindSignatureRequest {
  /**
   * The commitment to the blinded messages
   */
  commitment: Uint8Array;
  /**
   * The messages at these indices were committed to in the commitment and are not revealed to the signer. This is expected
   * to be sorted in ascending order
   */
  blindedIndices: number[];
  /**
   * The messages which are known to the signer. Here the key is message index (as per the `SignatureParams`). This is not
   * mandatory as the signer might already know the messages to sign. This is used when the requester wants to inform the
   * signer of some or all of the message
   */
  revealedMessages?: Map<number, Uint8Array>;
}
