import { BBSSignatureParams } from './params';
import { bbsVerify, bbsSign, VerifyResult } from '@docknetwork/crypto-wasm';
import { BBSPublicKey, BBSSecretKey } from './keys';
import { BytearrayWrapper } from '../bytearray-wrapper';
import { bbsBlindSign } from '@docknetwork/crypto-wasm';
import { Encoder, MessageEncoder } from '../encoder';
import { encodeRevealedMessageObject, getBlindedIndicesAndRevealedMessages } from '../sign-verify-js-objs';
import { MessageStructure, SignedMessages } from '../types';

/**
 * `BBS` signature.
 */
export class BBSSignature extends MessageEncoder {
  /**
   * Signer creates a new signature
   * @param messages - Ordered list of messages. Order and contents should be kept same for both signer and verifier
   * @param secretKey
   * @param params
   * @param encodeMessages - If true, the messages are encoded as field elements otherwise they are assumed to be already encoded.
   */
  static generate(
    messages: Uint8Array[],
    secretKey: BBSSecretKey,
    params: BBSSignatureParams,
    encodeMessages: boolean
  ): BBSSignature {
    if (messages.length !== params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    const sig = bbsSign(messages, secretKey.value, params.value, encodeMessages);
    return new BBSSignature(sig);
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
    publicKey: BBSPublicKey,
    params: BBSSignatureParams,
    encodeMessages: boolean
  ): VerifyResult {
    if (messages.length !== params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    return bbsVerify(messages, this.value, publicKey.value, params.value, encodeMessages);
  }

  static signMessageObject(
    messages: Object,
    secretKey: BBSSecretKey,
    labelOrParams: Uint8Array | BBSSignatureParams,
    encoder: Encoder
  ): SignedMessages<BBSSignature> {
    const encodedMessages = encoder.encodeMessageObjectAsObject(messages);
    const encodedMessageList = Object.values(encodedMessages);

    const sigParams = BBSSignatureParams.getSigParamsOfRequiredSize(encodedMessageList.length, labelOrParams);
    const signature = BBSSignature.generate(encodedMessageList, secretKey, sigParams, false);

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
   */
  verifyMessageObject(
    messages: object,
    publicKey: BBSPublicKey,
    labelOrParams: Uint8Array | BBSSignatureParams,
    encoder: Encoder
  ): VerifyResult {
    const [_, encodedValues] = encoder.encodeMessageObject(messages);
    const msgCount = encodedValues.length;

    const sigParams = BBSSignatureParams.getSigParamsOfRequiredSize(msgCount, labelOrParams);
    return this.verify(encodedValues, publicKey, sigParams, false);
  }
}

export class BBSBlindSignature extends BytearrayWrapper {
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
    secretKey: BBSSecretKey,
    params: BBSSignatureParams,
    encodeMessages: boolean
  ): BBSBlindSignature {
    if (revealedMessages.size >= params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          revealedMessages.size
        } must be less than ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    const sig = bbsBlindSign(commitment, revealedMessages, secretKey.value, params.value, encodeMessages);
    return new BBSBlindSignature(sig);
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
    publicKey: BBSPublicKey,
    params: BBSSignatureParams,
    encodeMessages: boolean
  ): VerifyResult {
    if (messages.length !== params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    return bbsVerify(messages, this.value, publicKey.value, params.value, encodeMessages);
  }

  /**
   * Generate a request for a blind signature
   * @param messagesToBlind - messages the requester wants to hide from the signer. The key of the map is the index of the
   * message as per the params.
   * @param params
   * @param encodeMessages
   * @param revealedMessages - Any messages that the requester wishes to inform the signer about. This is for informational
   * purpose only and has no cryptographic use.
   */
  static generateRequest(
    messagesToBlind: Map<number, Uint8Array>,
    params: BBSSignatureParams,
    encodeMessages: boolean,
    revealedMessages?: Map<number, Uint8Array>
  ): BBSBlindSignatureRequest {
    const commitment = params.commitToMessages(messagesToBlind, encodeMessages);
    const [blindedIndices, encodedRevealedMessages] = getBlindedIndicesAndRevealedMessages(
      messagesToBlind,
      encodeMessages,
      revealedMessages
    );
    return { commitment, blindedIndices, revealedMessages: encodedRevealedMessages };
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
    blindSigRequest: BBSBlindSignatureRequest,
    revealedMessages: object,
    secretKey: BBSSecretKey,
    msgStructure: MessageStructure,
    labelOrParams: Uint8Array | BBSSignatureParams,
    encoder: Encoder
  ): SignedMessages<BBSBlindSignature> {
    const {
      encodedByName: encodedMessages,
      encodedByIndex: revealedMessagesEncoded,
      total
    } = encodeRevealedMessageObject(revealedMessages, blindSigRequest.blindedIndices.length, msgStructure, encoder);

    const sigParams = BBSSignatureParams.getSigParamsOfRequiredSize(total, labelOrParams);
    const blindSig = this.generate(blindSigRequest.commitment, revealedMessagesEncoded, secretKey, sigParams, false);

    return {
      encodedMessages,
      signature: blindSig
    };
  }

  /**
   * Generate a blind signature from request
   * @param request
   * @param secretKey
   * @param params
   * @returns {BBSBlindSignature}
   */
  static fromRequest(
    { commitment, revealedMessages }: BBSBlindSignatureRequest,
    secretKey: BBSSecretKey,
    params: BBSSignatureParams
  ): BBSBlindSignature {
    return this.generate(commitment, revealedMessages ?? new Map(), secretKey, params, false);
  }
}

/**
 * Structure to send to the signer to request a blind signature for `BBS` scheme.
 */
export interface BBSBlindSignatureRequest {
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
