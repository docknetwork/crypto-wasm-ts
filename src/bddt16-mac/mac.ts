import { BytearrayWrapper } from '../bytearray-wrapper';
import { Encoder, MessageEncoder } from '../encoder';
import {
  bddt16BlindMacGenerate,
  bddt16MacGenerate,
  bddt16MacVerify,
  bddt16UnblindMac,
  bddt16MacProofOfValidity,
  bddt16MacVerifyProofOfValidity,
  VerifyResult
} from 'crypto-wasm-new';
import { MessageStructure, SignedMessages } from '../types';
import { BDDT16MacParams } from './params';
import { BDDT16MacSecretKey, BDDT16MacPublicKeyG1 } from './keys';
import { encodeRevealedMessageObject, getBlindedIndicesAndRevealedMessages } from '../sign-verify-js-objs';

/**
 * Proof of knowledge of BDDT16 MAC protocol
 */
export class BDDT16Mac extends MessageEncoder {
  /**
   * Signer creates a new MAC
   * @param messages - Ordered list of messages. Order and contents should be kept same for both signer and verifier
   * @param secretKey
   * @param params
   * @param encodeMessages - If true, the messages are encoded as field elements otherwise they are assumed to be already encoded.
   */
  static generate(
    messages: Uint8Array[],
    secretKey: BDDT16MacSecretKey,
    params: BDDT16MacParams,
    encodeMessages: boolean
  ): BDDT16Mac {
    if (messages.length !== params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${params.supportedMessageCount()} supported by the MAC params`
      );
    }
    const mac = bddt16MacGenerate(messages, secretKey.value, params.value, encodeMessages);
    return new BDDT16Mac(mac);
  }

  /**
   * Verify the MAC
   * @param messages - Ordered list of messages. Order and contents should be kept same for both signer and verifier
   * @param secretKey
   * @param params
   * @param encodeMessages - If true, the messages are encoded as field elements otherwise they are assumed to be already encoded.
   */
  verify(
    messages: Uint8Array[],
    secretKey: BDDT16MacSecretKey,
    params: BDDT16MacParams,
    encodeMessages: boolean
  ): VerifyResult {
    if (messages.length !== params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${params.supportedMessageCount()} supported by the MAC params`
      );
    }
    return bddt16MacVerify(messages, this.value, secretKey.value, params.value, encodeMessages);
  }

  static signMessageObject(
    messages: Object,
    secretKey: BDDT16MacSecretKey,
    labelOrParams: Uint8Array | BDDT16MacParams,
    encoder: Encoder
  ): SignedMessages<BDDT16Mac> {
    const encodedMessages = encoder.encodeMessageObjectAsObject(messages);
    const encodedMessageList = Object.values(encodedMessages);

    const sigParams = BDDT16MacParams.getMacParamsOfRequiredSize(encodedMessageList.length, labelOrParams);
    const signature = BDDT16Mac.generate(encodedMessageList, secretKey, sigParams, false);

    return {
      encodedMessages,
      signature
    };
  }

  static getSignedMessageObjectWithProof(
    messages: Object,
    secretKey: BDDT16MacSecretKey,
    publicKey: BDDT16MacPublicKeyG1,
    labelOrParams: Uint8Array | BDDT16MacParams,
    encoder: Encoder
  ): [SignedMessages<BDDT16Mac>, BDDT16MacProofOfValidity] {
    const encodedMessages = encoder.encodeMessageObjectAsObject(messages);
    const encodedMessageList = Object.values(encodedMessages);

    const sigParams = BDDT16MacParams.getMacParamsOfRequiredSize(encodedMessageList.length, labelOrParams);
    const signature = BDDT16Mac.generate(encodedMessageList, secretKey, sigParams, false);
    const proof = new BDDT16MacProofOfValidity(signature, secretKey, publicKey, sigParams);
    return [{
      encodedMessages,
      signature
    }, proof];
  }

  /**
   * Verifies the MAC on the given messages. Takes the messages as a JS object, flattens it, encodes the values similar
   * to signing and then verifies the MAC.
   * @param messages
   * @param secretKey
   * @param labelOrParams
   * @param encoder
   */
  verifyMessageObject(
    messages: object,
    secretKey: BDDT16MacSecretKey,
    labelOrParams: Uint8Array | BDDT16MacParams,
    encoder: Encoder
  ): VerifyResult {
    const [_, encodedValues] = encoder.encodeMessageObject(messages);
    const msgCount = encodedValues.length;

    const sigParams = BDDT16MacParams.getMacParamsOfRequiredSize(msgCount, labelOrParams);
    return this.verify(encodedValues, secretKey, sigParams, false);
  }
}

export class BDDT16BlindMac extends MessageEncoder {
  /**
   * Generates a blind MAC over the commitment of unrevealed messages and revealed messages
   * @param commitment - Commitment over unrevealed messages sent by the requester of the blind MAC. Its assumed that
   * the signers has verified the knowledge of committed messages
   * @param revealedMessages
   * @param secretKey
   * @param params
   * @param encodeMessages
   */
  static generate(
    commitment: Uint8Array,
    revealedMessages: Map<number, Uint8Array>,
    secretKey: BDDT16MacSecretKey,
    params: BDDT16MacParams,
    encodeMessages: boolean
  ): BDDT16BlindMac {
    if (revealedMessages.size >= params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          revealedMessages.size
        } must be less than ${params.supportedMessageCount()} supported by the MAC params`
      );
    }
    const sig = bddt16BlindMacGenerate(commitment, revealedMessages, secretKey.value, params.value, encodeMessages);
    return new BDDT16BlindMac(sig);
  }

  /**
   * Generate a blind MAC from request
   * @param request
   * @param secretKey
   * @param params
   * @returns {BDDT16BlindMac}
   */
  static fromRequest(
    { commitment, revealedMessages }: BDDT16BlindMacRequest,
    secretKey: BDDT16MacSecretKey,
    params: BDDT16MacParams
  ): BDDT16BlindMac {
    return this.generate(commitment, revealedMessages ?? new Map(), secretKey, params, false);
  }

  /**
   * Unblind the blind MAC to get a regular MAC that can be verified
   * @param blinding
   */
  unblind(blinding: Uint8Array): BDDT16Mac {
    const sig = bddt16UnblindMac(this.value, blinding);
    return new BDDT16Mac(sig);
  }

  /**
   * Generate a request for a blind MAC
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
    params: BDDT16MacParams,
    encodeMessages: boolean,
    blinding?: Uint8Array,
    revealedMessages?: Map<number, Uint8Array>
  ): [Uint8Array, BDDT16BlindMacRequest] {
    const [commitment, b] = params.commitToMessages(messagesToBlind, encodeMessages, blinding);
    const [blindedIndices, encodedRevealedMessages] = getBlindedIndicesAndRevealedMessages(
      messagesToBlind,
      encodeMessages,
      revealedMessages
    );
    return [b, { commitment, blindedIndices, revealedMessages: encodedRevealedMessages }];
  }

  /**
   * Used by the signer to create a blind MAC
   * @param blindSigRequest - The blind sig request sent by user.
   * @param revealedMessages - The messages known to the signer
   * @param secretKey
   * @param msgStructure
   * @param labelOrParams
   * @param encoder
   */
  static blindSignMessageObject(
    blindSigRequest: BDDT16BlindMacRequest,
    revealedMessages: object,
    secretKey: BDDT16MacSecretKey,
    msgStructure: MessageStructure,
    labelOrParams: Uint8Array | BDDT16MacParams,
    encoder: Encoder
  ): SignedMessages<BDDT16BlindMac> {
    const {
      encodedByName: encodedMessages,
      encodedByIndex: revealedMessagesEncoded,
      total
    } = encodeRevealedMessageObject(revealedMessages, blindSigRequest.blindedIndices.length, msgStructure, encoder);

    const macParams = BDDT16MacParams.getMacParamsOfRequiredSize(total, labelOrParams);
    const signature = this.generate(blindSigRequest.commitment, revealedMessagesEncoded, secretKey, macParams, false);

    return {
      encodedMessages,
      signature
    };
  }
}

/**
 * Structure to send to the signer to request a blind MAC for BDDT16 scheme.
 */
export interface BDDT16BlindMacRequest {
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
   * The messages which are known to the signer. Here the key is message index (as per the `MACParams`). This is not
   * mandatory as the signer might already know the messages to sign. This is used when the requester wants to inform the
   * signer of some or all of the message
   */
  revealedMessages?: Map<number, Uint8Array>;
}

/**
 * This MAC cannot be verified without the secret key but the signer can give a proof to the user that the MAC is
 * correct, i.e. it was created with the public key of the secret key.
 */
export class BDDT16MacProofOfValidity extends BytearrayWrapper {
  constructor(mac: BDDT16Mac, secretKey: BDDT16MacSecretKey, publicKey: BDDT16MacPublicKeyG1, params: BDDT16MacParams) {
    const proof = bddt16MacProofOfValidity(mac.value, secretKey.value, publicKey.value, params.value);
    super(proof);
  }

  verify(
    mac: BDDT16Mac,
    messages: Uint8Array[],
    publicKey: BDDT16MacPublicKeyG1,
    params: BDDT16MacParams,
    encodeMessages: boolean
  ): VerifyResult {
    if (messages.length !== params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${params.supportedMessageCount()} supported by the MAC params`
      );
    }
    return bddt16MacVerifyProofOfValidity(
      this.value,
      mac.value,
      messages,
      publicKey.value,
      params.value,
      encodeMessages
    );
  }

  verifyWithMessageObject(
    mac: BDDT16Mac,
    messages: object,
    publicKey: BDDT16MacPublicKeyG1,
    labelOrParams: Uint8Array | BDDT16MacParams,
    encoder: Encoder
  ): VerifyResult {
    const [_, encodedValues] = encoder.encodeMessageObject(messages);
    const msgCount = encodedValues.length;

    const params = BDDT16MacParams.getMacParamsOfRequiredSize(msgCount, labelOrParams);
    return this.verify(mac, encodedValues, publicKey, params, false);
  }
}
