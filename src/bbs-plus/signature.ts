import { BBSPlusSignatureParamsG1 } from './params';
import {
  bbsPlusBlindSignG1,
  encodeMessageForSigning,
  bbsPlusSignG1,
  bbsPlusUnblindSigG1,
  bbsPlusVerifyG1,
  generateRandomFieldElement,
  fieldElementAsBytes,
  generateFieldElementFromNumber,
  VerifyResult
} from '@docknetwork/crypto-wasm';
import { BBSPlusPublicKeyG2, BBSPlusSecretKey } from './keys';
import { BytearrayWrapper } from '../bytearray-wrapper';
import LZUTF8 from 'lzutf8';
import { MessageStructure, SignedMessages, flattenMessageStructure } from '../sign-verify-js-objs';
import { Encoder } from '../encoder';

export abstract class BBSPlusSignature extends BytearrayWrapper {
  // The field element size is 32 bytes so the maximum byte size of encoded message must be 32.
  static readonly maxEncodedLength = 32;
  static readonly textEncoder = new TextEncoder();
  static readonly textDecoder = new TextDecoder();

  /**
   * This is an irreversible encoding as a hash function is used to convert a message of
   * arbitrary length to a fixed length encoding.
   * @param message
   */
  static encodeMessageForSigning(message: Uint8Array): Uint8Array {
    return encodeMessageForSigning(message);
  }

  /**
   * Encodes a positive safe integer, i.e. of 53 bits
   * @param num
   */
  static encodePositiveNumberForSigning(num: number): Uint8Array {
    return generateFieldElementFromNumber(num);
  }

  /**
   * Encode the given string to bytes and create a field element by considering the bytes in little-endian format.
   * Use this way of encoding only if the input string's UTF-8 representation is <= 32 bytes else this will throw an error.
   * Also adds trailing 0s to the bytes to make the size 32 bytes so use this function carefully. The only place this is
   * currently useful is verifiable encryption as in some cases the prover might not be willing/available at the time of
   * decryption and thus the decryptor must be able to decrypt it independently. This is different from selective disclosure
   * where the verifier can check that the revealed message is same as the encoded one before even verifying the proof.
   * @param message - utf-8 string of at most 32 bytes
   * @param compress - whether to compress the text before encoding to bytes. Compression might not always help as things
   * like public keys, DIDs, UUIDs, etc. are designed to be random and thus won't be compressed
   */
  static reversibleEncodeStringForSigning(message: string, compress = false): Uint8Array {
    const bytes = compress ? LZUTF8.compress(message) : BBSPlusSignatureG1.textEncoder.encode(message);
    if (bytes.length > BBSPlusSignatureG1.maxEncodedLength) {
      throw new Error(`Expects a string with at most ${BBSPlusSignatureG1.maxEncodedLength} bytes`);
    }
    // Create a little-endian representation
    const fieldElementBytes = new Uint8Array(BBSPlusSignatureG1.maxEncodedLength);
    fieldElementBytes.set(bytes);
    fieldElementBytes.set(new Uint8Array(BBSPlusSignatureG1.maxEncodedLength - bytes.length), bytes.length);
    return fieldElementAsBytes(fieldElementBytes, true);
  }

  /**
   * Decode the given representation. This should **only** be used when the encoding was done
   * using `this.reversibleEncodeStringMessageForSigning`. Also, this function trims any characters from the first
   * occurrence of a null characters (UTF-16 code unit 0) so if the encoded (using `this.reversibleEncodeStringMessageForSigning`)
   * string also had a null then the decoded string will be different from it.
   * @param message
   * @param decompress - whether to decompress the bytes before converting to a string
   */
  static reversibleDecodeStringForSigning(message: Uint8Array, decompress = false): string {
    if (message.length > BBSPlusSignatureG1.maxEncodedLength) {
      throw new Error(`Expects a message with at most ${BBSPlusSignatureG1.maxEncodedLength} bytes`);
    }
    if (decompress) {
      const strippedMsg = message.slice(0, message.indexOf(0));
      const str = LZUTF8.decompress(strippedMsg) as string;
      if (str.length > BBSPlusSignatureG1.maxEncodedLength) {
        throw new Error(
          `Expects a message that can be decompressed to at most ${BBSPlusSignatureG1.maxEncodedLength} bytes but decompressed size was ${str.length}`
        );
      }
      return str;
    } else {
      const decoded = BBSPlusSignatureG1.textDecoder.decode(message);
      const chars: string[] = [];
      for (let i = 0; i < BBSPlusSignatureG1.maxEncodedLength; i++) {
        // If a null character found then stop looking further
        if (decoded.charCodeAt(i) == 0) {
          break;
        }
        chars.push(decoded.charAt(i));
      }
      return chars.join('');
    }
  }
}

export class BBSPlusSignatureG1 extends BBSPlusSignature {
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

export class BBSPlusBlindSignatureG1 extends BBSPlusBlindSignature {
  /**
   * Generates a blind signature over the commitment of unknown messages and known messages
   * @param commitment - Commitment over unknown messages sent by the requester of the blind signature. Its assumed that
   * the signers has verified the knowledge of committed messages
   * @param knownMessages
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
   * @param h 
   * @returns {BBSPlusBlindSignatureG1}
   */
  static fromRequest(
    { commitment, unblindedMessages }: BBSPlusBlindSignatureRequest,
    secretKey: BBSPlusSecretKey,
    params: BBSPlusSignatureParamsG1
  ): BBSPlusBlindSignatureG1 {
    return this.generate(commitment, unblindedMessages || new Map(), secretKey, params, false);
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
   * @param unblindedMessages - Any messages that the requester wishes to inform the signer about. This is for informational
   * purpose only and has no cryptographic use.
   */
  static generateRequest(
    messagesToBlind: Map<number, Uint8Array>,
    params: BBSPlusSignatureParamsG1,
    encodeMessages: boolean,
    blinding?: Uint8Array,
    unblindedMessages?: Map<number, Uint8Array>
  ): [Uint8Array, BBSPlusBlindSignatureRequest] {
    const [commitment, b] = params.commitToMessages(messagesToBlind, encodeMessages, blinding);
    const blindedIndices: number[] = [];
    for (const k of messagesToBlind.keys()) {
      blindedIndices.push(k);
    }

    blindedIndices.sort((a, b) => a - b);
    return [b, { commitment, blindedIndices, unblindedMessages }];
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
 static blindSignMessageObject(
  blindSigRequest: BBSPlusBlindSignatureRequest,
  knownMessages: object,
  secretKey: BBSPlusSecretKey,
  msgStructure: MessageStructure,
  labelOrParams: Uint8Array | BBSPlusSignatureParamsG1,
  encoder: Encoder
): SignedMessages<BBSPlusBlindSignatureG1> {
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

  const sigParams = BBSPlusSignatureParamsG1.getSigParamsOfRequiredSize(flattenedAllNames.length, labelOrParams);
  const signature = this.generate(
    blindSigRequest.commitment,
    knownMessagesEncoded,
    secretKey,
    sigParams,
    false
  );

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
  unblindedMessages?: Map<number, Uint8Array>;
}
