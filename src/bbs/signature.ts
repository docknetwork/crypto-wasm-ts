import { BBSSignatureParams } from './params';
import {
  bbsEncodeMessageForSigning,
  bbsVerify,
  bbsSign,
  generateRandomFieldElement,
  fieldElementAsBytes,
  generateFieldElementFromNumber,
  VerifyResult,
} from '@docknetwork/crypto-wasm';
import { BBSPublicKey, BBSSecretKey } from './keys';
import { BytearrayWrapper } from '../bytearray-wrapper';
import LZUTF8 from 'lzutf8';
import { bbsBlindSign } from '@docknetwork/crypto-wasm';

export class BBSSignature extends BytearrayWrapper {
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
    return bbsEncodeMessageForSigning(message);
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
    const bytes = compress ? LZUTF8.compress(message) : BBSSignature.textEncoder.encode(message);
    if (bytes.length > BBSSignature.maxEncodedLength) {
      throw new Error(`Expects a string with at most ${BBSSignature.maxEncodedLength} bytes`);
    }
    // Create a little-endian representation
    const fieldElementBytes = new Uint8Array(BBSSignature.maxEncodedLength);
    fieldElementBytes.set(bytes);
    fieldElementBytes.set(new Uint8Array(BBSSignature.maxEncodedLength - bytes.length), bytes.length);
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
    if (message.length > BBSSignature.maxEncodedLength) {
      throw new Error(`Expects a message with at most ${BBSSignature.maxEncodedLength} bytes`);
    }
    if (decompress) {
      const strippedMsg = message.slice(0, message.indexOf(0));
      const str = LZUTF8.decompress(strippedMsg) as string;
      if (str.length > BBSSignature.maxEncodedLength) {
        throw new Error(
          `Expects a message that can be decompressed to at most ${BBSSignature.maxEncodedLength} bytes but decompressed size was ${str.length}`
        );
      }
      return str;
    } else {
      const decoded = BBSSignature.textDecoder.decode(message);
      const chars: string[] = [];
      for (let i = 0; i < BBSSignature.maxEncodedLength; i++) {
        // If a null character found then stop looking further
        if (decoded.charCodeAt(i) == 0) {
          break;
        }
        chars.push(decoded.charAt(i));
      }
      return chars.join('');
    }
  }

  /**
   * Signer creates a new signature
   * @param messages - Ordered list of messages. Order and contents should be kept same for both signer and verifier
   * @param secretKey
   * @param params
   * @param encodeMessages - If true, the messages are encoded as field elements otherwise they are assumed to be already encoded.
   */
  static generate(messages: Uint8Array[], secretKey: BBSSecretKey, params: BBSSignatureParams, encodeMessages: boolean): BBSSignature {
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
}

export class BBSBlindSignature extends BytearrayWrapper {
  /**
   * Generate blinding for creating the commitment used in the request for blind signature
   * @param seed - Optional seed to serve as entropy for the blinding.
   */
  static generateBlinding(seed?: Uint8Array): Uint8Array {
    return generateRandomFieldElement(seed);
  }

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
    knownMessages: Map<number, Uint8Array>,
    secretKey: BBSSecretKey,
    params: BBSSignatureParams,
    encodeMessages: boolean
  ): BBSBlindSignature {
    if (knownMessages.size >= params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          knownMessages.size
        } must be less than ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    const sig = bbsBlindSign(commitment, knownMessages, secretKey.value, params.value, encodeMessages);
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
   * @param blindings - If not provided, a random blinding is generated
   * @param params
   * @param h
   * @param revealedMessages - Any messages that the requester wishes to inform the signer about. This is for informational
   * purpose only and has no cryptographic use.
   */
  static generateRequest(
    messagesToBlind: Map<number, Uint8Array>,
    params: BBSSignatureParams,
    encodeMessages: boolean,
    blinding?: Uint8Array,
    unblindedMessages?: Map<number, Uint8Array>
  ): [Uint8Array, BBSBlindSignatureRequest] {
    const [commitment, b] = params.commitToMessages(messagesToBlind, encodeMessages, blinding);
    const blindedIndices: number[] = [];
    for (const k of messagesToBlind.keys()) {
      blindedIndices.push(k);
    }

    blindedIndices.sort();
    return [b, { commitment, blindedIndices, unblindedMessages }];
  }
}

/**
 * Structure to send to the signer to request a blind signature
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
  unblindedMessages?: Map<number, Uint8Array>;
}
