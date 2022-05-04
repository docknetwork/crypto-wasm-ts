import { SignatureParamsG1 } from './params';
import { fieldElementAsBytes, generateFieldElementFromNumber, VerifyResult } from '@docknetwork/crypto-wasm';
import {
  bbsBlindSignG1,
  bbsEncodeMessageForSigning,
  bbsSignG1,
  bbsUnblindSigG1,
  bbsVerifyG1,
  generateRandomFieldElement
} from '@docknetwork/crypto-wasm';
import { BBSPlusPublicKeyG2, BBSPlusSecretKey } from './keys';
import { ensurePositiveIntegerOfSize } from '../util';
import { BytearrayWrapper } from '../bytearray-wrapper';

export abstract class Signature extends BytearrayWrapper {
  /**
   * This is an irreversible encoding as a hash function is used to convert a message of
   * arbitrary length to a fixed length encoding.
   * @param message
   */
  static encodeMessageForSigning(message: Uint8Array): Uint8Array {
    return bbsEncodeMessageForSigning(message);
  }

  /**
   * Encodes a positive integer of at most 4 bytes
   * @param num
   */
  static encodePositiveNumberForSigning(num: number): Uint8Array {
    ensurePositiveIntegerOfSize(num, 32);
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
   */
  static reversibleEncodeStringMessageForSigning(message: string): Uint8Array {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(message);
    const maxLength = 32;
    if (bytes.length > maxLength) {
      throw new Error(`Expects a string with at most ${maxLength} bytes`);
    }
    // Create a little-endian representation
    const fieldElementBytes = new Uint8Array(maxLength);
    fieldElementBytes.set(bytes);
    fieldElementBytes.set(new Uint8Array(maxLength - bytes.length), bytes.length);
    return fieldElementAsBytes(fieldElementBytes);
  }

  /**
   * Decode the given representation. This should **only** be used when the encoding was done
   * using `this.reversibleEncodeStringMessageForSigning`. Also, this function trims any characters from the first
   * occurrence of a null characters (UTF-16 code unit 0) so if the encoded (using `this.reversibleEncodeStringMessageForSigning`)
   * string also had a null then the decoded string will be different from it.
   * @param message
   */
  static reversibleDecodeStringMessageForSigning(message: Uint8Array): string {
    const maxLength = 32;
    if (message.length > maxLength) {
      throw new Error(`Expects a message with at most ${maxLength} bytes`);
    }
    const decoder = new TextDecoder();
    const decoded = decoder.decode(message);
    const chars = [];
    for (let i = 0; i < maxLength; i++) {
      // If a null character found then stop looking further
      if (decoded.charCodeAt(i) == 0) {
        break;
      }
      chars.push(decoded.charAt(i));
    }
    return chars.join('');
  }
}

export class SignatureG1 extends Signature {
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
    params: SignatureParamsG1,
    encodeMessages: boolean
  ): SignatureG1 {
    if (messages.length !== params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    const sig = bbsSignG1(messages, secretKey.value, params.value, encodeMessages);
    return new SignatureG1(sig);
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
    params: SignatureParamsG1,
    encodeMessages: boolean
  ): VerifyResult {
    if (messages.length !== params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          messages.length
        } is different from ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    return bbsVerifyG1(messages, this.value, publicKey.value, params.value, encodeMessages);
  }
}

export abstract class BlindSignature extends BytearrayWrapper {
  /**
   * Generate blinding for creating the commitment used in the request for blind signature
   * @param seed - Optional seed to serve as entropy for the blinding.
   */
  static generateBlinding(seed?: Uint8Array): Uint8Array {
    return generateRandomFieldElement(seed);
  }
}

export class BlindSignatureG1 extends BlindSignature {
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
    secretKey: BBSPlusSecretKey,
    params: SignatureParamsG1,
    encodeMessages: boolean
  ): BlindSignatureG1 {
    if (knownMessages.size >= params.supportedMessageCount()) {
      throw new Error(
        `Number of messages ${
          knownMessages.size
        } must be less than ${params.supportedMessageCount()} supported by the signature params`
      );
    }
    const sig = bbsBlindSignG1(commitment, knownMessages, secretKey.value, params.value, encodeMessages);
    return new BlindSignatureG1(sig);
  }

  /**
   * Unblind the blind signature to get a regular signature that can be verified
   * @param blinding
   */
  unblind(blinding: Uint8Array): SignatureG1 {
    const sig = bbsUnblindSigG1(this.value, blinding);
    return new SignatureG1(sig);
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
    params: SignatureParamsG1,
    encodeMessages: boolean,
    blinding?: Uint8Array,
    unblindedMessages?: Map<number, Uint8Array>
  ): [Uint8Array, BlindSignatureRequest] {
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
interface BlindSignatureRequest {
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
