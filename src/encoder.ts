import { encodeMessageForSigning, fieldElementAsBytes, generateFieldElementFromNumber } from '@docknetwork/crypto-wasm';
import { flattenObjectToKeyValuesList, isPositiveInteger } from './util';
import LZUTF8 from 'lzutf8';
import { BytearrayWrapper } from './bytearray-wrapper';

/**
 * A function that encodes the input to field element bytes
 */
export type EncodeFunc = (value: unknown) => Uint8Array;

/**
 * A function that encodes the input to a positive integer
 */
export type ToPositiveIntFunc = (value: unknown) => number;

/**
 * A class extending `BytearrayWrapper` containing instruments for dealing with message encoding/decoding.
 */
export abstract class MessageEncoder extends BytearrayWrapper {
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
    const bytes = compress ? LZUTF8.compress(message) : this.textEncoder.encode(message);
    if (bytes.length > this.maxEncodedLength) {
      throw new Error(`Expects a string with at most ${this.maxEncodedLength} bytes`);
    }
    // Create a little-endian representation
    const fieldElementBytes = new Uint8Array(this.maxEncodedLength);
    fieldElementBytes.set(bytes);
    fieldElementBytes.set(new Uint8Array(this.maxEncodedLength - bytes.length), bytes.length);
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
    if (message.length > this.maxEncodedLength) {
      throw new Error(`Expects a message with at most ${this.maxEncodedLength} bytes`);
    }
    if (decompress) {
      const strippedMsg = message.slice(0, message.indexOf(0));
      const str = LZUTF8.decompress(strippedMsg) as string;
      if (str.length > this.maxEncodedLength) {
        throw new Error(
          `Expects a message that can be decompressed to at most ${this.maxEncodedLength} bytes but decompressed size was ${str.length}`
        );
      }
      return str;
    } else {
      const decoded = this.textDecoder.decode(message);
      const chars: string[] = [];
      for (let i = 0; i < this.maxEncodedLength; i++) {
        // If a null character found then stop looking further
        if (decoded.charCodeAt(i) === 0) {
          break;
        }
        chars.push(decoded.charAt(i));
      }
      return chars.join('');
    }
  }
}

/**
 * Encodes the input to a field element for signing.
 * Used when working with messages that are specified as JS objects. This encoder object will contain
 * the mapping from message name (key in JS object) to an encoding function.
 *
 * TODO: Support identity encoder for values that are already field elements.
 */
export class Encoder {
  // Mapping from the message name to the encoding function
  encoders?: Map<string, EncodeFunc>;
  // Encoding function to use when message name not found in mapping `encoders`
  defaultEncoder?: EncodeFunc;

  constructor(encoders?: Map<string, EncodeFunc>, defaultEncoder?: EncodeFunc) {
    if ((encoders === undefined || encoders.size === 0) && defaultEncoder === undefined) {
      throw new Error('Provide either a non-empty "encoders" or a default encoder');
    }
    this.encoders = encoders;
    this.defaultEncoder = defaultEncoder;
  }

  /**
   * Encode a message with given name and value. Will throw an error if no appropriate encoder found.
   * @param name
   * @param value
   * @param strict - If set to false and no appropriate encoder is found but the value is a bytearray, it will encode it using the built-in mechanism
   */
  encodeMessage(name: string, value: unknown, strict = false): Uint8Array {
    const encoder = this.encoders?.get(name) || this.defaultEncoder;
    if (encoder !== undefined) {
      if (typeof value === undefined) {
        throw new Error(`Cannot encode message with name ${name} as it is undefined`);
      }
      return encoder(value);
    } else {
      if (!strict && value instanceof Uint8Array) {
        return MessageEncoder.encodeMessageForSigning(value);
      } else {
        throw new Error(
          `Cannot encode message with name ${name} and value ${value} as neither was any encoder provided nor it was an Uint8Array. Its type was ${typeof value}`
        );
      }
    }
  }

  /**
   * Encode messages given as JS object. It flattens the object into a sorted list and encodes each value as per the known
   * encoding functions.
   * Returns 2 arrays, 1st with message names and 2nd with encoded values.
   * @param messages
   * @param strict - If set to false and no appropriate encoder is found but the value is a bytearray, it will encode it using the built-in mechanism
   */
  encodeMessageObject(messages: object, strict = false): [string[], Uint8Array[]] {
    const [names, values] = flattenObjectToKeyValuesList(messages);
    const encoded: Uint8Array[] = [];
    for (let i = 0; i < names.length; i++) {
      encoded.push(this.encodeMessage(names[i], values[i], strict));
    }
    return [names, encoded];
  }

  /**
   * Encode messages given as JS object. It flattens the object into a sorted list and encodes each value as per the known
   * encoding functions.
   * Returns an object with names as keys and encoded messages as values.
   * @param messages
   * @param strict - If set to false and no appropriate encoder is found but the value is a bytearray, it will encode it using the built-in mechanism
   */
  encodeMessageObjectAsObject(messages: object, strict = false): { [name: string]: Uint8Array } {
    const [names, values] = this.encodeMessageObject(messages, strict);

    return Object.fromEntries(names.map((name, idx) => [name, values[idx]]));
  }

  /**
   * Encode messages given as JS object. It flattens the object into a sorted list and encodes each value as per the known
   * encoding functions.
   * Returns a Map with names as keys and encoded messages as values.
   * @param messages
   * @param strict - If set to false and no appropriate encoder is found but the value is a bytearray, it will encode it using the built-in mechanism
   */
  encodeMessageObjectAsMap(messages: object, strict = false): Map<string, Uint8Array> {
    const [names, values] = this.encodeMessageObject(messages, strict);

    return new Map(names.map((name, idx) => [name, values[idx]]));
  }

  encodeDefault(value: unknown, strict = false): Uint8Array {
    if (this.defaultEncoder !== undefined) {
      return this.defaultEncoder(value);
    } else {
      if (!strict && value instanceof Uint8Array) {
        return MessageEncoder.encodeMessageForSigning(value);
      } else {
        throw new Error(
          `Cannot encode value ${value} as neither was default encoder present nor it was an Uint8Array. Its type was ${typeof value}`
        );
      }
    }
  }
  /**
   * Returns an encoding function to be used on a message that is a positive integer.
   */
  static positiveIntegerEncoder(): EncodeFunc {
    return (v: unknown) => {
      if (!isPositiveInteger(v)) {
        throw new Error(`Expected positive integer but ${v} has type ${typeof v}`);
      }
      return MessageEncoder.encodePositiveNumberForSigning(v as number);
    };
  }

  /**
   * Returns an encoding function to be used on a message that is a boolean, encoded as positive int (0 or 1)
   */
  static booleanEncoder(): EncodeFunc {
    return (v: unknown) => {
      if (typeof v !== 'boolean') {
        throw new Error(`Expected boolean but ${v} has type ${typeof v}`);
      }
      return MessageEncoder.encodePositiveNumberForSigning(v ? 1 : 0);
    };
  }

  /**
   * Returns a function that can convert any input integer to a positive integer when its minimum
   * negative value is known. Does that by adding an offset of abs(minimum) to the input
   * @param minimum
   */
  static integerToPositiveInt(minimum: number): ToPositiveIntFunc {
    if (!Number.isInteger(minimum)) {
      throw new Error(`Expected integer but ${minimum} has type ${typeof minimum}`);
    }
    const offset = Math.abs(minimum);
    return (v: unknown) => {
      if (!Number.isInteger(v)) {
        throw new Error(`Expected integer but ${v} has type ${typeof v}`);
      }
      const vNum = v as number;
      if (vNum < minimum) {
        throw new Error(`Encoder was created with minimum value ${minimum} but was asked to encode ${vNum}`);
      }
      return offset + vNum;
    };
  }

  /**
   * Returns an encoding function to be used on a message that can be a positive or negative integer.
   * @param minimum - The minimum negative value that the message can take
   */
  static integerEncoder(minimum: number): EncodeFunc {
    const f = Encoder.integerToPositiveInt(minimum);
    return (v: unknown) => {
      return MessageEncoder.encodePositiveNumberForSigning(f(v));
    };
  }

  /**
   * Returns a function that can convert any positive number to a positive integer when its maximum decimal
   * places are known. Does that by multiplying it by 10^max_decimal_places, eg. 23.452 -> 23452
   * @param maxDecimalPlaces
   */
  static positiveDecimalNumberToPositiveInt(maxDecimalPlaces: number): ToPositiveIntFunc {
    if (!isPositiveInteger(maxDecimalPlaces)) {
      throw new Error(`Maximum decimal places should be a positive integer but was ${maxDecimalPlaces}`);
    }
    const multiple = Math.pow(10, maxDecimalPlaces);
    return (v: unknown) => {
      Encoder.ensureNumber(v);
      const vNum = v as number;
      Encoder.ensureCorrectDecimalNumberPlaces(vNum, maxDecimalPlaces);
      return Math.trunc(vNum * multiple);
    };
  }

  /**
   * Returns an encoding function to be used on a message that can be a positive decimal number, eg. 2.7
   * @param maxDecimalPlaces - The maximum decimal places
   */
  static positiveDecimalNumberEncoder(maxDecimalPlaces: number): EncodeFunc {
    const f = Encoder.positiveDecimalNumberToPositiveInt(maxDecimalPlaces);
    return (v: unknown) => {
      return MessageEncoder.encodePositiveNumberForSigning(f(v));
    };
  }

  /**
   * Returns a reversible encoding function to be used on a string message. The output can of the `EncodeFunc` can be
   * reversed.
   * @param compress
   */
  static reversibleEncoderString(compress = false): EncodeFunc {
    return (v: unknown) => {
      return MessageEncoder.reversibleEncodeStringForSigning(v as string, compress);
    };
  }

  /**
   * Returns a function that can convert any number to a positive integer when its minimum negative value and maximum
   * decimal places are known. Does that by adding an offset of abs(minimum) and then multiplying it by 10^max_decimal_places
   * @param minimum
   * @param maxDecimalPlaces
   */
  static decimalNumberToPositiveInt(minimum: number, maxDecimalPlaces: number): ToPositiveIntFunc {
    if (!isPositiveInteger(maxDecimalPlaces)) {
      throw new Error(`Maximum decimal places should be a positive integer but was ${maxDecimalPlaces}`);
    }
    const offset = Math.abs(minimum);
    const multiple = Math.pow(10, maxDecimalPlaces);
    return (v: unknown) => {
      Encoder.ensureNumber(v);
      const vNum = v as number;
      if (vNum < minimum) {
        throw new Error(`Encoder was created with minimum value ${minimum} but was asked to encode ${vNum}`);
      }
      Encoder.ensureCorrectDecimalNumberPlaces(vNum, maxDecimalPlaces);
      return Math.trunc((offset + vNum) * multiple);
    };
  }

  /**
   * Returns an encoding function to be used on a message that can be a positive, negative or decimal number, eg. -2.35
   * @param minimum - The minimum negative value that the message can take
   * @param maxDecimalPlaces - The maximum decimal places
   */
  static decimalNumberEncoder(minimum: number, maxDecimalPlaces: number): EncodeFunc {
    const f = Encoder.decimalNumberToPositiveInt(minimum, maxDecimalPlaces);
    return (v: unknown) => {
      return MessageEncoder.encodePositiveNumberForSigning(f(v));
    };
  }

  /**
   * Returns an encoding function to convert utf-8 string message. It might fail of the encoding target cannot be made a string
   */
  static defaultEncodeFunc(): EncodeFunc {
    const te = new TextEncoder();
    return (v: unknown) => {
      // @ts-ignore
      return MessageEncoder.encodeMessageForSigning(te.encode(v.toString()));
    };
  }

  private static ensureNumber(v: unknown) {
    if (typeof v !== 'number') {
      throw new Error(`Expected number but ${v} has type ${typeof v}`);
    }
  }

  private static ensureCorrectDecimalNumberPlaces(n: number, maxDecimalPlaces: number) {
    const parts = n.toString().split('.');
    if (parts.length > 1 && parts[1].length > maxDecimalPlaces) {
      throw new Error(
        `Encoder was created with maximum decimal places ${maxDecimalPlaces} but was asked to encode ${n}`
      );
    }
  }
}
