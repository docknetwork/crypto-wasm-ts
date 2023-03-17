import { SignatureG1 } from './signature';
import { flattenObjectToKeyValuesList, isPositiveInteger } from '../util';

/**
 * A function that encodes the input to field element bytes
 */
export type EncodeFunc = (value: unknown) => Uint8Array;

/**
 * A function that encodes the input to a positive integer
 */
export type ToPositiveIntFunc = (value: unknown) => number;

/**
 * Encodes the input to a field element for signing with BBS+ in group G1.
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
        return SignatureG1.encodeMessageForSigning(value);
      } else {
        throw new Error(
          `Cannot encode message with name ${name} and value ${value} as neither was any encoder provided nor it was an Uint8Array. Its type was ${typeof value}`
        );
      }
    }
  }

  /**
   * Encode messages given as JS object. It flattens the object into a sorted list and encodes each value as per the known
   * encoding functions Returns 2 arrays, 1st with message names and 2nd with encoded values.
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

  encodeDefault(value: unknown, strict = false): Uint8Array {
    if (this.defaultEncoder !== undefined) {
      return this.defaultEncoder(value);
    } else {
      if (!strict && value instanceof Uint8Array) {
        return SignatureG1.encodeMessageForSigning(value);
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
      return SignatureG1.encodePositiveNumberForSigning(v as number);
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
      return SignatureG1.encodePositiveNumberForSigning(f(v));
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
      return SignatureG1.encodePositiveNumberForSigning(f(v));
    };
  }

  /**
   * Returns a reversible encoding function to be used on a string message. The output can of the `EncodeFunc` can be
   * reversed.
   * @param compress
   */
  static reversibleEncoderString(compress = false): EncodeFunc {
    return (v: unknown) => {
      return SignatureG1.reversibleEncodeStringForSigning(v as string, compress);
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
      return SignatureG1.encodePositiveNumberForSigning(f(v));
    };
  }

  /**
   * Returns an encoding function to convert utf-8 string message. It might fail of the encoding target cannot be made a string
   */
  static defaultEncodeFunc(): EncodeFunc {
    const te = new TextEncoder();
    return (v: unknown) => {
      // @ts-ignore
      return SignatureG1.encodeMessageForSigning(te.encode(v.toString()));
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
