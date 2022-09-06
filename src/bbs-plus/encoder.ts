import { SignatureG1 } from './signature';
import { flattenObjectToKeyValuesList, isPositiveInteger } from '../util';

/**
 * A function that encodes the input to field element bytes
 */
export type EncodeFunc = (value: unknown) => Uint8Array;

/**
 * Encodes the input to a field element for signing with BBS+ in group G1.
 * Used when working with messages that are specified as JS objects. This encoder object will contain
 * the mapping from message name (key in JS object) to an encoding function
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
   */
  encodeMessage(name: string, value: unknown): Uint8Array {
    const encoder = this.encoders?.get(name) || this.defaultEncoder;
    if (encoder !== undefined) {
      return encoder(value);
    } else {
      if (value instanceof Uint8Array) {
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
   */
  encodeMessageObject(messages: object): [string[], Uint8Array[]] {
    const [names, values] = flattenObjectToKeyValuesList(messages);
    const encoded: Uint8Array[] = [];
    for (let i = 0; i < names.length; i++) {
      encoded.push(this.encodeMessage(names[i], values[i]));
    }
    return [names, encoded];
  }

  /**
   * Returns an encoding function to be used on a message that is a positive integer.
   */
  static positiveIntegerEncoder(): EncodeFunc {
    return (v: unknown) => {
      if (!isPositiveInteger(v)) {
        throw new Error(`Expected positive integer but ${v} has type ${typeof v}`);
      }
      // @ts-ignore
      return SignatureG1.encodePositiveNumberForSigning(v);
    };
  }

  /**
   * Returns an encoding function to be used on a message that can be a positive or negative integer.
   * @param minimum - The minimum negative value that the message can take
   */
  static integerEncoder(minimum: number): EncodeFunc {
    const offset = Math.abs(minimum);
    return (v: unknown) => {
      if (!Number.isInteger(v)) {
        throw new Error(`Expected integer but ${v} has type ${typeof v}`);
      }
      // @ts-ignore
      if (v < minimum) {
        throw new Error(`Encoder was created with minimum value ${minimum} but was asked to encode ${v}`);
      }
      // @ts-ignore
      return SignatureG1.encodePositiveNumberForSigning(offset + v);
    };
  }

  /**
   * Returns an encoding function to be used on a message that can be a positive decimal number, eg. 2.7
   * @param maxDecimalPlaces - The maximum decimal places
   */
  static positiveDecimalNumberEncoder(maxDecimalPlaces: number): EncodeFunc {
    if (!Number.isInteger(maxDecimalPlaces) || maxDecimalPlaces < 1) {
      throw new Error(`Maximum decimal places should be a positive integer greater than 1 but was ${maxDecimalPlaces}`);
    }
    const multiple = Math.pow(10, maxDecimalPlaces);
    return (v: unknown) => {
      Encoder.ensureNumber(v);
      // @ts-ignore
      Encoder.ensureCorrectDecimalNumberPlaces(v, maxDecimalPlaces);
      // @ts-ignore
      return SignatureG1.encodePositiveNumberForSigning(Math.trunc(v * multiple));
    };
  }

  /**
   * Returns an encoding function to be used on a message that can be a positive, negative or decimal number, eg. -2.35
   * @param minimum - The minimum negative value that the message can take
   * @param maxDecimalPlaces - The maximum decimal places
   */
  static decimalNumberEncoder(minimum: number, maxDecimalPlaces: number): EncodeFunc {
    if (!Number.isInteger(maxDecimalPlaces) || maxDecimalPlaces < 1) {
      throw new Error(`Maximum decimal places should be a positive integer greater than 1 but was ${maxDecimalPlaces}`);
    }
    const offset = Math.abs(minimum);
    const multiple = Math.pow(10, maxDecimalPlaces);
    return (v: unknown) => {
      Encoder.ensureNumber(v);
      // @ts-ignore
      if (v < minimum) {
        throw new Error(`Encoder was created with minimum value ${minimum} but was asked to encode ${v}`);
      }
      // @ts-ignore
      Encoder.ensureCorrectDecimalNumberPlaces(v, maxDecimalPlaces);
      // @ts-ignore
      return SignatureG1.encodePositiveNumberForSigning(Math.trunc((offset + v) * multiple));
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
