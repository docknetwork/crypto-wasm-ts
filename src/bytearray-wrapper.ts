import { bytearrayToHex, hexToBytearray } from './util';

/**
 * Wraps a bytearray, i.e. Uint8Array. Used to give distinct types to objects as most of them are bytearrays because that
 * is what the WASM bindings accept and return.
 */
export class BytearrayWrapper {
  value: Uint8Array;

  constructor(value: Uint8Array) {
    this.value = value;
  }

  static fromBytes(bytes: Uint8Array) {
    return new this(bytes);
  }

  /**
   * Return the wrapped bytearray
   */
  get bytes(): Uint8Array {
    return this.value;
  }

  /**
   * Return the length of the wrapped bytearray
   */
  get length(): number {
    return this.value.length;
  }

  /**
   * Return the hex representation of the wrapped bytearray
   */
  get hex(): string {
    return bytearrayToHex(this.value);
  }

  static fromHex(hex: string) {
    return new this(hexToBytearray(hex));
  }
}
