/**
 * Wraps a bytearray, i.e. Uint8Array. Used to give distinct types to objects as most of them are bytearrays because that
 * is what the WASM bindings accept and return.
 */
export class BytearrayWrapper {
  value: Uint8Array;

  constructor(value: Uint8Array) {
    this.value = value;
  }
}
