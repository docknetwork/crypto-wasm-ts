import {
  psGenerateSignatureParams,
  psSignatureParamsToBytes,
  psSignatureParamsFromBytes,
  psIsSignatureParamsValid,
  psAdaptSignatureParamsForMsgCount,
  PSSigParams
} from '@docknetwork/crypto-wasm';

/**
 * Signature parameters.
 */
export class PSSignatureParams {
  label?: Uint8Array;
  value: PSSigParams;

  constructor(params: PSSigParams, label?: Uint8Array) {
    this.value = params;
    this.label = label;
  }

  static generate(numMessages: number, label?: Uint8Array): PSSignatureParams {
    const params = psGenerateSignatureParams(numMessages, label);
    return new PSSignatureParams(params, label);
  }

  static generateAsBytes(numMessages: number, label?: Uint8Array): Uint8Array {
    return PSSignatureParams.generate(numMessages, label).toBytes();
  }

  toBytes(): Uint8Array {
    return psSignatureParamsToBytes(this.value);
  }

  isValid(): boolean {
    return psIsSignatureParamsValid(this.value);
  }

  static valueFromBytes(bytes: Uint8Array): PSSigParams {
    return psSignatureParamsFromBytes(bytes);
  }

  /**
   * Transform current signature params to sign a different number of messages. Needs the `label` field to be present
   * @param newMsgCount
   */
  adapt(newMsgCount: number): PSSignatureParams {
    if (this.label === undefined) {
      throw new Error(`Label should be present`);
    }
    let newParams;

    if (newMsgCount <= this.supportedMessageCount()) {
      newParams = {
        g: this.value.g,
        g_tilde: this.value.g_tilde,
        h: this.value.h.slice(0, newMsgCount)
      };
    } else {
      newParams = psAdaptSignatureParamsForMsgCount(this.value, this.label, newMsgCount);
    }
    return new PSSignatureParams(newParams, this.label);
  }

  /**
   * Number of messages that these params support and can be signed. If less or more messages are to be signed, use
   * `adapt`
   */
  supportedMessageCount(): number {
    return this.value.h.length;
  }

  /**
   * Is message index valid as per the params
   * @param index
   */
  isValidIndex(index: number): boolean {
    return index >= 0 && index < this.supportedMessageCount();
  }

  /**
   * Get params, i.e. generator from `this.value.h` for certain indices
   * @param indices
   */
  getParamsForIndices(indices: number[]): Uint8Array[] {
    const p: Uint8Array[] = [];
    p.push(this.value.g_tilde);
    for (const i of indices) {
      if (!this.isValidIndex(i)) {
        throw new Error(`Invalid index ${i} for params with supported message count ${this.supportedMessageCount()}`);
      }
      p.push(this.value.h[i]);
    }
    return p;
  }

  toJSON(): string {
    return JSON.stringify({
      value: {
        g: Array.from(this.value.g),
        g_tilde: Array.from(this.value.g_tilde),
        h: this.value.h.map((h: Uint8Array) => Array.from(h))
      },
      label: this.label
    });
  }
}
