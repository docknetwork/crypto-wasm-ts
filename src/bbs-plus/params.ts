import {
  generateSignatureParamsG1,
  generateSignatureParamsG2,
  bbsSignatureParamsG1ToBytes,
  bbsSignatureParamsG2ToBytes,
  bbsSignatureParamsG1FromBytes,
  isSignatureParamsG2Valid,
  isSignatureParamsG1Valid,
  bbsSignatureParamsG2FromBytes,
  bbsAdaptSigParamsG1ForMsgCount,
  bbsAdaptSigParamsG2ForMsgCount,
  bbsCommitMsgsInG1,
  generateRandomFieldElement,
  BbsSigParams
} from '@docknetwork/crypto-wasm';

/**
 * Signature parameters.
 */
export abstract class SignatureParams {
  label?: Uint8Array;
  value: BbsSigParams;

  constructor(params: BbsSigParams, label?: Uint8Array) {
    this.value = params;
    this.label = label;
  }

  // static generateAsBytes(numMessages: number, label?: Uint8Array): Uint8Array;

  abstract toBytes(): Uint8Array;
  abstract isValid(): boolean;

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
    const p = [];
    p.push(this.value.h_0);
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
        g1: Array.from(this.value.g1),
        g2: Array.from(this.value.g2),
        h_0: Array.from(this.value.h_0),
        h: this.value.h.map((h: Uint8Array) => Array.from(h))
      },
      label: this.label
    });
  }
}

export class SignatureParamsG1 extends SignatureParams {
  static generate(numMessages: number, label?: Uint8Array): SignatureParamsG1 {
    const params = generateSignatureParamsG1(numMessages, label);
    return new SignatureParamsG1(params, label);
  }

  static generateAsBytes(numMessages: number, label?: Uint8Array): Uint8Array {
    return SignatureParamsG1.generate(numMessages, label).toBytes();
  }

  toBytes(): Uint8Array {
    return bbsSignatureParamsG1ToBytes(this.value);
  }

  isValid(): boolean {
    return isSignatureParamsG1Valid(this.value);
  }

  static valueFromBytes(bytes: Uint8Array): BbsSigParams {
    return bbsSignatureParamsG1FromBytes(bytes);
  }

  /**
   * Transform current signature params to sign a different number of messages. Needs the `label` field to be present
   * @param newMsgCount
   */
  adapt(newMsgCount: number): SignatureParamsG1 {
    if (this.label === undefined) {
      throw new Error(`Label should be present`);
    }
    // Possible optimization: if `newMsgCount` is smaller than current size, then WASM call can be avoided by dropping some `h`
    const newParams = bbsAdaptSigParamsG1ForMsgCount(this.value, this.label, newMsgCount);
    return new SignatureParamsG1(newParams, this.label);
  }

  /**
   * Commit to given messages and return the pair [blinding, commitment]
   * @param messageToCommit
   * @param encodeMessages
   * @param blinding - If not provided, a random blinding is generated
   */
  commitToMessages(
    messageToCommit: Map<number, Uint8Array>,
    encodeMessages: boolean,
    blinding?: Uint8Array
  ): [Uint8Array, Uint8Array] {
    const b = blinding === undefined ? generateRandomFieldElement() : blinding;
    const commitment = bbsCommitMsgsInG1(messageToCommit, b, this.value, encodeMessages);
    return [commitment, b];
  }
}

export class SignatureParamsG2 extends SignatureParams {
  static generate(numMessages: number, label?: Uint8Array) {
    const params = generateSignatureParamsG2(numMessages, label);
    return new SignatureParamsG2(params, label);
  }

  static generateAsBytes(numMessages: number, label?: Uint8Array): Uint8Array {
    return SignatureParamsG2.generate(numMessages, label).toBytes();
  }

  isValid(): boolean {
    return isSignatureParamsG2Valid(this.value);
  }

  toBytes(): Uint8Array {
    return bbsSignatureParamsG2ToBytes(this.value);
  }

  static valueFromBytes(bytes: Uint8Array): BbsSigParams {
    return bbsSignatureParamsG2FromBytes(bytes);
  }

  /**
   * Transform current signature params to sign a different number of messages. Needs the `label` field to be present
   * @param newMsgCount
   */
  adapt(newMsgCount: number): SignatureParamsG2 {
    if (this.label === undefined) {
      throw new Error(`Label should be present`);
    }
    const newParams = bbsAdaptSigParamsG2ForMsgCount(this.value, this.label, newMsgCount);
    return new SignatureParamsG2(newParams, this.label);
  }
}
