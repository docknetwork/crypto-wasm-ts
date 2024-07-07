import {
  bbsPlusGenerateSignatureParamsG1,
  bbsPlusGenerateSignatureParamsG2,
  bbsPlusSignatureParamsG1ToBytes,
  bbsPlusSignatureParamsG2ToBytes,
  bbsPlusSignatureParamsG1FromBytes,
  bbsPlusIsSignatureParamsG2Valid,
  bbsPlusIsSignatureParamsG1Valid,
  bbsPlusSignatureParamsG2FromBytes,
  bbsPlusAdaptSigParamsG1ForMsgCount,
  bbsPlusAdaptSigParamsG2ForMsgCount,
  bbsPlusCommitMsgsInG1,
  generateRandomFieldElement,
  BbsPlusSigParams, bbsPlusCommitMsgsInG1ConstantTime
} from 'crypto-wasm-new';
import { flattenMessageStructure, getSigParamsOfRequiredSize } from '../sign-verify-js-objs';
import { ISignatureParams, MessageStructure } from '../types';
/**
 * `BBS+` Signature parameters.
 */
export abstract class BBSPlusSignatureParams implements ISignatureParams {
  label?: Uint8Array;
  value: BbsPlusSigParams;

  constructor(params: BbsPlusSigParams, label?: Uint8Array) {
    this.value = params;
    this.label = label;
  }

  // static generateAsBytes(numMessages: number, label?: Uint8Array): Uint8Array;

  abstract toBytes(): Uint8Array;
  abstract isValid(): boolean;

  abstract adapt(newMsgCount: number): this;

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

/**
 * `BBS+` Signature parameters in `G1`.
 */
export class BBSPlusSignatureParamsG1 extends BBSPlusSignatureParams {
  static generate(numMessages: number, label?: Uint8Array): BBSPlusSignatureParamsG1 {
    const params = bbsPlusGenerateSignatureParamsG1(numMessages, label);
    return new BBSPlusSignatureParamsG1(params, label);
  }

  static generateAsBytes(numMessages: number, label?: Uint8Array): Uint8Array {
    return BBSPlusSignatureParamsG1.generate(numMessages, label).toBytes();
  }

  toBytes(): Uint8Array {
    return bbsPlusSignatureParamsG1ToBytes(this.value);
  }

  isValid(): boolean {
    return bbsPlusIsSignatureParamsG1Valid(this.value);
  }

  static valueFromBytes(bytes: Uint8Array): BbsPlusSigParams {
    return bbsPlusSignatureParamsG1FromBytes(bytes);
  }

  /**
   * Transform current signature params to sign a different number of messages. Needs the `label` field to be present
   * @param newMsgCount
   */
  adapt(newMsgCount: number): this {
    if (this.label === undefined) {
      throw new Error(`Label should be present`);
    }
    let newParams;

    if (newMsgCount <= this.supportedMessageCount()) {
      newParams = {
        g1: this.value.g1,
        g2: this.value.g2,
        h_0: this.value.h_0,
        h: this.value.h.slice(0, newMsgCount)
      };
    } else {
      newParams = bbsPlusAdaptSigParamsG1ForMsgCount(this.value, this.label, newMsgCount);
    }
    return new (this.constructor as typeof BBSPlusSignatureParamsG1)(newParams, this.label) as this;
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
    blinding: Uint8Array = generateRandomFieldElement()
  ): [Uint8Array, Uint8Array] {
    const commitment = bbsPlusCommitMsgsInG1(messageToCommit, blinding, this.value, encodeMessages);
    return [commitment, blinding];
  }

  /**
   * Commit to given messages and return the pair [blinding, commitment]
   * @param messageToCommit
   * @param encodeMessages
   * @param blinding - If not provided, a random blinding is generated
   */
  commitToMessagesConstantTime(
    messageToCommit: Map<number, Uint8Array>,
    encodeMessages: boolean,
    blinding: Uint8Array = generateRandomFieldElement()
  ): [Uint8Array, Uint8Array] {
    const commitment = bbsPlusCommitMsgsInG1ConstantTime(messageToCommit, blinding, this.value, encodeMessages);
    return [commitment, blinding];
  }

  /**
   * Gives `BBSPlusSignatureParamsG1` that can sign `msgCount` number of messages.
   * @param msgCount
   * @param labelOrParams
   */
  static getSigParamsOfRequiredSize(
    msgCount: number,
    labelOrParams: Uint8Array | BBSPlusSignatureParamsG1
  ): BBSPlusSignatureParamsG1 {
    return getSigParamsOfRequiredSize(BBSPlusSignatureParamsG1, msgCount, labelOrParams);
  }

  static getSigParamsForMsgStructure(
    msgStructure: MessageStructure,
    labelOrParams: Uint8Array | BBSPlusSignatureParamsG1
  ): BBSPlusSignatureParamsG1 {
    const msgCount = Object.keys(flattenMessageStructure(msgStructure)).length;
    return this.getSigParamsOfRequiredSize(msgCount, labelOrParams);
  }
}

/**
 * `BBS+` Signature parameters in `G2`.
 */
export class BBSPlusSignatureParamsG2 extends BBSPlusSignatureParams {
  static generate(numMessages: number, label?: Uint8Array) {
    const params = bbsPlusGenerateSignatureParamsG2(numMessages, label);
    return new BBSPlusSignatureParamsG2(params, label);
  }

  static generateAsBytes(numMessages: number, label?: Uint8Array): Uint8Array {
    return BBSPlusSignatureParamsG2.generate(numMessages, label).toBytes();
  }

  isValid(): boolean {
    return bbsPlusIsSignatureParamsG2Valid(this.value);
  }

  toBytes(): Uint8Array {
    return bbsPlusSignatureParamsG2ToBytes(this.value);
  }

  static valueFromBytes(bytes: Uint8Array): BbsPlusSigParams {
    return bbsPlusSignatureParamsG2FromBytes(bytes);
  }

  /**
   * Transform current signature params to sign a different number of messages. Needs the `label` field to be present
   * @param newMsgCount
   */
  adapt(newMsgCount: number): this {
    if (this.label === undefined) {
      throw new Error(`Label should be present`);
    }
    const newParams = bbsPlusAdaptSigParamsG2ForMsgCount(this.value, this.label, newMsgCount);
    return new (this.constructor as typeof BBSPlusSignatureParamsG2)(newParams, this.label) as this;
  }
}
