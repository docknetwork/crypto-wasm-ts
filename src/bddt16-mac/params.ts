import { ISignatureParams, MessageStructure } from '../types';
import {
  bddt16GenerateMacParams,
  bddt16IsMacParamsValid,
  bddt16MacAdaptParamsForMsgCount,
  bddt16MacCommitMsgs,
  Bddt16MacParams,
  bddt16MacParamsFromBytes,
  bddt16MacParamsToBytes,
  generateRandomFieldElement
} from 'crypto-wasm-new';
import { flattenMessageStructure, getSigParamsOfRequiredSize } from '../sign-verify-js-objs';

/**
 * BDDT16 MAC parameters.
 */
export class BDDT16MacParams implements ISignatureParams {
  label?: Uint8Array;
  value: Bddt16MacParams;

  constructor(params: Bddt16MacParams, label?: Uint8Array) {
    this.value = params;
    this.label = label;
  }

  /**
   * Number of messages that these params support and can be signed. If less or more messages are to be signed, use
   * `adapt`
   */
  supportedMessageCount(): number {
    return this.value.g_vec.length;
  }

  /**
   * Is message index valid as per the params
   * @param index
   */
  isValidIndex(index: number): boolean {
    return index >= 0 && index < this.supportedMessageCount();
  }

  getParamsForIndices(indices: number[]): Uint8Array[] {
    const p: Uint8Array[] = [];
    p.push(this.value.g);
    for (const i of indices) {
      if (!this.isValidIndex(i)) {
        throw new Error(`Invalid index ${i} for params with supported message count ${this.supportedMessageCount()}`);
      }
      p.push(this.value.g_vec[i]);
    }
    return p;
  }

  static generate(numMessages: number, label?: Uint8Array): BDDT16MacParams {
    const params = bddt16GenerateMacParams(numMessages, label);
    return new BDDT16MacParams(params, label);
  }

  static generateAsBytes(numMessages: number, label?: Uint8Array): Uint8Array {
    return BDDT16MacParams.generate(numMessages, label).toBytes();
  }

  toBytes(): Uint8Array {
    return bddt16MacParamsToBytes(this.value);
  }

  isValid(): boolean {
    return bddt16IsMacParamsValid(this.value);
  }

  static valueFromBytes(bytes: Uint8Array): Bddt16MacParams {
    return bddt16MacParamsFromBytes(bytes);
  }

  /**
   * Transform current MAC params to sign a different number of messages. Needs the `label` field to be present
   * @param newMsgCount
   */
  adapt(newMsgCount: number): this {
    if (this.label === undefined) {
      throw new Error(`Label should be present`);
    }
    let newParams;

    if (newMsgCount <= this.supportedMessageCount()) {
      newParams = {
        g_0: this.value.g_0,
        g: this.value.g,
        h: this.value.h,
        g_vec: this.value.g_vec.slice(0, newMsgCount)
      };
    } else {
      newParams = bddt16MacAdaptParamsForMsgCount(this.value, this.label, newMsgCount);
    }
    return new (this.constructor as typeof BDDT16MacParams)(newParams, this.label) as this;
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
    const commitment = bddt16MacCommitMsgs(messageToCommit, blinding, this.value, encodeMessages);
    return [commitment, blinding];
  }

  /**
   * Gives `BDDT16MacParams` that can sign `msgCount` number of messages.
   * @param msgCount
   * @param labelOrParams
   */
  static getMacParamsOfRequiredSize(msgCount: number, labelOrParams: Uint8Array | BDDT16MacParams): BDDT16MacParams {
    return getSigParamsOfRequiredSize(BDDT16MacParams, msgCount, labelOrParams);
  }

  static getMacParamsForMsgStructure(
    msgStructure: MessageStructure,
    labelOrParams: Uint8Array | BDDT16MacParams
  ): BDDT16MacParams {
    const msgCount = Object.keys(flattenMessageStructure(msgStructure)).length;
    return this.getMacParamsOfRequiredSize(msgCount, labelOrParams);
  }

  toJSON(): string {
    return JSON.stringify({
      value: {
        g_0: Array.from(this.value.g_0),
        g: Array.from(this.value.g),
        h: Array.from(this.value.h),
        g_vec: this.value.g_vec.map((g: Uint8Array) => Array.from(g))
      },
      label: this.label
    });
  }
}
