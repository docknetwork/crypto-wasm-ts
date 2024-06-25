import { bbsCommitMsgs } from 'crypto-wasm-new';
import {
  bbsGenerateSignatureParams,
  bbsSignatureParamsToBytes,
  bbsSignatureParamsFromBytes,
  bbsIsSignatureParamsValid,
  bbsAdaptSigParamsForMsgCount,
  BbsSigParams
} from 'crypto-wasm-new';
import { flattenMessageStructure, getSigParamsOfRequiredSize } from '../sign-verify-js-objs';
import { ISignatureParams, MessageStructure } from '../types';

/**
 * `BBS` signature parameters.
 */
export class BBSSignatureParams implements ISignatureParams {
  label?: Uint8Array;
  value: BbsSigParams;

  constructor(params: BbsSigParams, label?: Uint8Array) {
    this.value = params;
    this.label = label;
  }

  static generate(numMessages: number, label?: Uint8Array): BBSSignatureParams {
    const params = bbsGenerateSignatureParams(numMessages, label);
    return new BBSSignatureParams(params, label);
  }

  static generateAsBytes(numMessages: number, label?: Uint8Array): Uint8Array {
    return BBSSignatureParams.generate(numMessages, label).toBytes();
  }

  /**
   * Commit to given messages and return the commitment
   * @param messageToCommit
   * @param encodeMessages
   */
  commitToMessages(messageToCommit: Map<number, Uint8Array>, encodeMessages: boolean): Uint8Array {
    return bbsCommitMsgs(messageToCommit, this.value, encodeMessages);
  }

  toBytes(): Uint8Array {
    return bbsSignatureParamsToBytes(this.value);
  }

  isValid(): boolean {
    return bbsIsSignatureParamsValid(this.value);
  }

  static valueFromBytes(bytes: Uint8Array): BbsSigParams {
    return bbsSignatureParamsFromBytes(bytes);
  }

  /**
   * Transform current signature params to sign a different number of messages. Needs the `label` field to be present
   * @param newMsgCount
   */
  adapt(newMsgCount: number): this {
    if (this.label === undefined) {
      throw new Error(`Label should be present`);
    }
    let newParams: BbsSigParams;

    if (newMsgCount <= this.supportedMessageCount()) {
      newParams = {
        g1: this.value.g1,
        g2: this.value.g2,
        h: this.value.h.slice(0, newMsgCount)
      };
    } else {
      newParams = bbsAdaptSigParamsForMsgCount(this.value, this.label, newMsgCount);
    }
    return new (this.constructor as typeof BBSSignatureParams)(newParams, this.label) as this;
  }

  /**
   * Gives `BBSSignatureParams` that can sign `msgCount` number of messages.
   * @param msgCount
   * @param labelOrParams
   */
  static getSigParamsOfRequiredSize(
    msgCount: number,
    labelOrParams: Uint8Array | BBSSignatureParams
  ): BBSSignatureParams {
    return getSigParamsOfRequiredSize(BBSSignatureParams, msgCount, labelOrParams);
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
    for (const i of indices) {
      if (!this.isValidIndex(i)) {
        throw new Error(`Invalid index ${i} for params with supported message count ${this.supportedMessageCount()}`);
      }
      p.push(this.value.h[i]);
    }
    return p;
  }

  static getSigParamsForMsgStructure(
    msgStructure: MessageStructure,
    labelOrParams: Uint8Array | BBSSignatureParams
  ): BBSSignatureParams {
    const msgCount = Object.keys(flattenMessageStructure(msgStructure)).length;
    return this.getSigParamsOfRequiredSize(msgCount, labelOrParams);
  }

  toJSON(): string {
    return JSON.stringify({
      value: {
        g1: Array.from(this.value.g1),
        g2: Array.from(this.value.g2),
        h: this.value.h.map((h: Uint8Array) => Array.from(h))
      },
      label: this.label
    });
  }
}
