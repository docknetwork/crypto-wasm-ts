import { bbsCommitMsgs } from '@docknetwork/crypto-wasm';
import { generateRandomFieldElement } from '@docknetwork/crypto-wasm';
import {
  bbsGenerateSignatureParams,
  bbsSignatureParamsToBytes,
  bbsSignatureParamsFromBytes,
  bbsIsSignatureParamsValid,
  bbsAdaptSigParamsForMsgCount,
  BbsSigParams
} from '@docknetwork/crypto-wasm';

/**
 * Signature parameters.
 */
export class BBSSignatureParams {
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
    const commitment = bbsCommitMsgs(messageToCommit, b, this.value, encodeMessages);
    return [commitment, b];
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
  adapt(newMsgCount: number): BBSSignatureParams {
    if (this.label === undefined) {
      throw new Error(`Label should be present`);
    }
    let newParams;

    if (newMsgCount <= this.supportedMessageCount()) {
      newParams = {
        g1: this.value.g1,
        g2: this.value.g2,
        h: this.value.h.slice(0, newMsgCount)
      };
    } else {
      newParams = bbsAdaptSigParamsForMsgCount(this.value, this.label, newMsgCount);
    }
    return new BBSSignatureParams(newParams, this.label);
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
