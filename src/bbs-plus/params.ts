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
  BbsPlusSigParams
} from '@docknetwork/crypto-wasm';
import { IParams, MessageStructure, SignedMessages, flattenMessageStructure } from '../sign-verify-js-objs';
import { BBSPlusPublicKeyG1, BBSPlusSecretKey } from './keys';
import { BBSPlusSignatureG1 } from './signature';
import { Encoder } from '../encoder';
import { VerifyResult } from '@docknetwork/crypto-wasm';

/**
 * `BBS+` Signature parameters.
 */
export abstract class BBSPlusSignatureParams implements IParams {
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
    return new (this.constructor as any)(newParams, this.label);
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
    const commitment = bbsPlusCommitMsgsInG1(messageToCommit, b, this.value, encodeMessages);
    return [commitment, b];
  }

  static signMessageObject(
    messages: Object,
    secretKey: BBSPlusSecretKey,
    labelOrParams: Uint8Array | BBSPlusSignatureParamsG1,
    encoder: Encoder
  ): SignedMessages<BBSPlusSignatureG1> {
    const [names, encodedValues] = encoder.encodeMessageObject(messages);
    const msgCount = names.length;
  
    const sigParams = this.getSigParamsOfRequiredSize(msgCount, labelOrParams);
    const signature = BBSPlusSignatureG1.generate(encodedValues, secretKey, sigParams, false);
  
    // Encoded message as an object with key as the flattened name
    const encodedMessages: { [key: string]: Uint8Array } = {};
    for (let i = 0; i < msgCount; i++) {
      encodedMessages[names[i]] = encodedValues[i];
    }
  
    return {
      encodedMessages,
      signature
    };
  }

  /**
   * Verifies the signature on the given messages. Takes the messages as a JS object, flattens it, encodes the values similar
   * to signing and then verifies the signature.
   * @param messages
   * @param signature
   * @param publicKey
   * @param labelOrParams
   * @param encoder
   */
  static verifyMessageObject(
    messages: object,
    signature: BBSPlusSignatureG1,
    publicKey: BBSPlusPublicKeyG1,
    labelOrParams: Uint8Array | BBSPlusSignatureParamsG1,
    encoder: Encoder
  ): VerifyResult {
    const [_, encodedValues] = encoder.encodeMessageObject(messages);
    const msgCount = encodedValues.length;

    const sigParams = this.getSigParamsOfRequiredSize(msgCount, labelOrParams);
    return signature.verify(encodedValues, publicKey, sigParams, false);
  }

  /**
  * Gives `SignatureParamsG1` that can sign `msgCount` number of messages.
  * @param msgCount
  * @param labelOrParams
  */
  static getSigParamsOfRequiredSize(
    msgCount: number,
    labelOrParams: Uint8Array | BBSPlusSignatureParamsG1
  ): BBSPlusSignatureParamsG1 {
    let sigParams;
    if (labelOrParams instanceof this) {
      labelOrParams = labelOrParams as BBSPlusSignatureParamsG1;
      if (labelOrParams.supportedMessageCount() !== msgCount) {
        if (labelOrParams.label === undefined) {
          throw new Error(`Signature params mismatch, needed ${msgCount}, got ${labelOrParams.supportedMessageCount()}`);
        } else {
          sigParams = labelOrParams.adapt(msgCount);
        }
      } else {
        sigParams = labelOrParams;
      }
    } else {
      sigParams = this.generate(msgCount, labelOrParams as Uint8Array);
    }
    return sigParams;
  }

  static getSigParamsForMsgStructure(
    msgStructure: MessageStructure,
    labelOrParams: Uint8Array | BBSPlusSignatureParamsG1,
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
    return new (this.constructor as any)(newParams, this.label);
  }
}
