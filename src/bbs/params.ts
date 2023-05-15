import { VerifyResult, bbsCommitMsgs } from '@docknetwork/crypto-wasm';
import { generateRandomFieldElement } from '@docknetwork/crypto-wasm';
import {
  bbsGenerateSignatureParams,
  bbsSignatureParamsToBytes,
  bbsSignatureParamsFromBytes,
  bbsIsSignatureParamsValid,
  bbsAdaptSigParamsForMsgCount,
  BbsSigParams
} from '@docknetwork/crypto-wasm';
import { BBSSignature } from './signature';
import { BBSPublicKey, BBSSecretKey } from './keys';
import { Encoder } from '../encoder';
import { flattenMessageStructure } from '../sign-verify-js-objs';
import { ISignatureParams, MessageStructure, SignedMessages } from '../types';

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
  commitToMessages(
    messageToCommit: Map<number, Uint8Array>,
    encodeMessages: boolean
  ): Uint8Array {
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
    return new (this.constructor as typeof BBSSignatureParams)(newParams, this.label) as this;
  }

  static signMessageObject(
    messages: Object,
    secretKey: BBSSecretKey,
    labelOrParams: Uint8Array | BBSSignatureParams,
    encoder: Encoder
  ): SignedMessages<BBSSignature> {
    const [names, encodedValues] = encoder.encodeMessageObject(messages);
    const msgCount = names.length;
  
    const sigParams = this.getSigParamsOfRequiredSize(msgCount, labelOrParams);
    const signature = BBSSignature.generate(encodedValues, secretKey, sigParams, false);
  
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
    signature: BBSSignature,
    publicKey: BBSPublicKey,
    labelOrParams: Uint8Array | BBSSignatureParams,
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
    labelOrParams: Uint8Array | BBSSignatureParams
  ): BBSSignatureParams {
    let sigParams;
    if (labelOrParams instanceof this) {
      labelOrParams = labelOrParams as BBSSignatureParams;
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
    labelOrParams: Uint8Array | BBSSignatureParams,
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
