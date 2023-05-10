import {
  psGenerateSignatureParams,
  psSignatureParamsToBytes,
  psSignatureParamsFromBytes,
  psIsSignatureParamsValid,
  psAdaptSignatureParamsForMsgCount,
  PSSigParams,
  VerifyResult,
  psMessageCommitment
} from '@docknetwork/crypto-wasm';
import { flattenMessageStructure, getSigParamsOfRequiredSize } from '../sign-verify-js-objs';
import { PSPublicKey, PSSecretKey } from './keys';
import { PSSignature } from './signature';
import { Encoder } from '../encoder';
import { psMultiMessageCommitment } from '@docknetwork/crypto-wasm';
import { ISignatureParams, MessageStructure, SignedMessages } from '../types';

/**
 * Modified Pointcheval-Sanders signature parameters used in `Coconut`.
 */
export class PSSignatureParams implements ISignatureParams {
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
  adapt(newMsgCount: number): this {
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
    return new (this.constructor as typeof PSSignatureParams)(newParams, this.label) as this;
  }

  static signMessageObject(
    messages: Object,
    secretKey: PSSecretKey,
    labelOrParams: Uint8Array | PSSignatureParams,
    encoder: Encoder
  ): SignedMessages<PSSignature> {
    const encodedMessages = encoder.encodeMessageObjectAsObject(messages);
    const encodedMessageList = Object.values(encodedMessages);
    const msgCount = encodedMessageList.length;

    const sigParams = this.getSigParamsOfRequiredSize(msgCount, labelOrParams);
    const supportedMsgCount = secretKey.supportedMessageCount();
    if (supportedMsgCount < msgCount) {
      throw new Error(`Unsupported message count - supported up to ${supportedMsgCount}, received: ${msgCount}`);
    } else if (supportedMsgCount > msgCount) {
      secretKey = secretKey.adaptForLess(msgCount);
    }
    const signature = PSSignature.generate(encodedMessageList, secretKey, sigParams);

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
    signature: PSSignature,
    publicKey: PSPublicKey,
    labelOrParams: Uint8Array | PSSignatureParams,
    encoder: Encoder
  ): VerifyResult {
    const [_, encodedValues] = encoder.encodeMessageObject(messages);
    const msgCount = encodedValues.length;

    const sigParams = this.getSigParamsOfRequiredSize(msgCount, labelOrParams);
    const supportedMsgCount = publicKey.supportedMessageCount();
    if (supportedMsgCount < msgCount) {
      throw new Error(`Unsupported message count - supported up to ${supportedMsgCount}, received: ${msgCount}`);
    } else if (supportedMsgCount > msgCount) {
      publicKey = publicKey.adaptForLess(msgCount);
    }
    return signature.verify(encodedValues, publicKey, sigParams);
  }

  /**
   * Gives `PSSignatureParams` that can sign `msgCount` number of messages.
   * @param msgCount
   * @param labelOrParams
   */
  static getSigParamsOfRequiredSize(
    msgCount: number,
    labelOrParams: Uint8Array | PSSignatureParams
  ): PSSignatureParams {
    return getSigParamsOfRequiredSize(PSSignatureParams, msgCount, labelOrParams);
  }

  static getSigParamsForMsgStructure(
    msgStructure: MessageStructure,
    labelOrParams: Uint8Array | PSSignatureParams
  ): PSSignatureParams {
    const msgCount = Object.keys(flattenMessageStructure(msgStructure)).length;
    return this.getSigParamsOfRequiredSize(msgCount, labelOrParams);
  }

  /**
   * Produces a commitment for the given message using supplied blinding.
   * @param message
   * @param blinding
   * @param h
   */
  messageCommitment(message: Uint8Array, blinding: Uint8Array, h: Uint8Array): Uint8Array {
    return psMessageCommitment(message, blinding, h, this.value.g);
  }

  /**
   * Produces a multi message commitment for the given message using supplied blinding.
   * @param messages
   * @param h (from params)
   * @param g
   * @param blinding
   */
  multiMessageCommitment(messages: Uint8Array[], h: Uint8Array[], blinding: Uint8Array): Uint8Array {
    return psMultiMessageCommitment(messages, h, this.value.g, blinding);
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
        g: Array.from(this.value.g),
        g_tilde: Array.from(this.value.g_tilde),
        h: this.value.h.map((h: Uint8Array) => Array.from(h))
      },
      label: this.label
    });
  }
}
