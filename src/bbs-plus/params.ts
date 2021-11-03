import {BbsSigParams} from '../../../crypto-wasm/src/js';

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
    bbsAdaptSigParamsG2ForMsgCount, bbsCommitMsgsInG1, generateRandomFieldElement
} from "../../../crypto-wasm/src/js";

export abstract class SignatureParams {
    label?: Uint8Array;
    value: BbsSigParams;

    constructor(params: BbsSigParams, label?: Uint8Array) {
        this.value = params;
        this.label = label;
    }

    // static generateAsBytes(numMessages: number, label?: Uint8Array): Uint8Array;

    abstract paramsToBytes(): Uint8Array;
    abstract isValid(): boolean;

    /**
     * Number of messages that these params support and can be signed. If less or more messages are to be signed, use
     * `adapt`
     */
    supportedMessageCount(): number {
        return this.value.h.length;
    }

    isValidIndex(i: number): boolean {
        return i >= 0 && i < this.supportedMessageCount();
    }

    /**
     * Get params, i.e. generator from `this.value.h` for certain indices
     * @param indices
     */
    getParamsForIndices(indices: number[]): Uint8Array[] {
        const p = [];
        p.push(this.value.h_0)
        for (const i of indices) {
            if (!this.isValidIndex(i)) {
                throw new Error(`Invalid index ${i} for params with supported message count ${this.supportedMessageCount()}`)
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
                h: this.value.h.map(h => Array.from(h))
            }, label: this.label
        })
    }
}

export class SignatureParamsG1 extends SignatureParams {
    static generate(numMessages: number, label?: Uint8Array): SignatureParamsG1 {
        const params = generateSignatureParamsG1(numMessages, label);
        return new SignatureParamsG1(params, label);
    }

    static generateAsBytes(numMessages: number, label?: Uint8Array): Uint8Array {
        return SignatureParamsG1.generate(numMessages, label).paramsToBytes();
    }

    paramsToBytes(): Uint8Array {
        return bbsSignatureParamsG1ToBytes(this.value);
    }

    isValid(): boolean {
        return isSignatureParamsG1Valid(this.value);
    }

    paramsFromBytes(bytes: Uint8Array): BbsSigParams {
        return bbsSignatureParamsG1FromBytes(bytes);
    }

    adapt(newMsgCount: number): SignatureParamsG1 {
        if (this.label === undefined) {
            throw new Error(`Label should be present`);
        }
        const newParams = bbsAdaptSigParamsG1ForMsgCount(this.value, this.label, newMsgCount);
        return new SignatureParamsG1(newParams, this.label);
    }

    commitToMessages(messageToCommit: Map<number, Uint8Array>, encodeMessages: boolean, blinding?: Uint8Array): [Uint8Array, Uint8Array] {
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
        return SignatureParamsG2.generate(numMessages, label).paramsToBytes();
    }

    isValid(): boolean {
        return isSignatureParamsG2Valid(this.value);
    }

    paramsToBytes(): Uint8Array {
        return bbsSignatureParamsG2ToBytes(this.value);
    }

    paramsFromBytes(bytes: Uint8Array): BbsSigParams {
        return bbsSignatureParamsG2FromBytes(bytes);
    }

    adapt(newMsgCount: number): SignatureParamsG2 {
        if (this.label === undefined) {
            throw new Error(`Label should be present`);
        }
        const newParams = bbsAdaptSigParamsG2ForMsgCount(this.value, this.label, newMsgCount);
        return new SignatureParamsG2(newParams, this.label);
    }
}
