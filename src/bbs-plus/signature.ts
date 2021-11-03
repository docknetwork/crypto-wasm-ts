import {SignatureParamsG1} from "./params";
import {VerifyResult} from "../../../crypto-wasm/src/js";
import {
    bbsBlindSignG1,
    bbsEncodeMessageForSigning,
    bbsSignG1, bbsUnblindSigG1,
    bbsVerifyG1, generateRandomFieldElement,
} from "../../../crypto-wasm/src/js";

export abstract class Signature {
    value: Uint8Array;

    constructor(value: Uint8Array) {
        this.value = value;
    }

    static encodeMessageForSigning(message: Uint8Array): Uint8Array {
        return bbsEncodeMessageForSigning(message)
    }
}

export class SignatureG1 extends Signature {
    static generate(messages: Uint8Array[], secretKey: Uint8Array, params: SignatureParamsG1, encodeMessages: boolean): SignatureG1 {
        const sig = bbsSignG1(messages, secretKey, params.value, encodeMessages);
        return new SignatureG1(sig);
    }

    verify(messages: Uint8Array[], publicKey: Uint8Array, params: SignatureParamsG1, encodeMessages: boolean): VerifyResult {
        return bbsVerifyG1(messages, this.value, publicKey, params.value, encodeMessages);
    }
}

export abstract class BlindSignature {
    value: Uint8Array;

    constructor(value: Uint8Array) {
        this.value = value;
    }

    /**
     * Generate blinding for creating the commitment used in the request for blind signature
     * @param seed - Optional seed to serve as entropy for the blinding.
     */
    static generateBlinding(seed?: Uint8Array): Uint8Array {
        return generateRandomFieldElement(seed);
    }
}

export class BlindSignatureG1 extends BlindSignature {
    static generate(commitment: Uint8Array, knownMessages: Map<number, Uint8Array>, secretKey: Uint8Array, params: SignatureParamsG1, encodeMessages: boolean): BlindSignatureG1 {
        const sig = bbsBlindSignG1(commitment, knownMessages, secretKey, params.value, encodeMessages);
        return new BlindSignatureG1(sig);
    }

    unblind(blinding: Uint8Array): SignatureG1 {
        const sig = bbsUnblindSigG1(this.value, blinding);
        return new SignatureG1(sig);
    }
}

/**
 * Structure to send to the signer to request a blind signature
 */
interface BlindSignatureG1Request {
    /**
     * The commitment to the blinded messages
     */
    commitment: Uint8Array,
    /**
     * The messages at these indices were committed to in the commitment and are not revealed to the signer
     */
    blindedIndices: Set<number>,
    /**
     * The messages which are known to the signer. Here the key is message index (as per the `SignatureParams`). This is not
     * mandatory as the signer might already know the messages to sign. This is used when the requester wants to inform the
     * signer of some or all of the message
     */
    unblindedMessages?: Map<number, Uint8Array>
}
