import { SignatureParamsG1 } from './params';
import { VerifyResult } from '@docknetwork/crypto-wasm';
import {
  bbsBlindSignG1,
  bbsEncodeMessageForSigning,
  bbsSignG1,
  bbsUnblindSigG1,
  bbsVerifyG1,
  generateRandomFieldElement
} from '@docknetwork/crypto-wasm';

export abstract class Signature {
  value: Uint8Array;

  constructor(value: Uint8Array) {
    this.value = value;
  }

  static encodeMessageForSigning(message: Uint8Array): Uint8Array {
    return bbsEncodeMessageForSigning(message);
  }
}

export class SignatureG1 extends Signature {
  /**
   * Signer creates a new signature
   * @param messages - Ordered list of messages. Order and contents should be kept same for both signer and verifier
   * @param secretKey
   * @param params
   * @param encodeMessages - If true, the messages are encoded as field elements otherwise they are assumed to be already encoded.
   */
  static generate(
    messages: Uint8Array[],
    secretKey: Uint8Array,
    params: SignatureParamsG1,
    encodeMessages: boolean
  ): SignatureG1 {
    const sig = bbsSignG1(messages, secretKey, params.value, encodeMessages);
    return new SignatureG1(sig);
  }

  /**
   * Verify the signature
   * @param messages - Ordered list of messages. Order and contents should be kept same for both signer and verifier
   * @param publicKey
   * @param params
   * @param encodeMessages - If true, the messages are encoded as field elements otherwise they are assumed to be already encoded.
   */
  verify(
    messages: Uint8Array[],
    publicKey: Uint8Array,
    params: SignatureParamsG1,
    encodeMessages: boolean
  ): VerifyResult {
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
  /**
   * Generates a blind signature over the commitment of unknown messages and known messages
   * @param commitment - Commitment over unknown messages sent by the requester of the blind signature. Its assumed that
   * the signers has verified the knowledge of committed messages
   * @param knownMessages
   * @param secretKey
   * @param params
   * @param encodeMessages
   */
  static generate(
    commitment: Uint8Array,
    knownMessages: Map<number, Uint8Array>,
    secretKey: Uint8Array,
    params: SignatureParamsG1,
    encodeMessages: boolean
  ): BlindSignatureG1 {
    const sig = bbsBlindSignG1(commitment, knownMessages, secretKey, params.value, encodeMessages);
    return new BlindSignatureG1(sig);
  }

  /**
   * Unblind the blind signature to get a regular signature that can be verified
   * @param blinding
   */
  unblind(blinding: Uint8Array): SignatureG1 {
    const sig = bbsUnblindSigG1(this.value, blinding);
    return new SignatureG1(sig);
  }

  /**
   * Generate a request for a blind signature
   * @param messagesToBlind - messages the requester wants to hide from the signer. The key of the map is the index of the
   * message as per the params.
   * @param params
   * @param encodeMessages
   * @param blinding - If not provided, a random blinding is generated
   * @param unblindedMessages - Any messages that the requester wishes to inform the signer about. This is for informational
   * purpose only and has no cryptographic use.
   */
  static generateRequest(
    messagesToBlind: Map<number, Uint8Array>,
    params: SignatureParamsG1,
    encodeMessages: boolean,
    blinding?: Uint8Array,
    unblindedMessages?: Map<number, Uint8Array>
  ): [Uint8Array, BlindSignatureRequest] {
    const [commitment, b] = params.commitToMessages(messagesToBlind, encodeMessages, blinding);
    const blindedIndices = new Set<number>();
    for (const k of messagesToBlind.keys()) {
      blindedIndices.add(k);
    }

    return [b, { commitment, blindedIndices, unblindedMessages }];
  }
}

/**
 * Structure to send to the signer to request a blind signature
 */
interface BlindSignatureRequest {
  /**
   * The commitment to the blinded messages
   */
  commitment: Uint8Array;
  /**
   * The messages at these indices were committed to in the commitment and are not revealed to the signer
   */
  blindedIndices: Set<number>;
  /**
   * The messages which are known to the signer. Here the key is message index (as per the `SignatureParams`). This is not
   * mandatory as the signer might already know the messages to sign. This is used when the requester wants to inform the
   * signer of some or all of the message
   */
  unblindedMessages?: Map<number, Uint8Array>;
}
