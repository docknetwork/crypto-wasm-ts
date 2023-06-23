import { BytearrayWrapper } from './bytearray-wrapper';

export interface ISignatureParams {
  label?: Uint8Array;

  supportedMessageCount(): number;
  adapt(messageCount: number): this;
}

// The following `ts-ignore` shouldn't be necessary as per https://github.com/microsoft/TypeScript/pull/33050 but it still is (on TS 4.8)
// @ts-ignore
export type MessageStructure = Record<string, null | MessageStructure>;

export interface SignedMessages<Signature> {
  encodedMessages: { [key: string]: Uint8Array };
  signature: Signature;
}

/**
 * The publicly known value (elliptic curve base point) which is used with (multiplied by) the secret key to generate the public key
 */
export class PublicKeyBase extends BytearrayWrapper {}