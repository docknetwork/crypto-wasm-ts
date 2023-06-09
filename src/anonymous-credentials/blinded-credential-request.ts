import { Versioned } from './versioned';
import { Presentation } from './presentation';
import { PredicateParamType, PublicKey, VERSION_STR } from './types-and-consts';
import { AccumulatorPublicKey } from '../accumulator';
import { VerifyResult } from '@docknetwork/crypto-wasm';
import { BBSBlindedCredentialBuilder, BBSPlusBlindedCredentialBuilder } from './blinded-credential-builder';

/**
 * A request for getting a blinded credential. Sent by the user to the signer who will verify it and then sign a blinded credential
 */
export abstract class BlindedCredentialRequest extends Versioned {
  // A blinded credential request will contain a presentation
  presentation: Presentation;

  protected constructor(version: string, presentation: Presentation) {
    if (presentation.spec.blindCredentialRequest === undefined) {
      throw new Error(
        'Presentation should contain a key "blindCredentialRequest" and that should contain data about the request'
      );
    }
    super(version);
    this.presentation = presentation;
  }

  verify(
    publicKeys: PublicKey[],
    accumulatorPublicKeys?: Map<number, AccumulatorPublicKey>,
    predicateParams?: Map<string, PredicateParamType>,
    circomOutputs?: Map<number, Uint8Array[][]>,
    blindedAttributesCircomOutputs?: Uint8Array[][]
  ): VerifyResult {
    return this.presentation.verify(
      publicKeys,
      accumulatorPublicKeys,
      predicateParams,
      circomOutputs,
      blindedAttributesCircomOutputs
    );
  }

  get sigType(): string {
    // @ts-ignore
    return this.presentation.spec.blindCredentialRequest?.sigType;
  }

  get builderVersion(): string {
    // @ts-ignore
    return this.presentation.spec.blindCredentialRequest?.version;
  }

  get schema(): string {
    // @ts-ignore
    return this.presentation.spec.blindCredentialRequest?.schema;
  }

  get blindedAttributes(): object {
    // @ts-ignore
    return this.presentation.spec.blindCredentialRequest?.blindedAttributes;
  }

  get commitment(): Uint8Array {
    // @ts-ignore
    return this.presentation.spec.blindCredentialRequest?.commitment;
  }

  toJSON(): object {
    return {
      [VERSION_STR]: this.version,
      presentation: this.presentation.toJSON()
    };
  }
}

export class BBSBlindedCredentialRequest extends BlindedCredentialRequest {
  constructor(version: string, presentation: Presentation) {
    super(version, presentation);
  }

  /**
   * Return the blinded credential builder which will be used to create the blinded credential
   * @returns 
   */
  generateBlindedCredentialBuilder(): BBSBlindedCredentialBuilder {
    // @ts-ignore
    return new BBSBlindedCredentialBuilder(this.presentation.spec.blindCredentialRequest);
  }

  static fromJSON(j: object): BBSBlindedCredentialRequest {
    // @ts-ignore
    const { version, presentation } = j;
    return new BBSBlindedCredentialRequest(version, Presentation.fromJSON(presentation));
  }
}

export class BBSPlusBlindedCredentialRequest extends BlindedCredentialRequest {
  constructor(version: string, presentation: Presentation) {
    super(version, presentation);
  }

  /**
   * Return the blinded credential builder which will be used to create the blinded credential
   * @returns 
   */
  generateBlindedCredentialBuilder(): BBSPlusBlindedCredentialBuilder {
    // @ts-ignore
    return new BBSPlusBlindedCredentialBuilder(this.presentation.spec.blindCredentialRequest);
  }

  static fromJSON(j: object): BBSPlusBlindedCredentialRequest {
    // @ts-ignore
    const { version, presentation } = j;
    return new BBSPlusBlindedCredentialRequest(version, Presentation.fromJSON(presentation));
  }
}
