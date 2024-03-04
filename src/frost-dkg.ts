import { BytearrayWrapper } from './bytearray-wrapper';
import {
  frostKeygenG1Round1Finish,
  frostKeygenG1Round1ProcessReceivedMessage,
  frostKeygenG1Round2Finish,
  frostKeygenG1Round2ProcessReceivedMessage,
  frostKeygenG1StartRound1,
  frostKeygenG1ThresholdPubkeyFromPubkeys,
  frostKeygenG2Round1Finish,
  frostKeygenG2Round1ProcessReceivedMessage,
  frostKeygenG2Round2Finish,
  frostKeygenG2Round2ProcessReceivedMessage,
  frostKeygenG2StartRound1,
  frostKeygenG2ThresholdPubkeyFromPubkeys,
  generateKeyBaseFromGivenG2Point
} from 'crypto-wasm-new';
import { PublicKeyBase } from './types';
import { BBSPlusSignatureParamsG1 } from './bbs-plus';
import { BBSSignatureParams } from './bbs';
import { ThresholdPublicKey } from './threshold-sigs';

export class Round1Msg extends BytearrayWrapper {}

export class Share extends BytearrayWrapper {}

/**
 * Participant in the FROST DKG mentioned in Figure 1 of the paper https://eprint.iacr.org/2020/852.pdf
 * Each participant has a unique integer id > 0 and ids form a contiguous set, i.e. no gaps. Protocol has 2 rounds and
 * in each round each participant sends message to others
 */
export abstract class Participant {
  // Id of this participant
  readonly id: number;
  readonly threshold: number;
  readonly total: number;
  // Id of this execution of the DKG. Use different ids in different protocol executions.
  readonly protocolId: Uint8Array;

  // Message to be sent in round 1
  round1Msg?: Round1Msg;
  // Shares to be sent in round 2
  shares?: Share[];

  // Count of messages received from others in round 1
  receivedFromInRound1Count?: number;
  // Sender ids who sent message in round 2
  receivedFromInRound2?: Set<number>;

  // The secret key of the participant
  secretKey?: Uint8Array;
  // The public key of the participant
  publicKey?: Uint8Array;
  // The threshold public key and all participants will have the same public key
  thresholdPublicKey?: Uint8Array;

  private round1State?: Uint8Array;
  private round2State?: Uint8Array;

  constructor(id: number, threshold: number, total: number, protocolId: Uint8Array) {
    this.id = id;
    this.threshold = threshold;
    this.total = total;
    this.protocolId = protocolId;
  }

  /**
   * Returns the message to be broadcast to all others
   * @param pkBase
   */
  startRound1(pkBase: PublicKeyBase): Round1Msg {
    const r = this.startRound1Func()(this.id, this.threshold, this.total, this.protocolId, pkBase.value);
    this.round1State = r[0];
    this.round1Msg = new Round1Msg(r[1]);
    this.receivedFromInRound1Count = 0;
    return this.round1Msg;
  }

  processReceivedMessageInRound1(msg: Round1Msg, pkBase: PublicKeyBase) {
    if (this.round1State === undefined) {
      throw new Error(`Round 1 has not started yet`);
    }
    this.round1State = this.processRound1MsgFunc()(this.round1State, msg.value, this.protocolId, pkBase.value);
    // @ts-ignore
    this.receivedFromInRound1Count++;
  }

  // Returns the shares where each share must be sent to its intended recipient
  finishRound1(unchecked = true): Share[] {
    if (this.round1State === undefined) {
      throw new Error(`Round 1 has not started yet`);
    }
    if (!unchecked && !this.hasThresholdParticipatedInRound1()) {
      throw new Error(`Only ${this.receivedFromInRound1Count} participated but atleast ${this.threshold} should have`);
    }
    const r = this.finishRound1Func()(this.round1State);
    this.round2State = r[0];
    this.shares = r[1].map((s) => new BytearrayWrapper(s));
    return this.shares;
  }

  processReceivedSharesInRound2(senderId: number, share: Share, pkBase: PublicKeyBase) {
    if (this.round2State === undefined) {
      throw new Error(`Round 2 has not started yet`);
    }
    this.round2State = this.processRound2MsgFunc()(this.round2State, senderId, share.value, pkBase.value);
    this.receivedFromInRound2?.add(senderId);
  }

  /**
   * Returns the secret key, public key and the threshold key
   * @param pkBase
   * @param unchecked
   */
  finishRound2(pkBase: PublicKeyBase, unchecked = true): [Uint8Array, Uint8Array, Uint8Array] {
    if (this.round2State === undefined) {
      throw new Error(`Round 2 has not started yet`);
    }
    if (!unchecked && !this.hasThresholdParticipatedInRound2()) {
      throw new Error(`Only ${this.receivedFromInRound2?.size} participated but atleast ${this.threshold} should have`);
    }
    const [sk, pk, tpk] = this.finishRound2Func()(this.round2State, pkBase.value);
    this.secretKey = sk;
    this.publicKey = pk;
    this.thresholdPublicKey = tpk;
    return [sk, pk, tpk];
  }

  // TODO: Ideally this and the function it calls should be static but TS does not allow static abstract yet
  generateThresholdPublicKeyFromPublicKeys(pubkeys: [number, Uint8Array][]): ThresholdPublicKey {
    return new ThresholdPublicKey(this.thresholdPublicKeyFromPublicKeysFunc()(pubkeys, this.threshold));
  }

  hasStarted(): boolean {
    return this.round1State !== undefined;
  }

  hasFinishedRound1(): boolean {
    return this.round2State !== undefined;
  }

  hasFinishedRound2(): boolean {
    return this.secretKey !== undefined;
  }

  hasThresholdParticipatedInRound1(): boolean {
    if (this.receivedFromInRound1Count === undefined) {
      throw new Error(`Round 1 has not started yet`);
    }
    return this.receivedFromInRound1Count >= this.threshold;
  }

  haveAllParticipatedInRound1(): boolean {
    if (this.receivedFromInRound1Count === undefined) {
      throw new Error(`Round 1 has not started yet`);
    }
    return this.receivedFromInRound1Count == this.total - 1;
  }

  hasThresholdParticipatedInRound2(): boolean {
    if (this.receivedFromInRound2 === undefined) {
      throw new Error(`Round 2 has not started yet`);
    }
    return this.receivedFromInRound2?.size >= this.threshold;
  }

  haveAllParticipatedInRound2(): boolean {
    if (this.receivedFromInRound2 === undefined) {
      throw new Error(`Round 2 has not started yet`);
    }
    return this.receivedFromInRound2?.size == this.total - 1;
  }

  protected abstract startRound1Func(): (
    participantId: number,
    threshold: number,
    total: number,
    protocolId: Uint8Array,
    pkBase: Uint8Array
  ) => [Uint8Array, Uint8Array];

  protected abstract processRound1MsgFunc(): (
    roundState: Uint8Array,
    msg: Uint8Array,
    protocolId: Uint8Array,
    pkBase: Uint8Array
  ) => Uint8Array;

  protected abstract finishRound1Func(): (roundState: Uint8Array) => [Uint8Array, Uint8Array[]];

  protected abstract processRound2MsgFunc(): (
    roundState: Uint8Array,
    senderId: number,
    share: Uint8Array,
    pkBase: Uint8Array
  ) => Uint8Array;

  protected abstract finishRound2Func(): (
    roundState: Uint8Array,
    pkBase: Uint8Array
  ) => [Uint8Array, Uint8Array, Uint8Array];

  protected abstract thresholdPublicKeyFromPublicKeysFunc(): (
    pubkeys: [number, Uint8Array][],
    threshold: number
  ) => Uint8Array;
}

export class ParticipantG1 extends Participant {
  protected startRound1Func(): (
    participantId: number,
    threshold: number,
    total: number,
    protocolId: Uint8Array,
    pkBase: Uint8Array
  ) => [Uint8Array, Uint8Array] {
    return frostKeygenG1StartRound1;
  }

  protected processRound1MsgFunc(): (
    roundState: Uint8Array,
    msg: Uint8Array,
    protocolId: Uint8Array,
    pkBase: Uint8Array
  ) => Uint8Array {
    return frostKeygenG1Round1ProcessReceivedMessage;
  }

  protected finishRound1Func(): (roundState: Uint8Array) => [Uint8Array, Uint8Array[]] {
    return frostKeygenG1Round1Finish;
  }

  protected processRound2MsgFunc(): (
    roundState: Uint8Array,
    senderId: number,
    share: Uint8Array,
    pkBase: Uint8Array
  ) => Uint8Array {
    return frostKeygenG1Round2ProcessReceivedMessage;
  }

  protected finishRound2Func(): (roundState: Uint8Array, pkBase: Uint8Array) => [Uint8Array, Uint8Array, Uint8Array] {
    return frostKeygenG1Round2Finish;
  }

  protected thresholdPublicKeyFromPublicKeysFunc(): (pubkeys: [number, Uint8Array][], threshold: number) => Uint8Array {
    return frostKeygenG1ThresholdPubkeyFromPubkeys;
  }
}

export class ParticipantG2 extends Participant {
  protected startRound1Func(): (
    participantId: number,
    threshold: number,
    total: number,
    protocolId: Uint8Array,
    pkBase: Uint8Array
  ) => [Uint8Array, Uint8Array] {
    return frostKeygenG2StartRound1;
  }

  protected processRound1MsgFunc(): (
    roundState: Uint8Array,
    msg: Uint8Array,
    protocolId: Uint8Array,
    pkBase: Uint8Array
  ) => Uint8Array {
    return frostKeygenG2Round1ProcessReceivedMessage;
  }

  protected finishRound1Func(): (roundState: Uint8Array) => [Uint8Array, Uint8Array[]] {
    return frostKeygenG2Round1Finish;
  }

  protected processRound2MsgFunc(): (
    roundState: Uint8Array,
    senderId: number,
    share: Uint8Array,
    pkBase: Uint8Array
  ) => Uint8Array {
    return frostKeygenG2Round2ProcessReceivedMessage;
  }

  protected finishRound2Func(): (roundState: Uint8Array, pkBase: Uint8Array) => [Uint8Array, Uint8Array, Uint8Array] {
    return frostKeygenG2Round2Finish;
  }

  protected thresholdPublicKeyFromPublicKeysFunc(): (pubkeys: [number, Uint8Array][], threshold: number) => Uint8Array {
    return frostKeygenG2ThresholdPubkeyFromPubkeys;
  }

  /**
   * The public key in BBS+ uses the elliptic curve point from the signature params so returns that
   * @param params
   */
  static generatePublicKeyBaseFromBbsPlusParams(params: BBSPlusSignatureParamsG1): PublicKeyBase {
    return new PublicKeyBase(generateKeyBaseFromGivenG2Point(params.value.g2));
  }

  /**
   * The public key in BBS uses the elliptic curve point from the signature params so returns that
   * @param params
   */
  static generatePublicKeyBaseFromBbsParams(params: BBSSignatureParams): PublicKeyBase {
    return new PublicKeyBase(generateKeyBaseFromGivenG2Point(params.value.g2));
  }
}
