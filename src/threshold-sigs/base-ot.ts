import {
  baseOTPhaseFinish,
  baseOTPhaseProcessChallenges,
  baseOTPhaseProcessReceiverPubkey,
  baseOTPhaseProcessResponses,
  baseOTPhaseProcessSenderPubkey,
  startBaseOTPhase
} from 'crypto-wasm-new';
import { BytearrayWrapper } from '../bytearray-wrapper';
import { PublicKeyBase } from '../types';
import { BaseOTOutput } from './common';

export class SenderPublicKey extends BytearrayWrapper {}

export class ReceiverPublicKey extends BytearrayWrapper {}

export class Challenges extends BytearrayWrapper {}

export class Responses extends BytearrayWrapper {}

export class HashedKeys extends BytearrayWrapper {}

export class Participant {
  // Id of this participant
  readonly id: number;
  // Ids of the other participants of the protocol.
  readonly others: Set<number>;

  senderPks?: Map<number, SenderPublicKey>;
  receiverPks?: Map<number, ReceiverPublicKey>;
  challenges?: Map<number, Challenges>;
  responses?: Map<number, Responses>;
  hashedKeys?: Map<number, HashedKeys>;
  outputs?: BaseOTOutput;

  private state?: Uint8Array;

  constructor(id: number, others: Set<number>) {
    this.id = id;
    this.others = others;
  }

  /**
   * Returns a map of `SenderPublicKey`s where the key is intended recipient of the `SenderPublicKey`
   * @param pkBase - This EC curve point is independent of the one use in generating the public keys
   */
  start(pkBase: PublicKeyBase): Map<number, SenderPublicKey> {
    const r = startBaseOTPhase(this.id, this.others, pkBase.value);
    this.state = r[0];
    this.senderPks = new Map();
    for (const [i, p] of r[1]) {
      this.senderPks.set(i, new SenderPublicKey(p));
    }
    return this.senderPks;
  }

  /**
   * Returns `ReceiverPublicKey` that must be sent to participant with id `senderId`
   * @param senderId
   * @param pk
   * @param pkBase
   */
  processSenderPublicKey(senderId: number, pk: SenderPublicKey, pkBase: PublicKeyBase): ReceiverPublicKey {
    if (this.state === undefined) {
      throw new Error(`OT has not started yet`);
    }
    const r = baseOTPhaseProcessSenderPubkey(this.state, senderId, pk.value, pkBase.value);
    this.state = r[0];
    const receiverPk = new ReceiverPublicKey(r[1]);
    if (this.receiverPks === undefined) {
      this.receiverPks = new Map();
    }
    this.receiverPks.set(senderId, receiverPk);
    return receiverPk;
  }

  /**
   * Returns `Challenges` that must be sent to participant with id `senderId`
   * @param senderId
   * @param pk
   */
  processReceiverPublicKey(senderId: number, pk: ReceiverPublicKey): Challenges {
    if (this.state === undefined) {
      throw new Error(`OT has not started yet`);
    }
    const r = baseOTPhaseProcessReceiverPubkey(this.state, senderId, pk.value);
    this.state = r[0];
    const chal = new Challenges(r[1]);
    if (this.challenges === undefined) {
      this.challenges = new Map();
    }
    this.challenges.set(senderId, chal);
    return chal;
  }

  processChallenges(senderId: number, challenges: Challenges): Responses {
    if (this.state === undefined) {
      throw new Error(`OT has not started yet`);
    }
    const r = baseOTPhaseProcessChallenges(this.state, senderId, challenges.value);
    this.state = r[0];
    const resp = new Responses(r[1]);
    if (this.responses === undefined) {
      this.responses = new Map();
    }
    this.responses.set(senderId, resp);
    return resp;
  }

  processResponses(senderId: number, responses: Responses): HashedKeys {
    if (this.state === undefined) {
      throw new Error(`OT has not started yet`);
    }
    const r = baseOTPhaseProcessResponses(this.state, senderId, responses.value);
    this.state = r[0];
    const hk = new HashedKeys(r[1]);
    if (this.hashedKeys === undefined) {
      this.hashedKeys = new Map();
    }
    this.hashedKeys.set(senderId, hk);
    return hk;
  }

  finish() {
    if (this.state === undefined) {
      throw new Error(`OT has not started yet`);
    }
    this.outputs = new BaseOTOutput(baseOTPhaseFinish(this.state));
  }

  hasStarted(): boolean {
    return this.state !== undefined;
  }

  hasFinished(): boolean {
    return this.outputs !== undefined;
  }
}
