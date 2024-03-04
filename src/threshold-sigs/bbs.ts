import { ThresholdBbsSignatureShare, ThresholdSigner } from './common';
import {
  thresholdBbsPhase1ProcessCommitments,
  thresholdBbsAggregateSignatureShares,
  thresholdBbsCreateSignatureShare,
  thresholdBbsPhase1Finish,
  thresholdBbsPhase1GetSharesForOther,
  thresholdBbsPhase1GetSharesForOthers,
  thresholdBbsPhase1ProcessShares,
  thresholdBbsPhase2Finish,
  thresholdBbsPhase2ReceiveMessage1,
  thresholdBbsPhase2ReceiveMessage2,
  thresholdBbsPhase2Start,
  thresholdBbsStartPhase1
} from 'crypto-wasm-new';
import { BBSSecretKey, BBSSignature, BBSSignatureParams } from '../bbs';

export class ThresholdBbsSigner extends ThresholdSigner {
  finishRound1(secretKey: BBSSecretKey) {
    this.finishR1(secretKey.value);
  }

  /**
   * Create a share of the BBS signature to be given to the user
   * @param messages - the messages to be signed for this signature
   * @param indexInBatch - the index (0-based) of this signature in the batch
   * @param params
   * @param encodeMessages
   */
  createSigShare(
    messages: Uint8Array[],
    indexInBatch: number,
    params: BBSSignatureParams,
    encodeMessages: boolean
  ): ThresholdBbsSignatureShare {
    this.ensureRound2Finished();
    const sigShare = thresholdBbsCreateSignatureShare(
      messages,
      indexInBatch,
      this.round1Output as Uint8Array,
      this.round2Output as Uint8Array,
      params.value,
      encodeMessages
    );
    return new ThresholdBbsSignatureShare(sigShare);
  }

  /**
   * Aggregate many signature shares to form a BBS signature
   * @param shares
   */
  static aggregateShares(shares: ThresholdBbsSignatureShare[]): BBSSignature {
    return new BBSSignature(thresholdBbsAggregateSignatureShares(shares.map((s) => s.value)));
  }

  protected startRound1Func(): (
    sigBatchSize: number,
    participantId: number,
    others: Set<number>,
    protocolId: Uint8Array
  ) => [Uint8Array, Uint8Array, Map<number, Uint8Array>] {
    return thresholdBbsStartPhase1;
  }

  protected processCommFunc(): (
    phase1: Uint8Array,
    senderId: number,
    commitments: Uint8Array,
    commitmentsZeroShare: Uint8Array
  ) => Uint8Array {
    return thresholdBbsPhase1ProcessCommitments;
  }

  protected getSharesForOtherFunc(): (phase1: Uint8Array, otherId: number) => [Uint8Array, Uint8Array] {
    return thresholdBbsPhase1GetSharesForOther;
  }

  protected getSharesForOthersFunc(): (phase1: Uint8Array, otherIds: number[]) => [Uint8Array, Uint8Array][] {
    return thresholdBbsPhase1GetSharesForOthers;
  }

  protected processSharesFunc(): (
    phase1: Uint8Array,
    senderId: number,
    shares: Uint8Array,
    zeroShares: Uint8Array
  ) => Uint8Array {
    return thresholdBbsPhase1ProcessShares;
  }

  protected finishRound1Func(): (phase1: Uint8Array, secretKey: Uint8Array) => Uint8Array {
    return thresholdBbsPhase1Finish;
  }

  protected startRound2Func(): (
    participantId: number,
    others: Set<number>,
    phase1Output: Uint8Array,
    baseOTOutput: Uint8Array,
    gadgetVector: Uint8Array
  ) => [Uint8Array, Map<number, Uint8Array>] {
    return thresholdBbsPhase2Start;
  }

  protected recvMsg1Func(): (
    phase2: Uint8Array,
    senderId: number,
    message: Uint8Array,
    gadgetVector: Uint8Array
  ) => [Uint8Array, Uint8Array] {
    return thresholdBbsPhase2ReceiveMessage1;
  }

  protected recvMsg2Func(): (
    phase2: Uint8Array,
    senderId: number,
    message: Uint8Array,
    gadgetVector: Uint8Array
  ) => Uint8Array {
    return thresholdBbsPhase2ReceiveMessage2;
  }

  protected finishRound2Func(): (phase2: Uint8Array) => Uint8Array {
    return thresholdBbsPhase2Finish;
  }
}
