import { ThresholdBbsPlusSignatureShare, ThresholdSigner } from './common';
import {
  thresholdBbsPlusStartPhase1,
  thresholdBbsPlusPhase1ProcessCommitments,
  thresholdBbsPlusPhase1GetSharesForOther,
  thresholdBbsPlusPhase1GetSharesForOthers,
  thresholdBbsPlusPhase1ProcessShares,
  thresholdBbsPlusPhase1Finish,
  thresholdBbsPlusPhase2Start,
  thresholdBbsPlusPhase2ReceiveMessage1,
  thresholdBbsPlusPhase2ReceiveMessage2,
  thresholdBbsPlusPhase2Finish,
  thresholdBbsPlusCreateSignatureShare,
  thresholdBbsPlusAggregateSignatureShares
} from '@docknetwork/crypto-wasm';
import { BBSPlusSecretKey, BBSPlusSignatureParamsG1, BBSPlusSignatureG1 } from '../bbs-plus';

export class ThresholdBbsPlusSigner extends ThresholdSigner {
  finishRound1(secretKey: BBSPlusSecretKey) {
    this.finishR1(secretKey.value);
  }

  /**
   * Create a share of the BBS+ signature to be given to the user
   * @param messages - the messages to be signed for this signature
   * @param indexInBatch - the index (0-based) of this signature in the batch
   * @param params
   * @param encodeMessages
   */
  createSigShare(
    messages: Uint8Array[],
    indexInBatch: number,
    params: BBSPlusSignatureParamsG1,
    encodeMessages: boolean
  ): ThresholdBbsPlusSignatureShare {
    this.ensureRound2Finished();
    const sigShare = thresholdBbsPlusCreateSignatureShare(
      messages,
      indexInBatch,
      this.round1Output as Uint8Array,
      this.round2Output as Uint8Array,
      params.value,
      encodeMessages
    );
    return new ThresholdBbsPlusSignatureShare(sigShare);
  }

  /**
   * Aggregate many signature shares to form a BBS+ signature
   * @param shares
   */
  static aggregateShares(shares: ThresholdBbsPlusSignatureShare[]): BBSPlusSignatureG1 {
    return new BBSPlusSignatureG1(thresholdBbsPlusAggregateSignatureShares(shares.map((s) => s.value)));
  }

  protected startRound1Func(): (
    sigBatchSize: number,
    participantId: number,
    others: Set<number>,
    protocolId: Uint8Array
  ) => [Uint8Array, Uint8Array, Map<number, Uint8Array>] {
    return thresholdBbsPlusStartPhase1;
  }

  protected processCommFunc(): (
    phase1: Uint8Array,
    senderId: number,
    commitments: Uint8Array,
    commitmentsZeroShare: Uint8Array
  ) => Uint8Array {
    return thresholdBbsPlusPhase1ProcessCommitments;
  }

  protected getSharesForOtherFunc(): (phase1: Uint8Array, otherId: number) => [Uint8Array, Uint8Array] {
    return thresholdBbsPlusPhase1GetSharesForOther;
  }

  protected getSharesForOthersFunc(): (phase1: Uint8Array, otherIds: number[]) => [Uint8Array, Uint8Array][] {
    return thresholdBbsPlusPhase1GetSharesForOthers;
  }

  protected processSharesFunc(): (
    phase1: Uint8Array,
    senderId: number,
    shares: Uint8Array,
    zeroShares: Uint8Array
  ) => Uint8Array {
    return thresholdBbsPlusPhase1ProcessShares;
  }

  protected finishRound1Func(): (phase1: Uint8Array, secretKey: Uint8Array) => Uint8Array {
    return thresholdBbsPlusPhase1Finish;
  }

  protected startRound2Func(): (
    participantId: number,
    others: Set<number>,
    phase1Output: Uint8Array,
    baseOTOutput: Uint8Array,
    gadgetVector: Uint8Array
  ) => [Uint8Array, Map<number, Uint8Array>] {
    return thresholdBbsPlusPhase2Start;
  }

  protected recvMsg1Func(): (
    phase2: Uint8Array,
    senderId: number,
    message: Uint8Array,
    gadgetVector: Uint8Array
  ) => [Uint8Array, Uint8Array] {
    return thresholdBbsPlusPhase2ReceiveMessage1;
  }

  protected recvMsg2Func(): (
    phase2: Uint8Array,
    senderId: number,
    message: Uint8Array,
    gadgetVector: Uint8Array
  ) => Uint8Array {
    return thresholdBbsPlusPhase2ReceiveMessage2;
  }

  protected finishRound2Func(): (phase2: Uint8Array) => Uint8Array {
    return thresholdBbsPlusPhase2Finish;
  }
}
