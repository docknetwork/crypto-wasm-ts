import { generateRandomG1Element } from 'crypto-wasm-new';
import {
  BBSPlusPublicKeyG2,
  BBSPlusSecretKey,
  BBSPlusSignatureParamsG1,
  BBSPublicKey,
  BBSSecretKey,
  BBSSignatureParams,
  initializeWasm
} from '../src';
import { ParticipantG2 } from '../src/frost-dkg';
import {
  BaseOTOutput,
  Challenges,
  Commitments,
  CommitmentsForZeroSharing,
  GadgetVector,
  HashedKeys,
  Message1,
  Message2,
  Participant as BaseOTParticipant,
  ReceiverPublicKey,
  Responses,
  SenderPublicKey,
  ThresholdBbsPlusSignatureShare,
  ThresholdBbsPlusSigner,
  ThresholdBbsSignatureShare
} from '../src/threshold-sigs';
import { ThresholdBbsSigner } from '../src/threshold-sigs/bbs';
import { PublicKeyBase } from '../src/types';
import { checkResult, runFrostKeygen, stringToBytes } from './utils';

describe('Threshold BBS+ and BBS', () => {
  const threshold = 3;
  const total = 5;
  const messageCount = 10;
  const sigBatchSize = 2;
  const allSignerIds = new Set(Array.from({ length: total }, (_, i) => i + 1));

  let paramsBbsPlus: BBSPlusSignatureParamsG1;
  const skBbsPlus: BBSPlusSecretKey[] = [];
  const pkBbsPlus: BBSPlusPublicKeyG2[] = [];
  let thresholdPkBbsPlus: BBSPlusPublicKeyG2;

  let paramsBbs: BBSSignatureParams;
  const skBbs: BBSSecretKey[] = [];
  const pkBbs: BBSPublicKey[] = [];
  let thresholdPkBbs: BBSPublicKey;

  const baseOTOutputs: BaseOTOutput[] = [];

  let gadgetVector: GadgetVector;

  beforeAll(async () => {
    await initializeWasm();
    const label = stringToBytes('BBS+ sig params');
    paramsBbsPlus = BBSPlusSignatureParamsG1.generate(messageCount, label);
    paramsBbs = BBSSignatureParams.generate(messageCount, label);

    const keygenBbsPlus: ParticipantG2[] = [];
    const keygenBbs: ParticipantG2[] = [];
    const protocolIdBbsPlus = stringToBytes('DKG for BBS+');
    const protocolIdBbs = stringToBytes('DKG for BBS');
    for (let i = 1; i <= total; i++) {
      keygenBbsPlus.push(new ParticipantG2(i, threshold, total, protocolIdBbsPlus));
      keygenBbs.push(new ParticipantG2(i, threshold, total, protocolIdBbs));
    }

    // The public key in both BBS+ and BBS uses the elliptic curve point from signature params
    const pkBaseBbsPlus = ParticipantG2.generatePublicKeyBaseFromBbsPlusParams(paramsBbsPlus);
    const pkBaseBbs = ParticipantG2.generatePublicKeyBaseFromBbsParams(paramsBbs);

    // All participants generate their secret key, public key and the threshold key
    const [s1, p1, t1] = runFrostKeygen(keygenBbsPlus, pkBaseBbsPlus);
    const [s2, p2, t2] = runFrostKeygen(keygenBbs, pkBaseBbs);

    for (let i = 0; i < total; i++) {
      skBbsPlus.push(new BBSPlusSecretKey(s1[i]));
      pkBbsPlus.push(skBbsPlus[i].generatePublicKeyG2(paramsBbsPlus));
      expect(pkBbsPlus[i].value).toEqual(p1[i]);
      expect(pkBbsPlus[i].isValid()).toEqual(true);

      skBbs.push(new BBSSecretKey(s2[i]));
      pkBbs.push(skBbs[i].generatePublicKey(paramsBbs));
      expect(pkBbs[i].value).toEqual(p2[i]);
      expect(pkBbs[i].isValid()).toEqual(true);
    }

    thresholdPkBbsPlus = new BBSPlusPublicKeyG2(t1);
    thresholdPkBbs = new BBSPublicKey(t2);

    gadgetVector = GadgetVector.generate(stringToBytes('testing'));
  });

  it('run base OT phase', () => {
    // The base OT phase will be used for both BBS+ and BBS
    let pkBase = new PublicKeyBase(generateRandomG1Element());
    const participants: BaseOTParticipant[] = [];
    const senderPks = new Map<number, Map<number, SenderPublicKey>>();
    const receiverPks = new Map<[number, number], ReceiverPublicKey>();
    const challenges = new Map<[number, number], Challenges>();
    const responses = new Map<[number, number], Responses>();
    const hashedKeys = new Map<[number, number], HashedKeys>();

    for (let i = 1; i <= total; i++) {
      const others = new Set(allSignerIds);
      others.delete(i);
      const p = new BaseOTParticipant(i, others);
      expect(p.hasStarted()).toEqual(false);
      const pk = p.start(pkBase);
      senderPks.set(p.id, pk);
      expect(p.hasStarted()).toEqual(true);
      participants.push(p);
    }

    for (const [senderId, pks] of senderPks) {
      for (const [receiverId, pk] of pks) {
        const rpk = participants[receiverId - 1].processSenderPublicKey(senderId, pk, pkBase);
        receiverPks.set([receiverId, senderId], rpk);
      }
    }

    for (const [[senderId, receiverId], pk] of receiverPks) {
      const chal = participants[receiverId - 1].processReceiverPublicKey(senderId, pk);
      challenges.set([receiverId, senderId], chal);
    }

    for (const [[senderId, receiverId], chal] of challenges) {
      const resp = participants[receiverId - 1].processChallenges(senderId, chal);
      responses.set([receiverId, senderId], resp);
    }

    for (const [[senderId, receiverId], resp] of responses) {
      const hk = participants[receiverId - 1].processResponses(senderId, resp);
      hashedKeys.set([receiverId, senderId], hk);
    }

    for (let i = 0; i < total; i++) {
      expect(participants[i].hasFinished()).toEqual(false);
      participants[i].finish();
      expect(participants[i].hasFinished()).toEqual(true);
      baseOTOutputs.push(participants[i].outputs as BaseOTOutput);
    }
  });

  function checkThresholdSig(
    protocolId: Uint8Array,
    signerClass: typeof ThresholdBbsPlusSigner | typeof ThresholdBbsSigner,
    sigShareClass: typeof ThresholdBbsPlusSignatureShare | typeof ThresholdBbsSignatureShare,
    secretKeys: BBSPlusSecretKey[] | BBSSecretKey[],
    thresholdPk: BBSPlusPublicKeyG2 | BBSPublicKey,
    params: BBSPlusSignatureParamsG1 | BBSSignatureParams
  ) {
    const participatingSignerIds = new Set(Array.from({ length: threshold }, (_, i) => i + 1));
    // @ts-ignore
    const signers: signerClass[] = [];
    for (let i = 1; i <= threshold; i++) {
      const others = new Set(participatingSignerIds);
      others.delete(i);
      // @ts-ignore
      const signer = new signerClass(i, others, threshold, sigBatchSize, protocolId);
      signers.push(signer);
    }

    const comms: Map<number, Commitments> = new Map();
    const commsZero: Map<number, Map<number, Commitments>> = new Map();

    for (let i = 0; i < threshold; i++) {
      expect(signers[i].hasStarted()).toEqual(false);
      const [c, z] = signers[i].startRound1();
      comms.set(signers[i].id, c);
      commsZero.set(signers[i].id, z);
      expect(signers[i].hasStarted()).toEqual(true);
    }

    for (let i = 0; i < threshold; i++) {
      expect(signers[i].hasReceivedCommitmentsFromAll()).toEqual(false);
    }

    for (let i = 0; i < threshold; i++) {
      for (const [senderId, comm] of comms) {
        const receiverId = signers[i].id;
        if (receiverId !== senderId) {
          signers[i].processReceivedCommitments(
            senderId,
            comm,
            commsZero.get(senderId)?.get(receiverId) as CommitmentsForZeroSharing
          );
        }
      }
    }

    for (let i = 0; i < threshold; i++) {
      expect(signers[i].hasReceivedCommitmentsFromAll()).toEqual(true);
    }

    for (let i = 0; i < threshold; i++) {
      expect(signers[i].hasReceivedSharesFromAll()).toEqual(false);
    }

    for (let senderId = 1; senderId <= threshold; senderId++) {
      for (let receiverId = 1; receiverId <= threshold; receiverId++) {
        if (receiverId !== senderId) {
          const [s, z] = signers[senderId - 1].getSharesForOtherSigner(receiverId);
          signers[receiverId - 1].processReceivedShares(senderId, s, z);
        }
      }
    }

    for (let i = 0; i < threshold; i++) {
      expect(signers[i].hasReceivedSharesFromAll()).toEqual(true);
    }

    // Test if `getSharesForOtherSigners` works correctly
    for (let senderId = 1; senderId <= threshold; senderId++) {
      const receivers: number[] = [];
      const shares = [];
      for (let receiverId = 1; receiverId <= threshold; receiverId++) {
        if (receiverId !== senderId) {
          const s = signers[senderId - 1].getSharesForOtherSigner(receiverId);
          // @ts-ignore
          shares.push(s);
          receivers.push(receiverId);
        }
      }
      expect(signers[senderId - 1].getSharesForOtherSigners(receivers)).toEqual(shares);
    }

    for (let i = 0; i < threshold; i++) {
      expect(signers[i].hasFinishedRound1()).toEqual(false);
      signers[i].finishRound1(secretKeys[i]);
      expect(signers[i].hasFinishedRound1()).toEqual(true);
    }

    const msg1s: Map<number, Map<number, Message1>> = new Map();
    const msg2s: Map<[number, number], Message2> = new Map();

    for (let i = 0; i < threshold; i++) {
      const m = signers[i].startRound2(baseOTOutputs[i], gadgetVector);
      msg1s.set(signers[i].id, m);
    }

    for (const [senderId, msgs] of msg1s) {
      for (const [receiverId, msg] of msgs) {
        if (receiverId !== senderId) {
          const m2 = signers[receiverId - 1].processReceivedMsg1(senderId, msg, gadgetVector);
          msg2s.set([receiverId, senderId], m2);
        }
      }
    }

    for (const [[senderId, receiverId], msg] of msg2s) {
      signers[receiverId - 1].processReceivedMsg2(senderId, msg, gadgetVector);
    }

    for (let i = 0; i < threshold; i++) {
      expect(signers[i].hasFinishedRound2()).toEqual(false);
      signers[i].finishRound2();
      expect(signers[i].hasFinishedRound2()).toEqual(true);
    }

    // For each sig, create signature shares, aggregate them to form a sig and verify them
    for (let i = 0; i < sigBatchSize; i++) {
      const msgsToSign: Uint8Array[] = [];
      for (let j = 0; j < messageCount; j++) {
        msgsToSign.push(stringToBytes(`Message-${i}-${j}`));
      }

      // Create sig shares
      // @ts-ignore
      const shares: sigShareClass[] = [];
      for (let j = 0; j < threshold; j++) {
        shares.push(signers[j].createSigShare(msgsToSign, i, params, true));
      }

      // Aggregate shares to form a sig
      // @ts-ignore
      const sig = signerClass.aggregateShares(shares);

      // Verify sig
      // @ts-ignore
      const res = sig.verify(msgsToSign, thresholdPk, params, true);
      checkResult(res);
    }
  }

  it('create a threshold BBS+ signature', () => {
    const protocolId = stringToBytes('test BBS+');
    checkThresholdSig(
      protocolId,
      ThresholdBbsPlusSigner,
      ThresholdBbsPlusSignatureShare,
      skBbsPlus,
      thresholdPkBbsPlus,
      paramsBbsPlus
    );
  });

  it('create a threshold BBS signature', () => {
    const protocolId = stringToBytes('test BBS');
    checkThresholdSig(protocolId, ThresholdBbsSigner, ThresholdBbsSignatureShare, skBbs, thresholdPkBbs, paramsBbs);
  });
});
