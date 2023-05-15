import { generateRandomG1Element, encodeMessageForSigning } from '@docknetwork/crypto-wasm';
import { initializeWasm, randomFieldElement, bytesToChallenge, PSBlindSignature } from '../src';
import { checkResult, getRevealedUnrevealed, stringToBytes } from './utils';
import {
  BlindSignature,
  PoKSignatureProtocol,
  isPS,
  Signature,
  SignatureParams,
  SecretKey,
  encodeMessageForSigningIfPS,
  isBBSPlus,
  Scheme
} from './scheme';

function getMessages(count: number): Uint8Array[] {
  const messages: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    messages.push(stringToBytes(`Message-${i + 1}`));
  }
  return messages;
}

describe(`${Scheme} signature sunny day scenario`, () => {
  it('runs', async () => {
    // Load the WASM module
    await initializeWasm();

    const messageCount = 10;
    const messages: Uint8Array[] = [];
    for (let i = 0; i < messageCount; i++) {
      messages.push(encodeMessageForSigning(stringToBytes(`Message-${i + 1}`)));
    }

    const label = stringToBytes('My sig params in g1');
    const params = SignatureParams.generate(messageCount, label);

    const sk = SecretKey.generate(isPS() ? messageCount : void 0);
    const pk = isBBSPlus() ? sk.generatePublicKeyG2(params) : sk.generatePublicKey(params);

    const sig = Signature.generate(messages, sk, params);
    const result = sig.verify(messages, pk, params);
    console.log(`Signature verified ? ${JSON.stringify(result)}`);
    expect(result.verified).toEqual(true);

    // 2 revealed messages and 1 user supplied blinding
    let revealed: Set<number> = new Set();
    let revealedMsgs: Map<number, Uint8Array> = new Map();
    revealed.add(0);
    revealed.add(2);
    revealedMsgs.set(0, messages[0]);
    revealedMsgs.set(2, messages[2]);
    const blindings: Map<number, Uint8Array> = new Map();
    blindings.set(1, randomFieldElement());

    const protocol = isPS()
      ? PoKSignatureProtocol.initialize(messages, sig, pk, params, blindings, revealed)
      : PoKSignatureProtocol.initialize(messages, sig, params, false, blindings, revealed);
    const challengeContributionP = protocol.challengeContribution(params, pk);
    const challengeProver = bytesToChallenge(challengeContributionP);
    const proof = protocol.generateProof(challengeProver);

    let challengeContributionV = proof.challengeContribution(params, pk);
    let challengeVerifier = bytesToChallenge(challengeContributionV);

    const result1 = isPS()
      ? proof.verify(challengeVerifier, pk, params, revealedMsgs)
      : proof.verify(challengeVerifier, pk, params, false, revealedMsgs);
    console.log(`Proof verified ? ${JSON.stringify(result1)}`);
    checkResult(result1);
  });
});

describe(`${Scheme} signature`, () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it('should sign and verify signature and create and verify proof of knowledge', () => {
    const messageCount = 10;
    const messages = getMessages(messageCount).map((m) => Signature.encodeMessageForSigning(m));
    let blindings = new Map();

    const label = stringToBytes('My sig params in g1');
    const params = SignatureParams.generate(messageCount, label);

    expect(params.isValid()).toEqual(true);
    expect(params.supportedMessageCount()).toEqual(messageCount);

    const paramBytes = params.toBytes();
    const deserializedParams = SignatureParams.valueFromBytes(paramBytes);
    expect(params.value).toEqual(deserializedParams);

    const sk = SecretKey.generate(isPS() ? messageCount : void 0);
    const pk = isBBSPlus() ? sk.generatePublicKeyG2(params) : sk.generatePublicKey(params);

    expect(pk.isValid()).toEqual(true);

    const sig = Signature.generate(messages, sk, params);
    expect(sig.verify(messages, pk, params).verified).toEqual(true);
    // Passing different `encodeMessages` to verify and sign results in error
    expect(() => sig.verify(getMessages(messageCount), pk, params)).toThrow();

    // Pre encoded message
    const sig1 = Signature.generate(messages, sk, params);
    expect(sig1.verify(messages, pk, params).verified).toEqual(true);

    // No revealed messages and no user supplied blindings
    let protocol = isPS()
      ? PoKSignatureProtocol.initialize(messages, sig, pk, params, blindings)
      : PoKSignatureProtocol.initialize(messages, sig, params, false, blindings);
    let challengeContributionP = protocol.challengeContribution(params, pk);
    let challengeProver = bytesToChallenge(challengeContributionP);
    let proof = protocol.generateProof(challengeProver);

    let challengeContributionV = proof.challengeContribution(params, pk);
    let challengeVerifier = bytesToChallenge(challengeContributionV);

    expect(challengeProver).toEqual(challengeVerifier);

    expect(proof.verify(challengeVerifier, pk, params).verified).toEqual(true);

    // 2 revealed messages but no user supplied blindings
    let revealed: Set<number> = new Set();
    let revealedMsgs: Map<number, Uint8Array> = new Map();
    revealed.add(0);
    revealed.add(2);
    revealedMsgs.set(0, messages[0]);
    revealedMsgs.set(2, messages[2]);

    protocol = isPS()
      ? PoKSignatureProtocol.initialize(messages, sig, pk, params, blindings, revealed)
      : PoKSignatureProtocol.initialize(messages, sig, params, false, blindings, revealed);
    challengeContributionP = protocol.challengeContribution(params, pk);
    challengeProver = bytesToChallenge(challengeContributionP);
    proof = protocol.generateProof(challengeProver);

    challengeContributionV = proof.challengeContribution(params, pk);
    challengeVerifier = bytesToChallenge(challengeContributionV);

    expect(challengeProver).toEqual(challengeVerifier);

    checkResult(
      isPS()
        ? proof.verify(challengeVerifier, pk, params, revealedMsgs)
        : proof.verify(challengeVerifier, pk, params, false, revealedMsgs)
    );

    // 2 revealed messages and 1 user supplied blinding
    blindings = new Map();
    blindings.set(1, randomFieldElement());
    protocol = isPS()
      ? PoKSignatureProtocol.initialize(messages, sig, pk, params, blindings, revealed)
      : PoKSignatureProtocol.initialize(messages, sig, params, false, blindings, revealed);
    challengeContributionP = protocol.challengeContribution(params, pk);
    challengeProver = bytesToChallenge(challengeContributionP);
    proof = protocol.generateProof(challengeProver);

    challengeContributionV = proof.challengeContribution(params, pk);
    challengeVerifier = bytesToChallenge(challengeContributionV);

    expect(challengeProver).toEqual(challengeVerifier);

    checkResult(
      isPS()
        ? proof.verify(challengeVerifier, pk, params, revealedMsgs)
        : proof.verify(challengeVerifier, pk, params, false, revealedMsgs)
    );
  });

  it('should sign and verify blind signature', () => {
    const messageCount = 10;
    const messages = getMessages(messageCount).map(encodeMessageForSigningIfPS);
    const label = stringToBytes('My new sig params');
    const params = SignatureParams.generate(messageCount, label);

    const sk = SecretKey.generate(isPS() ? messageCount : void 0);
    const pk = isBBSPlus() ? sk.generatePublicKeyG2(params) : sk.generatePublicKey(params);

    const messagesToHide = new Map();
    messagesToHide.set(1, messages[1]);
    messagesToHide.set(2, messages[2]);
    const blindings = new Map();
    const h = generateRandomG1Element();

    // Simulation of signer picking up known messages
    const revealedMessages = new Map();
    for (let i = 0; i < messageCount; i++) {
      if (!messagesToHide.has(i)) {
        revealedMessages.set(i, messages[i]);
      }
    }

    let blinding, request;
    if (isPS()) {
      [blinding, request] = BlindSignature.generateRequest(
        messagesToHide,
        params,
        h,
        blindings,
        void 0,
        revealedMessages
      );
    } else if (isBBSPlus()) {
      [blinding, request] = BlindSignature.generateRequest(messagesToHide, params, true, void 0, revealedMessages);
    } else {
      request = BlindSignature.generateRequest(messagesToHide, params, true, revealedMessages);
    }

    let blindSig = isPS()
      ? BlindSignature.generate(
          messages.map((message, idx) => {
            if (revealedMessages.has(idx)) {
              return { RevealedMessage: message };
            } else {
              return { BlindedMessage: request.commitments.get(idx)! };
            }
          }),
          sk,
          h
        )
      : BlindSignature.fromRequest(request, sk, params);

    const sig = isPS() ? blindSig.unblind(blindings, pk) : isBBSPlus() ? blindSig.unblind(blinding) : blindSig;
    expect(sig.verify(messages, pk, params, true).verified).toEqual(true);
  });

  it('params should be adaptable', () => {
    const ten = 10;
    const messages10 = getMessages(ten).map(encodeMessageForSigningIfPS);
    const label = stringToBytes('Some label for params');
    const params10 = SignatureParams.generate(ten, label);

    const sk10 = SecretKey.generate(isPS() ? ten : void 0);
    const pk10 = isBBSPlus() ? sk10.generatePublicKeyG2(params10) : sk10.generatePublicKey(params10);

    const sig = Signature.generate(messages10, sk10, params10, true);
    expect(sig.verify(messages10, pk10, params10, true).verified).toEqual(true);

    const twelve = 12;
    const messages12 = getMessages(twelve).map(encodeMessageForSigningIfPS);

    expect(() => Signature.generate(messages12, sk10, params10, true)).toThrow();

    const params12 = params10.adapt(twelve);
    const sk12 = SecretKey.generate(isPS() ? twelve : void 0);
    const pk12 = isBBSPlus() ? sk12.generatePublicKeyG2(params12): sk12.generatePublicKey(params12);
    expect(params12.isValid()).toEqual(true);
    expect(params12.supportedMessageCount()).toEqual(twelve);

    const sig1 = Signature.generate(messages12, sk12, params12, true);
    expect(sig1.verify(messages12, pk12, params12, true).verified).toEqual(true);

    const five = 5;
    const messages5 = getMessages(five).map(encodeMessageForSigningIfPS);

    expect(() => Signature.generate(messages5, sk12, params10, true)).toThrow();
    expect(() => Signature.generate(messages5, sk12, params12, true)).toThrow();

    const params5 = params12.adapt(five);
    const sk5 = SecretKey.generate(isPS() ? five : void 0);
    const pk5 = isBBSPlus() ? sk5.generatePublicKeyG2(params5): sk5.generatePublicKey(params5);
    expect(params5.isValid()).toEqual(true);
    expect(params5.supportedMessageCount()).toEqual(five);

    const sig2 = Signature.generate(messages5, sk5, params5, true);
    expect(sig2.verify(messages5, pk5, params5, true).verified).toEqual(true);

    const params10Again = params10.adapt(ten);
    expect(params10Again.isValid()).toEqual(true);
    expect(params10Again.supportedMessageCount()).toEqual(ten);

    const sig3 = Signature.generate(messages10, sk10, params10Again, true);
    expect(sig3.verify(messages10, pk10, params10Again, true).verified).toEqual(true);
  });

  it('should support reversible encoding', () => {
    function check(compress: boolean) {
      const messages = [
        'John Jacob Smith Sr.',
        'San Francisco, California',
        'john.jacob.smith.1971@gmail.com',
        '+1 123-4567890009',
        'user-id:1234567890012134'
      ];
      const blindings = new Map();
      const count = messages.length;
      const encodedMessages = new Array<Uint8Array>(5);
      for (let i = 0; i < count; i++) {
        encodedMessages[i] = Signature.reversibleEncodeStringForSigning(messages[i], compress);
        const decoded = Signature.reversibleDecodeStringForSigning(encodedMessages[i], compress);
        expect(decoded).toEqual(messages[i]);
      }
      const params = SignatureParams.generate(count);
      const sk = SecretKey.generate(isPS() ? messages.length : void 0);
      const pk = isBBSPlus() ? sk.generatePublicKeyG2(params) : sk.generatePublicKey(params);

      const sig = Signature.generate(encodedMessages, sk, params);
      expect(sig.verify(encodedMessages, pk, params).verified).toEqual(true);

      // Reveal all messages! This is done for testing purposes only.
      let revealed: Set<number> = new Set();
      for (let i = 0; i < count - 1; i++) {
        revealed.add(i);
      }

      const [revealedMsgs] = getRevealedUnrevealed(encodedMessages, revealed);
      const protocol = isPS()
        ? PoKSignatureProtocol.initialize(encodedMessages, sig, pk, params, blindings, revealed)
        : PoKSignatureProtocol.initialize(encodedMessages, sig, params, false, blindings, revealed);

      const challengeContributionP = protocol.challengeContribution(params, pk);
      const challengeProver = bytesToChallenge(challengeContributionP);
      const proof = protocol.generateProof(challengeProver);

      const challengeContributionV = proof.challengeContribution(params, pk);
      const challengeVerifier = bytesToChallenge(challengeContributionV);

      expect(challengeProver).toEqual(challengeVerifier);

      checkResult(
        isPS()
          ? proof.verify(challengeVerifier, pk, params, revealedMsgs)
          : proof.verify(challengeVerifier, pk, params, false, revealedMsgs)
      );
      for (let i = 0; i < count - 1; i++) {
        const decoded = Signature.reversibleDecodeStringForSigning(revealedMsgs.get(i) as Uint8Array);
        expect(decoded).toEqual(messages[i]);
      }
    }

    check(false);
    check(true);
  });

  if (isPS())
    it('should aggregate signatures', () => {
      const messageCount = 10;
      const h = generateRandomG1Element();

      const [thresholdSk, sks] = SecretKey.dealShamirSS(10, 5, 10);
      const messages = getMessages(10).map(encodeMessageForSigningIfPS);
      const label = stringToBytes('My sig params in g1');
      const params = SignatureParams.generate(messageCount, label);

      const pSigs = new Map();
      let idx = 0;

      for (const sk of sks) {
        expect(params.isValid()).toEqual(true);
        expect(params.supportedMessageCount()).toEqual(messageCount);

        const pk = isBBSPlus() ? sk.generatePublicKeyG2(params) : sk.generatePublicKey(params);

        expect(pk.isValid()).toEqual(true);
        const blindings = new Map();
        const [b, req] = PSBlindSignature.generateRequest(
          new Map(messages.map((msg, idx) => [idx, msg])) as any,
          params,
          h,
          blindings
        );

        const sig = BlindSignature.fromRequest(req, sk, h).unblind(blindings, pk);

        pSigs.set(++idx, sig);
      }

      expect(
        Signature.aggregate(pSigs, h).verify(messages, thresholdSk.generatePublicKey(params), params).verified
      ).toBe(true);
      expect(() =>
        Signature.aggregate(new Map([...pSigs.entries()].slice(0, 4)), h).verify(
          messages,
          thresholdSk.generatePublicKey(params),
          params
        )
      ).toThrow();
      expect(
        Signature.aggregate(new Map([...pSigs.entries()].slice(0, 6)), h).verify(
          messages,
          thresholdSk.generatePublicKey(params),
          params
        ).verified
      ).toBe(true);
    });
});
