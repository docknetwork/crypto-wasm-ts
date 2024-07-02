import { encodeMessageForSigning, generateRandomG1Element } from 'crypto-wasm-new';
import {
  BBDT16MacProofOfValidity,
  bytesToChallenge,
  initializeWasm,
  PSBlindSignature,
  randomFieldElement
} from '../src';
import { checkResult, getParamsAndKeys, getRevealedUnrevealed, signAndVerify, stringToBytes } from './utils';
import {
  BlindSignature,
  encodeMessageForSigningIfPS,
  isBBS,
  isBBSPlus,
  isKvac,
  isPS, KeyPair,
  PoKSignatureProtocol,
  PublicKey,
  Scheme,
  SecretKey,
  Signature,
  SignatureParams
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
    const [params, sk, pk] = getParamsAndKeys(messageCount, label);

    const [sig, result] = signAndVerify(messages, params, sk, pk, false);
    console.log(`Signature verified ? ${JSON.stringify(result)}`);
    checkResult(result);

    // Check serialization
    const pkH = isKvac() ? undefined : PublicKey.fromHex(pk.hex);
    const skH = SecretKey.fromHex(sk.hex);
    const [, result_] = signAndVerify(messages, params, skH, pkH, false);
    checkResult(result_);

    // For KVAC, proof of knowledge is integrated in the composite proof system only
    if (!isKvac()) {
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
      const challengeContributionP = isPS() ? protocol.challengeContribution(params, pk) : protocol.challengeContribution(params, false, revealedMsgs);
      const challengeProver = bytesToChallenge(challengeContributionP);
      const proof = protocol.generateProof(challengeProver);

      let challengeContributionV = isPS() ? proof.challengeContribution(params, pk) : proof.challengeContribution(params, false, revealedMsgs);
      let challengeVerifier = bytesToChallenge(challengeContributionV);

      const result1 = isPS()
        ? proof.verify(challengeVerifier, pk, params, revealedMsgs)
        : proof.verify(challengeVerifier, pk, params, false, revealedMsgs);
      console.log(`Proof verified ? ${JSON.stringify(result1)}`);
      checkResult(result1);
    }
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
    const [params, sk, pk] = getParamsAndKeys(messageCount, label);

    expect(params.isValid()).toEqual(true);
    expect(params.supportedMessageCount()).toEqual(messageCount);

    const paramBytes = params.toBytes();
    const deserializedParams = SignatureParams.valueFromBytes(paramBytes);
    expect(params.value).toEqual(deserializedParams);

    if (!isKvac()) {
      expect(pk.isValid()).toEqual(true);
    }

    const [sig, result] = signAndVerify(messages, params, sk, pk, false);
    checkResult(result);

    // Passing different `encodeMessages` to verify and sign results in error
    expect(() => isKvac() ? sig.verify(getMessages(messageCount), sk, params, false) : isPS() ? sig.verify(getMessages(messageCount), pk, params) : sig.verify(getMessages(messageCount), pk, params, false)).toThrow();

    // Pre encoded message
    const [, result1] = signAndVerify(messages, params, sk, pk, false);
    checkResult(result1);

    if (!isKvac()) {
      // No revealed messages and no user supplied blindings
      let protocol = isPS()
        ? PoKSignatureProtocol.initialize(messages, sig, pk, params, blindings)
        : PoKSignatureProtocol.initialize(messages, sig, params, false, blindings);
      let challengeContributionP = isPS() ? protocol.challengeContribution(params, pk) : protocol.challengeContribution(params, false, new Map());
      let challengeProver = bytesToChallenge(challengeContributionP);
      let proof = protocol.generateProof(challengeProver);

      let challengeContributionV = isPS() ? proof.challengeContribution(params, pk) : proof.challengeContribution(params, false, new Map());
      let challengeVerifier = bytesToChallenge(challengeContributionV);

      expect(challengeProver).toEqual(challengeVerifier);

      const result2 = isPS()
        ? proof.verify(challengeVerifier, pk, params, new Map())
        : proof.verify(challengeVerifier, pk, params, false, new Map());
      expect(result2.verified).toEqual(true);

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
      challengeContributionP = isPS() ? protocol.challengeContribution(params, pk) : protocol.challengeContribution(params, false, revealedMsgs);
      challengeProver = bytesToChallenge(challengeContributionP);
      proof = protocol.generateProof(challengeProver);

      challengeContributionV = isPS() ? proof.challengeContribution(params, pk) : proof.challengeContribution(params, false, revealedMsgs);
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
      challengeContributionP = isPS() ? protocol.challengeContribution(params, pk) : protocol.challengeContribution(params, false, revealedMsgs);
      challengeProver = bytesToChallenge(challengeContributionP);
      proof = protocol.generateProof(challengeProver);

      challengeContributionV = isPS() ? proof.challengeContribution(params, pk) : proof.challengeContribution(params, false, revealedMsgs);
      challengeVerifier = bytesToChallenge(challengeContributionV);

      expect(challengeProver).toEqual(challengeVerifier);

      checkResult(
        isPS()
          ? proof.verify(challengeVerifier, pk, params, revealedMsgs)
          : proof.verify(challengeVerifier, pk, params, false, revealedMsgs)
      );
    }
  });

  it('should sign and verify blind signature', () => {
    const messageCount = 10;
    const messages = getMessages(messageCount).map(encodeMessageForSigningIfPS);
    const label = stringToBytes('My new sig params');
    const [params, sk, pk] = getParamsAndKeys(messageCount, label);

    const messagesToHide = new Map();
    messagesToHide.set(1, messages[1]);
    messagesToHide.set(2, messages[2]);
    const blindings = new Map();
    const h = generateRandomG1Element();

    // Simulation of signer picking up revealed messages
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
    } else if (isBBS()) {
      request = BlindSignature.generateRequest(messagesToHide, params, true, revealedMessages);
    } else {
      [blinding, request] = BlindSignature.generateRequest(messagesToHide, params, true, void 0, revealedMessages);
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

    const sig = isPS() ? blindSig.unblind(blindings, pk) : isBBS() ? blindSig : blindSig.unblind(blinding);
    expect((isKvac() ? sig.verify(messages, sk, params, true) : sig.verify(messages, pk, params, true)).verified).toEqual(true);
  });

  it('params should be adaptable', () => {
    const ten = 10;
    const messages10 = getMessages(ten).map(encodeMessageForSigningIfPS);
    const label = stringToBytes('Some label for params');
    const [params10, sk10, pk10] = getParamsAndKeys(ten, label);

    const [, result] = signAndVerify(messages10, params10, sk10, pk10, true);
    checkResult(result);

    const twelve = 12;
    const messages12 = getMessages(twelve).map(encodeMessageForSigningIfPS);

    expect(() => Signature.generate(messages12, sk10, params10, true)).toThrow();

    const [params12, sk12, pk12] = getParamsAndKeys(twelve, label);
    expect(params12.isValid()).toEqual(true);
    expect(params12.supportedMessageCount()).toEqual(twelve);

    const [, result1] = signAndVerify(messages12, params12, sk12, pk12, true);
    checkResult(result1);

    const five = 5;
    const messages5 = getMessages(five).map(encodeMessageForSigningIfPS);

    expect(() => Signature.generate(messages5, sk12, params10, true)).toThrow();
    expect(() => Signature.generate(messages5, sk12, params12, true)).toThrow();

    const [params5, sk5, pk5] = getParamsAndKeys(five, label);
    expect(params5.isValid()).toEqual(true);
    expect(params5.supportedMessageCount()).toEqual(five);

    const [, result2] = signAndVerify(messages5, params5, sk5, pk5, true);
    checkResult(result2);

    const params10Again = params10.adapt(ten);
    expect(params10Again.isValid()).toEqual(true);
    expect(params10Again.supportedMessageCount()).toEqual(ten);

    const [, result3] = signAndVerify(messages10, params10Again, sk10, pk10, true);
    checkResult(result3);
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
      const [params, sk, pk] = getParamsAndKeys(count);

      const [sig, result] = signAndVerify(encodedMessages, params, sk, pk, false);
      checkResult(result);

      if (!isKvac()) {
        // Reveal all messages! This is done for testing purposes only.
        let revealed: Set<number> = new Set();
        for (let i = 0; i < count - 1; i++) {
          revealed.add(i);
        }

        const [revealedMsgs] = getRevealedUnrevealed(encodedMessages, revealed);
        const protocol = isPS()
          ? PoKSignatureProtocol.initialize(encodedMessages, sig, pk, params, blindings, revealed)
          : PoKSignatureProtocol.initialize(encodedMessages, sig, params, false, blindings, revealed);

        const challengeContributionP = isPS() ? protocol.challengeContribution(params, pk) : protocol.challengeContribution(params, false, revealedMsgs);
        const challengeProver = bytesToChallenge(challengeContributionP);
        const proof = protocol.generateProof(challengeProver);

        const challengeContributionV = isPS() ? proof.challengeContribution(params, pk) : proof.challengeContribution(params, false, revealedMsgs);
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

  if (isKvac()) {
    it('should have proof of validity of mac', () => {
      const messageCount = 10;
      const messages = getMessages(messageCount).map((m) => Signature.encodeMessageForSigning(m));
      const label = stringToBytes('My sig params in g1');
      const params = SignatureParams.generate(messageCount, label);
      const keypair = KeyPair.generate(params);
      const sk = keypair.sk;
      const pk = keypair.pk;
      expect(pk.isValid()).toEqual(true);

      const [mac, result] = signAndVerify(messages, params, sk, pk, false);
      checkResult(result);

      const proof = new BBDT16MacProofOfValidity(mac, sk, pk, params);
      checkResult(proof.verify(mac, messages, pk, params, false));
    })
  }
});
