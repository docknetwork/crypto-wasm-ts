import { generateRandomG1Element, psEncodeMessageForSigning } from '@docknetwork/crypto-wasm';
import {
  initializeWasm,
  randomFieldElement,
  PSBlindSignature,
  bytesToChallenge,
  PSPoKSignatureProtocol,
  PSSignature,
  PSSignatureParams,
  PSSecretKey,
  PSPublicKey
} from '../src';
import { getRevealedUnrevealed, stringToBytes } from './utils';

function getMessages(count: number): Uint8Array[] {
  const messages: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    messages.push(stringToBytes(`Message-${i + 1}`));
  }
  return messages;
}

describe('BBS+ signature sunny day scenario', () => {
  it('runs', async () => {
    // Load the WASM module
    await initializeWasm();

    const messageCount = 10;
    const messages: Uint8Array[] = [];
    for (let i = 0; i < messageCount; i++) {
      messages.push(psEncodeMessageForSigning(stringToBytes(`Message-${i + 1}`)));
    }

    const label = stringToBytes('My sig params in g1');
    const params = PSSignatureParams.generate(messageCount, label);

    const sk = PSSecretKey.generate(messageCount);
    const pk = sk.generatePublicKey(params);

    const sig = PSSignature.generate(messages, sk, params);
    const result = sig.verify(messages, pk, params);
    console.log(`PSSignature verified ? ${JSON.stringify(result)}`);
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

    const protocol = PSPoKSignatureProtocol.initialize(messages, sig, pk, params, blindings, revealed);
    const challengeContributionP = protocol.challengeContribution(params, pk);
    const challengeProver = bytesToChallenge(challengeContributionP);
    const proof = protocol.generateProof(challengeProver);

    let challengeContributionV = proof.challengeContribution(params, pk);
    let challengeVerifier = bytesToChallenge(challengeContributionV);

    const result1 = proof.verify(challengeVerifier, pk, params, revealedMsgs);
    console.log(`Proof verified ? ${JSON.stringify(result1)}`);
    expect(result1.verified).toEqual(true);
  });
});

describe('BBS+ signature', () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it('should sign and verify signature and create and verify proof of knowledge', () => {
    const messageCount = 10;
    const messages = getMessages(messageCount).map((m) => PSSignature.encodeMessageForSigning(m));

    const label = stringToBytes('My sig params in g1');
    const params = PSSignatureParams.generate(messageCount, label);

    expect(params.isValid()).toEqual(true);
    expect(params.supportedMessageCount()).toEqual(messageCount);

    const paramBytes = params.toBytes();
    const deserializedParams = PSSignatureParams.valueFromBytes(paramBytes);
    expect(params.value).toEqual(deserializedParams);

    const sk = PSSecretKey.generate(messageCount);
    const pk = sk.generatePublicKey(params);

    expect(pk.isValid()).toEqual(true);

    const sig = PSSignature.generate(messages, sk, params);
    expect(sig.verify(messages, pk, params).verified).toEqual(true);
    // Passing different `encodeMessages` to verify and sign results in error
    expect(() => sig.verify(getMessages(messageCount), pk, params)).toThrow();

    // Pre encoded message
    const sig1 = PSSignature.generate(messages, sk, params);
    expect(sig1.verify(messages, pk, params).verified).toEqual(true);

    // No revealed messages and no user supplied blindings
    let protocol = PSPoKSignatureProtocol.initialize(messages, sig, pk, params);
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

    protocol = PSPoKSignatureProtocol.initialize(messages, sig, pk, params, undefined, revealed);
    challengeContributionP = protocol.challengeContribution(params, pk);
    challengeProver = bytesToChallenge(challengeContributionP);
    proof = protocol.generateProof(challengeProver);

    challengeContributionV = proof.challengeContribution(params, pk);
    challengeVerifier = bytesToChallenge(challengeContributionV);

    expect(challengeProver).toEqual(challengeVerifier);

    expect(proof.verify(challengeVerifier, pk, params, revealedMsgs).verified).toEqual(true);

    // 2 revealed messages and 1 user supplied blinding
    let blindings: Map<number, Uint8Array> = new Map();
    blindings.set(1, randomFieldElement());
    protocol = PSPoKSignatureProtocol.initialize(messages, sig, pk, params, blindings, revealed);
    challengeContributionP = protocol.challengeContribution(params, pk);
    challengeProver = bytesToChallenge(challengeContributionP);
    proof = protocol.generateProof(challengeProver);

    challengeContributionV = proof.challengeContribution(params, pk);
    challengeVerifier = bytesToChallenge(challengeContributionV);

    expect(challengeProver).toEqual(challengeVerifier);

    expect(proof.verify(challengeVerifier, pk, params, revealedMsgs).verified).toEqual(true);
  });

  it('should sign and verify blind signature', () => {
    const messageCount = 10;
    const messages = getMessages(messageCount).map(psEncodeMessageForSigning);
    const label = stringToBytes('My new sig params');
    const params = PSSignatureParams.generate(messageCount, label);

    const sk = PSSecretKey.generate(messageCount);
    const pk = sk.generatePublicKey(params);

    const messagesToHide = new Map();
    messagesToHide.set(1, messages[1]);
    messagesToHide.set(2, messages[2]);
    const blindings = new Map();
    const h = generateRandomG1Element();

    // Simulation of signer picking up known messages
    const knownMessages = new Map();
    for (let i = 0; i < messageCount; i++) {
        if (!messagesToHide.has(i)) {
        knownMessages.set(i, messages[i]);
        }
    }

    let req = PSBlindSignature.generateRequest(messagesToHide, blindings, params, h, knownMessages);

    let blindSig = PSBlindSignature.generate(
      messages.map((message, idx) => {
        if (knownMessages.has(idx)) {
          return { RevealedMessage: message };
        } else {
          return { BlindedMessage: req.commitments.get(idx)! };
        }
      }),
      sk,
      h
    );

    let sig = blindSig.unblind(blindings, pk);
    expect(sig.verify(messages, pk, params).verified).toEqual(true);
  });

  it('params should be adaptable', () => {
    const ten = 10;
    const messages10 = getMessages(ten).map(psEncodeMessageForSigning);
    const label = stringToBytes('Some label for params');
    const params10 = PSSignatureParams.generate(ten, label);

    const sk10 = PSSecretKey.generate(ten);
    const pk10 = sk10.generatePublicKey(params10);

    const sig = PSSignature.generate(messages10, sk10, params10);
    expect(sig.verify(messages10, pk10, params10).verified).toEqual(true);

    const twelve = 12;
    const messages12 = getMessages(twelve).map(psEncodeMessageForSigning);

    expect(() => PSSignature.generate(messages12, sk10, params10)).toThrow();

    const params12 = params10.adapt(twelve);
    const sk12 = PSSecretKey.generate(twelve);
    const pk12 = sk12.generatePublicKey(params12);
    expect(params12.isValid()).toEqual(true);
    expect(params12.supportedMessageCount()).toEqual(twelve);

    const sig1 = PSSignature.generate(messages12, sk12, params12);
    expect(sig1.verify(messages12, pk12, params12).verified).toEqual(true);

    const five = 5;
    const messages5 = getMessages(five).map(psEncodeMessageForSigning);

    expect(() => PSSignature.generate(messages5, sk12, params10)).toThrow();
    expect(() => PSSignature.generate(messages5, sk12, params12)).toThrow();

    const params5 = params12.adapt(five);
    const sk5 = PSSecretKey.generate(five);
    const pk5 = sk5.generatePublicKey(params5);
    expect(params5.isValid()).toEqual(true);
    expect(params5.supportedMessageCount()).toEqual(five);

    const sig2 = PSSignature.generate(messages5, sk5, params5);
    expect(sig2.verify(messages5, pk5, params5).verified).toEqual(true);

    const params10Again = params10.adapt(ten);
    expect(params10Again.isValid()).toEqual(true);
    expect(params10Again.supportedMessageCount()).toEqual(ten);

    const sig3 = PSSignature.generate(messages10, sk10, params10Again);
    expect(sig3.verify(messages10, pk10, params10Again).verified).toEqual(true);
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
      const count = messages.length;
      const encodedMessages = new Array<Uint8Array>(5);
      for (let i = 0; i < count; i++) {
        encodedMessages[i] = PSSignature.reversibleEncodeStringForSigning(messages[i], compress);
        const decoded = PSSignature.reversibleDecodeStringForSigning(encodedMessages[i], compress);
        expect(decoded).toEqual(messages[i]);
      }
      const params = PSSignatureParams.generate(count);
      const sk = PSSecretKey.generate(messages.length);
      const pk = sk.generatePublicKey(params);

      const sig = PSSignature.generate(encodedMessages, sk, params);
      expect(sig.verify(encodedMessages, pk, params).verified).toEqual(true);

      // Reveal all messages! This is done for testing purposes only.
      let revealed: Set<number> = new Set();
      for (let i = 0; i < count - 1; i++) {
        revealed.add(i);
      }

      const [revealedMsgs] = getRevealedUnrevealed(encodedMessages, revealed);
      const protocol = PSPoKSignatureProtocol.initialize(encodedMessages, sig, pk, params, undefined, revealed);
      const challengeContributionP = protocol.challengeContribution(params, pk);
      const challengeProver = bytesToChallenge(challengeContributionP);
      const proof = protocol.generateProof(challengeProver);

      const challengeContributionV = proof.challengeContribution(params, pk);
      const challengeVerifier = bytesToChallenge(challengeContributionV);

      expect(challengeProver).toEqual(challengeVerifier);

      expect(proof.verify(challengeVerifier, pk, params, revealedMsgs).verified).toEqual(true);
      for (let i = 0; i < count - 1; i++) {
        const decoded = PSSignature.reversibleDecodeStringForSigning(revealedMsgs.get(i) as Uint8Array);
        expect(decoded).toEqual(messages[i]);
      }
    }

    check(false);
    check(true);
  });
});
