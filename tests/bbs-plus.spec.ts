import {
  initializeWasm,
  randomFieldElement,
  BBSPlusBlindSignatureG1,
  bytesToChallenge,
  BBSPlusKeypairG2,
  BBSPlusPoKSignatureProtocol,
  BBSPlusSignatureG1,
  BBSPlusSignatureParamsG1
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
      messages.push(stringToBytes(`Message-${i + 1}`));
    }

    const label = stringToBytes('My sig params in g1');
    const params = BBSPlusSignatureParamsG1.generate(messageCount, label);

    const keypair = BBSPlusKeypairG2.generate(params);
    const sk = keypair.secretKey;
    const pk = keypair.publicKey;

    const sig = BBSPlusSignatureG1.generate(messages, sk, params, true);
    const result = sig.verify(messages, pk, params, true);
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

    const protocol = BBSPlusPoKSignatureProtocol.initialize(messages, sig, params, true, blindings, revealed);
    const challengeContributionP = protocol.challengeContribution(params, true, revealedMsgs);
    const challengeProver = bytesToChallenge(challengeContributionP);
    const proof = protocol.generateProof(challengeProver);

    let challengeContributionV = proof.challengeContribution(params, true, revealedMsgs);
    let challengeVerifier = bytesToChallenge(challengeContributionV);

    const result1 = proof.verify(challengeVerifier, pk, params, true, revealedMsgs);
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
    const messages = getMessages(messageCount);
    const encodedMessages = messages.map((m) => BBSPlusSignatureG1.encodeMessageForSigning(m));

    const label = stringToBytes('My sig params in g1');
    const params = BBSPlusSignatureParamsG1.generate(messageCount, label);

    expect(params.isValid()).toEqual(true);
    expect(params.supportedMessageCount()).toEqual(messageCount);

    const paramBytes = params.toBytes();
    const deserializedParams = BBSPlusSignatureParamsG1.valueFromBytes(paramBytes);
    expect(params.value).toEqual(deserializedParams);

    const keypair = BBSPlusKeypairG2.generate(params);
    const sk = keypair.secretKey;
    const pk = keypair.publicKey;

    expect(pk.isValid()).toEqual(true);

    const pk1 = sk.generatePublicKeyG2(params);
    expect([...pk.value]).toEqual([...pk1.value]);

    const sig = BBSPlusSignatureG1.generate(messages, sk, params, true);
    expect(sig.verify(messages, pk, params, true).verified).toEqual(true);
    // Passing different `encodeMessages` to verify and sign results in error
    expect(() => sig.verify(messages, pk, params, false)).toThrow();

    // Pre encoded message
    const sig1 = BBSPlusSignatureG1.generate(encodedMessages, sk, params, false);
    expect(sig1.verify(encodedMessages, pk, params, false).verified).toEqual(true);

    // No revealed messages and no user supplied blindings
    let protocol = BBSPlusPoKSignatureProtocol.initialize(messages, sig, params, true);
    let challengeContributionP = protocol.challengeContribution(params, true);
    let challengeProver = bytesToChallenge(challengeContributionP);
    let proof = protocol.generateProof(challengeProver);

    let challengeContributionV = proof.challengeContribution(params, true);
    let challengeVerifier = bytesToChallenge(challengeContributionV);

    expect(challengeProver).toEqual(challengeVerifier);

    expect(proof.verify(challengeVerifier, pk, params, true).verified).toEqual(true);

    // 2 revealed messages but no user supplied blindings
    let revealed: Set<number> = new Set();
    let revealedMsgs: Map<number, Uint8Array> = new Map();
    revealed.add(0);
    revealed.add(2);
    revealedMsgs.set(0, messages[0]);
    revealedMsgs.set(2, messages[2]);

    protocol = BBSPlusPoKSignatureProtocol.initialize(messages, sig, params, true, undefined, revealed);
    challengeContributionP = protocol.challengeContribution(params, true, revealedMsgs);
    challengeProver = bytesToChallenge(challengeContributionP);
    proof = protocol.generateProof(challengeProver);

    challengeContributionV = proof.challengeContribution(params, true, revealedMsgs);
    challengeVerifier = bytesToChallenge(challengeContributionV);

    expect(challengeProver).toEqual(challengeVerifier);

    expect(proof.verify(challengeVerifier, pk, params, true, revealedMsgs).verified).toEqual(true);

    // 2 revealed messages and 1 user supplied blinding
    let blindings: Map<number, Uint8Array> = new Map();
    blindings.set(1, randomFieldElement());
    protocol = BBSPlusPoKSignatureProtocol.initialize(messages, sig, params, true, blindings, revealed);
    challengeContributionP = protocol.challengeContribution(params, true, revealedMsgs);
    challengeProver = bytesToChallenge(challengeContributionP);
    proof = protocol.generateProof(challengeProver);

    challengeContributionV = proof.challengeContribution(params, true, revealedMsgs);
    challengeVerifier = bytesToChallenge(challengeContributionV);

    expect(challengeProver).toEqual(challengeVerifier);

    expect(proof.verify(challengeVerifier, pk, params, true, revealedMsgs).verified).toEqual(true);
  });

  it('should sign and verify blind signature', () => {
    const messageCount = 10;
    const messages = getMessages(messageCount);
    const label = stringToBytes('My new sig params');
    const params = BBSPlusSignatureParamsG1.generate(messageCount, label);

    const keypair = BBSPlusKeypairG2.generate(params);
    const sk = keypair.secretKey;
    const pk = keypair.publicKey;

    const messagesToHide = new Map();
    messagesToHide.set(1, messages[1]);
    messagesToHide.set(2, messages[2]);

    let [blinding, req] = BBSPlusBlindSignatureG1.generateRequest(messagesToHide, params, true);

    // Simulation of signer picking up known messages
    const knownMessages = new Map();
    for (let i = 0; i < messageCount; i++) {
      if (req.blindedIndices.indexOf(i) === -1) {
        knownMessages.set(i, messages[i]);
      }
    }

    let blindSig = BBSPlusBlindSignatureG1.generate(req.commitment, knownMessages, sk, params, true);

    let sig = blindSig.unblind(blinding);
    expect(sig.verify(messages, pk, params, true).verified).toEqual(true);
  });

  it('params should be adaptable', () => {
    const ten = 10;
    const messages10 = getMessages(ten);
    const label = stringToBytes('Some label for params');
    const params10 = BBSPlusSignatureParamsG1.generate(ten, label);
    const keypair = BBSPlusKeypairG2.generate(params10);
    const sk = keypair.secretKey;
    const pk = keypair.publicKey;

    const sig = BBSPlusSignatureG1.generate(messages10, sk, params10, true);
    expect(sig.verify(messages10, pk, params10, true).verified).toEqual(true);

    const twelve = 12;
    const messages12 = getMessages(twelve);

    expect(() => BBSPlusSignatureG1.generate(messages12, sk, params10, true)).toThrow();

    const params12 = params10.adapt(twelve);
    expect(params12.isValid()).toEqual(true);
    expect(params12.supportedMessageCount()).toEqual(twelve);

    const sig1 = BBSPlusSignatureG1.generate(messages12, sk, params12, true);
    expect(sig1.verify(messages12, pk, params12, true).verified).toEqual(true);

    const five = 5;
    const messages5 = getMessages(five);

    expect(() => BBSPlusSignatureG1.generate(messages5, sk, params10, true)).toThrow();
    expect(() => BBSPlusSignatureG1.generate(messages5, sk, params12, true)).toThrow();

    const params5 = params12.adapt(five);
    expect(params5.isValid()).toEqual(true);
    expect(params5.supportedMessageCount()).toEqual(five);

    const sig2 = BBSPlusSignatureG1.generate(messages5, sk, params5, true);
    expect(sig2.verify(messages5, pk, params5, true).verified).toEqual(true);

    const params10Again = params10.adapt(ten);
    expect(params10Again.isValid()).toEqual(true);
    expect(params10Again.supportedMessageCount()).toEqual(ten);

    const sig3 = BBSPlusSignatureG1.generate(messages10, sk, params10Again, true);
    expect(sig3.verify(messages10, pk, params10Again, true).verified).toEqual(true);
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
        encodedMessages[i] = BBSPlusSignatureG1.reversibleEncodeStringForSigning(messages[i], compress);
        const decoded = BBSPlusSignatureG1.reversibleDecodeStringForSigning(encodedMessages[i], compress);
        expect(decoded).toEqual(messages[i]);
      }
      const params = BBSPlusSignatureParamsG1.generate(count);
      const keypair = BBSPlusKeypairG2.generate(params);
      const sig = BBSPlusSignatureG1.generate(encodedMessages, keypair.secretKey, params, false);
      expect(sig.verify(encodedMessages, keypair.publicKey, params, false).verified).toEqual(true);

      // Reveal all messages! This is done for testing purposes only.
      let revealed: Set<number> = new Set();
      for (let i = 0; i < count; i++) {
        revealed.add(i);
      }

      const [revealedMsgs] = getRevealedUnrevealed(encodedMessages, revealed);
      const protocol = BBSPlusPoKSignatureProtocol.initialize(encodedMessages, sig, params, false, undefined, revealed);
      const challengeContributionP = protocol.challengeContribution(params, true, revealedMsgs);
      const challengeProver = bytesToChallenge(challengeContributionP);
      const proof = protocol.generateProof(challengeProver);

      const challengeContributionV = proof.challengeContribution(params, true, revealedMsgs);
      const challengeVerifier = bytesToChallenge(challengeContributionV);

      expect(challengeProver).toEqual(challengeVerifier);

      expect(proof.verify(challengeVerifier, keypair.publicKey, params, false, revealedMsgs).verified).toEqual(true);
      for (let i = 0; i < count; i++) {
        const decoded = BBSPlusSignatureG1.reversibleDecodeStringForSigning(revealedMsgs.get(i) as Uint8Array);
        expect(decoded).toEqual(messages[i]);
      }
    }

    check(false);
    check(true);
  });
});
