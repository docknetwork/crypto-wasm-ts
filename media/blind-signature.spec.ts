import { generateRandomG1Element } from 'crypto-wasm-new';
import { CompositeProof, initializeWasm, MetaStatements, ProofSpec, Statements, Witnesses } from '../../src';
import {
  BlindSignature,
  encodeMessageForSigningIfNotPS,
  encodeMessageForSigningIfPS,
  getStatementForBlindSigRequest,
  getWitnessForBlindSigRequest,
  isBBS,
  isKvac,
  isPS,
  Scheme
} from '../scheme';
import { checkResult, getParamsAndKeys, stringToBytes } from '../utils';

describe(`${Scheme} Getting a blind signature, i.e. signature where signer is not aware of certain attributes of the user`, () => {
  it('works', async () => {
    // Load the WASM module
    await initializeWasm();

    // No of total (hidden from the signer or otherwise) messages to sign
    const messageCount = 5;

    const label = stringToBytes('My sig params in g1');

    // Signers keys
    const [params, sk, pk] = getParamsAndKeys(messageCount, label);
    const h = generateRandomG1Element();

    // Prepare messages that will be blinded (hidden) and known to signer
    const blindedMessages = new Map();
    const revealedMessages = new Map();
    const blindings = new Map();

    // User wants to hide messages at indices 0 and 2 from signer
    const blindedIndices: number[] = [];
    blindedIndices.push(0);
    blindedMessages.set(0, encodeMessageForSigningIfPS(stringToBytes('my-secret')));
    blindedIndices.push(2);
    blindedMessages.set(2, encodeMessageForSigningIfPS(stringToBytes('my-another-secret')));

    // Signer will know these message
    revealedMessages.set(1, encodeMessageForSigningIfPS(stringToBytes('John Smith')));
    revealedMessages.set(3, encodeMessageForSigningIfPS(stringToBytes('john.smith@emample.com')));
    revealedMessages.set(4, encodeMessageForSigningIfPS(stringToBytes('New York')));

    // Blind signature request will contain a Pedersen commitment, and it can be given a blinding of choice
    // or it can generate on its own.
    let blinding, request;
    if (isPS()) {
      [blinding, request] = BlindSignature.generateRequest(
        blindedMessages,
        params,
        h,
        blindings,
        void 0,
        revealedMessages
      );
    } else if (isBBS()) {
      request = BlindSignature.generateRequest(blindedMessages, params, true, revealedMessages);
    } else {
      [blinding, request] = BlindSignature.generateRequest(blindedMessages, params, true, void 0, revealedMessages);
    }

    if (isPS()) expect([...request.commitments.keys()].sort((a, b) => a - b)).toEqual(blindedIndices);
    else expect(request.blindedIndices).toEqual(blindedIndices);

    const statements = new Statements(getStatementForBlindSigRequest(request, params, h));

    const proofSpec = new ProofSpec(statements, new MetaStatements());
    expect(proofSpec.isValid()).toEqual(true);

    // The witness to the Pedersen commitment contains the blinding at index 0 by convention and then the hidden messages
    const witnesses = new Witnesses(
      getWitnessForBlindSigRequest(
        new Map([...blindedMessages].map(([idx, attr]) => [idx, encodeMessageForSigningIfNotPS(attr)])),
        blinding,
        blindings
      )
    );

    const proof = CompositeProof.generate(proofSpec, witnesses);

    checkResult(proof.verify(proofSpec));

    // Signer is convinced that user knows the opening to the commitment
    const blindSig = isPS()
      ? BlindSignature.fromRequest(request, sk, h)
      : BlindSignature.fromRequest(request, sk, params);

    // User unblind the signature
    const sig = isPS() ? blindSig.unblind(blindings, pk, h) : isBBS() ? blindSig : blindSig.unblind(blinding);

    // Combine blinded and revealed messages in an array
    const messages = Array(blindedMessages.size + revealedMessages.size);
    for (const [i, m] of blindedMessages.entries()) {
      messages[i] = m;
    }
    for (const [i, m] of revealedMessages.entries()) {
      messages[i] = m;
    }

    const result = sig.verify(messages, isKvac() ? sk : pk, params, true);
    expect(result.verified).toEqual(true);
  });
});
