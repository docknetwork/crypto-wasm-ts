import { initializeWasm } from '@docknetwork/crypto-wasm';
import { checkResult, stringToBytes } from '../utils';
import { CompositeProofG1, MetaStatements, ProofSpecG1, Statements, Witness, Witnesses } from '../../src';
import {
  BlindSignature,
  KeyPair,
  SignatureParams,
  getStatementForBlindSigRequest,
  getWitnessForBlindSigRequest,
  isBBSPlus,
  encodeMessageForSigningIfPS,
  isPS,
  encodeMessageIfNotPS,
  Scheme
} from '../scheme';
import { generateRandomG1Element } from '@docknetwork/crypto-wasm';

describe(`${Scheme} Getting a blind signature, i.e. signature where signer is not aware of certain attributes of the user`, () => {
  it('works', async () => {
    // Load the WASM module
    await initializeWasm();

    // No of total (hidden from the signer or otherwise) messages to sign
    const messageCount = 5;

    const label = stringToBytes('My sig params in g1');
    const params = SignatureParams.generate(messageCount, label);

    // Signers keys
    const keypair = KeyPair.generate(params);
    const sk = keypair.secretKey;
    const pk = keypair.publicKey;
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
    } else if (isBBSPlus()) {
      [blinding, request] = BlindSignature.generateRequest(blindedMessages, params, true, void 0, revealedMessages);
    } else {
      request = BlindSignature.generateRequest(blindedMessages, params, true, revealedMessages);
    }

    if (isPS()) expect([...request.commitments.keys()].sort((a, b) => a - b)).toEqual(blindedIndices);
    else expect(request.blindedIndices).toEqual(blindedIndices);

    const statements = new Statements(getStatementForBlindSigRequest(request, params, h));

    const proofSpec = new ProofSpecG1(statements, new MetaStatements());
    expect(proofSpec.isValid()).toEqual(true);

    // The witness to the Pedersen commitment contains the blinding at index 0 by convention and then the hidden messages
    const witnesses = new Witnesses(
      getWitnessForBlindSigRequest(
        new Map([...blindedMessages].map(([idx, attr]) => [idx, encodeMessageIfNotPS(attr)])),
        blinding,
        blindings
      )
    );

    const proof = CompositeProofG1.generate(proofSpec, witnesses);

    checkResult(proof.verify(proofSpec));

    // Signer is convinced that user knows the opening to the commitment
    const blindSig = isPS()
      ? BlindSignature.fromRequest(request, sk, h)
      : BlindSignature.fromRequest(request, sk, params);

    // User unblind the signature
    const sig = isPS() ? blindSig.unblind(blindings, pk) : isBBSPlus() ? blindSig.unblind(blinding) : blindSig;

    // Combine blinded and revealed messages in an array
    const messages = Array(blindedMessages.size + revealedMessages.size);
    for (const [i, m] of blindedMessages.entries()) {
      messages[i] = m;
    }
    for (const [i, m] of revealedMessages.entries()) {
      messages[i] = m;
    }

    const result = sig.verify(messages, pk, params, true);
    expect(result.verified).toEqual(true);
  });
});
