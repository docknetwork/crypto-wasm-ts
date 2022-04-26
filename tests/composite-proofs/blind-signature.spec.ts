import { initializeWasm } from '@docknetwork/crypto-wasm';
import { stringToBytes } from '../utils';
import {
  BlindSignatureG1,
  CompositeProofG1,
  KeypairG2,
  MetaStatements,
  ProofSpecG1,
  Signature,
  SignatureParamsG1,
  Statement,
  Statements,
  Witness,
  Witnesses
} from '../../src';

describe('Getting a blind signature, i.e. signature where signer is not aware of certain attributes of the user', () => {
  it('works', async () => {
    // Load the WASM module
    await initializeWasm();

    // No of total (hidden from the signer or otherwise) messages to sign
    const messageCount = 5;

    const label = stringToBytes('My sig params in g1');
    const params = SignatureParamsG1.generate(messageCount, label);

    // Signers keys
    const keypair = KeypairG2.generate(params);
    const sk = keypair.secretKey;
    const pk = keypair.publicKey;

    // Prepare messages that will be blinded (hidden) and known to signer
    const blindedMessages = new Map();
    const knownMessages = new Map();

    // User wants to hide messages at indices 0 and 2 from signer
    const blindedIndices: number[] = [];
    blindedIndices.push(0);
    blindedMessages.set(0, stringToBytes('my-secret'));
    blindedIndices.push(2);
    blindedMessages.set(2, stringToBytes('my-another-secret'));

    // Blind signature request will contain a Pedersen commitment, and it can be given a blinding of choice
    // or it can generate on its own.
    const [blinding, request] = BlindSignatureG1.generateRequest(blindedMessages, params, true);

    expect(request.blindedIndices).toEqual(blindedIndices);

    // Take parts of the sig params corresponding to the blinded messages
    const commKey = params.getParamsForIndices(request.blindedIndices);
    const statement1 = Statement.pedersenCommitmentG1(commKey, request.commitment);

    const statements = new Statements();
    statements.add(statement1);

    const proofSpec = new ProofSpecG1(statements, new MetaStatements());

    // The witness to the Pedersen commitment contains the blinding at index 0 by convention and then the hidden messages
    const committeds = [blinding];
    for (const i of blindedIndices) {
      // The messages are encoded before committing
      committeds.push(Signature.encodeMessageForSigning(blindedMessages.get(i)));
    }
    const witness1 = Witness.pedersenCommitment(committeds);
    const witnesses = new Witnesses();
    witnesses.add(witness1);

    const proof = CompositeProofG1.generate(proofSpec, witnesses);

    expect(proof.verify(proofSpec).verified).toEqual(true);

    // Signer will know these message
    knownMessages.set(1, stringToBytes('John Smith'));
    knownMessages.set(3, stringToBytes('john.smith@emample.com'));
    knownMessages.set(4, stringToBytes('New York'));
    // Signer is convinced that user knows the opening to the commitment
    const blindSig = BlindSignatureG1.generate(request.commitment, knownMessages, sk, params, true);

    // User unblind the signature
    const sig = blindSig.unblind(blinding);

    // Combine blinded and known messages in an array
    const messages = Array(blindedMessages.size + knownMessages.size);
    for (const [i, m] of blindedMessages.entries()) {
      messages[i] = m;
    }
    for (const [i, m] of knownMessages.entries()) {
      messages[i] = m;
    }

    const result = sig.verify(messages, pk, params, true);
    expect(result.verified).toEqual(true);
  });
});
