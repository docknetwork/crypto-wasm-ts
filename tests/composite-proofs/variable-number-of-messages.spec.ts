import { initializeWasm } from '@docknetwork/crypto-wasm';
import { stringToBytes } from '../utils';
import {
  CompositeProofG1,
  KeypairG2,
  MetaStatements,
  ProofSpecG1,
  SignatureG1,
  SignatureParamsG1,
  Statement,
  Statements,
  Witness,
  Witnesses
} from '../../src';

describe('Proving knowledge of 1 BBS+ signature where some of the attributes are null, i.e.not applicable', () => {
  it('works', async () => {
    // Load the WASM module
    await initializeWasm();

    // Messages to sign; the messages are attributes of a user like SSN (Social Security Number), name, email, etc. The attributes
    // N/A don't apply to this user
    const messages: Uint8Array[] = [];
    // Comma separated indices of N/A messages. An efficient way, especially in large number of messages, could be to use a bitvector
    // where an unset bit would indicate N/A
    messages.push(stringToBytes('5,6,7,9'));
    // SSN
    messages.push(stringToBytes('123-456789-0'));
    // Name
    messages.push(stringToBytes('John Smith'));
    // High school name
    messages.push(stringToBytes('Some High School'));
    // High school year
    messages.push(stringToBytes('2010'));
    // College name
    messages.push(stringToBytes('N/A'));
    // Major
    messages.push(stringToBytes('N/A'));
    // College year
    messages.push(stringToBytes('N/A'));
    // City
    messages.push(stringToBytes('New York'));
    // Last employer
    messages.push(stringToBytes('N/A'));

    const messageCount = messages.length;
    const label = stringToBytes('My sig params in g1');
    const params = SignatureParamsG1.generate(messageCount, label);

    // Signers keys
    const keypair = KeypairG2.generate(params);
    const sk = keypair.secretKey;
    const pk = keypair.publicKey;

    // Signer knows all the messages and signs
    const sig = SignatureG1.generate(messages, sk, params, true);
    const result = sig.verify(messages, pk, params, true);
    expect(result.verified).toEqual(true);

    // User reveals his name, high school year and city to verifier, i.e. indices 2, 4 and 8. He also needs to reveal first
    // attribute (index 0) which indicates which attributes don't apply to him.
    const revealedMsgIndices: Set<number> = new Set();
    revealedMsgIndices.add(0);
    revealedMsgIndices.add(2);
    revealedMsgIndices.add(4);
    revealedMsgIndices.add(8);
    const revealedMsgs: Map<number, Uint8Array> = new Map();
    const unrevealedMsgs: Map<number, Uint8Array> = new Map();
    for (let i = 0; i < messageCount; i++) {
      if (revealedMsgIndices.has(i)) {
        revealedMsgs.set(i, messages[i]);
      } else {
        unrevealedMsgs.set(i, messages[i]);
      }
    }

    const statement1 = Statement.bbsSignature(params, pk, revealedMsgs, true);
    const statements = new Statements();
    statements.add(statement1);

    // Both the prover (user) and verifier should independently construct this `ProofSpec` but only for testing, i am reusing it.
    const proofSpec = new ProofSpecG1(statements, new MetaStatements());
    expect(proofSpec.isValid()).toEqual(true);

    const witness1 = Witness.bbsSignature(sig, unrevealedMsgs, true);
    const witnesses = new Witnesses();
    witnesses.add(witness1);

    const proof = CompositeProofG1.generate(proofSpec, witnesses);

    expect(proof.verify(proofSpec).verified).toEqual(true);
  });
});
