import { CompositeProof, initializeWasm, MetaStatements, ProofSpec, Statements, Witnesses } from '../../src';
import { buildWitness, encodeMessageForSigningIfPS, Scheme } from '../scheme';
import { checkResult, getParamsAndKeys, proverStmt, signAndVerify, stringToBytes, verifierStmt } from '../utils';

describe(`Proving knowledge of 1 ${Scheme} signature where some of the attributes are null, i.e. not applicable`, () => {
  it('encodes messages with null values in a meaningful way', async () => {
    // Load the WASM module
    await initializeWasm();

    // Messages to sign; the messages are attributes of a user like SSN (Social Security Number), name, email, etc.
    // The attributes N/A don't apply to this user.
    const messages: Uint8Array[] = [];
    // Comma separated indices of N/A messages. An efficient way, especially in large number of messages, could be to use a bitvector
    // where an unset bit would indicate N/A
    messages.push(encodeMessageForSigningIfPS(stringToBytes('5,6,7,9')));
    // SSN
    messages.push(encodeMessageForSigningIfPS(stringToBytes('123-456789-0')));
    // Name
    messages.push(encodeMessageForSigningIfPS(stringToBytes('John Smith')));
    // High school name
    messages.push(encodeMessageForSigningIfPS(stringToBytes('Some High School')));
    // High school year
    messages.push(encodeMessageForSigningIfPS(stringToBytes('2010')));
    // College name
    messages.push(encodeMessageForSigningIfPS(stringToBytes('N/A')));
    // Major
    messages.push(encodeMessageForSigningIfPS(stringToBytes('N/A')));
    // College year
    messages.push(encodeMessageForSigningIfPS(stringToBytes('N/A')));
    // City
    messages.push(encodeMessageForSigningIfPS(stringToBytes('New York')));
    // Last employer
    messages.push(encodeMessageForSigningIfPS(stringToBytes('N/A')));

    const messageCount = messages.length;
    const label = stringToBytes('My sig params in g1');

    // Signer's keys
    const [params, sk, pk] = getParamsAndKeys(messageCount, label);

    // Signer knows all the messages and signs
    const [sig, result] = signAndVerify(messages, params, sk, pk, true);
    checkResult(result);

    // User reveals his name, high school year, and city to verifier, i.e. indices 2, 4 and 8. 
    // He also needs to reveal first attribute (index 0) which indicates which attributes don't apply to him.
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

    const statement1 = proverStmt(params, revealedMsgs, pk, true);
    const statements = new Statements(statement1);

    // Prover constructing their ProofSpec
    const proverProofSpec = new ProofSpec(statements, new MetaStatements());
    expect(proverProofSpec.isValid()).toEqual(true);

    const witness1 = buildWitness(sig, unrevealedMsgs, true);
    const witnesses = new Witnesses(witness1);

    const proof = CompositeProof.generate(proverProofSpec, witnesses);

    const statement2 = verifierStmt(params, revealedMsgs, pk, true);
    const verifierStatements = new Statements(statement2);
    // Verifier constructing their own ProofSpec
    const verifierProofSpec = new ProofSpec(verifierStatements, new MetaStatements(), []);
    expect(verifierProofSpec.isValid()).toEqual(true);
    checkResult(proof.verify(verifierProofSpec));
  });
});
