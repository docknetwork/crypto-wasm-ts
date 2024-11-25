import { CompositeProof, initializeWasm, MetaStatements, ProofSpec, Statement, Statements, Witnesses } from '../../src';
import { buildWitness, encodeMessageForSigningIfPS, isKvac, Scheme } from '../scheme';
import { checkResult, getParamsAndKeys, proverStmt, signAndVerify, stringToBytes, verifierStmt } from '../utils';

describe(`${Scheme} Proving knowledge of 1 signature over the attributes`, () => {
  it('works', async () => {
    // Load the WASM module
    await initializeWasm();

    // Messages to sign; the messages are attributes of a user like SSN (Social Security Number), name, email, etc
    const messages: Uint8Array[] = [];
    // SSN
    messages.push(encodeMessageForSigningIfPS(stringToBytes('123-456789-0')));
    // First name
    messages.push(encodeMessageForSigningIfPS(stringToBytes('John')));
    // Last name
    messages.push(encodeMessageForSigningIfPS(stringToBytes('Smith')));
    // Email
    messages.push(encodeMessageForSigningIfPS(stringToBytes('john.smith@emample.com')));
    // City
    messages.push(encodeMessageForSigningIfPS(stringToBytes('New York')));

    const messageCount= messages.length;

    const label = stringToBytes('My sig params in g1');
    // Signers keys
    const [params, sk, pk] = getParamsAndKeys(messageCount, label);

    // Signer knows all the messages and signs
    const [sig, result] = signAndVerify(messages, params, sk, pk, true);
    checkResult(result);

    // User reveals 2 messages at index 2 and 4 to verifier, last name and city
    const revealedMsgIndices: Set<number> = new Set();
    revealedMsgIndices.add(2);
    revealedMsgIndices.add(4);
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
    const proverStatements = new Statements(statement1);

    // Optional context of the proof
    const context = stringToBytes('some context');

    // Both the prover (user) and verifier should independently construct this `ProofSpec` but only for testing, i am reusing it.
    const proverProofSpec = new ProofSpec(proverStatements, new MetaStatements(), [], context);
    expect(proverProofSpec.isValid()).toEqual(true);

    const witness1 = buildWitness(sig, unrevealedMsgs, true);
    const witnesses = new Witnesses(witness1);

    const nonce = stringToBytes('some unique nonce');

    const proof = CompositeProof.generate(proverProofSpec, witnesses, nonce);

    const statement2 = verifierStmt(params, revealedMsgs, pk, true);
    const verifierStatements = new Statements(statement2);
    const verifierProofSpec = new ProofSpec(verifierStatements, new MetaStatements(), [], context);
    expect(verifierProofSpec.isValid()).toEqual(true);
    checkResult(proof.verify(verifierProofSpec, nonce));

    if (isKvac()) {
      const statement3 = Statement.bbdt16MacFullVerifierConstantTime(params, sk, revealedMsgs, true);
      const verifierStatements = new Statements(statement3);
      const verifierProofSpec = new ProofSpec(verifierStatements, new MetaStatements(), [], context);
      expect(verifierProofSpec.isValid()).toEqual(true);
      checkResult(proof.verify(verifierProofSpec, nonce));
    }
  });
});
