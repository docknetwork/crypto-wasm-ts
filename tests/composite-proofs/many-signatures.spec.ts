import { initializeWasm } from '@docknetwork/crypto-wasm';
import { checkResult, stringToBytes } from '../utils';
import {
  CompositeProofG1,
  MetaStatement,
  MetaStatements,
  ProofSpecG1,
  Statements,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../src';
import {
  KeyPair,
  Scheme,
  Signature,
  SignatureParams,
  buildStatement,
  buildWitness,
  encodeMessageForSigningIfPS,
} from '../scheme'
import {  } from '@docknetwork/crypto-wasm';

describe(`${Scheme} Proving knowledge of 2 BBS+ signatures over attributes and equality of a specific attribute`, () => {
  it('works', async () => {
    // Load the WASM module
    await initializeWasm();

    // There are 2 signers, both have their own keys and they sign different messages

    // The messages represent a user's attributes. Both signatures have some attributes in common and the user wants to
    // prove that certain attributes, SSN and email in this case are same in both signatures.

    // Messages to be signed by the first signer
    const messages1: Uint8Array[] = [];
    // SSN
    messages1.push(encodeMessageForSigningIfPS(stringToBytes('123-456789-0')));
    // First name
    messages1.push(encodeMessageForSigningIfPS(stringToBytes('John')));
    // Last name
    messages1.push(encodeMessageForSigningIfPS(stringToBytes('Smith')));
    // Email
    messages1.push(encodeMessageForSigningIfPS(stringToBytes('john.smith@example.com')));
    // City
    messages1.push(encodeMessageForSigningIfPS(stringToBytes('New York')));

    const messageCount1 = messages1.length;

    // Messages to be signed by the 2nd signer
    const messages2: Uint8Array[] = [];
    // Name
    messages2.push(encodeMessageForSigningIfPS(stringToBytes('John Smith')));
    // Email
    messages2.push(encodeMessageForSigningIfPS(stringToBytes('john.smith@example.com')));
    // City
    messages2.push(encodeMessageForSigningIfPS(stringToBytes('New York')));
    // Employer
    messages2.push(encodeMessageForSigningIfPS(stringToBytes('Acme Corp')));
    // Employee id
    messages2.push(encodeMessageForSigningIfPS(stringToBytes('5010')));
    // SSN, this is same as in first signer's messages
    messages2.push(encodeMessageForSigningIfPS(stringToBytes('123-456789-0')));

    const messageCount2 = messages2.length;

    // 1st Signer's params
    const label1 = stringToBytes('Label-1');
    const params1 = SignatureParams.generate(messageCount1, label1);

    // 2nd Signer's params
    const label2 = stringToBytes('Label-2');
    const params2 = SignatureParams.generate(messageCount2, label2);

    // Signer 1 keys
    const keypair1 = KeyPair.generate(params1);
    const sk1 = keypair1.secretKey;
    const pk1 = keypair1.publicKey;

    // Signer 2 keys
    const keypair2 = KeyPair.generate(params2);
    const sk2 = keypair2.secretKey;
    const pk2 = keypair2.publicKey;

    // 1st Signer signs
    const sig1 = Signature.generate(messages1, sk1, params1, true);
    // User verifies signature from 1st signer
    const result1 = sig1.verify(messages1, pk1, params1, true);
    expect(result1.verified).toEqual(true);

    // 2nd Signer signs
    const sig2 = Signature.generate(messages2, sk2, params2, true);
    // User verifies signature from 2nd signer
    const result2 = sig2.verify(messages2, pk2, params2, true);
    expect(result2.verified).toEqual(true);

    // User wants to prove knowledge of 2 signatures and hence 2 statements

    // Statement for signature of 1st signer, not revealing any messages to the verifier
    const statement1 = buildStatement(params1, pk1, new Map(), true);

    // Statement for signature of 2nd signer, revealing 1 message to the verifier
    const revealedMsgIndices: Set<number> = new Set();
    revealedMsgIndices.add(3);
    const revealedMsgs: Map<number, Uint8Array> = new Map();
    const unrevealedMsgs2: Map<number, Uint8Array> = new Map();
    for (let i = 0; i < messageCount2; i++) {
      if (revealedMsgIndices.has(i)) {
        revealedMsgs.set(i, messages2[i]);
      } else {
        unrevealedMsgs2.set(i, messages2[i]);
      }
    }
    const statement2 = buildStatement(params2, pk2, revealedMsgs, true);

    const statements = new Statements();
    const sId1 = statements.add(statement1);
    const sId2 = statements.add(statement2);

    const metaStatements = new MetaStatements();
    // For proving equality of SSN, messages1[0] == messages2[5], specify using MetaStatement
    const witnessEq = new WitnessEqualityMetaStatement();
    witnessEq.addWitnessRef(sId1, 0);
    witnessEq.addWitnessRef(sId2, 5);
    const ms = MetaStatement.witnessEquality(witnessEq);

    // For proving equality of email, messages1[3] == messages2[1], specify using MetaStatement
    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(sId1, 3);
    witnessEq2.addWitnessRef(sId2, 1);
    const ms2 = MetaStatement.witnessEquality(witnessEq2);

    metaStatements;
    metaStatements.add(ms);
    metaStatements.add(ms2);

    const context = stringToBytes('test-context');

    const proofSpec = new ProofSpecG1(statements, metaStatements, [], context);
    expect(proofSpec.isValid()).toEqual(true);

    // Using the messages and signature from 1st signer
    const unrevealedMsgs1 = new Map(messages1.map((m, i) => [i, m]));
    const witness1 = buildWitness(sig1, unrevealedMsgs1, true);

    // Using the messages and signature from 2nd signer
    const witness2 = buildWitness(sig2, unrevealedMsgs2, true);

    const witnesses = new Witnesses([].concat(witness1, witness2));

    const nonce = stringToBytes('some unique nonce');

    const proof = CompositeProofG1.generate(proofSpec, witnesses, nonce);

    checkResult(proof.verify(proofSpec, nonce));
  });
});
