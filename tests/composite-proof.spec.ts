import { initializeWasm } from '@docknetwork/crypto-wasm';
import { stringToBytes } from './utils';
import {
  Accumulator,
  BlindSignatureG1,
  CompositeProof,
  KeypairG2,
  MetaStatement,
  MetaStatements, PositiveAccumulator,
  ProofSpec,
  Signature,
  SignatureG1,
  SignatureParamsG1,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../src';
import { InMemoryState } from '../src/accumulator/in-memory-persistence';

describe('Proving knowledge of 1 BBS+ signature over the attributes', () => {
  it('works', async () => {
    // Load the WASM module
    await initializeWasm();

    // Messages to sign; the messages are attributes of a user like SSN (Social Security Number), name, email, etc
    const messages: Uint8Array[] = [];
    // SSN
    messages.push(stringToBytes('123-456789-0'));
    // First name
    messages.push(stringToBytes('John'));
    // Last name
    messages.push(stringToBytes('Smith'));
    // Email
    messages.push(stringToBytes('john.smith@emample.com'));
    // City
    messages.push(stringToBytes('New York'));

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

    const statement1 = Statement.bbsSignature(params, pk, revealedMsgs, true);
    const statements = new Statements();
    statements.add(statement1);

    // Optional context of the proof
    const context = stringToBytes('some context');

    // Both the prover (user) and verifier should independently construct this `ProofSpec` but only for testing, i am reusing it.
    const proofSpec = new ProofSpec(statements, new MetaStatements(), context);

    const witness1 = Witness.bbsSignature(sig, unrevealedMsgs, true);
    const witnesses = new Witnesses();
    witnesses.add(witness1);

    const proof = CompositeProof.generate(proofSpec, witnesses);

    expect(proof.verify(proofSpec).verified).toEqual(true);
  });
});

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

    knownMessages.set(1, stringToBytes('John Smith'));
    knownMessages.set(3, stringToBytes('john.smith@emample.com'));
    knownMessages.set(4, stringToBytes('New York'));

    // Blind signature request will contain a Pedersen commitment and it can be given a blinding of choice
    // or it can generate on its own.
    const [blinding, request] = BlindSignatureG1.generateRequest(blindedMessages, params, true);

    expect(request.blindedIndices).toEqual(new Set(blindedIndices));

    const bases = params.getParamsForIndices(blindedIndices);
    const statement1 = Statement.pedersenCommitmentG1(bases, request.commitment);

    const statements = new Statements();
    statements.add(statement1);

    const proofSpec = new ProofSpec(statements, new MetaStatements());

    // The witness to the Pedersen commitment contains the blinding at index 0 and then the hidden messages
    const elements = [blinding];
    for (const i of blindedIndices) {
      // The messages are encoded before committing
      elements.push(Signature.encodeMessageForSigning(blindedMessages.get(i)));
    }
    const witness1 = Witness.pedersenCommitment(elements);
    const witnesses = new Witnesses();
    witnesses.add(witness1);

    const proof = CompositeProof.generate(proofSpec, witnesses);

    expect(proof.verify(proofSpec).verified).toEqual(true);

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

describe('Proving knowledge of 2 BBS+ signatures over attributes and equality of a specific attribute', () => {
  it('works', async () => {
    // Load the WASM module
    await initializeWasm();

    // There are 2 signers, both have their own keys and they sign different messages

    // The messages represent a user's attributes. Both signatures have some attributes in common and the user wants to
    // prove that certain attribute, SSN in this case is same in both signatures.

    // Messages to be signed by the first signer
    const messages1: Uint8Array[] = [];
    // SSN
    messages1.push(stringToBytes('123-456789-0'));
    // First name
    messages1.push(stringToBytes('John'));
    // Last name
    messages1.push(stringToBytes('Smith'));
    // Email
    messages1.push(stringToBytes('john.smith@emample.com'));
    // City
    messages1.push(stringToBytes('New York'));

    const messageCount1 = messages1.length;

    // Messages to be signed by the 2nd signer
    const messages2: Uint8Array[] = [];
    // Name
    messages2.push(stringToBytes('John Smith'));
    // Email
    messages2.push(stringToBytes('john.smith@emample.com'));
    // City
    messages2.push(stringToBytes('New York'));
    // Employer
    messages2.push(stringToBytes('Acme Corp'));
    // Employee id
    messages2.push(stringToBytes('5010'));
    // SSN, this is same as in first signer's messages
    messages2.push(stringToBytes('123-456789-0'));

    const messageCount2 = messages2.length;

    // 1st Signer's params
    const label1 = stringToBytes('Label-1');
    const params1 = SignatureParamsG1.generate(messageCount1, label1);

    // 2nd Signer's params
    const label2 = stringToBytes('Label-2');
    const params2 = SignatureParamsG1.generate(messageCount2, label2);

    // Signer 1 keys
    const keypair1 = KeypairG2.generate(params1);
    const sk1 = keypair1.secretKey;
    const pk1 = keypair1.publicKey;

    // Signer 2 keys
    const keypair2 = KeypairG2.generate(params2);
    const sk2 = keypair2.secretKey;
    const pk2 = keypair2.publicKey;

    // 1st Signer signs
    const sig1 = SignatureG1.generate(messages1, sk1, params1, true);
    // User verifies signature from 1st signer
    const result1 = sig1.verify(messages1, pk1, params1, true);
    expect(result1.verified).toEqual(true);

    // 2nd Signer signs
    const sig2 = SignatureG1.generate(messages2, sk2, params2, true);
    // User verifies signature from 2nd signer
    const result2 = sig2.verify(messages2, pk2, params2, true);
    expect(result2.verified).toEqual(true);

    // User wants to prove knowledge of 2 signatures and hence 2 statements

    // Statement for signature of 1st signer, not revealing any messages to the verifier
    const statement1 = Statement.bbsSignature(params1, pk1, new Map(), true);

    // Statement for signature of 2nd signer, not revealing any messages to the verifier
    const statement2 = Statement.bbsSignature(params2, pk2, new Map(), true);

    const statements = new Statements();
    const sId1 = statements.add(statement1);
    const sId2 = statements.add(statement2);

    // For proving messages1[0] == messages2[5], use specify using MetaStatement
    const witnessEq = new WitnessEqualityMetaStatement();
    witnessEq.addWitnessRef(sId1, 0);
    witnessEq.addWitnessRef(sId2, 5);
    const ms = MetaStatement.witnessEquality(witnessEq);

    const metaStatements = new MetaStatements();
    metaStatements.add(ms);

    const context = stringToBytes('test-context');

    const proofSpec = new ProofSpec(statements, metaStatements, context);

    // Using the messages and signature from 1st signer
    const unrevealedMsgs1 = new Map(messages1.map((m, i) => [i, m]));
    const witness1 = Witness.bbsSignature(sig1, unrevealedMsgs1, true);

    // Using the messages and signature from 2nd signer
    const unrevealedMsgs2 = new Map(messages2.map((m, i) => [i, m]));
    const witness2 = Witness.bbsSignature(sig2, unrevealedMsgs2, true);

    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);

    const proof = CompositeProof.generate(proofSpec, witnesses);

    expect(proof.verify(proofSpec).verified).toEqual(true);
  });
});

describe('Proving knowledge of 1 BBS+ signature and a certain message in the accumulator', () => {
  it('works', async () => {
    // Load the WASM module
    await initializeWasm();

    // Messages to sign
    const messages: Uint8Array[] = [];
    // SSN
    messages.push(stringToBytes('123-456789-0'));
    // First name
    messages.push(stringToBytes('John'));
    // Last name
    messages.push(stringToBytes('Smith'));
    // Email
    messages.push(stringToBytes('john.smith@emample.com'));
    // User id, this will be added to the accumulator
    messages.push(stringToBytes('user:123-xyz-#'));

    const messageCount = messages.length;

    // Encode messages for signing as well as adding to the accumulator
    const encodedMessages = [];
    for (let i = 0; i < messageCount; i++) {
      if (i === messageCount-1) {
        // Last one, i.e. user id is added to the accumulator so encode accordingly
        encodedMessages.push(Accumulator.encodeBytesAsAccumulatorMember(messages[i]));
      } else {
        encodedMessages.push(Signature.encodeMessageForSigning(messages[i]));
      }
    }

    const label = stringToBytes('My sig params in g1');
    const sigParams = SignatureParamsG1.generate(messageCount, label);

    // Signers keys
    const sigKeypair = KeypairG2.generate(sigParams);
    const sigSk = sigKeypair.secretKey;
    const sigPk = sigKeypair.publicKey;

    const accumParams = PositiveAccumulator.generateParams(stringToBytes('Accumulator params'));
    const accumKeypair = PositiveAccumulator.generateKeypair(accumParams);
    const accumulator = PositiveAccumulator.initialize(accumParams);
    const state = new InMemoryState();

    const sig = SignatureG1.generate(encodedMessages, sigSk, sigParams, false);
    const result = sig.verify(encodedMessages, sigPk, sigParams, false);
    expect(result.verified).toEqual(true);

    await accumulator.add(encodedMessages[messageCount-1], accumKeypair.secret_key, state);
    const witness = await accumulator.membershipWitness(encodedMessages[messageCount-1], accumKeypair.secret_key, state)

    // User reveals 1 message at index 1 to verifier
    const revealedMsgIndices: Set<number> = new Set();
    revealedMsgIndices.add(1);
    const revealedMsgs: Map<number, Uint8Array> = new Map();
    const unrevealedMsgs: Map<number, Uint8Array> = new Map();
    for (let i = 0; i < messageCount; i++) {
      if (revealedMsgIndices.has(i)) {
        revealedMsgs.set(i, encodedMessages[i]);
      } else {
        unrevealedMsgs.set(i, encodedMessages[i]);
      }
    }

    const provingKey = Accumulator.generateMembershipProvingKey();

    const statement1 = Statement.bbsSignature(sigParams, sigPk, revealedMsgs, false);
    const statement2 = Statement.accumulatorMembership(accumParams, accumKeypair.public_key, provingKey, accumulator.accumulated);
    const statements = new Statements();
    statements.add(statement1);
    statements.add(statement2);

    // The last message in the signature is same as the accumulator member
    const witnessEq = new WitnessEqualityMetaStatement();
    // Witness ref for last message in the signature
    witnessEq.addWitnessRef(0, messageCount-1);
    // Witness ref for accumulator member
    witnessEq.addWitnessRef(1, 0);
    const ms = MetaStatement.witnessEquality(witnessEq);

    const metaStatements = new MetaStatements();
    metaStatements.add(ms);

    const context = stringToBytes('some context');

    const proofSpec = new ProofSpec(statements, metaStatements, context);

    const witness1 = Witness.bbsSignature(sig, unrevealedMsgs, false);
    const witness2 = Witness.accumulatorMembership(encodedMessages[messageCount-1], witness);
    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);

    const proof = CompositeProof.generate(proofSpec, witnesses);

    expect(proof.verify(proofSpec).verified).toEqual(true);
  });
});
