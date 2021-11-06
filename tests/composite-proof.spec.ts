import { initializeWasm } from '@docknetwork/crypto-wasm';
import { stringToBytes } from './utils';
import {
  BlindSignatureG1,
  CompositeProof,
  KeypairG2,
  MetaStatement,
  MetaStatements,
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

describe('Proving knowledge of 1 BBS+ signature', () => {
  it('works', async () => {
    // Load the WASM module
    await initializeWasm();

    // Messages to sign
    const messageCount = 5;
    const messages: Uint8Array[] = [];
    for (let i = 0; i < messageCount; i++) {
      messages.push(stringToBytes(`Message-${i + 1}`));
    }

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

    // User reveals 2 messages at index 2 and 4 to verifier
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

    const statement1 = Statement.poKBBSSignature(params, pk, revealedMsgs, true);
    const statements = new Statements();
    statements.add(statement1);

    const context = stringToBytes('some context');

    const proofSpec = new ProofSpec(statements, new MetaStatements(), context);

    const witness1 = Witness.poKBBSSignature(sig, unrevealedMsgs, true);
    const witnesses = new Witnesses();
    witnesses.add(witness1);

    const proof = CompositeProof.generate(proofSpec, witnesses);

    expect(proof.verify(proofSpec).verified).toEqual(true);
  });
});

describe('Getting a blind signature', () => {
  it('works', async () => {
    // Load the WASM module
    await initializeWasm();

    // Messages to sign
    const messageCount = 5;
    const messages: Uint8Array[] = [];
    for (let i = 0; i < messageCount; i++) {
      messages.push(stringToBytes(`Message-${i + 1}`));
    }

    const label = stringToBytes('My sig params in g1');
    const params = SignatureParamsG1.generate(messageCount, label);

    // Signers keys
    const keypair = KeypairG2.generate(params);
    const sk = keypair.secretKey;
    const pk = keypair.publicKey;

    // User wants to hide messages at indices 0 and 2 from signer
    const blindedIndices: number[] = [];
    blindedIndices.push(0);
    blindedIndices.push(2);

    // Prepare message that will be blinded (hidden) and known to signer
    const messagesToBlind = new Map();
    const knownMessages = new Map();
    for (let i = 0; i < messageCount; i++) {
      if (blindedIndices.indexOf(i) > -1) {
        messagesToBlind.set(i, messages[i]);
      } else {
        knownMessages.set(i, messages[i]);
      }
    }

    // Blind signature request will contain a Pedersen commitment and it can be given a blinding of choice
    // or it can generate on its own.
    const [blinding, request] = BlindSignatureG1.generateRequest(messagesToBlind, params, true);

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
      elements.push(Signature.encodeMessageForSigning(messages[i]));
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
    const result = sig.verify(messages, pk, params, true);
    expect(result.verified).toEqual(true);
  });
});

describe('Proving knowledge of 2 BBS+ signature and certain message equality', () => {
  it('works', async () => {
    // Load the WASM module
    await initializeWasm();

    // There are 2 signers, both have their own keys and they sign different messages

    // 1st Signer's messages
    const messageCount1 = 5;
    const messages1: Uint8Array[] = [];
    for (let i = 0; i < messageCount1; i++) {
      messages1.push(stringToBytes(`Message-1-${i + 1}`));
    }

    // 2nd Signer's messages
    const messageCount2 = 6;
    const messages2: Uint8Array[] = [];
    for (let i = 0; i < messageCount2; i++) {
      messages2.push(stringToBytes(`Message-2-${i + 1}`));
    }

    // Make one message in both message lists equal
    messages1[1] = messages2[2];

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
    const statement1 = Statement.poKBBSSignature(params1, pk1, new Map(), true);

    // Statement for signature of 2nd signer, not revealing any messages to the verifier
    const statement2 = Statement.poKBBSSignature(params2, pk2, new Map(), true);

    const statements = new Statements();
    const sId1 = statements.add(statement1);
    const sId2 = statements.add(statement2);

    // For proving messages1[1] == messages2[2], use specify using MetaStatement
    const witnessEq = new WitnessEqualityMetaStatement();
    witnessEq.addWitnessRef(sId1, 1);
    witnessEq.addWitnessRef(sId2, 2);
    const ms = MetaStatement.witnessEquality(witnessEq);

    const metaStatements = new MetaStatements();
    metaStatements.add(ms);

    const context = stringToBytes('test-context');

    const proofSpec = new ProofSpec(statements, metaStatements, context);

    // Using the messages and signature from 1st signer
    const unrevealedMsgs1 = new Map(messages1.map((m, i) => [i, m]));
    const witness1 = Witness.poKBBSSignature(sig1, unrevealedMsgs1, true);

    // Using the messages and signature from 2nd signer
    const unrevealedMsgs2 = new Map(messages2.map((m, i) => [i, m]));
    const witness2 = Witness.poKBBSSignature(sig2, unrevealedMsgs2, true);

    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);

    const proof = CompositeProof.generate(proofSpec, witnesses);

    expect(proof.verify(proofSpec).verified).toEqual(true);
  });
});
