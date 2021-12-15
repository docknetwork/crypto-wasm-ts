import {
  CompositeProofG1,
  KeypairG2, MetaStatement, MetaStatements, ProofSpecG1,
  Signature,
  SignatureG1,
  SignatureParamsG1,
  Statement,
  Statements, Witness,
  WitnessEqualityMetaStatement, Witnesses
} from '../../src';
import {
  generateRandomFieldElement,
  generateRandomG1Element,
  initializeWasm,
  pedersenCommitmentG1
} from '@docknetwork/crypto-wasm';
import { stringToBytes } from '../utils';

describe('Verifier-local or opt-in linkability', () => {
  // A verifier wants to attach a unique identifier to a prover without either learning anything unintended (by prover)
  // from the prover's signature nor can that unique identifier be used by other verifiers to identify the prover,
  // eg. a seller (as a verifier) should be able to identify repeat customers (prover) by using a unique identifier, but
  // he should not be able to share that unique identifier with other sellers using their own identifier for that prover.
  // This is done by making the prover go through a one-time registration process with the verifier by creating a Pedersen
  // commitment to some value in the signature(s) which the verifier persists, lets call it registration commitment.
  // At each subsequent proof, the prover resends the commitment with the proof that commitment contains message from the prover's
  // signature (prover had persisted commitment and randomness) and the verifier checks that the commitment is same as the one during
  // registration. The registration commitment serves as an identifier.
  // Following shows a prover interacting with 2 different verifiers and creating and using 2 different registration commitments, 1 at each verifier

  const encodedMessages: Uint8Array[] = [];
  let sigParams: SignatureParamsG1;
  let sig: SignatureG1;
  let sigPk: Uint8Array, sigSk: Uint8Array;
  let bases1: Uint8Array[];
  let blinding1: Uint8Array;
  let registrationComm1: Uint8Array;
  let bases2: Uint8Array[];
  let blinding2: Uint8Array;
  let registrationComm2: Uint8Array;

  beforeAll(async () => {
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

    const messageCount = messages.length;
    // Encode messages for signing as well as adding to the accumulator
    for (let i = 0; i < messageCount; i++) {
      encodedMessages.push(Signature.encodeMessageForSigning(messages[i]));
    }

    const label = stringToBytes('My sig params in g1');
    sigParams = SignatureParamsG1.generate(messageCount, label);

    // Signers keys
    const sigKeypair = KeypairG2.generate(sigParams);
    sigSk = sigKeypair.secretKey;
    sigPk = sigKeypair.publicKey;

    sig = SignatureG1.generate(encodedMessages, sigSk, sigParams, false);
  });

  it('Registration at verifier 1', async () => {
    // Prover is not revealing any message
    const unrevealedMsgs: Map<number, Uint8Array> = new Map();
    for (let i = 0; i < encodedMessages.length; i++) {
      unrevealedMsgs.set(i, encodedMessages[i]);
    }

    // Verifier 1 wants a commitment to prover message at index 0. Eg, index 0 is the SSN of a citizen
    // Prover creates commitment for verifier 1 using group generators `bases1`
    bases1 = [generateRandomG1Element(), generateRandomG1Element()];
    blinding1 = generateRandomFieldElement();

    // This is the registration commitment of the prover for verifier 1
    registrationComm1 = pedersenCommitmentG1(bases1, [encodedMessages[0], blinding1]);

    // The prover must persist `blinding1` and `registrationComm1` as long as he ever wants to interact with verifier 1.

    // Prover registers at verifier 1, i.e. proves that his message at index 0 in the registration commitment `registrationComm1`
    const statement1 = Statement.bbsSignature(sigParams, sigPk, new Map(), false);
    const statement2 = Statement.pedersenCommitmentG1(bases1, registrationComm1);
    const statements = new Statements();
    statements.add(statement1);
    statements.add(statement2);

    // The 0th message in the signature is same as the committed message
    const witnessEq = new WitnessEqualityMetaStatement();
    // Witness ref for 0th message in the signature
    witnessEq.addWitnessRef(0, 0);
    // Witness ref for Pedersen commitment
    witnessEq.addWitnessRef(1, 0);
    const ms = MetaStatement.witnessEquality(witnessEq);

    const metaStatements = new MetaStatements();
    metaStatements.add(ms);

    const proofSpec = new ProofSpecG1(statements, metaStatements);

    const witness1 = Witness.bbsSignature(sig, unrevealedMsgs, false);
    const witness2 = Witness.pedersenCommitment([encodedMessages[0], blinding1]);
    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);

    const proof = CompositeProofG1.generate(proofSpec, witnesses);

    expect(proof.verify(proofSpec).verified).toEqual(true);
  });

  it('Registration at verifier 2', async () => {
    // Prover is not revealing any message
    const unrevealedMsgs: Map<number, Uint8Array> = new Map();
    for (let i = 0; i < encodedMessages.length; i++) {
      unrevealedMsgs.set(i, encodedMessages[i]);
    }

    // Verifier 2 also wants a commitment to prover message at index 1
    // Prover creates commitment for verifier 2 using group generators `bases2`
    bases2 = [generateRandomG1Element(), generateRandomG1Element()];
    blinding2 = generateRandomFieldElement();

    // This is the registration commitment of the prover for verifier 2
    registrationComm2 = pedersenCommitmentG1(bases2, [encodedMessages[0], blinding2]);

    // The prover must persist `blinding2` and `commitment2` as long as he ever wants to interact with verifier 2.

    // The commitments are different for both verifiers for the same message
    expect(registrationComm1).not.toEqual(registrationComm2);

    // Prover registers at verifier 2, i.e. proves that his message at index 0 in the registration commitment `registrationComm2`
    const statement1 = Statement.bbsSignature(sigParams, sigPk, new Map(), false);
    const statement2 = Statement.pedersenCommitmentG1(bases2, registrationComm2);
    const statements = new Statements();
    statements.add(statement1);
    statements.add(statement2);

    // The 0th message in the signature is same as the committed message
    const witnessEq = new WitnessEqualityMetaStatement();
    // Witness ref for 0th message in the signature
    witnessEq.addWitnessRef(0, 0);
    // Witness ref for Pedersen commitment
    witnessEq.addWitnessRef(1, 0);
    const ms = MetaStatement.witnessEquality(witnessEq);

    const metaStatements = new MetaStatements();
    metaStatements.add(ms);

    const proofSpec = new ProofSpecG1(statements, metaStatements);

    const witness1 = Witness.bbsSignature(sig, unrevealedMsgs, false);
    const witness2 = Witness.pedersenCommitment([encodedMessages[0], blinding2]);
    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);

    const proof = CompositeProofG1.generate(proofSpec, witnesses);

    expect(proof.verify(proofSpec).verified).toEqual(true);
  });

  it('Subsequent interaction with verifier 1', async () => {
    // Prover again proves to verifier 1, this time something different like revealing a message but still uses his registration
    // commitment corresponding to verifier 1.

    // Prover reveals a message at index 2
    const revealedMsgIndices: Set<number> = new Set();
    revealedMsgIndices.add(2)
    const revealedMsgs: Map<number, Uint8Array> = new Map();
    const unrevealedMsgs: Map<number, Uint8Array> = new Map();
    for (let i = 0; i < encodedMessages.length; i++) {
      if (revealedMsgIndices.has(i)) {
        revealedMsgs.set(i, encodedMessages[i]);
      } else {
        unrevealedMsgs.set(i, encodedMessages[i]);
      }
    }

    const statement1 = Statement.bbsSignature(sigParams, sigPk, revealedMsgs, false);
    const statement2 = Statement.pedersenCommitmentG1(bases1, registrationComm1);
    const statements = new Statements();
    statements.add(statement1);
    statements.add(statement2);

    // The 0th message in the signature is same as the committed message
    const witnessEq = new WitnessEqualityMetaStatement();
    // Witness ref for 0th message in the signature
    witnessEq.addWitnessRef(0, 0);
    // Witness ref for Pedersen commitment
    witnessEq.addWitnessRef(1, 0);
    const ms = MetaStatement.witnessEquality(witnessEq);

    const metaStatements = new MetaStatements();
    metaStatements.add(ms);

    const proofSpec = new ProofSpecG1(statements, metaStatements);

    const witness1 = Witness.bbsSignature(sig, unrevealedMsgs, false);
    const witness2 = Witness.pedersenCommitment([encodedMessages[0], blinding1]);
    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);

    const proof = CompositeProofG1.generate(proofSpec, witnesses);

    expect(proof.verify(proofSpec).verified).toEqual(true);
  });
});
