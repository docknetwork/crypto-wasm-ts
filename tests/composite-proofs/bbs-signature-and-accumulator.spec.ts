import { initializeWasm } from '@docknetwork/crypto-wasm';
import { checkResult, stringToBytes } from '../utils';
import {
  Accumulator,
  CompositeProofG1,
  MetaStatement,
  MetaStatements,
  PositiveAccumulator,
  ProofSpecG1,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../src';
import { KeyPair, Scheme, Signature, SignatureParams, buildStatement, buildWitness } from '../scheme';
import { InMemoryState } from '../../src/accumulator/in-memory-persistence';

describe(`Proving knowledge of 1 ${Scheme} signature and a certain message in the accumulator`, () => {
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
    const encodedMessages: Uint8Array[] = [];
    for (let i = 0; i < messageCount; i++) {
      if (i === messageCount - 1) {
        // Last one, i.e. user id is added to the accumulator so encode accordingly
        encodedMessages.push(Accumulator.encodeBytesAsAccumulatorMember(messages[i]));
      } else {
        encodedMessages.push(Signature.encodeMessageForSigning(messages[i]));
      }
    }

    const label = stringToBytes('My sig params in g1');
    const sigParams = SignatureParams.generate(messageCount, label);

    // Signers keys
    const sigKeypair = KeyPair.generate(sigParams);
    const sigSk = sigKeypair.secretKey;
    const sigPk = sigKeypair.publicKey;

    const accumParams = PositiveAccumulator.generateParams(stringToBytes('Accumulator params'));
    const accumKeypair = PositiveAccumulator.generateKeypair(accumParams);
    const accumulator = PositiveAccumulator.initialize(accumParams);
    const state = new InMemoryState();

    const sig = Signature.generate(encodedMessages, sigSk, sigParams, false);
    const result = sig.verify(encodedMessages, sigPk, sigParams, false);
    expect(result.verified).toEqual(true);

    const userIdIdx = messageCount - 1;
    await accumulator.add(encodedMessages[userIdIdx], accumKeypair.secretKey, state);
    const accumWitness = await accumulator.membershipWitness(encodedMessages[userIdIdx], accumKeypair.secretKey, state);

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

    const provingKey = Accumulator.generateMembershipProvingKey(stringToBytes('Our proving key'));

    const statement1 = buildStatement(sigParams, sigPk, revealedMsgs, false);
    const statement2 = Statement.accumulatorMembership(
      accumParams,
      accumKeypair.publicKey,
      provingKey,
      accumulator.accumulated
    );
    const statements = new Statements(statement1);
    statements.add(statement2);

    // The last message in the signature is same as the accumulator member
    const witnessEq = new WitnessEqualityMetaStatement();
    // Witness ref for last message in the signature
    witnessEq.addWitnessRef(0, userIdIdx);
    // Witness ref for accumulator member
    witnessEq.addWitnessRef(1, 0);
    const ms = MetaStatement.witnessEquality(witnessEq);

    const metaStatements = new MetaStatements();
    metaStatements.add(ms);

    const context = stringToBytes('some context');

    const proofSpec = new ProofSpecG1(statements, metaStatements, [], context);
    expect(proofSpec.isValid()).toEqual(true);

    const witness1 = buildWitness(sig, unrevealedMsgs, false);
    const witness2 = Witness.accumulatorMembership(encodedMessages[userIdIdx], accumWitness);
    const witnesses = new Witnesses(witness1);
    witnesses.add(witness2);

    const nonce = stringToBytes('some unique nonce');

    const proof = CompositeProofG1.generate(proofSpec, witnesses, nonce);
    checkResult(proof.verify(proofSpec, nonce));
  });
});
