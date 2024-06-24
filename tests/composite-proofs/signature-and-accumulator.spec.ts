import {
  Accumulator,
  CompositeProof,
  initializeWasm,
  MetaStatement,
  MetaStatements,
  PositiveAccumulator,
  ProofSpec,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../src';
import { InMemoryState } from '../../src/accumulator/in-memory-persistence';
import { buildWitness, isKvac, Scheme, Signature } from '../scheme';
import { checkResult, getParamsAndKeys, proverStmt, signAndVerify, stringToBytes, verifierStmt } from '../utils';

describe(`Proving knowledge of 1 ${Scheme} signature and a certain message in the accumulator`, () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  async function check(isKvAccum: boolean) {
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
        encodedMessages.push(Signature.encodeMessageForSigningConstantTime(messages[i]));
      }
    }

    const label = stringToBytes('My sig params in g1');

    // Signers keys
    const [sigParams, sigSk, sigPk] = getParamsAndKeys(messageCount, label);

    const accumParams = PositiveAccumulator.generateParams(stringToBytes('Accumulator params'));
    const accumKeypair = PositiveAccumulator.generateKeypair(accumParams);
    const accumulator = PositiveAccumulator.initialize(accumParams);
    const state = new InMemoryState();

    const [sig, result] = signAndVerify(encodedMessages, sigParams, sigSk, sigPk, false);
    checkResult(result);

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

    const statement1 = proverStmt(sigParams, revealedMsgs, sigPk);
    const statement2 = isKvAccum ? Statement.vbAccumulatorMembershipKV(accumulator.accumulated) : Statement.vbAccumulatorMembership(
      accumParams,
      accumKeypair.publicKey,
      provingKey,
      accumulator.accumulated
    );
    const proverStatements = new Statements(statement1);
    proverStatements.add(statement2);

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

    const proverProofSpec = new ProofSpec(proverStatements, metaStatements, [], context);
    expect(proverProofSpec.isValid()).toEqual(true);

    const witness1 = buildWitness(sig, unrevealedMsgs, false);
    const witness2 = Witness.vbAccumulatorMembership(encodedMessages[userIdIdx], accumWitness);
    const witnesses = new Witnesses(witness1);
    witnesses.add(witness2);

    const nonce = stringToBytes('some unique nonce');

    const proof = CompositeProof.generate(proverProofSpec, witnesses, nonce);

    const statement3 = verifierStmt(sigParams, revealedMsgs, sigPk);
    const verifierStatements = new Statements(statement3);
    verifierStatements.add(statement2);
    const verifierProofSpec = new ProofSpec(verifierStatements, metaStatements, [], context);
    expect(verifierProofSpec.isValid()).toEqual(true);
    checkResult(proof.verify(verifierProofSpec, nonce));

    if (isKvac()) {
      const statement4 = Statement.bddt16MacFullVerifierConstantTime(sigParams, sigSk, revealedMsgs, false);
      const verifierStatements = new Statements(statement4);
      if (isKvAccum) {
        verifierStatements.add(Statement.vbAccumulatorMembershipKVFullVerifier(accumKeypair.secretKey, accumulator.accumulated))
      } else {
        verifierStatements.add(statement2);
      }
      const verifierProofSpec = new ProofSpec(verifierStatements, metaStatements, [], context);
      expect(verifierProofSpec.isValid()).toEqual(true);
      checkResult(proof.verify(verifierProofSpec, nonce));
    }
  }

  it('works with non-kv accumulator', async () => {
    await check(false)
  });

  it('works with kv accumulator', async () => {
    await check(true)
  });
});
