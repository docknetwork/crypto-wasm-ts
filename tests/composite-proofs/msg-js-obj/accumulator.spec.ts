import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  Accumulator,
  AccumulatorSecretKey,
  CompositeProofG1,
  createWitnessEqualityMetaStatement,
  EncodeFunc,
  Encoder,
  encodeRevealedMsgs,
  getAdaptedSignatureParamsForMessages,
  getIndicesForMsgNames,
  getRevealedAndUnrevealed,
  IAccumulatorState,
  MetaStatements,
  PositiveAccumulator,
  ProofSpecG1,

  Statement,
  Statements,

  Witness,
  WitnessEqualityMetaStatement,
  Witnesses,
  WitnessUpdatePublicInfo
} from '../../../src';
import { checkResult, stringToBytes } from '../../utils';
import { InMemoryState } from '../../../src/accumulator/in-memory-persistence';
import { attributes1, attributes1Struct, attributes2, attributes2Struct, defaultEncoder } from './data-and-encoder';
import { checkMapsEqual } from './index';
import { buildStatement, buildWitness, KeyPair, SignatureParams } from '../../scheme';

describe('Accumulator', () => {
  beforeAll(async () => {
    // Load the WASM module
    await initializeWasm();
  });

  // Prefill the given accumulator with `totalMembers` members. The members are creates in a certain way for these tests
  async function prefillAccumulator(
    accumulator: Accumulator,
    secretKey: AccumulatorSecretKey,
    state: IAccumulatorState,
    totalMembers: number
  ) {
    const members: Uint8Array[] = [];
    for (let i = 1; i <= totalMembers; i++) {
      // For this test, user id is of this form
      const userId = `user:${i}-xyz-#`;
      members.push(Accumulator.encodeBytesAsAccumulatorMember(stringToBytes(userId)));
    }
    // Adding a single batch as `totalMembers` is fairly small (100s) in this test but in practice choose a reasonable
    // batch size to not take up complete system's memory
    await accumulator.addBatch(members, secretKey, state);
    // @ts-ignore
    expect(state.state.size).toEqual(totalMembers);
    return members;
  }

  it('signing and proof of knowledge of signatures and proof of accumulator membership', async () => {
    // This test check that 2 signatures can be produced and verified and proof of knowledge of both signatures can be
    // produced and verifier. Additionally, one of the message is also present in an accumulator and its proof of membership
    // can be done in zero-knowledge.

    // 1st signer's setup
    const label1 = stringToBytes('Sig params label 1');
    // Message count shouldn't matter as `label1` is known
    let params1 = SignatureParams.generate(1, label1);
    const keypair1 = KeyPair.generate(params1);
    const sk1 = keypair1.secretKey;
    const pk1 = keypair1.publicKey;

    // 2nd signer's setup
    const label2 = stringToBytes('Sig params label 2');
    // Message count shouldn't matter as `label2` is known
    let params2 = SignatureParams.generate(1, label2);
    const keypair2 = KeyPair.generate(params2);
    const sk2 = keypair2.secretKey;
    const pk2 = keypair2.publicKey;

    // Accumulator manager 1's setup
    const accumParams1 = PositiveAccumulator.generateParams(stringToBytes('Accumulator params 1'));
    const accumKeypair1 = PositiveAccumulator.generateKeypair(accumParams1);
    const accumulator1 = PositiveAccumulator.initialize(accumParams1);
    const accumState1 = new InMemoryState();
    const allMembers1 = await prefillAccumulator(accumulator1, accumKeypair1.secretKey, accumState1, 200);
    const provingKey1 = Accumulator.generateMembershipProvingKey(stringToBytes('Proving key1'));

    // Accumulator manager 2's setup
    const accumParams2 = PositiveAccumulator.generateParams(stringToBytes('Accumulator params 2'));
    const accumKeypair2 = PositiveAccumulator.generateKeypair(accumParams2);
    const accumulator2 = PositiveAccumulator.initialize(accumParams2);
    const accumState2 = new InMemoryState();
    const allMembers2 = await prefillAccumulator(accumulator2, accumKeypair2.secretKey, accumState2, 300);
    const provingKey2 = Accumulator.generateMembershipProvingKey(stringToBytes('Proving key2'));

    // Encoder knows how to encode the attribute being added to the accumulator.
    const encoders = new Map<string, EncodeFunc>();
    encoders.set('user-id', (v: unknown) => {
      // @ts-ignore
      return Accumulator.encodeBytesAsAccumulatorMember(stringToBytes(v));
    });
    encoders.set('sensitive.user-id', (v: unknown) => {
      // @ts-ignore
      return Accumulator.encodeBytesAsAccumulatorMember(stringToBytes(v));
    });

    const encoder = new Encoder(encoders, defaultEncoder);

    // Sign and verify all signatures

    // Signer 1 signs the attributes
    const signed1 = SignatureParams.signMessageObject(attributes1, sk1, label1, encoder);

    // Accumulator manager 1 generates the witness for the accumulator member, i.e. attribute signed1.encodedMessages['user-id']
    // and gives the witness to the user.
    const accumWitness1 = await accumulator1.membershipWitness(
      signed1.encodedMessages['user-id'],
      accumKeypair1.secretKey,
      accumState1
    );

    checkResult(SignatureParams.verifyMessageObject(attributes1, signed1.signature, pk1, label1, encoder));

    // The user verifies the accumulator membership by using the witness
    let verifAccumulator1 = PositiveAccumulator.fromAccumulated(accumulator1.accumulated);
    expect(
      verifAccumulator1.verifyMembershipWitness(
        signed1.encodedMessages['user-id'],
        accumWitness1,
        accumKeypair1.publicKey,
        accumParams1
      )
    ).toEqual(true);

    // Signer 2 signs the attributes
    const signed2 = SignatureParams.signMessageObject(attributes2, sk2, label2, encoder);

    // Accumulator manager 2 generates the witness and gives it to the user
    const accumWitness2 = await accumulator2.membershipWitness(
      signed2.encodedMessages['sensitive.user-id'],
      accumKeypair2.secretKey,
      accumState2
    );

    checkResult(SignatureParams.verifyMessageObject(attributes2, signed2.signature, pk2, label2, encoder));

    // The user verifies the accumulator membership by using the witness
    let verifAccumulator2 = PositiveAccumulator.fromAccumulated(accumulator2.accumulated);
    expect(
      verifAccumulator2.verifyMembershipWitness(
        signed2.encodedMessages['sensitive.user-id'],
        accumWitness2,
        accumKeypair2.publicKey,
        accumParams2
      )
    ).toEqual(true);

    // Reveal
    // - first name ("fname" attribute) from both sets of signed attributes
    // - attribute "country" from 1st signed attribute set
    // - attributes "location.country", "physical.BMI" from 2nd signed attribute set

    // Prove in zero knowledge that SSN is equal in both attribute sets

    const revealedNames1 = new Set<string>();
    revealedNames1.add('fname');
    revealedNames1.add('country');

    const revealedNames2 = new Set<string>();
    revealedNames2.add('fname');
    revealedNames2.add('location.country');
    revealedNames2.add('physical.BMI');

    // Both prover and verifier can independently create this struct
    const sigParams1 = getAdaptedSignatureParamsForMessages(params1, attributes1Struct);
    const sigParams2 = getAdaptedSignatureParamsForMessages(params2, attributes2Struct);

    const [revealedMsgs1, unrevealedMsgs1, revealedMsgsRaw1] = getRevealedAndUnrevealed(
      attributes1,
      revealedNames1,
      encoder
    );
    const statement1 = buildStatement(sigParams1, pk1, revealedMsgs1, false);

    const [revealedMsgs2, unrevealedMsgs2, revealedMsgsRaw2] = getRevealedAndUnrevealed(
      attributes2,
      revealedNames2,
      encoder
    );
    const statement2 = buildStatement(sigParams2, pk2, revealedMsgs2, false);

    const statement3 = Statement.accumulatorMembership(
      accumParams1,
      accumKeypair1.publicKey,
      provingKey1,
      accumulator1.accumulated
    );

    const statement4 = Statement.accumulatorMembership(
      accumParams2,
      accumKeypair2.publicKey,
      provingKey2,
      accumulator2.accumulated
    );

    const statementsProver = new Statements();
    const sIdx1 = statementsProver.add(statement1);
    const sIdx2 = statementsProver.add(statement2);
    const sIdx3 = statementsProver.add(statement3);
    const sIdx4 = statementsProver.add(statement4);

    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(sIdx1, getIndicesForMsgNames(['user-id'], attributes1Struct)[0]);
    witnessEq1.addWitnessRef(sIdx3, 0);

    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(sIdx2, getIndicesForMsgNames(['sensitive.user-id'], attributes2Struct)[0]);
    witnessEq2.addWitnessRef(sIdx4, 0);

    const witnessEq3 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx1, [['SSN'], attributes1Struct]);
        m.set(sIdx2, [['sensitive.SSN'], attributes2Struct]);
        return m;
      })()
    );

    const metaStmtsProver = new MetaStatements();
    metaStmtsProver.addWitnessEquality(witnessEq1);
    metaStmtsProver.addWitnessEquality(witnessEq2);
    metaStmtsProver.addWitnessEquality(witnessEq3);

    // The prover should independently construct this `ProofSpec`
    const proofSpecProver = new ProofSpecG1(statementsProver, metaStmtsProver);
    expect(proofSpecProver.isValid()).toEqual(true);

    const witness1 = buildWitness(signed1.signature, unrevealedMsgs1, false);
    const witness2 = buildWitness(signed2.signature, unrevealedMsgs2, false);
    const witness3 = Witness.accumulatorMembership(signed1.encodedMessages['user-id'], accumWitness1);
    const witness4 = Witness.accumulatorMembership(signed2.encodedMessages['sensitive.user-id'], accumWitness2);

    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);
    witnesses.add(witness3);
    witnesses.add(witness4);

    const proof = CompositeProofG1.generate(proofSpecProver, witnesses);

    // Verifier independently encodes revealed messages
    const revealedMsgs1FromVerifier = encodeRevealedMsgs(revealedMsgsRaw1, attributes1Struct, encoder);
    checkMapsEqual(revealedMsgs1, revealedMsgs1FromVerifier);
    const revealedMsgs2FromVerifier = encodeRevealedMsgs(revealedMsgsRaw2, attributes2Struct, encoder);
    checkMapsEqual(revealedMsgs2, revealedMsgs2FromVerifier);

    const statement5 = buildStatement(sigParams1, pk1, revealedMsgs1FromVerifier, false);
    const statement6 = buildStatement(sigParams2, pk2, revealedMsgs2FromVerifier, false);
    const statement7 = Statement.accumulatorMembership(
      accumParams1,
      accumKeypair1.publicKey,
      provingKey1,
      accumulator1.accumulated
    );
    const statement8 = Statement.accumulatorMembership(
      accumParams2,
      accumKeypair2.publicKey,
      provingKey2,
      accumulator2.accumulated
    );

    const statementsVerifier = new Statements();
    const sIdx5 = statementsVerifier.add(statement5);
    const sIdx6 = statementsVerifier.add(statement6);
    const sIdx7 = statementsVerifier.add(statement7);
    const sIdx8 = statementsVerifier.add(statement8);

    const witnessEq4 = new WitnessEqualityMetaStatement();
    witnessEq4.addWitnessRef(sIdx5, getIndicesForMsgNames(['user-id'], attributes1Struct)[0]);
    witnessEq4.addWitnessRef(sIdx7, 0);
    const witnessEq5 = new WitnessEqualityMetaStatement();
    witnessEq5.addWitnessRef(sIdx6, getIndicesForMsgNames(['sensitive.user-id'], attributes2Struct)[0]);
    witnessEq5.addWitnessRef(sIdx8, 0);
    const witnessEq6 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx5, [['SSN'], attributes1Struct]);
        m.set(sIdx6, [['sensitive.SSN'], attributes2Struct]);
        return m;
      })()
    );

    const metaStmtsVerifier = new MetaStatements();
    metaStmtsVerifier.addWitnessEquality(witnessEq4);
    metaStmtsVerifier.addWitnessEquality(witnessEq5);
    metaStmtsVerifier.addWitnessEquality(witnessEq6);

    // The verifier should independently construct this `ProofSpec`
    const proofSpecVerifier = new ProofSpecG1(statementsVerifier, metaStmtsVerifier);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    checkResult(proof.verify(proofSpecVerifier));

    // Remove members from accumulator

    // Prepare witness update info that needs to be shared with the members
    const witnessUpdInfo1 = WitnessUpdatePublicInfo.new(
      accumulator1.accumulated,
      [],
      [allMembers1[5]],
      accumKeypair1.secretKey
    );
    const witnessUpdInfo2 = WitnessUpdatePublicInfo.new(
      accumulator2.accumulated,
      [],
      [allMembers1[20]],
      accumKeypair2.secretKey
    );

    // Accumulator managers remove the member from accumulator
    await accumulator1.remove(allMembers1[5], accumKeypair1.secretKey, accumState1);
    await accumulator2.remove(allMembers2[20], accumKeypair2.secretKey, accumState2);

    // Prover updates its witnesses
    accumWitness1.updateUsingPublicInfoPostBatchUpdate(
      signed1.encodedMessages['user-id'],
      [],
      [allMembers1[5]],
      witnessUpdInfo1
    );
    accumWitness2.updateUsingPublicInfoPostBatchUpdate(
      signed2.encodedMessages['sensitive.user-id'],
      [],
      [allMembers2[20]],
      witnessUpdInfo2
    );

    // The witnesses are still valid. Proof can be created as above
    verifAccumulator1 = PositiveAccumulator.fromAccumulated(accumulator1.accumulated);
    expect(
      verifAccumulator1.verifyMembershipWitness(
        signed1.encodedMessages['user-id'],
        accumWitness1,
        accumKeypair1.publicKey,
        accumParams1
      )
    ).toEqual(true);

    verifAccumulator2 = PositiveAccumulator.fromAccumulated(accumulator2.accumulated);
    expect(
      verifAccumulator2.verifyMembershipWitness(
        signed2.encodedMessages['sensitive.user-id'],
        accumWitness2,
        accumKeypair2.publicKey,
        accumParams2
      )
    ).toEqual(true);
  });
});
