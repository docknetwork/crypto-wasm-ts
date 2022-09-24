import { generateFieldElementFromNumber, initializeWasm } from '@docknetwork/crypto-wasm';
import { checkResult, getWasmBytes, parseR1CSFile, stringToBytes } from '../../../utils';
import {
  BBSPlusPublicKeyG2,
  CircomInputs,
  CompositeProofG1,
  EncodeFunc,
  Encoder,
  encodeRevealedMsgs,
  getIndicesForMsgNames,
  getRevealedAndUnrevealed,
  getSigParamsForMsgStructure,
  KeypairG2,
  LegoProvingKeyUncompressed,
  LegoVerifyingKeyUncompressed,
  MetaStatements,
  ParsedR1CSFile,
  ProofSpecG1,
  R1CSSnarkSetup,
  SetupParam,
  SignatureParamsG1,
  SignedMessages,
  signMessageObject,
  Statement,
  Statements,
  verifyMessageObject,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../../../src';
import { checkMapsEqual, defaultEncoder } from '../index';

// Test for a scenario where a user wants to prove that he has 10 receipts where:
// 1. all are unique because they have different ids
// 2. all were issued after a certain date
// 3. all have amounts greater than 1000
// This test shows using multiple instances of different circuits
describe('Proving the possession of 10 unique receipts, with each recent enough and over a 1000', () => {
  let encoder: Encoder;

  // Amount on each receipt should be greater than this
  const minAmount = 1000;
  // Date (seconds from epoch) on each receipt should be greater than this
  const minDate = 1663525800;

  let minAmountEncoded: Uint8Array;
  let minDateEncoded: Uint8Array;

  const label = stringToBytes('Sig params label');
  let sigPk: BBSPlusPublicKeyG2;

  let r1csForUnique: ParsedR1CSFile, wasmForUnique: Uint8Array;
  let r1csForGreaterThan: ParsedR1CSFile, wasmForGreaterThan: Uint8Array;

  let provingKeyForUniqueness: LegoProvingKeyUncompressed, verifyingKeyForUniqueness: LegoVerifyingKeyUncompressed;
  let provingKeyForGreaterThan: LegoProvingKeyUncompressed, verifyingKeyForGreaterThan: LegoVerifyingKeyUncompressed;

  // Structure of receipt
  const receiptAttributesStruct = {
    id: undefined,
    date: undefined,
    posId: undefined,
    amount: undefined,
    otherDetails: undefined
  };

  // There are 10 receipts in total
  const numReceipts = 10;
  const receiptsAttributes: object[] = [];
  const signed: SignedMessages[] = [];


  beforeAll(async () => {
    await initializeWasm();

    // Setup encoder
    const encoders = new Map<string, EncodeFunc>();
    encoders.set('date', Encoder.positiveIntegerEncoder());
    encoders.set('amount', Encoder.positiveDecimalNumberEncoder(2));
    encoder = new Encoder(encoders, defaultEncoder);
    minAmountEncoded = encoder.encodeMessage('amount', minAmount);
    minDateEncoded = encoder.encodeMessage('date', minDate);

    // This should ideally be done by the verifier but the verifier can publish only the Circom program and
    // prover can check that the same R1CS and WASM are generated.
    r1csForUnique = await parseR1CSFile('all_different_10.r1cs');
    wasmForUnique = getWasmBytes('all_different_10.wasm');

    r1csForGreaterThan = await parseR1CSFile('greater_than_public_64.r1cs');
    wasmForGreaterThan = getWasmBytes('greater_than_public_64.wasm');
  });

  it('verifier generates SNARk proving and verifying keys for both circuits', async () => {
    // There are 10 private inputs to this circuit
    const pk1 = R1CSSnarkSetup.fromParsedR1CSFile(r1csForUnique, 10);
    provingKeyForUniqueness = pk1.decompress();
    verifyingKeyForUniqueness = pk1.getVerifyingKeyUncompressed();

    // There is 1 private inputs to this circuit
    const pk2 = R1CSSnarkSetup.fromParsedR1CSFile(r1csForGreaterThan, 1);
    provingKeyForGreaterThan = pk2.decompress();
    verifyingKeyForGreaterThan = pk2.getVerifyingKeyUncompressed();
  });

  it('signers signs attributes', () => {
    // Message count shouldn't matter as `label` is known
    let params = SignatureParamsG1.generate(1, label);
    const keypair = KeypairG2.generate(params);
    const sk = keypair.secretKey;
    sigPk = keypair.publicKey;

    for (let i = 0; i < numReceipts; i++) {
      receiptsAttributes.push({
        id: 'e-123-987-1-22-' + (i + 1).toString(), // Unique id for each receipt
        date: minDate + 1000*(i+1),
        posId: '1234567',
        amount: minAmount + Math.ceil(Math.random() * 100),
        otherDetails: Math.random().toString(36).slice(2, 20),  // https://stackoverflow.com/a/38622545
      });
      signed.push(signMessageObject(receiptsAttributes[i], sk, label, encoder));
      expect(verifyMessageObject(receiptsAttributes[i], signed[i].signature, sigPk, label, encoder)).toBe(true);
    }
  });

  it('proof verifies when all receipt ids are different', () => {
    const ids = new Set<string>();
    for (let i = 0; i < numReceipts; i++) {
      // @ts-ignore
      ids.add(receiptsAttributes[i].id);
      //
      expect(receiptsAttributes[i]['amount'] > minAmount);
      expect(receiptsAttributes[i]['date'] > minDate);
    }
    // Check that receipt ids are indeed different
    expect(ids.size).toEqual(numReceipts);



    // Reveal "posId" attribute in all 10 receipts

    const revealedNames = new Set<string>();
    revealedNames.add('posId');

    const sigParams = getSigParamsForMsgStructure(receiptAttributesStruct, label);

    const revealedMsgs: Map<number, Uint8Array>[] = [];
    const unrevealedMsgs: Map<number, Uint8Array>[] = [];
    const revealedMsgsRaw: object[] = [];

    for (let i = 0; i < numReceipts; i++) {
      const [r, u, rRaw] = getRevealedAndUnrevealed(receiptsAttributes[i], revealedNames, encoder);
      revealedMsgs.push(r);
      unrevealedMsgs.push(u);
      revealedMsgsRaw.push(rRaw);
      expect(rRaw).toEqual({ posId: '1234567' });
    }

    const proverSetupParams: SetupParam[] = [];
    // Setup params for the BBS+ signaure
    proverSetupParams.push(SetupParam.bbsSignatureParamsG1(sigParams));
    proverSetupParams.push(SetupParam.bbsSignaturePublicKeyG2(sigPk));
    // Setup params for the uniqueness check SNARK
    proverSetupParams.push(SetupParam.r1cs(r1csForUnique));
    proverSetupParams.push(SetupParam.bytes(wasmForUnique));
    proverSetupParams.push(SetupParam.legosnarkProvingKeyUncompressed(provingKeyForUniqueness));
    // Setup params for the greater than check SNARK
    proverSetupParams.push(SetupParam.r1cs(r1csForGreaterThan));
    proverSetupParams.push(SetupParam.bytes(wasmForGreaterThan));
    proverSetupParams.push(SetupParam.legosnarkProvingKeyUncompressed(provingKeyForGreaterThan));

    const statementsProver = new Statements();

    // 1 statement for proving knowledge of 1 signature (receipt)
    const sIdxs: number[] = [];
    for (let i = 0; i < numReceipts; i++) {
      sIdxs.push(statementsProver.add(Statement.bbsSignatureFromSetupParamRefs(0, 1, revealedMsgs[i], false)));
    }

    // Statement to prove uniqueness of all receipt-ids
    sIdxs.push(statementsProver.add(Statement.r1csCircomProverFromSetupParamRefs(2, 3, 4)));

    // Creating 2 statements for greater than check, one for amount and other for date of each receipt
    for (let i = 0; i < numReceipts; i++) {
      // For greater than check on amount
      sIdxs.push(statementsProver.add(Statement.r1csCircomProverFromSetupParamRefs(5, 6, 7)));
      // For greater than check on date
      sIdxs.push(statementsProver.add(Statement.r1csCircomProverFromSetupParamRefs(5, 6, 7)));
    }

    const metaStmtsProver = new MetaStatements();

    for (let i = 0; i < numReceipts; i++) {
      // he input to the uniqueness check circuit should match the signed `id` attribute
      const witnessEq1 = new WitnessEqualityMetaStatement();
      witnessEq1.addWitnessRef(sIdxs[i], getIndicesForMsgNames(['id'], receiptAttributesStruct)[0]);
      witnessEq1.addWitnessRef(sIdxs[numReceipts], i);
      metaStmtsProver.addWitnessEquality(witnessEq1);

      // The input to the greater than check circuit should match the signed "amount" attribute.
      const witnessEq2 = new WitnessEqualityMetaStatement();
      witnessEq2.addWitnessRef(sIdxs[i], getIndicesForMsgNames(['amount'], receiptAttributesStruct)[0]);
      witnessEq2.addWitnessRef(sIdxs[numReceipts + (i * 2) + 1], 0);
      metaStmtsProver.addWitnessEquality(witnessEq2);

      // The input to the greater than check circuit should match the signed "date" attribute.
      const witnessEq3 = new WitnessEqualityMetaStatement();
      witnessEq3.addWitnessRef(sIdxs[i], getIndicesForMsgNames(['date'], receiptAttributesStruct)[0]);
      witnessEq3.addWitnessRef(sIdxs[numReceipts + (i * 2) + 2], 0);
      metaStmtsProver.addWitnessEquality(witnessEq3);
    }

    const proofSpecProver = new ProofSpecG1(statementsProver, metaStmtsProver, proverSetupParams);
    expect(proofSpecProver.isValid()).toEqual(true);

    const witnesses = new Witnesses();
    for (let i = 0; i < numReceipts; i++) {
      witnesses.add(Witness.bbsSignature(signed[i].signature, unrevealedMsgs[i], false));
    }

    const inputs1 = new CircomInputs();
    // Add each id as the circuit input
    inputs1.setPrivateArrayInput(
      'in',
      signed.map((s) => s.encodedMessages['id'])
    );
    witnesses.add(Witness.r1csCircomWitness(inputs1));

    for (let i = 0; i < numReceipts; i++) {
      const inputs2 = new CircomInputs();
      // Add each amount as the circuit input
      inputs2.setPrivateInput(
        'a',
        signed[i].encodedMessages['amount']
      );
      inputs2.setPublicInput('b', minAmountEncoded);
      witnesses.add(Witness.r1csCircomWitness(inputs2));

      const inputs3 = new CircomInputs();
      // Add each date as the circuit input
      inputs3.setPrivateInput(
        'a',
        signed[i].encodedMessages['date']
      );
      inputs3.setPublicInput('b', minDateEncoded);
      witnesses.add(Witness.r1csCircomWitness(inputs3));
    }

    const proof = CompositeProofG1.generate(proofSpecProver, witnesses);

    // Verifier independently encodes revealed messages
    const revealedMsgsFromVerifier: Map<number, Uint8Array>[] = [];
    for (let i = 0; i < numReceipts; i++) {
      revealedMsgsFromVerifier.push(encodeRevealedMsgs(revealedMsgsRaw[i], receiptAttributesStruct, encoder));
      checkMapsEqual(revealedMsgs[i], revealedMsgsFromVerifier[i]);
    }

    const verifierSetupParams: SetupParam[] = [];
    verifierSetupParams.push(SetupParam.bbsSignatureParamsG1(sigParams));
    verifierSetupParams.push(SetupParam.bbsSignaturePublicKeyG2(sigPk));
    // generateFieldElementFromNumber(1) as uniqueness check passes, i.e. all ids are different
    verifierSetupParams.push(SetupParam.fieldElementVec([generateFieldElementFromNumber(1)]));
    verifierSetupParams.push(SetupParam.legosnarkVerifyingKeyUncompressed(verifyingKeyForUniqueness));
    // generateFieldElementFromNumber(1) as greater than check involving amount attribute passes
    verifierSetupParams.push(SetupParam.fieldElementVec([generateFieldElementFromNumber(1), minAmountEncoded]));
    // generateFieldElementFromNumber(1) as greater than check involving date attribute passes
    verifierSetupParams.push(SetupParam.fieldElementVec([generateFieldElementFromNumber(1), minDateEncoded]));
    verifierSetupParams.push(SetupParam.legosnarkVerifyingKeyUncompressed(verifyingKeyForGreaterThan));

    const statementsVerifier = new Statements();

    const sIdxVs: number[] = [];
    for (let i = 0; i < numReceipts; i++) {
      sIdxVs.push(
        statementsVerifier.add(Statement.bbsSignatureFromSetupParamRefs(0, 1, revealedMsgsFromVerifier[i], false))
      );
    }

    sIdxVs.push(statementsVerifier.add(Statement.r1csCircomVerifierFromSetupParamRefs(2, 3)));

    for (let i = 0; i < numReceipts; i++) {
      sIdxVs.push(statementsVerifier.add(Statement.r1csCircomVerifierFromSetupParamRefs(4, 6)));
      sIdxVs.push(statementsVerifier.add(Statement.r1csCircomVerifierFromSetupParamRefs(5, 6)));
    }

    const metaStmtsVerifier = new MetaStatements();

    for (let i = 0; i < numReceipts; i++) {
      const witnessEq1 = new WitnessEqualityMetaStatement();
      witnessEq1.addWitnessRef(sIdxVs[i], getIndicesForMsgNames(['id'], receiptAttributesStruct)[0]);
      witnessEq1.addWitnessRef(sIdxVs[numReceipts], i);
      metaStmtsVerifier.addWitnessEquality(witnessEq1);

      const witnessEq2 = new WitnessEqualityMetaStatement();
      witnessEq2.addWitnessRef(sIdxVs[i], getIndicesForMsgNames(['amount'], receiptAttributesStruct)[0]);
      witnessEq2.addWitnessRef(sIdxVs[numReceipts + (i * 2) + 1], 0);
      metaStmtsVerifier.addWitnessEquality(witnessEq2);

      const witnessEq3 = new WitnessEqualityMetaStatement();
      witnessEq3.addWitnessRef(sIdxVs[i], getIndicesForMsgNames(['date'], receiptAttributesStruct)[0]);
      witnessEq3.addWitnessRef(sIdxVs[numReceipts + (i * 2) + 2], 0);
      metaStmtsVerifier.addWitnessEquality(witnessEq3);
    }

    const proofSpecVerifier = new ProofSpecG1(statementsVerifier, metaStmtsVerifier, verifierSetupParams);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    checkResult(proof.verify(proofSpecVerifier));
  }, 60000);
});
