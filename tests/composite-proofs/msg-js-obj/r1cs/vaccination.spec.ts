import { generateFieldElementFromNumber, initializeWasm } from '@docknetwork/crypto-wasm';
import { checkResult, getWasmBytes, parseR1CSFile, stringToBytes } from '../../../utils';
import {
  BBSPlusPublicKeyG2,
  BBSPlusSecretKey,
  CircomInputs,
  CompositeProofG1,
  createWitnessEqualityMetaStatement,
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
import { checkMapsEqual } from '../index';
import { defaultEncoder } from '../data-and-encoder';

// Test for a scenario where a user wants to prove that he either got the vaccination less than 30 days ago or got
// tested negative less than 2 days ago but does not reveal when these events happened or which of these conditions is true.
describe('Proving that either vaccinated less than 30 days ago OR last checked negative less than 2 days ago', () => {
  let encoder: Encoder;

  const label = stringToBytes('Sig params label');
  let sigPk: BBSPlusPublicKeyG2;
  let sigSk: BBSPlusSecretKey;

  const secondsInADay = 24 * 60 * 60;
  // Time in seconds as of now
  const now = 1663525800;
  const time30DaysAgo = now - 30 * secondsInADay;
  const time2DaysAgo = now - 2 * secondsInADay;

  let encodedNow: Uint8Array;
  let encodedTime30DaysAgo: Uint8Array;
  let encodedTime2DaysAgo: Uint8Array;

  let r1cs: ParsedR1CSFile;
  let wasm: Uint8Array;

  let provingKey: LegoProvingKeyUncompressed, verifyingKey: LegoVerifyingKeyUncompressed;

  const vaccinationAttributesStruct = {
    fname: null,
    lname: null,
    sensitive: {
      email: null,
      SSN: null
    },
    vaccination: {
      date: null,
      name: null
    }
  };

  const diseaseTestAttributesStruct = {
    fname: null,
    lname: null,
    sensitive: {
      email: null,
      SSN: null
    },
    test: {
      date: null,
      type: null,
      result: null
    }
  };

  const vaccinationAttributes = {
    fname: 'John',
    lname: 'Smith',
    sensitive: {
      email: 'john.smith@example.com',
      SSN: '123-456789-0'
    },
    vaccination: {
      date: 1663525800,
      name: 'Moderna'
    }
  };

  const diseaseTestAttributes = {
    fname: 'John',
    lname: 'Smith',
    sensitive: {
      email: 'john.smith@example.com',
      SSN: '123-456789-0'
    },
    test: {
      date: 1663525800,
      type: 'Antigen',
      result: 'Negative'
    }
  };

  function sign(vDays: number, tDays: number): [SignedMessages, SignedMessages] {
    vaccinationAttributes.vaccination.date = now - vDays * secondsInADay;
    diseaseTestAttributes.test.date = now - tDays * secondsInADay;
    const signedV = signMessageObject(vaccinationAttributes, sigSk, label, encoder);
    checkResult(verifyMessageObject(vaccinationAttributes, signedV.signature, sigPk, label, encoder));
    const signedT = signMessageObject(diseaseTestAttributes, sigSk, label, encoder);
    checkResult(verifyMessageObject(diseaseTestAttributes, signedT.signature, sigPk, label, encoder));
    return [signedV, signedT];
  }

  beforeAll(async () => {
    await initializeWasm();

    // Setup encoder
    const dateEncoder = Encoder.positiveIntegerEncoder();
    const encoders = new Map<string, EncodeFunc>();
    encoders.set('vaccination.date', dateEncoder);
    encoders.set('test.date', dateEncoder);
    encoder = new Encoder(encoders, defaultEncoder);

    encodedNow = dateEncoder(now);
    encodedTime30DaysAgo = dateEncoder(time30DaysAgo);
    encodedTime2DaysAgo = dateEncoder(time2DaysAgo);

    // This should ideally be done by the verifier but the verifier can publish only the Circom program and
    // prover can check that the same R1CS and WASM are generated.
    r1cs = await parseR1CSFile('greater_than_or_public_64.r1cs');
    wasm = getWasmBytes('greater_than_or_public_64.wasm');

    // Message count shouldn't matter as `label` is known
    let params = SignatureParamsG1.generate(1, label);
    const keypair = KeypairG2.generate(params);
    sigSk = keypair.secretKey;
    sigPk = keypair.publicKey;
  });

  it('verifier generates SNARk proving and verifying key', async () => {
    const pk = R1CSSnarkSetup.fromParsedR1CSFile(r1cs, 2);
    provingKey = pk.decompress();
    verifyingKey = pk.getVerifyingKeyUncompressed();
  });

  function check(
    vaccinationAttributesSigned: SignedMessages,
    testAttributesSigned: SignedMessages,
    checkShouldPass: boolean
  ) {
    const revealedNamesV = new Set<string>();
    revealedNamesV.add('fname');
    revealedNamesV.add('vaccination.name');

    const sigParamsV = getSigParamsForMsgStructure(vaccinationAttributesStruct, label);
    const [revealedMsgsV, unrevealedMsgsV, revealedMsgsRawV] = getRevealedAndUnrevealed(
      vaccinationAttributes,
      revealedNamesV,
      encoder
    );
    expect(revealedMsgsRawV).toEqual({ fname: 'John', vaccination: { name: 'Moderna' } });

    const revealedNamesT = new Set<string>();
    revealedNamesT.add('fname');
    revealedNamesT.add('test.type');
    revealedNamesT.add('test.result');

    const sigParamsT = getSigParamsForMsgStructure(diseaseTestAttributesStruct, label);
    const [revealedMsgsT, unrevealedMsgsT, revealedMsgsRawT] = getRevealedAndUnrevealed(
      diseaseTestAttributes,
      revealedNamesT,
      encoder
    );
    expect(revealedMsgsRawT).toEqual({ fname: 'John', test: { type: 'Antigen', result: 'Negative' } });

    const statement1 = Statement.bbsSignature(sigParamsV, sigPk, revealedMsgsV, false);
    const statement2 = Statement.bbsSignature(sigParamsT, sigPk, revealedMsgsT, false);
    const statement3 = Statement.r1csCircomProver(r1cs, wasm, provingKey);

    const statementsProver = new Statements();
    const sIdx1 = statementsProver.add(statement1);
    const sIdx2 = statementsProver.add(statement2);
    const sIdx3 = statementsProver.add(statement3);

    const metaStmtsProver = new MetaStatements();

    const witnessEq1 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx1, [['sensitive.SSN'], vaccinationAttributesStruct]);
        m.set(sIdx2, [['sensitive.SSN'], diseaseTestAttributesStruct]);
        return m;
      })()
    );

    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(sIdx1, getIndicesForMsgNames(['vaccination.date'], vaccinationAttributesStruct)[0]);
    witnessEq2.addWitnessRef(sIdx3, 0);

    const witnessEq3 = new WitnessEqualityMetaStatement();
    witnessEq3.addWitnessRef(sIdx2, getIndicesForMsgNames(['test.date'], diseaseTestAttributesStruct)[0]);
    witnessEq3.addWitnessRef(sIdx3, 1);

    metaStmtsProver.addWitnessEquality(witnessEq1);
    metaStmtsProver.addWitnessEquality(witnessEq2);
    metaStmtsProver.addWitnessEquality(witnessEq3);

    const proofSpecProver = new ProofSpecG1(statementsProver, metaStmtsProver);
    expect(proofSpecProver.isValid()).toEqual(true);

    const witnesses = new Witnesses();
    witnesses.add(Witness.bbsSignature(vaccinationAttributesSigned.signature, unrevealedMsgsV, false));
    witnesses.add(Witness.bbsSignature(testAttributesSigned.signature, unrevealedMsgsT, false));

    const inputs = new CircomInputs();
    inputs.setPrivateInput('in1', vaccinationAttributesSigned.encodedMessages['vaccination.date']);
    inputs.setPrivateInput('in2', testAttributesSigned.encodedMessages['test.date']);
    inputs.setPublicInput('in3', encodedTime30DaysAgo);
    inputs.setPublicInput('in4', encodedTime2DaysAgo);
    witnesses.add(Witness.r1csCircomWitness(inputs));

    const proof = CompositeProofG1.generate(proofSpecProver, witnesses);

    const revealedMsgsFromVerifierV = encodeRevealedMsgs(revealedMsgsRawV, vaccinationAttributesStruct, encoder);
    checkMapsEqual(revealedMsgsV, revealedMsgsFromVerifierV);

    const revealedMsgsFromVerifierT = encodeRevealedMsgs(revealedMsgsRawT, diseaseTestAttributesStruct, encoder);
    checkMapsEqual(revealedMsgsT, revealedMsgsFromVerifierT);

    const statement4 = Statement.bbsSignature(sigParamsV, sigPk, revealedMsgsFromVerifierV, false);
    const statement5 = Statement.bbsSignature(sigParamsT, sigPk, revealedMsgsFromVerifierT, false);
    const pub = [generateFieldElementFromNumber(checkShouldPass ? 1 : 0), encodedTime30DaysAgo, encodedTime2DaysAgo];
    const statement6 = Statement.r1csCircomVerifier(pub, verifyingKey);

    const statementsVerifier = new Statements();
    const sIdx4 = statementsVerifier.add(statement4);
    const sIdx5 = statementsVerifier.add(statement5);
    const sIdx6 = statementsVerifier.add(statement6);

    const metaStmtsVerifier = new MetaStatements();

    const witnessEq4 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx4, [['sensitive.SSN'], vaccinationAttributesStruct]);
        m.set(sIdx5, [['sensitive.SSN'], diseaseTestAttributesStruct]);
        return m;
      })()
    );

    const witnessEq5 = new WitnessEqualityMetaStatement();
    witnessEq5.addWitnessRef(sIdx4, getIndicesForMsgNames(['vaccination.date'], vaccinationAttributesStruct)[0]);
    witnessEq5.addWitnessRef(sIdx6, 0);

    const witnessEq6 = new WitnessEqualityMetaStatement();
    witnessEq6.addWitnessRef(sIdx5, getIndicesForMsgNames(['test.date'], diseaseTestAttributesStruct)[0]);
    witnessEq6.addWitnessRef(sIdx6, 1);

    metaStmtsVerifier.addWitnessEquality(witnessEq4);
    metaStmtsVerifier.addWitnessEquality(witnessEq5);
    metaStmtsVerifier.addWitnessEquality(witnessEq6);

    const proofSpecVerifier = new ProofSpecG1(statementsVerifier, metaStmtsVerifier);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    checkResult(proof.verify(proofSpecVerifier));
  }

  it('proof verifies when both vaccination and negative test are recent enough', () => {
    // Set both vaccination date and test date to 25 days and 1 day in the past respectively
    const [vaccinationAttributesSigned, testAttributesSigned] = sign(25, 1);
    check(vaccinationAttributesSigned, testAttributesSigned, true);
  });

  it('proof verifies when vaccination date is recent but negative test is older than required', () => {
    // Set both vaccination date and test date to 25 days and 4 day in the past respectively
    const [vaccinationAttributesSigned, testAttributesSigned] = sign(25, 4);
    check(vaccinationAttributesSigned, testAttributesSigned, true);
  });

  it('proof verifies when vaccination date is older than required but negative test is recent', () => {
    // Set both vaccination date and test date to 31 days and 1 day in the past respectively
    const [vaccinationAttributesSigned, testAttributesSigned] = sign(31, 1);
    check(vaccinationAttributesSigned, testAttributesSigned, true);
  });

  it('proof does not verify successfully when both vaccination date and negative test are older than required', () => {
    // Set both vaccination date and test date to 31 days and 4 day in the past respectively
    const [vaccinationAttributesSigned, testAttributesSigned] = sign(31, 4);
    check(vaccinationAttributesSigned, testAttributesSigned, false);
  });
});
