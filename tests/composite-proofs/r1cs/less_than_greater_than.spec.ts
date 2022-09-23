import { generateFieldElementFromNumber, initializeWasm } from '@docknetwork/crypto-wasm';
import { checkResult, getRevealedUnrevealed, getWasmBytes, parseR1CSFile, stringToBytes } from '../../utils';
import {
  BBSPlusPublicKeyG2,
  BBSPlusSecretKey,
  CircomInputs,
  CompositeProofG1,
  KeypairG2,
  LegoProvingKeyUncompressed,
  LegoVerifyingKeyUncompressed,
  MetaStatement,
  MetaStatements,
  ParsedR1CSFile,
  QuasiProofSpecG1,
  R1CSSnarkSetup,
  SignatureG1,
  SignatureParamsG1,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../../src';

describe('Proof with R1CS and Circom circuits: less than checks', () => {
  let ltR1cs: ParsedR1CSFile;
  let ltPubR1cs: ParsedR1CSFile;
  let ltWasm: Uint8Array;
  let ltPubWasm: Uint8Array;

  let ltProvingKey: LegoProvingKeyUncompressed, ltVerifyingKey: LegoVerifyingKeyUncompressed;
  let ltPubProvingKey: LegoProvingKeyUncompressed, ltPubVerifyingKey: LegoVerifyingKeyUncompressed;

  // There are 2 signers
  let sigParams1: SignatureParamsG1,
    sigSk1: BBSPlusSecretKey,
    sigPk1: BBSPlusPublicKeyG2,
    sigParams2: SignatureParamsG1,
    sigSk2: BBSPlusSecretKey,
    sigPk2: BBSPlusPublicKeyG2;
  let messages1: Uint8Array[], messages2: Uint8Array[], sig1: SignatureG1, sig2: SignatureG1;

  const messageCount = 5;

  beforeAll(async () => {
    await initializeWasm();

    ltR1cs = await parseR1CSFile('less_than_32.r1cs');
    ltPubR1cs = await parseR1CSFile('less_than_public_64.r1cs');
    ltWasm = getWasmBytes('less_than_32.wasm');
    ltPubWasm = getWasmBytes('less_than_public_64.wasm');
  });

  it('do verifier setup', () => {
    const pk = R1CSSnarkSetup.fromParsedR1CSFile(ltR1cs);
    ltProvingKey = pk.decompress();
    ltVerifyingKey = pk.getVerifyingKeyUncompressed();

    const pk1 = R1CSSnarkSetup.fromParsedR1CSFile(ltPubR1cs);
    ltPubProvingKey = pk1.decompress();
    ltPubVerifyingKey = pk1.getVerifyingKeyUncompressed();
  });

  it('do signers setup', () => {
    sigParams1 = SignatureParamsG1.generate(messageCount);
    const sigKeypair1 = KeypairG2.generate(sigParams1);
    sigSk1 = sigKeypair1.secretKey;
    sigPk1 = sigKeypair1.publicKey;

    sigParams2 = SignatureParamsG1.generate(messageCount);
    const sigKeypair2 = KeypairG2.generate(sigParams2);
    sigSk2 = sigKeypair2.secretKey;
    sigPk2 = sigKeypair2.publicKey;

    messages1 = [];
    messages2 = [];
    for (let i = 0; i < messageCount; i++) {
      messages1.push(generateFieldElementFromNumber(1000 + i));
      messages2.push(generateFieldElementFromNumber(2000 + i));
    }

    sig1 = SignatureG1.generate(messages1, sigSk1, sigParams1, false);
    sig2 = SignatureG1.generate(messages2, sigSk2, sigParams2, false);
    expect(sig1.verify(messages1, sigPk1, sigParams1, false).verified).toEqual(true);
    expect(sig2.verify(messages2, sigPk2, sigParams2, false).verified).toEqual(true);
  });

  function proveAndVerifyLessThan(
    sigParams: SignatureParamsG1,
    sigPk: BBSPlusPublicKeyG2,
    messages: Uint8Array[],
    sig: SignatureG1
  ) {
    const publicMax = generateFieldElementFromNumber(5000);

    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(messages, new Set<number>());
    const statement1 = Statement.bbsSignature(sigParams, sigPk, revealedMsgs, false);
    const statement2 = Statement.r1csCircomProver(ltR1cs, ltWasm, ltProvingKey);
    const statement3 = Statement.r1csCircomProver(ltPubR1cs, ltPubWasm, ltPubProvingKey);

    const proverStatements = new Statements();
    proverStatements.add(statement1);
    proverStatements.add(statement2);
    proverStatements.add(statement3);

    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(0, 1);
    witnessEq1.addWitnessRef(1, 0);

    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(0, 2);
    witnessEq2.addWitnessRef(1, 1);

    const witnessEq3 = new WitnessEqualityMetaStatement();
    witnessEq3.addWitnessRef(0, 2);
    witnessEq3.addWitnessRef(2, 0);

    const metaStatements = new MetaStatements();
    metaStatements.add(MetaStatement.witnessEquality(witnessEq1));
    metaStatements.add(MetaStatement.witnessEquality(witnessEq2));
    metaStatements.add(MetaStatement.witnessEquality(witnessEq3));

    const witness1 = Witness.bbsSignature(sig, unrevealedMsgs, false);

    const inputs1 = new CircomInputs();
    inputs1.setPrivateInput('a', messages[1]);
    inputs1.setPrivateInput('b', messages[2]);
    const witness2 = Witness.r1csCircomWitness(inputs1);

    const inputs2 = new CircomInputs();
    inputs2.setPrivateInput('a', messages[2]);
    inputs2.setPublicInput('b', publicMax);
    const witness3 = Witness.r1csCircomWitness(inputs2);

    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);
    witnesses.add(witness3);

    const proverProofSpec = new QuasiProofSpecG1(proverStatements, metaStatements);

    const proof = CompositeProofG1.generateUsingQuasiProofSpec(proverProofSpec, witnesses);

    const statement4 = Statement.r1csCircomVerifier([generateFieldElementFromNumber(1)], ltVerifyingKey);
    const statement5 = Statement.r1csCircomVerifier([generateFieldElementFromNumber(1), publicMax], ltPubVerifyingKey);

    const verifierStatements = new Statements();
    verifierStatements.add(statement1);
    verifierStatements.add(statement4);
    verifierStatements.add(statement5);

    const verifierProofSpec = new QuasiProofSpecG1(verifierStatements, metaStatements);
    checkResult(proof.verifyUsingQuasiProofSpec(verifierProofSpec));
  }

  it('inputs of the circuit are from 1st signature', () => {
    proveAndVerifyLessThan(sigParams1, sigPk1, messages1, sig1);
  }, 20000);

  it('inputs of the circuit are from 2nd signature', () => {
    proveAndVerifyLessThan(sigParams2, sigPk2, messages2, sig2);
  }, 20000);

  it('inputs of the circuit are in different signatures', () => {
    const [revealedMsgs1, unrevealedMsgs1] = getRevealedUnrevealed(messages1, new Set<number>());
    const [revealedMsgs2, unrevealedMsgs2] = getRevealedUnrevealed(messages2, new Set<number>());

    const statement1 = Statement.bbsSignature(sigParams1, sigPk1, revealedMsgs1, false);
    const statement2 = Statement.bbsSignature(sigParams2, sigPk2, revealedMsgs2, false);

    const statement3 = Statement.r1csCircomProver(ltR1cs, ltWasm, ltProvingKey);

    const proverStatements = new Statements();
    proverStatements.add(statement1);
    proverStatements.add(statement2);
    proverStatements.add(statement3);

    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(0, 2);
    witnessEq1.addWitnessRef(2, 0);

    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(1, 2);
    witnessEq2.addWitnessRef(2, 1);

    const metaStatements = new MetaStatements();
    metaStatements.add(MetaStatement.witnessEquality(witnessEq1));
    metaStatements.add(MetaStatement.witnessEquality(witnessEq2));

    const witness1 = Witness.bbsSignature(sig1, unrevealedMsgs1, false);
    const witness2 = Witness.bbsSignature(sig2, unrevealedMsgs2, false);

    const inputs = new CircomInputs();
    inputs.setPrivateInput('a', messages1[2]);
    inputs.setPrivateInput('b', messages2[2]);
    const witness3 = Witness.r1csCircomWitness(inputs);

    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);
    witnesses.add(witness3);

    const proverProofSpec = new QuasiProofSpecG1(proverStatements, metaStatements);

    const proof = CompositeProofG1.generateUsingQuasiProofSpec(proverProofSpec, witnesses);

    const statement4 = Statement.r1csCircomVerifier([generateFieldElementFromNumber(1)], ltVerifyingKey);

    const verifierStatements = new Statements();
    verifierStatements.add(statement1);
    verifierStatements.add(statement2);
    verifierStatements.add(statement4);

    const verifierProofSpec = new QuasiProofSpecG1(verifierStatements, metaStatements);
    checkResult(proof.verifyUsingQuasiProofSpec(verifierProofSpec));
  });
});
