import { generateFieldElementFromNumber, initializeWasm } from '@docknetwork/crypto-wasm';
import {
  BBSPlusPublicKeyG2,
  BBSPlusSecretKey,
  BoundCheckSnarkSetup,
  CompositeProofG1,
  KeypairG2,
  LegoProvingKeyUncompressed,
  LegoVerifyingKeyUncompressed,
  MetaStatement,
  MetaStatements,
  QuasiProofSpecG1,
  SetupParam,
  SignatureG1,
  SignatureParamsG1,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../src';
import { getRevealedUnrevealed } from '../utils';

describe('Bound check of signed messages', () => {
  const messageCount = 5;
  const msgIdx = 1;
  // All messages will be between 100 and 150
  const min1 = 50,
    min2 = 65,
    max1 = 200,
    max2 = 300,
    min3 = 75,
    max3 = 350,
    min4 = 90,
    max4 = 365;

  let snarkProvingKey: LegoProvingKeyUncompressed, snarkVerifyingKey: LegoVerifyingKeyUncompressed;
  // There are 2 signers
  let sigParams1: SignatureParamsG1,
    sigSk1: BBSPlusSecretKey,
    sigPk1: BBSPlusPublicKeyG2,
    sigParams2: SignatureParamsG1,
    sigSk2: BBSPlusSecretKey,
    sigPk2: BBSPlusPublicKeyG2;
  let messages1: Uint8Array[], messages2: Uint8Array[], sig1: SignatureG1, sig2: SignatureG1;

  beforeAll(async () => {
    await initializeWasm();
  });

  it('do verifier setup', () => {
    const pk = BoundCheckSnarkSetup();
    snarkProvingKey = pk.decompress();
    snarkVerifyingKey = pk.getVerifyingKeyUncompressed();
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
      messages1.push(generateFieldElementFromNumber(100 + i));
      messages2.push(generateFieldElementFromNumber(125 + i));
    }

    sig1 = SignatureG1.generate(messages1, sigSk1, sigParams1, false);
    sig2 = SignatureG1.generate(messages2, sigSk2, sigParams2, false);
    expect(sig1.verify(messages1, sigPk1, sigParams1, false).verified).toEqual(true);
    expect(sig2.verify(messages2, sigPk2, sigParams2, false).verified).toEqual(true);
  });

  it('accept positive integer bounds only', () => {
    expect(() => Statement.boundCheckProver(-6, max1, snarkProvingKey)).toThrow();
    expect(() => Statement.boundCheckProverFromSetupParamRefs(-6, max1, 0)).toThrow();
    expect(() => Statement.boundCheckVerifier(-6, max1, snarkVerifyingKey)).toThrow();
    expect(() => Statement.boundCheckVerifierFromSetupParamRefs(-6, max1, 0)).toThrow();

    expect(() => Statement.boundCheckProver(10.1, max1, snarkProvingKey)).toThrow();
    expect(() => Statement.boundCheckProverFromSetupParamRefs(10.1, max1, 0)).toThrow();
    expect(() => Statement.boundCheckVerifier(10.1, max1, snarkVerifyingKey)).toThrow();
    expect(() => Statement.boundCheckVerifierFromSetupParamRefs(10.1, max1, 0)).toThrow();

    expect(() => Statement.boundCheckProver(10, 20.8, snarkProvingKey)).toThrow();
    expect(() => Statement.boundCheckProverFromSetupParamRefs(10, 20.8, 0)).toThrow();
    expect(() => Statement.boundCheckVerifier(10, 20.8, snarkVerifyingKey)).toThrow();
    expect(() => Statement.boundCheckVerifierFromSetupParamRefs(10, 20.8, 0)).toThrow();

    expect(() => Statement.boundCheckProver(10, -90, snarkProvingKey)).toThrow();
    expect(() => Statement.boundCheckProverFromSetupParamRefs(10, -90, 0)).toThrow();
    expect(() => Statement.boundCheckVerifier(10, -90, snarkVerifyingKey)).toThrow();
    expect(() => Statement.boundCheckVerifierFromSetupParamRefs(10, -90, 0)).toThrow();
  });

  function proveAndVerifySingle(
    sigParams: SignatureParamsG1,
    sigPk: BBSPlusPublicKeyG2,
    messages: Uint8Array[],
    sig: SignatureG1
  ) {
    const revealedIndices = new Set<number>();
    revealedIndices.add(0);
    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(messages, revealedIndices);
    const statement1 = Statement.bbsSignature(sigParams, sigPk, revealedMsgs, false);
    const statement2 = Statement.boundCheckProver(min1, max1, snarkProvingKey);
    const proverStatements = new Statements();
    proverStatements.add(statement1);
    proverStatements.add(statement2);

    const witnessEq = new WitnessEqualityMetaStatement();
    witnessEq.addWitnessRef(0, msgIdx);
    witnessEq.addWitnessRef(1, 0);
    const metaStatements = new MetaStatements();
    metaStatements.add(MetaStatement.witnessEquality(witnessEq));

    const witness1 = Witness.bbsSignature(sig, unrevealedMsgs, false);
    const witness2 = Witness.boundCheckLegoGroth16(messages[msgIdx]);
    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);

    const proverProofSpec = new QuasiProofSpecG1(proverStatements, metaStatements);
    const proof = CompositeProofG1.generateUsingQuasiProofSpec(proverProofSpec, witnesses);

    const statement3 = Statement.boundCheckVerifier(min1, max1, snarkVerifyingKey);
    const verifierStatements = new Statements();
    verifierStatements.add(statement1);
    verifierStatements.add(statement3);

    const verifierProofSpec = new QuasiProofSpecG1(verifierStatements, metaStatements);
    expect(proof.verifyUsingQuasiProofSpec(verifierProofSpec).verified).toEqual(true);
  }

  it('prove knowledge of 1 bounded message from 1st signature', () => {
    proveAndVerifySingle(sigParams1, sigPk1, messages1, sig1);
  }, 20000);

  it('prove knowledge of 1 bounded message from 2nd signature', () => {
    proveAndVerifySingle(sigParams2, sigPk2, messages2, sig2);
  }, 20000);

  it('prove knowledge of 2 bounded messages from both signatures with different bounds for each message', () => {
    const proverSetupParams = [];
    proverSetupParams.push(SetupParam.legosnarkProvingKeyUncompressed(snarkProvingKey));

    const [revealedMsgs1, unrevealedMsgs1] = getRevealedUnrevealed(messages1, new Set<number>());
    const [revealedMsgs2, unrevealedMsgs2] = getRevealedUnrevealed(messages2, new Set<number>());

    const statement1 = Statement.bbsSignature(sigParams1, sigPk1, revealedMsgs1, false);
    const statement2 = Statement.bbsSignature(sigParams2, sigPk2, revealedMsgs2, false);
    const statement3 = Statement.boundCheckProverFromSetupParamRefs(min1, max1, 0);
    const statement4 = Statement.boundCheckProverFromSetupParamRefs(min2, max2, 0);
    const statement5 = Statement.boundCheckProverFromSetupParamRefs(min3, max3, 0);
    const statement6 = Statement.boundCheckProverFromSetupParamRefs(min4, max4, 0);

    const proverStatements = new Statements();
    proverStatements.add(statement1);
    proverStatements.add(statement2);
    proverStatements.add(statement3);
    proverStatements.add(statement4);
    proverStatements.add(statement5);
    proverStatements.add(statement6);

    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(0, msgIdx);
    witnessEq1.addWitnessRef(2, 0);

    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(0, msgIdx + 1);
    witnessEq2.addWitnessRef(3, 0);

    const witnessEq3 = new WitnessEqualityMetaStatement();
    witnessEq3.addWitnessRef(1, msgIdx);
    witnessEq3.addWitnessRef(4, 0);

    const witnessEq4 = new WitnessEqualityMetaStatement();
    witnessEq4.addWitnessRef(1, msgIdx + 1);
    witnessEq4.addWitnessRef(5, 0);

    const metaStatements = new MetaStatements();
    metaStatements.add(MetaStatement.witnessEquality(witnessEq1));
    metaStatements.add(MetaStatement.witnessEquality(witnessEq2));
    metaStatements.add(MetaStatement.witnessEquality(witnessEq3));
    metaStatements.add(MetaStatement.witnessEquality(witnessEq4));

    const witnesses = new Witnesses();
    witnesses.add(Witness.bbsSignature(sig1, unrevealedMsgs1, false));
    witnesses.add(Witness.bbsSignature(sig2, unrevealedMsgs2, false));
    witnesses.add(Witness.boundCheckLegoGroth16(messages1[msgIdx]));
    witnesses.add(Witness.boundCheckLegoGroth16(messages1[msgIdx + 1]));
    witnesses.add(Witness.boundCheckLegoGroth16(messages2[msgIdx]));
    witnesses.add(Witness.boundCheckLegoGroth16(messages2[msgIdx + 1]));

    const proverProofSpec = new QuasiProofSpecG1(proverStatements, metaStatements, proverSetupParams);
    const proof = CompositeProofG1.generateUsingQuasiProofSpec(proverProofSpec, witnesses);

    const verifierSetupParams = [];
    verifierSetupParams.push(SetupParam.legosnarkVerifyingKeyUncompressed(snarkVerifyingKey));

    const statement7 = Statement.boundCheckVerifierFromSetupParamRefs(min1, max1, 0);
    const statement8 = Statement.boundCheckVerifierFromSetupParamRefs(min2, max2, 0);
    const statement9 = Statement.boundCheckVerifierFromSetupParamRefs(min3, max3, 0);
    const statement10 = Statement.boundCheckVerifierFromSetupParamRefs(min4, max4, 0);

    const verifierStatements = new Statements();
    verifierStatements.add(statement1);
    verifierStatements.add(statement2);
    verifierStatements.add(statement7);
    verifierStatements.add(statement8);
    verifierStatements.add(statement9);
    verifierStatements.add(statement10);

    const verifierProofSpec = new QuasiProofSpecG1(verifierStatements, metaStatements, verifierSetupParams);

    expect(proof.verifyUsingQuasiProofSpec(verifierProofSpec).verified).toEqual(true);
  });
});
