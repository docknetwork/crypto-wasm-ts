import {
  BoundCheckBppParams,
  BoundCheckBppParamsUncompressed,
  BoundCheckSmcParams,
  BoundCheckSmcParamsUncompressed,
  BoundCheckSmcWithKVProverParamsUncompressed,
  BoundCheckSmcWithKVSetup,
  BoundCheckSmcWithKVVerifierParamsUncompressed,
  CompositeProof,
  createWitnessEqualityMetaStatement,
  Encoder,
  encodeRevealedMsgs,
  getAdaptedSignatureParamsForMessages,
  getIndicesForMsgNames,
  getRevealedAndUnrevealed,
  initializeWasm,
  LegoProvingKeyUncompressed,
  LegoVerifyingKeyUncompressed,
  MetaStatements,
  ProofSpec,
  SetupParam,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../../src';
import { buildWitness, PublicKey, Scheme, SecretKey, SignatureParams } from '../../scheme';
import { checkResult, getBoundCheckSnarkKeys, getParamsAndKeys, stringToBytes } from '../../utils';
import {
  attributes1,
  attributes1Struct,
  attributes2,
  attributes2Struct,
  attributes3,
  attributes3Struct,
  GlobalEncoder
} from './data-and-encoder';
import { checkMapsEqual } from './index';
import { proverStmt, signAndVerify, verifierStmt } from './util';

const loadSnarkSetupFromFiles = true;

let params1: SignatureParams,
  sk1: SecretKey,
  pk1: PublicKey,
  params2: SignatureParams,
  sk2: SecretKey,
  pk2: PublicKey,
  params3: SignatureParams,
  sk3: SecretKey,
  pk3: PublicKey;

let snarkProvingKey: LegoProvingKeyUncompressed, snarkVerifyingKey: LegoVerifyingKeyUncompressed;
let boundCheckBppParams: BoundCheckBppParamsUncompressed;
let boundCheckSmcParams: BoundCheckSmcParamsUncompressed;
let boundCheckSmcKVProverParams: BoundCheckSmcWithKVProverParamsUncompressed;
let boundCheckSmcKVVerifierParams: BoundCheckSmcWithKVVerifierParamsUncompressed;

let signed1, signed2, signed3;

describe(`${Scheme} Range proof using LegoGroth16`, () => {
  beforeAll(async () => {
    // Load the WASM module
    await initializeWasm();

    // 1st signer's setup
    const label1 = stringToBytes('Sig params label 1');
    // Message count shouldn't matter as `label1` is known
    [params1, sk1, pk1] = getParamsAndKeys(100, label1);

    // 2nd signer's setup
    const label2 = stringToBytes('Sig params label 2');
    // Message count shouldn't matter as `label2` is known
    [params2, sk2, pk2] = getParamsAndKeys(100, label2);

    // 3rd signer's setup
    const label3 = stringToBytes('Sig params label 3');
    // Message count shouldn't matter as `label3` is known
    [params3, sk3, pk3] = getParamsAndKeys(100, label3);

    [snarkProvingKey, snarkVerifyingKey] = getBoundCheckSnarkKeys(loadSnarkSetupFromFiles);

    const p = new BoundCheckBppParams(stringToBytes('Bulletproofs++ testing'));
    boundCheckBppParams = p.decompress();
    const p1 = new BoundCheckSmcParams(stringToBytes('set-membership check based range proof testing'));
    boundCheckSmcParams = p1.decompress();
    const p2 = BoundCheckSmcWithKVSetup(
      stringToBytes('set-membership check based range proof with keyed verification testing')
    );
    boundCheckSmcKVProverParams = p2[0].decompress();
    boundCheckSmcKVVerifierParams = p2[1].decompress();

    // Sign and verify all signatures
    signed1 = signAndVerify(attributes1, GlobalEncoder, label1, sk1, pk1);
    signed2 = signAndVerify(attributes2, GlobalEncoder, label2, sk2, pk2);
    signed3 = signAndVerify(attributes3, GlobalEncoder, label3, sk3, pk3);
  });

  function check(
    proverSetupParamGen,
    verifierSetupParamGen,
    pStmt,
    witnessGen,
    vStmt,
    proverParams,
    verifierParams
  ) {
    // This checks that a multiple signatures created by different signers can be verified and proof of knowledge of
    // signatures can be done selective-disclosure while also proving equality between some of the hidden attributes.
    // In addition, it checks that bounds of several attributes can be proven in zero knowledge. Some attributes have negative
    // values, some have decimal and some both

    // The lower and upper bounds of attributes involved in the bound check
    const timeMin = 1662010819619;
    const timeMax = 1662011149654;
    const weightMin = 60;
    const weightMax = 600;

    const heightMin = Encoder.positiveDecimalNumberToPositiveInt(1)(100); // min height is 100
    const heightMax = Encoder.positiveDecimalNumberToPositiveInt(1)(240); // max height is 240
    const bmiMin = Encoder.positiveDecimalNumberToPositiveInt(2)(10); // min BMI is 10
    const bmiMax = Encoder.positiveDecimalNumberToPositiveInt(2)(40); // max BMI is 40

    // min score is -100 and max is 100 and it can have at most 1 decimal place
    const scoreMin = 0;
    const scoreMax = Encoder.decimalNumberToPositiveInt(-100, 1)(100);

    // min lat is -90 and max is 90 and it can have at most 3 decimal places
    const latMin = 0;
    const latMax = Encoder.decimalNumberToPositiveInt(-90, 3)(90);

    // min long is -180 and max is 180 and it can have at most 3 decimal places
    const longMin = 0;
    const longMax = Encoder.decimalNumberToPositiveInt(-180, 3)(180); // (180 + 180)*1000

    // Reveal
    // - first name ("fname" attribute) from all 3 sets of signed attributes
    // - attribute "country" from 1st signed attribute set
    // - attribute "location.country" from 2nd signed attribute set
    // - attributes "lessSensitive.location.country", "lessSensitive.department.name" from 3rd signed attribute set

    // Prove equality in zero knowledge of last name ("lname" attribute), Social security number ("SSN" attribute) and city in all 3 sets of signed attributes

    const revealedNames1 = new Set<string>();
    revealedNames1.add('fname');
    revealedNames1.add('country');

    const revealedNames2 = new Set<string>();
    revealedNames2.add('fname');
    revealedNames2.add('location.country');

    const revealedNames3 = new Set<string>();
    revealedNames3.add('fname');
    revealedNames3.add('lessSensitive.location.country');
    revealedNames3.add('lessSensitive.department.name');

    // Both prover and verifier can independently create this struct
    const sigParams1 = getAdaptedSignatureParamsForMessages(params1, attributes1Struct);
    const sigParams2 = getAdaptedSignatureParamsForMessages(params2, attributes2Struct);
    const sigParams3 = getAdaptedSignatureParamsForMessages(params3, attributes3Struct);

    // Prover needs to do many bound checks with the same verification key
    const proverSetupParams: SetupParam[] = [];
    proverSetupParams.push(proverSetupParamGen(proverParams));

    const [revealedMsgs1, unrevealedMsgs1, revealedMsgsRaw1] = getRevealedAndUnrevealed(
      attributes1,
      revealedNames1,
      GlobalEncoder
    );
    expect(revealedMsgsRaw1).toEqual({ fname: 'John', country: 'USA' });

    const statement1 = proverStmt(
      sigParams1,
      revealedMsgs1,
      pk1,
    );

    const [revealedMsgs2, unrevealedMsgs2, revealedMsgsRaw2] = getRevealedAndUnrevealed(
      attributes2,
      revealedNames2,
      GlobalEncoder
    );
    expect(revealedMsgsRaw2).toEqual({ fname: 'John', location: { country: 'USA' } });

    const statement2 = proverStmt(
      sigParams2,
      revealedMsgs2,
      pk2,
    );

    const [revealedMsgs3, unrevealedMsgs3, revealedMsgsRaw3] = getRevealedAndUnrevealed(
      attributes3,
      revealedNames3,
      GlobalEncoder
    );
    expect(revealedMsgsRaw3).toEqual({
      fname: 'John',
      lessSensitive: {
        location: {
          country: 'USA'
        },
        department: {
          name: 'Random'
        }
      }
    });

    const statement3 = proverStmt(
      sigParams3,
      revealedMsgs3,
      pk3,
    );

    // Construct statements for bound check
    const statement4 = pStmt(timeMin, timeMax, 0);
    const statement5 = pStmt(weightMin, weightMax, 0);
    const statement6 = pStmt(heightMin, heightMax, 0);
    const statement7 = pStmt(bmiMin, bmiMax, 0);
    const statement8 = pStmt(scoreMin, scoreMax, 0);
    const statement9 = pStmt(latMin, latMax, 0);
    const statement10 = pStmt(longMin, longMax, 0);

    const statementsProver = new Statements();
    const sIdx1 = statementsProver.add(statement1);
    const sIdx2 = statementsProver.add(statement2);
    const sIdx3 = statementsProver.add(statement3);
    const sIdx4 = statementsProver.add(statement4);
    const sIdx5 = statementsProver.add(statement5);
    const sIdx6 = statementsProver.add(statement6);
    const sIdx7 = statementsProver.add(statement7);
    const sIdx8 = statementsProver.add(statement8);
    const sIdx9 = statementsProver.add(statement9);
    const sIdx10 = statementsProver.add(statement10);

    // Construct new `MetaStatement`s to enforce attribute equality
    const metaStmtsProver = new MetaStatements();
    const witnessEq1 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx1, [['lname'], attributes1Struct]);
        m.set(sIdx2, [['lname'], attributes2Struct]);
        m.set(sIdx3, [['lname'], attributes3Struct]);
        return m;
      })()
    );

    const witnessEq2 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx1, [['city'], attributes1Struct]);
        m.set(sIdx2, [['location.city'], attributes2Struct]);
        m.set(sIdx3, [['lessSensitive.location.city'], attributes3Struct]);
        return m;
      })()
    );

    const witnessEq3 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx1, [['SSN'], attributes1Struct]);
        m.set(sIdx2, [['sensitive.SSN'], attributes2Struct]);
        m.set(sIdx3, [['sensitive.SSN'], attributes3Struct]);
        return m;
      })()
    );

    const witnessEq4 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx1, [['timeOfBirth'], attributes1Struct]);
        m.set(sIdx2, [['timeOfBirth'], attributes2Struct]);
        return m;
      })()
    );

    const witnessEq5 = new WitnessEqualityMetaStatement();
    witnessEq5.addWitnessRef(sIdx1, getIndicesForMsgNames(['timeOfBirth'], attributes1Struct)[0]);
    witnessEq5.addWitnessRef(sIdx4, 0);

    const witnessEq6 = new WitnessEqualityMetaStatement();
    witnessEq6.addWitnessRef(sIdx1, getIndicesForMsgNames(['weight'], attributes1Struct)[0]);
    witnessEq6.addWitnessRef(sIdx5, 0);

    const witnessEq7 = new WitnessEqualityMetaStatement();
    witnessEq7.addWitnessRef(sIdx1, getIndicesForMsgNames(['height'], attributes1Struct)[0]);
    witnessEq7.addWitnessRef(sIdx6, 0);

    const witnessEq8 = new WitnessEqualityMetaStatement();
    witnessEq8.addWitnessRef(sIdx1, getIndicesForMsgNames(['BMI'], attributes1Struct)[0]);
    witnessEq8.addWitnessRef(sIdx7, 0);

    const witnessEq9 = new WitnessEqualityMetaStatement();
    witnessEq9.addWitnessRef(sIdx1, getIndicesForMsgNames(['score'], attributes1Struct)[0]);
    witnessEq9.addWitnessRef(sIdx8, 0);

    const witnessEq10 = new WitnessEqualityMetaStatement();
    witnessEq10.addWitnessRef(
      sIdx3,
      getIndicesForMsgNames(['lessSensitive.department.location.geo.lat'], attributes3Struct)[0]
    );
    witnessEq10.addWitnessRef(sIdx9, 0);

    const witnessEq11 = new WitnessEqualityMetaStatement();
    witnessEq11.addWitnessRef(
      sIdx3,
      getIndicesForMsgNames(['lessSensitive.department.location.geo.long'], attributes3Struct)[0]
    );
    witnessEq11.addWitnessRef(sIdx10, 0);

    metaStmtsProver.addWitnessEquality(witnessEq1);
    metaStmtsProver.addWitnessEquality(witnessEq2);
    metaStmtsProver.addWitnessEquality(witnessEq3);
    metaStmtsProver.addWitnessEquality(witnessEq4);
    metaStmtsProver.addWitnessEquality(witnessEq5);
    metaStmtsProver.addWitnessEquality(witnessEq6);
    metaStmtsProver.addWitnessEquality(witnessEq7);
    metaStmtsProver.addWitnessEquality(witnessEq8);
    metaStmtsProver.addWitnessEquality(witnessEq9);
    metaStmtsProver.addWitnessEquality(witnessEq10);
    metaStmtsProver.addWitnessEquality(witnessEq11);

    // The prover should independently construct this `ProofSpec`
    const proofSpecProver = new ProofSpec(statementsProver, metaStmtsProver, proverSetupParams);
    expect(proofSpecProver.isValid()).toEqual(true);

    const witness1 = buildWitness(signed1.signature, unrevealedMsgs1, false);
    const witness2 = buildWitness(signed2.signature, unrevealedMsgs2, false);
    const witness3 = buildWitness(signed3.signature, unrevealedMsgs3, false);

    const witnesses = new Witnesses([].concat(witness1, witness2, witness3));

    witnesses.add(witnessGen(signed1.encodedMessages['timeOfBirth']));
    witnesses.add(witnessGen(signed1.encodedMessages['weight']));
    witnesses.add(witnessGen(signed1.encodedMessages['height']));
    witnesses.add(witnessGen(signed1.encodedMessages['BMI']));
    witnesses.add(witnessGen(signed1.encodedMessages['score']));
    witnesses.add(witnessGen(signed3.encodedMessages['lessSensitive.department.location.geo.lat']));
    witnesses.add(witnessGen(signed3.encodedMessages['lessSensitive.department.location.geo.long']));

    const proof = CompositeProof.generate(proofSpecProver, witnesses);

    const verifierSetupParams: SetupParam[] = [];
    verifierSetupParams.push(verifierSetupParamGen(verifierParams));

    // Verifier independently encodes revealed messages
    const revealedMsgs1FromVerifier = encodeRevealedMsgs(revealedMsgsRaw1, attributes1Struct, GlobalEncoder);
    checkMapsEqual(revealedMsgs1, revealedMsgs1FromVerifier);
    const revealedMsgs2FromVerifier = encodeRevealedMsgs(revealedMsgsRaw2, attributes2Struct, GlobalEncoder);
    checkMapsEqual(revealedMsgs2, revealedMsgs2FromVerifier);
    const revealedMsgs3FromVerifier = encodeRevealedMsgs(revealedMsgsRaw3, attributes3Struct, GlobalEncoder);
    checkMapsEqual(revealedMsgs3, revealedMsgs3FromVerifier);

    const statement11 = verifierStmt(sigParams1, revealedMsgs1FromVerifier, pk1);
    const statement12 = verifierStmt(sigParams2, revealedMsgs2FromVerifier, pk2);
    const statement13 = verifierStmt(sigParams3, revealedMsgs3FromVerifier, pk3);

    // Construct statements for bound check
    const statement14 = vStmt(timeMin, timeMax, 0);
    const statement15 = vStmt(weightMin, weightMax, 0);
    const statement16 = vStmt(heightMin, heightMax, 0);
    const statement17 = vStmt(bmiMin, bmiMax, 0);
    const statement18 = vStmt(scoreMin, scoreMax, 0);
    const statement19 = vStmt(latMin, latMax, 0);
    const statement20 = vStmt(longMin, longMax, 0);

    const statementsVerifier = new Statements();
    const sIdx11 = statementsVerifier.add(statement11);
    const sIdx12 = statementsVerifier.add(statement12);
    const sIdx13 = statementsVerifier.add(statement13);
    const sIdx14 = statementsVerifier.add(statement14);
    const sIdx15 = statementsVerifier.add(statement15);
    const sIdx16 = statementsVerifier.add(statement16);
    const sIdx17 = statementsVerifier.add(statement17);
    const sIdx18 = statementsVerifier.add(statement18);
    const sIdx19 = statementsVerifier.add(statement19);
    const sIdx20 = statementsVerifier.add(statement20);

    const metaStmtsVerifier = new MetaStatements();
    const witnessEq12 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx11, [['lname'], attributes1Struct]);
        m.set(sIdx12, [['lname'], attributes2Struct]);
        m.set(sIdx13, [['lname'], attributes3Struct]);
        return m;
      })()
    );

    const witnessEq13 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx11, [['city'], attributes1Struct]);
        m.set(sIdx12, [['location.city'], attributes2Struct]);
        m.set(sIdx13, [['lessSensitive.location.city'], attributes3Struct]);
        return m;
      })()
    );

    const witnessEq14 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx11, [['SSN'], attributes1Struct]);
        m.set(sIdx12, [['sensitive.SSN'], attributes2Struct]);
        m.set(sIdx13, [['sensitive.SSN'], attributes3Struct]);
        return m;
      })()
    );

    const witnessEq15 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx11, [['timeOfBirth'], attributes1Struct]);
        m.set(sIdx12, [['timeOfBirth'], attributes2Struct]);
        return m;
      })()
    );

    const witnessEq16 = new WitnessEqualityMetaStatement();
    witnessEq16.addWitnessRef(sIdx11, getIndicesForMsgNames(['timeOfBirth'], attributes1Struct)[0]);
    witnessEq16.addWitnessRef(sIdx14, 0);

    const witnessEq17 = new WitnessEqualityMetaStatement();
    witnessEq17.addWitnessRef(sIdx11, getIndicesForMsgNames(['weight'], attributes1Struct)[0]);
    witnessEq17.addWitnessRef(sIdx15, 0);

    const witnessEq18 = new WitnessEqualityMetaStatement();
    witnessEq18.addWitnessRef(sIdx11, getIndicesForMsgNames(['height'], attributes1Struct)[0]);
    witnessEq18.addWitnessRef(sIdx16, 0);

    const witnessEq19 = new WitnessEqualityMetaStatement();
    witnessEq19.addWitnessRef(sIdx11, getIndicesForMsgNames(['BMI'], attributes1Struct)[0]);
    witnessEq19.addWitnessRef(sIdx17, 0);

    const witnessEq20 = new WitnessEqualityMetaStatement();
    witnessEq20.addWitnessRef(sIdx11, getIndicesForMsgNames(['score'], attributes1Struct)[0]);
    witnessEq20.addWitnessRef(sIdx18, 0);

    const witnessEq21 = new WitnessEqualityMetaStatement();
    witnessEq21.addWitnessRef(
      sIdx13,
      getIndicesForMsgNames(['lessSensitive.department.location.geo.lat'], attributes3Struct)[0]
    );
    witnessEq21.addWitnessRef(sIdx19, 0);

    const witnessEq22 = new WitnessEqualityMetaStatement();
    witnessEq22.addWitnessRef(
      sIdx13,
      getIndicesForMsgNames(['lessSensitive.department.location.geo.long'], attributes3Struct)[0]
    );
    witnessEq22.addWitnessRef(sIdx20, 0);

    metaStmtsVerifier.addWitnessEquality(witnessEq12);
    metaStmtsVerifier.addWitnessEquality(witnessEq13);
    metaStmtsVerifier.addWitnessEquality(witnessEq14);
    metaStmtsVerifier.addWitnessEquality(witnessEq15);
    metaStmtsVerifier.addWitnessEquality(witnessEq16);
    metaStmtsVerifier.addWitnessEquality(witnessEq17);
    metaStmtsVerifier.addWitnessEquality(witnessEq18);
    metaStmtsVerifier.addWitnessEquality(witnessEq19);
    metaStmtsVerifier.addWitnessEquality(witnessEq20);
    metaStmtsVerifier.addWitnessEquality(witnessEq21);
    metaStmtsVerifier.addWitnessEquality(witnessEq22);

    // The verifier should independently construct this `ProofSpec`
    const proofSpecVerifier = new ProofSpec(statementsVerifier, metaStmtsVerifier, verifierSetupParams);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    checkResult(proof.verify(proofSpecVerifier));
  }

  it('signing and proof of knowledge of signatures and range proofs - using LegoGroth16', () => {
    check(
      SetupParam.legosnarkProvingKeyUncompressed,
      SetupParam.legosnarkVerifyingKeyUncompressed,
      Statement.boundCheckLegoProverFromSetupParamRefs,
      Witness.boundCheckLegoGroth16,
      Statement.boundCheckLegoVerifierFromSetupParamRefs,
      snarkProvingKey,
      snarkVerifyingKey
    );
  });

  it('signing and proof of knowledge of signatures and range proofs - using Bulletproofs++', () => {
    check(
      SetupParam.bppSetupParamsUncompressed,
      SetupParam.bppSetupParamsUncompressed,
      Statement.boundCheckBppFromSetupParamRefs,
      Witness.boundCheckBpp,
      Statement.boundCheckBppFromSetupParamRefs,
      boundCheckBppParams,
      boundCheckBppParams
    );
  });

  it('signing and proof of knowledge of signatures and range proofs - using set membership check', () => {
    check(
      SetupParam.smcSetupParamsUncompressed,
      SetupParam.smcSetupParamsUncompressed,
      Statement.boundCheckSmcFromSetupParamRefs,
      Witness.boundCheckSmc,
      Statement.boundCheckSmcFromSetupParamRefs,
      boundCheckSmcParams,
      boundCheckSmcParams
    );
  });

  it('signing and proof of knowledge of signatures and range proofs - using set membership check with keyed verification', () => {
    check(
      SetupParam.smcSetupParamsKVUncompressed,
      SetupParam.smcSetupParamsKVWithSkUncompressed,
      Statement.boundCheckSmcWithKVProverFromSetupParamRefs,
      Witness.boundCheckSmcWithKV,
      Statement.boundCheckSmcWithKVVerifierFromSetupParamRefs,
      boundCheckSmcKVProverParams,
      boundCheckSmcKVVerifierParams
    );
  });
});
