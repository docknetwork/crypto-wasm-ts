import { initializeWasm } from '@docknetwork/crypto-wasm';
import { checkResult, getBoundCheckSnarkKeys, stringToBytes } from '../../utils';
import {
  CompositeProofG1,
  createWitnessEqualityMetaStatement,
  Encoder,
  encodeRevealedMsgs,
  getAdaptedSignatureParamsForMessages,
  getIndicesForMsgNames,
  getRevealedAndUnrevealed,
  BBSPlusKeypairG2,
  MetaStatements,
  ProofSpecG1,
  SetupParam,
  BBSPlusSignatureParamsG1,
  signMessageObject,
  Statement,
  Statements,
  verifyMessageObject,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../../src';
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

const loadSnarkSetupFromFiles = true;

describe('Range proof using LegoGroth16', () => {
  beforeAll(async () => {
    // Load the WASM module
    await initializeWasm();
  });

  it('signing and proof of knowledge of signatures and range proofs', () => {
    // This test check that a multiple signatures created by different signers can be verified and proof of knowledge of
    // signatures can be done selective-disclosure while also proving equality between some of the hidden attributes.
    // In addition, it checks that bounds of several attributes can be proven in zero knowledge. Some attributes have negative
    // values, some have decimal and some both

    // 1st signer's setup
    const label1 = stringToBytes('Sig params label 1');
    // Message count shouldn't matter as `label1` is known
    let params1 = BBSPlusSignatureParamsG1.generate(1, label1);
    const keypair1 = BBSPlusKeypairG2.generate(params1);
    const sk1 = keypair1.secretKey;
    const pk1 = keypair1.publicKey;

    // 2nd signer's setup
    const label2 = stringToBytes('Sig params label 2');
    // Message count shouldn't matter as `label2` is known
    let params2 = BBSPlusSignatureParamsG1.generate(1, label2);
    const keypair2 = BBSPlusKeypairG2.generate(params2);
    const sk2 = keypair2.secretKey;
    const pk2 = keypair2.publicKey;

    // 3rd signer's setup
    const label3 = stringToBytes('Sig params label 3');
    // Message count shouldn't matter as `label3` is known
    let params3 = BBSPlusSignatureParamsG1.generate(1, label3);
    const keypair3 = BBSPlusKeypairG2.generate(params3);
    const sk3 = keypair3.secretKey;
    const pk3 = keypair3.publicKey;

    // Sign and verify all signatures
    const signed1 = signMessageObject(attributes1, sk1, label1, GlobalEncoder);
    checkResult(verifyMessageObject(attributes1, signed1.signature, pk1, label1, GlobalEncoder));

    const signed2 = signMessageObject(attributes2, sk2, label2, GlobalEncoder);
    checkResult(verifyMessageObject(attributes2, signed2.signature, pk2, label2, GlobalEncoder));

    const signed3 = signMessageObject(attributes3, sk3, label3, GlobalEncoder);
    checkResult(verifyMessageObject(attributes3, signed3.signature, pk3, label3, GlobalEncoder));

    // Verifier creates SNARK proving and verification key
    const [snarkProvingKey, snarkVerifyingKey] = getBoundCheckSnarkKeys(loadSnarkSetupFromFiles);

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
    proverSetupParams.push(SetupParam.legosnarkProvingKeyUncompressed(snarkProvingKey));

    const [revealedMsgs1, unrevealedMsgs1, revealedMsgsRaw1] = getRevealedAndUnrevealed(
      attributes1,
      revealedNames1,
      GlobalEncoder
    );
    expect(revealedMsgsRaw1).toEqual({ fname: 'John', country: 'USA' });

    const statement1 = Statement.bbsPlusSignature(sigParams1, pk1, revealedMsgs1, false);

    const [revealedMsgs2, unrevealedMsgs2, revealedMsgsRaw2] = getRevealedAndUnrevealed(
      attributes2,
      revealedNames2,
      GlobalEncoder
    );
    expect(revealedMsgsRaw2).toEqual({ fname: 'John', location: { country: 'USA' } });

    const statement2 = Statement.bbsPlusSignature(sigParams2, pk2, revealedMsgs2, false);

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

    const statement3 = Statement.bbsPlusSignature(sigParams3, pk3, revealedMsgs3, false);

    // Construct statements for bound check
    const statement4 = Statement.boundCheckProverFromSetupParamRefs(timeMin, timeMax, 0);
    const statement5 = Statement.boundCheckProverFromSetupParamRefs(weightMin, weightMax, 0);
    const statement6 = Statement.boundCheckProverFromSetupParamRefs(heightMin, heightMax, 0);
    const statement7 = Statement.boundCheckProverFromSetupParamRefs(bmiMin, bmiMax, 0);
    const statement8 = Statement.boundCheckProverFromSetupParamRefs(scoreMin, scoreMax, 0);
    const statement9 = Statement.boundCheckProverFromSetupParamRefs(latMin, latMax, 0);
    const statement10 = Statement.boundCheckProverFromSetupParamRefs(longMin, longMax, 0);

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

    const metaStmtsProver = new MetaStatements();
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
    const proofSpecProver = new ProofSpecG1(statementsProver, metaStmtsProver, proverSetupParams);
    expect(proofSpecProver.isValid()).toEqual(true);

    const witness1 = Witness.bbsPlusSignature(signed1.signature, unrevealedMsgs1, false);
    const witness2 = Witness.bbsPlusSignature(signed2.signature, unrevealedMsgs2, false);
    const witness3 = Witness.bbsPlusSignature(signed3.signature, unrevealedMsgs3, false);

    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);
    witnesses.add(witness3);

    witnesses.add(Witness.boundCheckLegoGroth16(signed1.encodedMessages['timeOfBirth']));
    witnesses.add(Witness.boundCheckLegoGroth16(signed1.encodedMessages['weight']));
    witnesses.add(Witness.boundCheckLegoGroth16(signed1.encodedMessages['height']));
    witnesses.add(Witness.boundCheckLegoGroth16(signed1.encodedMessages['BMI']));
    witnesses.add(Witness.boundCheckLegoGroth16(signed1.encodedMessages['score']));
    witnesses.add(Witness.boundCheckLegoGroth16(signed3.encodedMessages['lessSensitive.department.location.geo.lat']));
    witnesses.add(Witness.boundCheckLegoGroth16(signed3.encodedMessages['lessSensitive.department.location.geo.long']));

    const proof = CompositeProofG1.generate(proofSpecProver, witnesses);

    const verifierSetupParams: SetupParam[] = [];
    verifierSetupParams.push(SetupParam.legosnarkVerifyingKeyUncompressed(snarkVerifyingKey));

    // Verifier independently encodes revealed messages
    const revealedMsgs1FromVerifier = encodeRevealedMsgs(revealedMsgsRaw1, attributes1Struct, GlobalEncoder);
    checkMapsEqual(revealedMsgs1, revealedMsgs1FromVerifier);
    const revealedMsgs2FromVerifier = encodeRevealedMsgs(revealedMsgsRaw2, attributes2Struct, GlobalEncoder);
    checkMapsEqual(revealedMsgs2, revealedMsgs2FromVerifier);
    const revealedMsgs3FromVerifier = encodeRevealedMsgs(revealedMsgsRaw3, attributes3Struct, GlobalEncoder);
    checkMapsEqual(revealedMsgs3, revealedMsgs3FromVerifier);

    const statement11 = Statement.bbsPlusSignature(sigParams1, pk1, revealedMsgs1FromVerifier, false);
    const statement12 = Statement.bbsPlusSignature(sigParams2, pk2, revealedMsgs2FromVerifier, false);
    const statement13 = Statement.bbsPlusSignature(sigParams3, pk3, revealedMsgs3FromVerifier, false);

    // Construct statements for bound check
    const statement14 = Statement.boundCheckVerifierFromSetupParamRefs(timeMin, timeMax, 0);
    const statement15 = Statement.boundCheckVerifierFromSetupParamRefs(weightMin, weightMax, 0);
    const statement16 = Statement.boundCheckVerifierFromSetupParamRefs(heightMin, heightMax, 0);
    const statement17 = Statement.boundCheckVerifierFromSetupParamRefs(bmiMin, bmiMax, 0);
    const statement18 = Statement.boundCheckVerifierFromSetupParamRefs(scoreMin, scoreMax, 0);
    const statement19 = Statement.boundCheckVerifierFromSetupParamRefs(latMin, latMax, 0);
    const statement20 = Statement.boundCheckVerifierFromSetupParamRefs(longMin, longMax, 0);

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

    const metaStmtsVerifier = new MetaStatements();
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
    const proofSpecVerifier = new ProofSpecG1(statementsVerifier, metaStmtsVerifier, verifierSetupParams);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    checkResult(proof.verify(proofSpecVerifier));
  });
});
