import { generateFieldElementFromNumber, initializeWasm } from 'crypto-wasm-new';
import {
  BoundCheckBppParams,
  BoundCheckBppParamsUncompressed,
  BoundCheckSmcParams,
  BoundCheckSmcParamsUncompressed,
  BoundCheckSmcWithKVProverParamsUncompressed,
  BoundCheckSmcWithKVSetup,
  BoundCheckSmcWithKVVerifierParamsUncompressed,
  CompositeProof,
  LegoProvingKeyUncompressed,
  LegoVerifyingKeyUncompressed,
  MetaStatement,
  MetaStatements,
  QuasiProofSpec,
  SetupParam,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../src';
import { buildWitness, PublicKey, Scheme, SecretKey, Signature, SignatureParams } from '../scheme';
import {
  checkResult,
  getBoundCheckSnarkKeys,
  getParamsAndKeys,
  getRevealedUnrevealed,
  proverStmt,
  signAndVerify,
  stringToBytes,
  verifierStmt
} from '../utils';

describe(`Bound check of ${Scheme} signed messages`, () => {
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
  let boundCheckBppParams: BoundCheckBppParamsUncompressed;
  let boundCheckSmcParams: BoundCheckSmcParamsUncompressed;
  let boundCheckSmcKVProverParams: BoundCheckSmcWithKVProverParamsUncompressed;
  let boundCheckSmcKVVerifierParams: BoundCheckSmcWithKVVerifierParamsUncompressed;

  // There are 2 signers
  let sigParams1: SignatureParams,
    sigSk1: SecretKey,
    sigPk1: PublicKey,
    sigParams2: SignatureParams,
    sigSk2: SecretKey,
    sigPk2: PublicKey;
  let messages1: Uint8Array[], messages2: Uint8Array[], sig1: Signature, sig2: Signature;

  beforeAll(async () => {
    await initializeWasm();
  });

  // Setting it to false will make the test run the SNARK setups making tests quite slow
  const loadSnarkSetupFromFiles = true;

  it('do verifier setup', () => {
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
  });

  it('do signers setup', () => {
    [sigParams1, sigSk1, sigPk1] = getParamsAndKeys(messageCount);
    [sigParams2, sigSk2, sigPk2] = getParamsAndKeys(messageCount);

    messages1 = [];
    messages2 = [];
    for (let i = 0; i < messageCount; i++) {
      if (i === msgIdx || i === msgIdx + 1) {
        messages1.push(generateFieldElementFromNumber(100 + i));
        messages2.push(generateFieldElementFromNumber(125 + i));
      } else {
        messages1.push(generateFieldElementFromNumber(2000 + i));
        messages2.push(generateFieldElementFromNumber(3000 + i));
      }
    }

    let result1, result2;
    [sig1, result1] = signAndVerify(messages1, sigParams1, sigSk1, sigPk1);
    checkResult(result1);
    [sig2, result2] = signAndVerify(messages2, sigParams2, sigSk2, sigPk2);
    checkResult(result2);

  });

  function validateBounds(boundCheckProver, boundCheckProverFromRefs, boundCheckVerifier, boundCheckVerifierFromRefs) {
    expect(() => boundCheckProver(-6, max1, snarkProvingKey)).toThrow();
    expect(() => boundCheckProverFromRefs(-6, max1, 0)).toThrow();
    expect(() => boundCheckVerifier(-6, max1, snarkVerifyingKey)).toThrow();
    expect(() => boundCheckVerifierFromRefs(-6, max1, 0)).toThrow();

    expect(() => boundCheckProver(10.1, max1, snarkProvingKey)).toThrow();
    expect(() => boundCheckProverFromRefs(10.1, max1, 0)).toThrow();
    expect(() => boundCheckVerifier(10.1, max1, snarkVerifyingKey)).toThrow();
    expect(() => boundCheckVerifierFromRefs(10.1, max1, 0)).toThrow();

    expect(() => boundCheckProver(10, 20.8, snarkProvingKey)).toThrow();
    expect(() => boundCheckProverFromRefs(10, 20.8, 0)).toThrow();
    expect(() => boundCheckVerifier(10, 20.8, snarkVerifyingKey)).toThrow();
    expect(() => boundCheckVerifierFromRefs(10, 20.8, 0)).toThrow();

    expect(() => boundCheckProver(10, -90, snarkProvingKey)).toThrow();
    expect(() => boundCheckProverFromRefs(10, -90, 0)).toThrow();
    expect(() => boundCheckVerifier(10, -90, snarkVerifyingKey)).toThrow();
    expect(() => boundCheckVerifierFromRefs(10, -90, 0)).toThrow();
  }

  it('accept positive integer bounds only - using LegoGroth16', () => {
    validateBounds(
      Statement.boundCheckLegoProver,
      Statement.boundCheckLegoProverFromSetupParamRefs,
      Statement.boundCheckLegoVerifier,
      Statement.boundCheckLegoVerifierFromSetupParamRefs
    );
  });

  it('accept positive integer bounds only - using Bulletproofs++', () => {
    validateBounds(
      Statement.boundCheckBpp,
      Statement.boundCheckBppFromSetupParamRefs,
      Statement.boundCheckBpp,
      Statement.boundCheckBppFromSetupParamRefs
    );
  });

  it('accept positive integer bounds only - using set membership check', () => {
    validateBounds(
      Statement.boundCheckSmc,
      Statement.boundCheckSmcFromSetupParamRefs,
      Statement.boundCheckSmc,
      Statement.boundCheckSmcFromSetupParamRefs
    );
  });

  it('accept positive integer bounds only - using set membership check with keyed verification', () => {
    validateBounds(
      Statement.boundCheckSmcWithKVProver,
      Statement.boundCheckSmcWithKVProverFromSetupParamRefs,
      Statement.boundCheckSmcWithKVVerifier,
      Statement.boundCheckSmcWithKVVerifierFromSetupParamRefs
    );
  });

  function proveAndVerifySingle(
    sigParams: SignatureParams,
    sigPk: PublicKey,
    messages: Uint8Array[],
    sig: Signature,
    pStmt,
    witnessGen,
    vStmt,
    proverParams,
    verifierParams
  ) {
    const revealedIndices = new Set<number>();
    revealedIndices.add(0);
    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(messages, revealedIndices);
    const statement1 = proverStmt(sigParams, revealedMsgs, sigPk);
    const statement2 = pStmt(min1, max1, proverParams);
    const proverStatements = new Statements(statement1);
    proverStatements.add(statement2);

    const witnessEq = new WitnessEqualityMetaStatement();
    witnessEq.addWitnessRef(0, msgIdx);
    witnessEq.addWitnessRef(1, 0);
    const metaStatements = new MetaStatements();
    metaStatements.add(MetaStatement.witnessEquality(witnessEq));

    const witness1 = buildWitness(sig, unrevealedMsgs, false);
    const witness2 = witnessGen(messages[msgIdx]);
    const witnesses = new Witnesses(witness1);
    witnesses.add(witness2);

    const proverProofSpec = new QuasiProofSpec(proverStatements, metaStatements);

    const nonce = stringToBytes('a nonce');

    const proof = CompositeProof.generateUsingQuasiProofSpec(proverProofSpec, witnesses, nonce);

    const statement3 = vStmt(min1, max1, verifierParams);
    const statement4 = verifierStmt(sigParams, revealedMsgs, sigPk);
    const verifierStatements = new Statements(statement4);
    verifierStatements.add(statement3);

    const verifierProofSpec = new QuasiProofSpec(verifierStatements, metaStatements);
    checkResult(proof.verifyUsingQuasiProofSpec(verifierProofSpec, nonce));
  }

  function proveAndVerifyMultiple(
    proverSetupParamGen,
    verifierSetupParamGen,
    pStmt,
    witnessGen,
    vStmt,
    proverParams,
    verifierParams
  ) {
    const proverSetupParams: SetupParam[] = [];
    proverSetupParams.push(proverSetupParamGen(proverParams));

    const [revealedMsgs1, unrevealedMsgs1] = getRevealedUnrevealed(messages1, new Set<number>());
    const [revealedMsgs2, unrevealedMsgs2] = getRevealedUnrevealed(messages2, new Set<number>());

    const statement1 = proverStmt(sigParams1, revealedMsgs1, sigPk1);
    const statement2 = proverStmt(sigParams2, revealedMsgs2, sigPk2);
    const statement3 = pStmt(min1, max1, 0);
    const statement4 = pStmt(min2, max2, 0);
    const statement5 = pStmt(min3, max3, 0);
    const statement6 = pStmt(min4, max4, 0);

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
    witnesses.add(buildWitness(sig1, unrevealedMsgs1, false));
    witnesses.add(buildWitness(sig2, unrevealedMsgs2, false));
    witnesses.add(witnessGen(messages1[msgIdx]));
    witnesses.add(witnessGen(messages1[msgIdx + 1]));
    witnesses.add(witnessGen(messages2[msgIdx]));
    witnesses.add(witnessGen(messages2[msgIdx + 1]));

    const proverProofSpec = new QuasiProofSpec(proverStatements, metaStatements, proverSetupParams);

    const nonce = stringToBytes('a nonce');

    const proof = CompositeProof.generateUsingQuasiProofSpec(proverProofSpec, witnesses, nonce);

    const verifierSetupParams: SetupParam[] = [];
    verifierSetupParams.push(verifierSetupParamGen(verifierParams));

    const statement7 = vStmt(min1, max1, 0);
    const statement8 = vStmt(min2, max2, 0);
    const statement9 = vStmt(min3, max3, 0);
    const statement10 = vStmt(min4, max4, 0);
    const statement11 = verifierStmt(sigParams1, revealedMsgs1, sigPk1);
    const statement12 = verifierStmt(sigParams2, revealedMsgs2, sigPk2);

    const verifierStatements = new Statements([].concat(statement11, statement12));
    verifierStatements.add(statement7);
    verifierStatements.add(statement8);
    verifierStatements.add(statement9);
    verifierStatements.add(statement10);

    const verifierProofSpec = new QuasiProofSpec(verifierStatements, metaStatements, verifierSetupParams);

    checkResult(proof.verifyUsingQuasiProofSpec(verifierProofSpec, nonce));
  }

  function boundsOnTimestamps(
    proverSetupParamGen,
    verifierSetupParamGen,
    pStmt,
    witnessGen,
    vStmt,
    proverParams,
    verifierParams
  ) {
    // This test shows how to use the bound check protocol to do range proofs over attributes.

    // Various timestamps in milliseconds. These are provided by the verifier.
    const earliestIssuance = 642709800000; // Timestamp of the earliest acceptable issuance, used as lower bound
    const latestIssuance = 1588271400000; // Timestamp of the latest acceptable issuance, used as upper bound
    const bornAfter = 642709800000; // Timestamp of the latest acceptable birth date, used as lower bound
    const now = 1620585000000; // Timestamp as of now, i.e proof generation
    const someDistantFuture = 1777746600000; // Timestamp from future

    const attributes: Uint8Array[] = [];
    attributes.push(Signature.encodeMessageForSigning(stringToBytes('John Smith'))); // Name
    attributes.push(Signature.encodeMessageForSigning(stringToBytes('123-456789-0'))); // SSN
    attributes.push(Signature.encodePositiveNumberForSigning(bornAfter + 100000)); // Birth date as no. of milliseconds since epoch
    attributes.push(Signature.encodePositiveNumberForSigning(earliestIssuance + 100000)); // Issuance date as no. of milliseconds since epoch
    attributes.push(Signature.encodePositiveNumberForSigning(now + 2000000)); // Expiration date as no. of milliseconds since epoch

    // Signer creates the signature and shares with prover
    const [sig, result] = signAndVerify(attributes, sigParams1, sigSk1, sigPk1);
    checkResult(result);

    const proverSetupParams: SetupParam[] = [];
    proverSetupParams.push(proverSetupParamGen(proverParams));

    const revealedIndices = new Set<number>();
    revealedIndices.add(0);
    const [revealedAttrs, unrevealedAttrs] = getRevealedUnrevealed(attributes, revealedIndices);
    const statement1 = proverStmt(sigParams1, revealedAttrs, sigPk1);
    // For proving birth date was after `bornAfter`
    const statement2 = pStmt(bornAfter, now, 0);
    // For proving issuance date was between `earliestIssuance` and `latestIssuance`
    const statement3 = pStmt(earliestIssuance, latestIssuance, 0);
    // For proving expiration date was between `now` and `someDistantFuture`, i.e. its not expired as of now.
    const statement4 = pStmt(now, someDistantFuture, 0);

    const proverStatements = new Statements(statement1);
    proverStatements.add(statement2);
    proverStatements.add(statement3);
    proverStatements.add(statement4);

    // For birth date attribute
    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(0, 2);
    witnessEq1.addWitnessRef(1, 0);

    // For issuance date attribute
    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(0, 3);
    witnessEq2.addWitnessRef(2, 0);

    // For expiration date attribute
    const witnessEq3 = new WitnessEqualityMetaStatement();
    witnessEq3.addWitnessRef(0, 4);
    witnessEq3.addWitnessRef(3, 0);

    const metaStatements = new MetaStatements();
    metaStatements.add(MetaStatement.witnessEquality(witnessEq1));
    metaStatements.add(MetaStatement.witnessEquality(witnessEq2));
    metaStatements.add(MetaStatement.witnessEquality(witnessEq3));

    const witnesses = new Witnesses();
    witnesses.add(buildWitness(sig, unrevealedAttrs, false));
    witnesses.add(witnessGen(attributes[2]));
    witnesses.add(witnessGen(attributes[3]));
    witnesses.add(witnessGen(attributes[4]));

    const proverProofSpec = new QuasiProofSpec(proverStatements, metaStatements, proverSetupParams);

    const nonce = stringToBytes('a nonce');

    const proof = CompositeProof.generateUsingQuasiProofSpec(proverProofSpec, witnesses, nonce);

    const verifierSetupParams: SetupParam[] = [];
    verifierSetupParams.push(verifierSetupParamGen(verifierParams));

    // For verifying birth date was after `bornAfter`
    const statement5 = vStmt(bornAfter, now, 0);
    // For verifying issuance date was between `earliestIssuance` and `latestIssuance`
    const statement6 = vStmt(earliestIssuance, latestIssuance, 0);
    // For verifying expiration date was between `now` and `someDistantFuture`, i.e. its not expired as of now.
    const statement7 = vStmt(now, someDistantFuture, 0);
    const statement8 = verifierStmt(sigParams1, revealedAttrs, sigPk1);

    const verifierStatements = new Statements();
    verifierStatements.add(statement8);
    verifierStatements.add(statement5);
    verifierStatements.add(statement6);
    verifierStatements.add(statement7);

    const verifierProofSpec = new QuasiProofSpec(verifierStatements, metaStatements, verifierSetupParams);

    checkResult(proof.verifyUsingQuasiProofSpec(verifierProofSpec, nonce));
  }

  function boundsOnNegativeAndDecimal(
    proverSetupParamGen,
    verifierSetupParamGen,
    pStmt,
    witnessGen,
    vStmt,
    proverParams,
    verifierParams
  ) {
    // The protocol only works with positive integers to negative or decimal numbers must be converted. Following is an
    // example of showing how negative or decimal values for both attributes and bounds are transformed to be positive integers.
    // Note that these transformation rules should be well established between the signer, prover and verifier and the same
    // rules must be used the 3 parties over the same data.

    // The smallest negative value the attribute can take. Using the same value for all attributes but does not
    // need to be.
    const lowestNegativeValue = -300;
    // The maximum decimal places the attribute can have. Using the same value for all attributes but does not
    // need to be.
    const maxDecimalPlaces = 3;

    // Original values of the bounds, i.e the ones that make sense for the application, and they can be negative or decimal
    // Minimum value of 1st attribute
    const originalMin1 = -200;
    // Maximum value of 1st attribute
    const originalMax1 = 50;
    // Minimum value of 2nd attribute
    const originalMin2 = -250;
    // Maximum value of 2nd attribute
    const originalMax2 = -30;
    // Minimum value of 3rd and 4th attribute
    const originalMin3 = 1.2;
    // Maximum value of 3rd and 4th attribute
    const originalMax3 = 8.443;
    // Minimum value of 5th attribute
    const originalMin4 = -250.65;
    // Maximum value of 5th attribute
    const originalMax4 = 10.951;

    // Original values of the attributes, i.e the ones that make sense for the application, and they can be negative or decimal
    // They will be transformed but according to different application rules as mentioned below. These rules are arbitrary
    const originalAttributes = [
      40, // already a positive integer but could be an integer as low as `lowestNegativeValue` but won't be a decimal number as per the application rules
      -100, // negative integer that won't be a decimal number as per the application rules
      3.236, // decimal value that won't be negative as per the application rules
      6, // already a positive integer but could have 3 decimal points. Won't be negative as per the application rules.
      -90.45 // a negative decimal number
    ];

    // Ensure that original attribute values satisfy original bounds
    expect(originalAttributes[0]).toBeLessThanOrEqual(originalMax1);
    expect(originalAttributes[0]).toBeGreaterThanOrEqual(originalMin1);

    expect(originalAttributes[1]).toBeLessThanOrEqual(originalMax2);
    expect(originalAttributes[1]).toBeGreaterThanOrEqual(originalMin2);

    expect(originalAttributes[2]).toBeLessThanOrEqual(originalMax3);
    expect(originalAttributes[2]).toBeGreaterThanOrEqual(originalMin3);
    expect(originalAttributes[3]).toBeLessThanOrEqual(originalMax3);
    expect(originalAttributes[3]).toBeGreaterThanOrEqual(originalMin3);

    expect(originalAttributes[4]).toBeLessThanOrEqual(originalMax4);
    expect(originalAttributes[4]).toBeGreaterThanOrEqual(originalMin4);

    // Transform the attributes
    const transformedAttributes = [
      originalAttributes[0] + Math.abs(lowestNegativeValue), // this attribute could only be negative but not decimal
      originalAttributes[1] + Math.abs(lowestNegativeValue), // this attribute could only be negative but not decimal
      originalAttributes[2] * Math.pow(10, maxDecimalPlaces), // this attribute could only be decimal but not negative
      originalAttributes[3] * Math.pow(10, maxDecimalPlaces), // this attribute could only be decimal but not negative
      (originalAttributes[4] + Math.abs(lowestNegativeValue)) * Math.pow(10, maxDecimalPlaces) // this attribute could be both decimal and negative
    ];

    for (let i = 0; i < transformedAttributes.length; i++) {
      expect(Number.isInteger(transformedAttributes[i]) && transformedAttributes[i] > 0).toBe(true);
    }

    // Transform the bounds
    const transMin1 = originalMin1 + Math.abs(lowestNegativeValue); // this applies to an attribute that can be negative but not decimal
    const transMax1 = originalMax1 + Math.abs(lowestNegativeValue); // this applies to an attribute that can be negative but not decimal
    const transMin2 = originalMin2 + Math.abs(lowestNegativeValue); // this applies to an attribute that can be negative but not decimal
    const transMax2 = originalMax2 + Math.abs(lowestNegativeValue); // this applies to an attribute that can be negative but not decimal
    const transMin3 = originalMin3 * Math.pow(10, maxDecimalPlaces); // this applies to an attribute that can be decimal but not negative
    const transMax3 = originalMax3 * Math.pow(10, maxDecimalPlaces); // this applies to an attribute that can be decimal but not negative
    const transMin4 = Math.floor((originalMin4 + Math.abs(lowestNegativeValue)) * Math.pow(10, maxDecimalPlaces)); // this applies to an attribute that can be both decimal and negative
    const transMax4 = Math.ceil((originalMax4 + Math.abs(lowestNegativeValue)) * Math.pow(10, maxDecimalPlaces)); // this applies to an attribute that can be both decimal and negative

    // Transformed attributes satisfy transformed bounds
    expect(transformedAttributes[0]).toBeLessThanOrEqual(transMax1);
    expect(transformedAttributes[0]).toBeGreaterThanOrEqual(transMin1);

    expect(transformedAttributes[1]).toBeLessThanOrEqual(transMax2);
    expect(transformedAttributes[1]).toBeGreaterThanOrEqual(transMin2);

    expect(transformedAttributes[2]).toBeLessThanOrEqual(transMax3);
    expect(transformedAttributes[2]).toBeGreaterThanOrEqual(transMin3);
    expect(transformedAttributes[3]).toBeLessThanOrEqual(transMax3);
    expect(transformedAttributes[3]).toBeGreaterThanOrEqual(transMin3);

    expect(transformedAttributes[4]).toBeLessThanOrEqual(transMax4);
    expect(transformedAttributes[4]).toBeGreaterThanOrEqual(transMin4);

    // Encode for signing
    const encodedAttributes: Uint8Array[] = [];
    for (let i = 0; i < transformedAttributes.length; i++) {
      encodedAttributes.push(Signature.encodePositiveNumberForSigning(transformedAttributes[i]));
    }

    // Signer creates the signature and shares with prover
    const [sig, result] = signAndVerify(encodedAttributes, sigParams1, sigSk1, sigPk1);
    checkResult(result);

    const proverSetupParams: SetupParam[] = [];
    proverSetupParams.push(proverSetupParamGen(proverParams));

    const [revealedAttrs, unrevealedAttrs] = getRevealedUnrevealed(encodedAttributes, new Set<number>());
    const statement1 = proverStmt(sigParams1, revealedAttrs, sigPk1);

    const statement2 = pStmt(transMin1, transMax1, 0);
    const statement3 = pStmt(transMin2, transMax2, 0);
    const statement4 = pStmt(transMin3, transMax3, 0);
    const statement5 = pStmt(transMin3, transMax3, 0);
    const statement6 = pStmt(transMin4, transMax4, 0);

    const proverStatements = new Statements(statement1);
    proverStatements.add(statement2);
    proverStatements.add(statement3);
    proverStatements.add(statement4);
    proverStatements.add(statement5);
    proverStatements.add(statement6);

    const metaStatements = new MetaStatements();
    for (let i = 0; i < encodedAttributes.length; i++) {
      const witnessEq = new WitnessEqualityMetaStatement();
      witnessEq.addWitnessRef(0, i);
      witnessEq.addWitnessRef(1 + i, 0);
      metaStatements.add(MetaStatement.witnessEquality(witnessEq));
    }

    const witnesses = new Witnesses();
    witnesses.add(buildWitness(sig, unrevealedAttrs, false));
    for (let i = 0; i < encodedAttributes.length; i++) {
      witnesses.add(witnessGen(encodedAttributes[i]));
    }

    const proverProofSpec = new QuasiProofSpec(proverStatements, metaStatements, proverSetupParams);

    const nonce = stringToBytes('a nonce');

    const proof = CompositeProof.generateUsingQuasiProofSpec(proverProofSpec, witnesses, nonce);

    const verifierSetupParams: SetupParam[] = [];
    verifierSetupParams.push(verifierSetupParamGen(verifierParams));

    const statement7 = vStmt(transMin1, transMax1, 0);
    const statement8 = vStmt(transMin2, transMax2, 0);
    const statement9 = vStmt(transMin3, transMax3, 0);
    const statement10 = vStmt(transMin3, transMax3, 0);
    const statement11 = vStmt(transMin4, transMax4, 0);
    const statement12 = verifierStmt(sigParams1, revealedAttrs, sigPk1);

    const verifierStatements = new Statements(statement12);
    verifierStatements.add(statement7);
    verifierStatements.add(statement8);
    verifierStatements.add(statement9);
    verifierStatements.add(statement10);
    verifierStatements.add(statement11);

    const verifierProofSpec = new QuasiProofSpec(verifierStatements, metaStatements, verifierSetupParams);

    checkResult(proof.verifyUsingQuasiProofSpec(verifierProofSpec, nonce));
  }

  it('prove knowledge of 1 bounded message from 1st signature - using LegoGroth16', () => {
    proveAndVerifySingle(
      sigParams1,
      sigPk1,
      messages1,
      sig1,
      Statement.boundCheckLegoProver,
      Witness.boundCheckLegoGroth16,
      Statement.boundCheckLegoVerifier,
      snarkProvingKey,
      snarkVerifyingKey
    );
  }, 20000);

  it('prove knowledge of 1 bounded message from 2nd signature - using LegoGroth16', () => {
    proveAndVerifySingle(
      sigParams2,
      sigPk2,
      messages2,
      sig2,
      Statement.boundCheckLegoProver,
      Witness.boundCheckLegoGroth16,
      Statement.boundCheckLegoVerifier,
      snarkProvingKey,
      snarkVerifyingKey
    );
  }, 20000);

  it('prove knowledge of 1 bounded message from 1st signature - using Bulletproofs++', () => {
    proveAndVerifySingle(
      sigParams1,
      sigPk1,
      messages1,
      sig1,
      Statement.boundCheckBpp,
      Witness.boundCheckBpp,
      Statement.boundCheckBpp,
      boundCheckBppParams,
      boundCheckBppParams
    );
  }, 20000);

  it('prove knowledge of 1 bounded message from 2nd signature - using Bulletproofs++', () => {
    proveAndVerifySingle(
      sigParams2,
      sigPk2,
      messages2,
      sig2,
      Statement.boundCheckBpp,
      Witness.boundCheckBpp,
      Statement.boundCheckBpp,
      boundCheckBppParams,
      boundCheckBppParams
    );
  }, 20000);

  it('prove knowledge of 1 bounded message from 1st signature - using set membership check', () => {
    proveAndVerifySingle(
      sigParams1,
      sigPk1,
      messages1,
      sig1,
      Statement.boundCheckSmc,
      Witness.boundCheckSmc,
      Statement.boundCheckSmc,
      boundCheckSmcParams,
      boundCheckSmcParams
    );
  }, 20000);

  it('prove knowledge of 1 bounded message from 2nd signature - set membership check', () => {
    proveAndVerifySingle(
      sigParams2,
      sigPk2,
      messages2,
      sig2,
      Statement.boundCheckSmc,
      Witness.boundCheckSmc,
      Statement.boundCheckSmc,
      boundCheckSmcParams,
      boundCheckSmcParams
    );
  }, 20000);

  it('prove knowledge of 1 bounded message from 1st signature - using set membership check with keyed verification', () => {
    proveAndVerifySingle(
      sigParams1,
      sigPk1,
      messages1,
      sig1,
      Statement.boundCheckSmcWithKVProver,
      Witness.boundCheckSmcWithKV,
      Statement.boundCheckSmcWithKVVerifier,
      boundCheckSmcKVProverParams,
      boundCheckSmcKVVerifierParams
    );
  }, 20000);

  it('prove knowledge of 1 bounded message from 2nd signature - set membership check with keyed verification', () => {
    proveAndVerifySingle(
      sigParams2,
      sigPk2,
      messages2,
      sig2,
      Statement.boundCheckSmcWithKVProver,
      Witness.boundCheckSmcWithKV,
      Statement.boundCheckSmcWithKVVerifier,
      boundCheckSmcKVProverParams,
      boundCheckSmcKVVerifierParams
    );
  }, 20000);

  it('prove knowledge of 2 bounded messages from both signatures with different bounds for each message - using LegoGroth16', () => {
    proveAndVerifyMultiple(
      SetupParam.legosnarkProvingKeyUncompressed,
      SetupParam.legosnarkVerifyingKeyUncompressed,
      Statement.boundCheckLegoProverFromSetupParamRefs,
      Witness.boundCheckLegoGroth16,
      Statement.boundCheckLegoVerifierFromSetupParamRefs,
      snarkProvingKey,
      snarkVerifyingKey
    );
  });

  it('prove knowledge of 2 bounded messages from both signatures with different bounds for each message - using Bulletproofs++', () => {
    proveAndVerifyMultiple(
      SetupParam.bppSetupParamsUncompressed,
      SetupParam.bppSetupParamsUncompressed,
      Statement.boundCheckBppFromSetupParamRefs,
      Witness.boundCheckBpp,
      Statement.boundCheckBppFromSetupParamRefs,
      boundCheckBppParams,
      boundCheckBppParams
    );
  });

  it('prove knowledge of 2 bounded messages from both signatures with different bounds for each message - using set membership check', () => {
    proveAndVerifyMultiple(
      SetupParam.smcSetupParamsUncompressed,
      SetupParam.smcSetupParamsUncompressed,
      Statement.boundCheckSmcFromSetupParamRefs,
      Witness.boundCheckSmc,
      Statement.boundCheckSmcFromSetupParamRefs,
      boundCheckSmcParams,
      boundCheckSmcParams
    );
  });

  it('prove knowledge of 2 bounded messages from both signatures with different bounds for each message - using set membership check with keyed verification', () => {
    proveAndVerifyMultiple(
      SetupParam.smcSetupParamsUncompressed,
      SetupParam.smcSetupParamsWithSkUncompressed,
      Statement.boundCheckSmcWithKVProverFromSetupParamRefs,
      Witness.boundCheckSmcWithKV,
      Statement.boundCheckSmcWithKVVerifierFromSetupParamRefs,
      boundCheckSmcKVProverParams,
      boundCheckSmcKVVerifierParams
    );
  });

  it('use bound check for proving earlier than or later than with timestamps - using LegoGroth16', () => {
    boundsOnTimestamps(
      SetupParam.legosnarkProvingKeyUncompressed,
      SetupParam.legosnarkVerifyingKeyUncompressed,
      Statement.boundCheckLegoProverFromSetupParamRefs,
      Witness.boundCheckLegoGroth16,
      Statement.boundCheckLegoVerifierFromSetupParamRefs,
      snarkProvingKey,
      snarkVerifyingKey
    );
  });

  it('use bound check for proving earlier than or later than with timestamps - using Bulletproofs++', () => {
    boundsOnTimestamps(
      SetupParam.bppSetupParamsUncompressed,
      SetupParam.bppSetupParamsUncompressed,
      Statement.boundCheckBppFromSetupParamRefs,
      Witness.boundCheckBpp,
      Statement.boundCheckBppFromSetupParamRefs,
      boundCheckBppParams,
      boundCheckBppParams
    );
  });

  it('use bound check for proving earlier than or later than with timestamps - using set membership check', () => {
    boundsOnTimestamps(
      SetupParam.smcSetupParamsUncompressed,
      SetupParam.smcSetupParamsUncompressed,
      Statement.boundCheckSmcFromSetupParamRefs,
      Witness.boundCheckSmc,
      Statement.boundCheckSmcFromSetupParamRefs,
      boundCheckSmcParams,
      boundCheckSmcParams
    );
  });

  it('use bound check for proving earlier than or later than with timestamps - using set membership check with keyed verification', () => {
    boundsOnTimestamps(
      SetupParam.smcSetupParamsUncompressed,
      SetupParam.smcSetupParamsWithSkUncompressed,
      Statement.boundCheckSmcWithKVProverFromSetupParamRefs,
      Witness.boundCheckSmcWithKV,
      Statement.boundCheckSmcWithKVVerifierFromSetupParamRefs,
      boundCheckSmcKVProverParams,
      boundCheckSmcKVVerifierParams
    );
  });

  it('use bound check for negative or decimal bounds - using LegoGroth16', () => {
    boundsOnNegativeAndDecimal(
      SetupParam.legosnarkProvingKeyUncompressed,
      SetupParam.legosnarkVerifyingKeyUncompressed,
      Statement.boundCheckLegoProverFromSetupParamRefs,
      Witness.boundCheckLegoGroth16,
      Statement.boundCheckLegoVerifierFromSetupParamRefs,
      snarkProvingKey,
      snarkVerifyingKey
    );
  });

  it('use bound check for negative or decimal bounds - using Bulletproofs++', () => {
    boundsOnNegativeAndDecimal(
      SetupParam.bppSetupParamsUncompressed,
      SetupParam.bppSetupParamsUncompressed,
      Statement.boundCheckBppFromSetupParamRefs,
      Witness.boundCheckBpp,
      Statement.boundCheckBppFromSetupParamRefs,
      boundCheckBppParams,
      boundCheckBppParams
    );
  });

  it('use bound check for negative or decimal bounds - using set membership check', () => {
    boundsOnNegativeAndDecimal(
      SetupParam.smcSetupParamsUncompressed,
      SetupParam.smcSetupParamsUncompressed,
      Statement.boundCheckSmcFromSetupParamRefs,
      Witness.boundCheckSmc,
      Statement.boundCheckSmcFromSetupParamRefs,
      boundCheckSmcParams,
      boundCheckSmcParams
    );
  });

  it('use bound check for negative or decimal bounds - using set membership check with keyed verification', () => {
    boundsOnNegativeAndDecimal(
      SetupParam.smcSetupParamsUncompressed,
      SetupParam.smcSetupParamsWithSkUncompressed,
      Statement.boundCheckSmcWithKVProverFromSetupParamRefs,
      Witness.boundCheckSmcWithKV,
      Statement.boundCheckSmcWithKVVerifierFromSetupParamRefs,
      boundCheckSmcKVProverParams,
      boundCheckSmcKVVerifierParams
    );
  });
});
