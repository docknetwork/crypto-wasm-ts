import { generateFieldElementFromNumber } from 'crypto-wasm-new';
import {
  CircomInputs,
  CompositeProof,
  createWitnessEqualityMetaStatement,
  EncodeFunc,
  Encoder,
  encodeRevealedMsgs,
  flattenObjectToKeyValuesList,
  getIndicesForMsgNames,
  getRevealedAndUnrevealed,
  initializeWasm,
  LegoProvingKeyUncompressed,
  LegoVerifyingKeyUncompressed,
  MetaStatements,
  ParsedR1CSFile,
  ProofSpec,
  R1CSSnarkSetup,
  SetupParam,
  SignedMessages,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../../../src';
import {
  buildPublicKeySetupParam,
  buildSignatureParamsSetupParam,
  buildWitness, isKvac,
  PublicKey,
  Scheme,
  Signature
} from '../../../scheme';
import { checkResult, getParamsAndKeys, getWasmBytes, parseR1CSFile, stringToBytes } from '../../../utils';
import { defaultEncoder } from '../data-and-encoder';
import { checkMapsEqual } from '../index';
import { adaptedSigParams, proverStmtFromSetupParamsRef, signAndVerify, verifierStmtFromSetupParamsRef } from '../util';

// Test for a scenario where a user wants to prove that his yearly income is less than 25000 where his income comprises
// of 12 payslip credentials, 1 for each month's.
describe(`${Scheme} Proving that yearly income calculated from monthly payslips is less than 25000`, () => {
  let encoder: Encoder;

  const label = stringToBytes('Sig params label');
  let pk: PublicKey, sk, params;

  let r1cs: ParsedR1CSFile;
  let wasm: Uint8Array;

  let provingKey: LegoProvingKeyUncompressed, verifyingKey: LegoVerifyingKeyUncompressed;

  const payslipAttributesStruct = {
    fname: null,
    lname: null,
    sensitive: {
      email: null,
      SSN: null
    },
    employer: null,
    empId: null,
    salary: {
      paySlipId: null,
      year: null,
      month: null,
      amount: null
    }
  };

  const numPayslips = 12;
  const payslipAttributes: object[] = [];
  const signed: SignedMessages<Signature>[] = [];

  const salaryLimit = 25000;
  let salaryLimitEncoded: Uint8Array;

  beforeAll(async () => {
    await initializeWasm();

    // Setup encoder
    const encoders = new Map<string, EncodeFunc>();
    encoders.set('salary.year', Encoder.positiveIntegerEncoder());
    encoders.set('salary.month', Encoder.positiveIntegerEncoder());
    encoders.set('salary.amount', Encoder.positiveDecimalNumberEncoder(2));
    encoder = new Encoder(encoders, defaultEncoder);

    // Important to encode the bound with the same encoder as attributes
    salaryLimitEncoded = encoder.encodeMessage('salary.amount', salaryLimit);

    // This can be done by the verifier or the verifier can publish only the Circom program and
    // prover can check that the same R1CS and WASM are generated.
    r1cs = await parseR1CSFile('sum_12_less_than_public.r1cs');
    wasm = getWasmBytes('sum_12_less_than_public.wasm');
  });

  it('verifier generates SNARk proving and verifying key', async () => {
    console.time('Snark setup');
    const pk = R1CSSnarkSetup.fromParsedR1CSFile(r1cs, 12);
    console.timeEnd('Snark setup');
    console.time('Decompress keys');
    provingKey = pk.decompress();
    verifyingKey = pk.getVerifyingKeyUncompressed();
    console.timeEnd('Decompress keys');
  });

  it('signers signs attributes', () => {
    const numAttrs = flattenObjectToKeyValuesList(payslipAttributesStruct)[0].length;
    // Issuing multiple credentials with the same number of attributes so create sig. params only once for faster execution
    [params, sk, pk] = getParamsAndKeys(numAttrs, label);

    for (let i = 0; i < numPayslips; i++) {
      payslipAttributes.push({
        fname: 'John',
        lname: 'Smith',
        sensitive: {
          email: 'john.smith@example.com',
          SSN: '123-456789-0'
        },
        employer: 'Acme Corp',
        empId: 'e-123-987-1',
        salary: {
          paySlipId: 'e-123-987-1-22-' + (i + 1).toString(),
          year: 2022,
          month: i + 1,
          amount: Math.floor(Math.random() * 2000) // salary will be under 2000
        }
      });
      signed.push(signAndVerify(payslipAttributes[i], encoder, label, sk, pk));
    }
  });

  it('proof verifies when yearly salary is less than 25000', () => {
    // Check that yearly salary is indeed less than required
    let salary = 0;
    for (let i = 0; i < numPayslips; i++) {
      // @ts-ignore
      salary += payslipAttributes[i].salary.amount;
    }
    expect(salary).toBeLessThan(salaryLimit);

    // Reveal first name ("fname" attribute), year ("salary.year" attribute) and month ("salary.month" attribute) from all 12 payslips

    // Prove equality in zero knowledge of last name ("lname" attribute) and Social security number ("SSN" attribute) in all 12 payslips

    console.time('Proof generate');
    const revealedNames = new Set<string>();
    revealedNames.add('fname');
    revealedNames.add('salary.year');
    revealedNames.add('salary.month');

    const sigParams = adaptedSigParams(payslipAttributesStruct, label);

    const revealedMsgs: Map<number, Uint8Array>[] = [];
    const unrevealedMsgs: Map<number, Uint8Array>[] = [];
    const revealedMsgsRaw: object[] = [];

    for (let i = 0; i < numPayslips; i++) {
      const [r, u, rRaw] = getRevealedAndUnrevealed(payslipAttributes[i], revealedNames, encoder);
      revealedMsgs.push(r);
      unrevealedMsgs.push(u);
      revealedMsgsRaw.push(rRaw);
      expect(rRaw).toEqual({ fname: 'John', salary: { year: 2022, month: i + 1 } });
    }

    const proverSetupParams: SetupParam[] = [];
    proverSetupParams.push(buildSignatureParamsSetupParam(sigParams));
    proverSetupParams.push(SetupParam.r1cs(r1cs));
    proverSetupParams.push(SetupParam.bytes(wasm));
    proverSetupParams.push(SetupParam.legosnarkProvingKeyUncompressed(provingKey));
    if (!isKvac()) {
      proverSetupParams.push(buildPublicKeySetupParam(pk));
    }

    const statementsProver = new Statements();

    const sIdxs: number[] = [];
    for (let i = 0; i < numPayslips; i++) {
      sIdxs.push(statementsProver.add(proverStmtFromSetupParamsRef(0, revealedMsgs[i], 4, false)));
    }

    sIdxs.push(statementsProver.add(Statement.r1csCircomProverFromSetupParamRefs(1, 2, 3)));

    const metaStmtsProver = new MetaStatements();

    const witnessEq1 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        for (let i = 0; i < numPayslips; i++) {
          m.set(sIdxs[i], [['lname'], payslipAttributesStruct]);
        }
        return m;
      })()
    );
    metaStmtsProver.addWitnessEquality(witnessEq1);

    const witnessEq2 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        for (let i = 0; i < numPayslips; i++) {
          m.set(sIdxs[i], [['sensitive.SSN'], payslipAttributesStruct]);
        }
        return m;
      })()
    );
    metaStmtsProver.addWitnessEquality(witnessEq2);

    // The input to the circuit should match the signed "salary.amount" attribute.
    for (let i = 0; i < numPayslips; i++) {
      const witnessEq = new WitnessEqualityMetaStatement();
      witnessEq.addWitnessRef(sIdxs[i], getIndicesForMsgNames(['salary.amount'], payslipAttributesStruct)[0]);
      witnessEq.addWitnessRef(sIdxs[numPayslips], i);
      metaStmtsProver.addWitnessEquality(witnessEq);
    }

    const proofSpecProver = new ProofSpec(statementsProver, metaStmtsProver, proverSetupParams);
    expect(proofSpecProver.isValid()).toEqual(true);

    const witnesses = new Witnesses();
    for (let i = 0; i < numPayslips; i++) {
      for (const wit of [].concat(buildWitness(signed[i].signature, unrevealedMsgs[i], false))) witnesses.add(wit);
    }

    const inputs = new CircomInputs();
    // Add each encoded salary as the circuit input
    inputs.setPrivateArrayInput(
      'in',
      signed.map((s) => s.encodedMessages['salary.amount'])
    );
    inputs.setPublicInput('max', salaryLimitEncoded);
    witnesses.add(Witness.r1csCircomWitness(inputs));

    const proof = CompositeProof.generate(proofSpecProver, witnesses);
    console.timeEnd('Proof generate');

    console.time('Proof verify');
    // Verifier independently encodes revealed messages
    const revealedMsgsFromVerifier: Map<number, Uint8Array>[] = [];
    for (let i = 0; i < numPayslips; i++) {
      revealedMsgsFromVerifier.push(encodeRevealedMsgs(revealedMsgsRaw[i], payslipAttributesStruct, encoder));
      checkMapsEqual(revealedMsgs[i], revealedMsgsFromVerifier[i]);
    }

    const verifierSetupParams: SetupParam[] = [];
    verifierSetupParams.push(buildSignatureParamsSetupParam(sigParams));

    // To prove not less than, i.e. <= or >, replace `generateFieldElementFromNumber(1)` with `generateFieldElementFromNumber(0)`
    // as 1 indicates success of the check, 0 indicates failure of the check
    verifierSetupParams.push(SetupParam.fieldElementVec([generateFieldElementFromNumber(1), salaryLimitEncoded]));

    verifierSetupParams.push(SetupParam.legosnarkVerifyingKeyUncompressed(verifyingKey));

    if (!isKvac()) {
      verifierSetupParams.push(buildPublicKeySetupParam(pk));
    }

    const statementsVerifier = new Statements();

    const sIdxVs: number[] = [];
    for (let i = 0; i < numPayslips; i++) {
      sIdxVs.push(statementsVerifier.add(verifierStmtFromSetupParamsRef(0, revealedMsgsFromVerifier[i], 3, false)));
    }

    sIdxVs.push(statementsVerifier.add(Statement.r1csCircomVerifierFromSetupParamRefs(1, 2)));

    const metaStmtsVerifier = new MetaStatements();

    const witnessEq5 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        for (let i = 0; i < numPayslips; i++) {
          m.set(sIdxVs[i], [['lname'], payslipAttributesStruct]);
        }
        return m;
      })()
    );
    metaStmtsVerifier.addWitnessEquality(witnessEq5);

    const witnessEq6 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        for (let i = 0; i < numPayslips; i++) {
          m.set(sIdxVs[i], [['sensitive.SSN'], payslipAttributesStruct]);
        }
        return m;
      })()
    );
    metaStmtsVerifier.addWitnessEquality(witnessEq6);

    for (let i = 0; i < numPayslips; i++) {
      const witnessEq = new WitnessEqualityMetaStatement();
      witnessEq.addWitnessRef(sIdxVs[i], getIndicesForMsgNames(['salary.amount'], payslipAttributesStruct)[0]);
      witnessEq.addWitnessRef(sIdxVs[numPayslips], i);
      metaStmtsVerifier.addWitnessEquality(witnessEq);
    }

    const proofSpecVerifier = new ProofSpec(statementsVerifier, metaStmtsVerifier, verifierSetupParams);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    checkResult(proof.verify(proofSpecVerifier));
    console.timeEnd('Proof verify');
  }, 40000);
});
