import { generateFieldElementFromNumber, initializeWasm } from '@docknetwork/crypto-wasm';
import {
  CredentialSchema,
  ParsedR1CSFile,
  R1CSSnarkSetup,
  getR1CS
} from '../../src';
import {
  SignatureParams,
  KeyPair,
  SecretKey,
  PublicKey,
  CredentialBuilder,
  Credential,
  PresentationBuilder,
  SignatureLabelBytes,
} from '../scheme'

import { getExampleSchema } from './utils';
import { checkResult, getWasmBytes, parseR1CSFile } from '../utils';

describe('Presentation creation and verification with Circom predicates', () => {
  let sk: SecretKey, pk: PublicKey;

  let credential1: Credential;
  let credential2: Credential;

  const requiredGrades = ['A+', 'A', 'B+', 'B', 'C'];

  // R1CS, WASM and keys for circuit set_membership_5_public
  let r1csGrade: ParsedR1CSFile;
  let wasmGrade: Uint8Array;
  let provingKeyGrade;
  let verifyingKeyGrade;

  // R1CS, WASM and keys for circuit less_than_public_64
  let r1csLtPub: ParsedR1CSFile;
  let wasmLtPub: Uint8Array;
  let provingKeyLtPub;
  let verifyingKeyLtPub;

  beforeAll(async () => {
    await initializeWasm();
    const params = SignatureParams.generate(100, SignatureLabelBytes);
    const keypair = KeyPair.generate(params);
    sk = keypair.sk;
    pk = keypair.pk;

    const schema1 = getExampleSchema(12);
    const credSchema1 = new CredentialSchema(schema1);
    const builder1 = new CredentialBuilder();
    builder1.schema = credSchema1;
    builder1.subject = {
      fname: 'John',
      lname: 'Smith',
      education: {
        score1: 55,
        score2: 60,
        score3: 45,
        grade: 'B+'
      }
    };
    credential1 = builder1.sign(sk);

    const builder2 = new CredentialBuilder();
    builder2.schema = credSchema1;
    builder2.subject = {
      fname: 'Bob',
      lname: 'Smith',
      education: {
        score1: 35,
        score2: 20,
        score3: 25,
        grade: 'E'
      }
    };
    credential2 = builder2.sign(sk);

    r1csGrade = await parseR1CSFile('set_membership_5_public.r1cs');
    wasmGrade = getWasmBytes('set_membership_5_public.wasm');
    let prk = R1CSSnarkSetup.fromParsedR1CSFile(r1csGrade, 1);
    provingKeyGrade = prk.decompress();
    verifyingKeyGrade = prk.getVerifyingKeyUncompressed();

    r1csLtPub = await parseR1CSFile('less_than_public_64.r1cs');
    wasmLtPub = getWasmBytes('less_than_public_64.wasm');
    prk = R1CSSnarkSetup.fromParsedR1CSFile(r1csLtPub, 1);
    provingKeyLtPub = prk.decompress();
    verifyingKeyLtPub = prk.getVerifyingKeyUncompressed();
  });

  it('with predicate checking that grade is or is not from a required set', () => {
    const pkId = 'random1';
    const circuitId = 'random2';

    const encodedGrades = requiredGrades.map((g: string) =>
      credential1.schema.encoder.encodeMessage('credentialSubject.education.grade', g)
    );

    // Test that the `grade` attribute in credential does belong to the set `requiredGrades`
    const builder1 = new PresentationBuilder();
    builder1.addCredential(credential1, pk);
    builder1.markAttributesRevealed(0, new Set<string>(['credentialSubject.fname']));
    builder1.enforceCircomPredicate(
      0,
      [['x', 'credentialSubject.education.grade']],
      [['set', encodedGrades]],
      circuitId,
      pkId,
      r1csGrade,
      wasmGrade,
      provingKeyGrade
    );

    const pres1 = builder1.finalize();

    // Verifier should check that the spec has the required predicates and also check the variable names are mapped
    // to the correct attributes
    expect(pres1.spec.credentials[0].circomPredicates?.length).toEqual(1);
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[0].privateVars.length).toEqual(1);
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[0].privateVars[0]).toEqual({
      varName: 'x',
      attributeName: { credentialSubject: { education: { grade: null } } }
    });
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[0].publicVars.length).toEqual(1);
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[0].publicVars[0].varName).toEqual('set');
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[0].publicVars[0].value).toEqual(encodedGrades);

    const pp = new Map();
    pp.set(pkId, verifyingKeyGrade);
    pp.set(PresentationBuilder.r1csParamId(circuitId), getR1CS(r1csGrade));
    pp.set(PresentationBuilder.wasmParamId(circuitId), wasmGrade);

    // Set output variable for circuit.
    // The output is set to "1" because the grade does belong to the required set
    const circomOutputs = new Map();
    circomOutputs.set(0, [[generateFieldElementFromNumber(1)]]);
    checkResult(pres1.verify([pk], undefined, pp, circomOutputs));

    // Setting the output variable "0" would fail the proof verification because the grade does belong to the required set
    let wrongCircomOutputs = new Map();
    wrongCircomOutputs.set(0, [[generateFieldElementFromNumber(0)]]);
    expect(pres1.verify([pk], undefined, pp, wrongCircomOutputs).verified).toBe(false);

    // Test that the `grade` attribute in credential does not belong to the set `requiredGrades`
    const builder2 = new PresentationBuilder();
    builder2.addCredential(credential2, pk);
    builder2.markAttributesRevealed(0, new Set<string>(['credentialSubject.fname']));
    builder2.enforceCircomPredicate(
      0,
      [['x', 'credentialSubject.education.grade']],
      [['set', encodedGrades]],
      circuitId,
      pkId,
      r1csGrade,
      wasmGrade,
      provingKeyGrade
    );

    const pres2 = builder2.finalize();

    // Verifier should check that the spec has the required predicates and also check the variable names are mapped
    // to the correct attributes
    expect(pres2.spec.credentials[0].circomPredicates?.length).toEqual(1);
    // @ts-ignore
    expect(pres2.spec.credentials[0].circomPredicates[0].privateVars.length).toEqual(1);
    // @ts-ignore
    expect(pres2.spec.credentials[0].circomPredicates[0].privateVars[0]).toEqual({
      varName: 'x',
      attributeName: { credentialSubject: { education: { grade: null } } }
    });
    // @ts-ignore
    expect(pres2.spec.credentials[0].circomPredicates[0].publicVars.length).toEqual(1);
    // @ts-ignore
    expect(pres2.spec.credentials[0].circomPredicates[0].publicVars[0].varName).toEqual('set');
    // @ts-ignore
    expect(pres2.spec.credentials[0].circomPredicates[0].publicVars[0].value).toEqual(encodedGrades);

    const pp1 = new Map();
    pp1.set(pkId, verifyingKeyGrade);
    pp1.set(PresentationBuilder.r1csParamId(circuitId), getR1CS(r1csGrade));
    pp1.set(PresentationBuilder.wasmParamId(circuitId), wasmGrade);

    // Set output variable for circuit.
    // The output is set to "0" because the grade does belong to the required set
    const circomOutputs1 = new Map();
    circomOutputs1.set(0, [[generateFieldElementFromNumber(0)]]);
    checkResult(pres2.verify([pk], undefined, pp1, circomOutputs1));

    // Setting the output variable "1" would fail the proof verification because the grade does not belong to the required set
    wrongCircomOutputs = new Map();
    wrongCircomOutputs.set(0, [[generateFieldElementFromNumber(1)]]);
    expect(pres2.verify([pk], undefined, pp1, wrongCircomOutputs).verified).toBe(false);
  });

  it('with predicate checking that grade is from a required set and certain scores are higher than required', () => {
    const pkId1 = 'random1';
    const circuitId1 = 'random2';
    const pkId2 = 'random3';
    const circuitId2 = 'random4';

    const encodedGrades = requiredGrades.map((g: string) =>
      credential1.schema.encoder.encodeMessage('credentialSubject.education.grade', g)
    );

    // Test that the `grade` attribute in credential does belong to the set `requiredGrades` and both `score1` and `score2` are >= 50
    const encoded50 = generateFieldElementFromNumber(50);

    const builder1 = new PresentationBuilder();
    builder1.addCredential(credential1, pk);
    builder1.markAttributesRevealed(0, new Set<string>(['credentialSubject.fname']));
    builder1.enforceCircomPredicate(
      0,
      [['x', 'credentialSubject.education.grade']],
      [['set', encodedGrades]],
      circuitId1,
      pkId1,
      r1csGrade,
      wasmGrade,
      provingKeyGrade
    );
    builder1.enforceCircomPredicate(
      0,
      [['a', 'credentialSubject.education.score1']],
      [['b', encoded50]],
      circuitId2,
      pkId2,
      r1csLtPub,
      wasmLtPub,
      provingKeyLtPub
    );
    builder1.enforceCircomPredicate(
      0,
      [['a', 'credentialSubject.education.score2']],
      [['b', encoded50]],
      circuitId2,
      pkId2
    );

    const pres1 = builder1.finalize();

    // Verifier should check that the spec has the required predicates and also check the variable names are mapped
    // to the correct attributes
    expect(pres1.spec.credentials[0].circomPredicates?.length).toEqual(3);
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[0].privateVars.length).toEqual(1);
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[0].privateVars[0]).toEqual({
      varName: 'x',
      attributeName: { credentialSubject: { education: { grade: null } } }
    });
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[0].publicVars.length).toEqual(1);
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[0].publicVars[0].varName).toEqual('set');
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[0].publicVars[0].value).toEqual(encodedGrades);

    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[1].privateVars.length).toEqual(1);
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[1].privateVars[0]).toEqual({
      varName: 'a',
      attributeName: { credentialSubject: { education: { score1: null } } }
    });
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[1].publicVars.length).toEqual(1);
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[1].publicVars[0].varName).toEqual('b');
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[1].publicVars[0].value).toEqual(encoded50);

    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[2].privateVars.length).toEqual(1);
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[2].privateVars[0]).toEqual({
      varName: 'a',
      attributeName: { credentialSubject: { education: { score2: null } } }
    });
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[2].publicVars.length).toEqual(1);
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[2].publicVars[0].varName).toEqual('b');
    // @ts-ignore
    expect(pres1.spec.credentials[0].circomPredicates[2].publicVars[0].value).toEqual(encoded50);

    const pp = new Map();
    pp.set(pkId1, verifyingKeyGrade);
    pp.set(PresentationBuilder.r1csParamId(circuitId1), getR1CS(r1csGrade));
    pp.set(PresentationBuilder.wasmParamId(circuitId1), wasmGrade);
    pp.set(pkId2, verifyingKeyLtPub);
    pp.set(PresentationBuilder.r1csParamId(circuitId2), getR1CS(r1csLtPub));
    pp.set(PresentationBuilder.wasmParamId(circuitId2), wasmLtPub);

    const circomOutputs = new Map();
    // Setting last 2 outputs to 0 as the circuit will output 1 when the private input (`score` attribute) is less than the public input (50 here) else 0.
    // Here the prover is proving that the private input is greater than or equal to 50
    circomOutputs.set(0, [
      [generateFieldElementFromNumber(1)],
      [generateFieldElementFromNumber(0)],
      [generateFieldElementFromNumber(0)]
    ]);
    checkResult(pres1.verify([pk], undefined, pp, circomOutputs));
  });
});
