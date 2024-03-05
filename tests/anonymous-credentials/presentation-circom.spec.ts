import { generateFieldElementFromNumber } from 'crypto-wasm-new';
import {
  CredentialSchema,
  DefaultSchemaParsingOpts,
  getR1CS,
  initializeWasm,
  META_SCHEMA_STR,
  ParsedR1CSFile,
  R1CSSnarkSetup,
  SUBJECT_STR
} from '../../src';
import { Credential, CredentialBuilder, PresentationBuilder, PublicKey, Scheme, SecretKey } from '../scheme';
import { checkResult, getWasmBytes, parseR1CSFile } from '../utils';

import { checkPresentationJson, getExampleSchema, getKeys, verifyCred } from './utils';

describe.each([true, false])(
  `${Scheme} Presentation creation and verification with Circom predicates with withSchemaRef=%s`,
  (withSchemaRef) => {
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

    const nonEmbeddedSchema = {
      $id: 'https://example.com?hash=abc123ff',
      [META_SCHEMA_STR]: 'http://json-schema.org/draft-07/schema#',
      type: 'object'
    };

    beforeAll(async () => {
      await initializeWasm();
      [sk, pk] = getKeys('seed1');

      let credSchema1: CredentialSchema, credSchema2: CredentialSchema;
      const schema1 = getExampleSchema(12);
      if (withSchemaRef) {
        credSchema1 = new CredentialSchema(nonEmbeddedSchema, DefaultSchemaParsingOpts, true, undefined, schema1);
      } else {
        credSchema1 = new CredentialSchema(schema1);
      }

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

      checkPresentationJson(pres1, [pk], undefined, pp, circomOutputs);

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

      checkPresentationJson(pres2, [pk], undefined, pp1, circomOutputs1);

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

      checkPresentationJson(pres1, [pk], undefined, pp, circomOutputs);
    });

    it('with predicate checking that all receipts are unique and amount is less than 1000', async () => {
      // Test for a scenario where a user wants to prove that he has 10 receipts where all are unique because they have
      // different ids and all have amounts less than 1000

      // If this is changed then the circuit should be changed as well
      const numReceipts = 10;

      const pkId1 = 'random1';
      const circuitId1 = 'random2';
      const pkId2 = 'random3';
      const circuitId2 = 'random4';

      const r1csForUnique = await parseR1CSFile('all_different_10.r1cs');
      const wasmForUnique = getWasmBytes('all_different_10.wasm');
      const snarkSetup = R1CSSnarkSetup.fromParsedR1CSFile(r1csForUnique, numReceipts);
      const provingKeyForUniqueness = snarkSetup.decompress();
      const verifyingKeyForUniqueness = snarkSetup.getVerifyingKeyUncompressed();

      const schema = CredentialSchema.essential();
      schema.properties[SUBJECT_STR] = {
        type: 'object',
        properties: {
          id: { type: 'string' },
          date: { type: 'string', format: 'date-time' },
          posId: { type: 'string' },
          amount: { type: 'number', minimum: 0.01, multipleOf: 0.01 }
        }
      };
      const cs = new CredentialSchema(schema);

      const maxAmount = 1000;
      const encodedMaxAmount = cs.encoder.encodeMessage('credentialSubject.amount', maxAmount);

      const credentials: Credential[] = [];
      for (let i = 0; i < numReceipts; i++) {
        const builder = new CredentialBuilder();
        builder.schema = cs;
        builder.subject = {
          id: 'e-123-987-1-22-' + (i + 1).toString(), // Unique id for each receipt
          date: `2023-09-14T1${i}:26:40.488Z`,
          posId: '1234567',
          amount: maxAmount - Math.ceil(Math.random() * 100)
        };
        expect(builder.subject.amount).toBeLessThan(maxAmount);
        credentials.push(builder.sign(sk));
        verifyCred(credentials[i], pk, sk);
      }

      const builder = new PresentationBuilder();

      const attrRefs: [number, string][] = [];
      for (let i = 0; i < numReceipts; i++) {
        builder.addCredential(credentials[i], pk);
        builder.markAttributesRevealed(i, new Set<string>(['credentialSubject.posId']));

        if (i == 0) {
          builder.enforceCircomPredicate(
            i,
            [['a', 'credentialSubject.amount']],
            [['b', encodedMaxAmount]],
            circuitId2,
            pkId2,
            r1csLtPub,
            wasmLtPub,
            provingKeyLtPub
          );
        } else {
          builder.enforceCircomPredicate(
            i,
            [['a', 'credentialSubject.amount']],
            [['b', encodedMaxAmount]],
            circuitId2,
            pkId2
          );
        }
        attrRefs.push([i, 'credentialSubject.id']);
      }
      builder.enforceCircomPredicateAcrossMultipleCredentials(
        [['in', attrRefs]],
        [],
        circuitId1,
        pkId1,
        r1csForUnique,
        wasmForUnique,
        provingKeyForUniqueness
      );

      const pres = builder.finalize();

      const pp = new Map();
      pp.set(pkId1, verifyingKeyForUniqueness);
      pp.set(PresentationBuilder.r1csParamId(circuitId1), getR1CS(r1csForUnique));
      pp.set(PresentationBuilder.wasmParamId(circuitId1), wasmForUnique);
      pp.set(pkId2, verifyingKeyLtPub);
      pp.set(PresentationBuilder.r1csParamId(circuitId2), getR1CS(r1csLtPub));
      pp.set(PresentationBuilder.wasmParamId(circuitId2), wasmLtPub);

      const circomOutputs = new Map();
      for (let i = 0; i < numReceipts; i++) {
        circomOutputs.set(i, [[generateFieldElementFromNumber(1)]]);
      }

      const circomOutputsMultiCred: Uint8Array[][] = [];
      circomOutputsMultiCred.push([generateFieldElementFromNumber(1)]);
      checkResult(
        pres.verify(Array(numReceipts).fill(pk), undefined, pp, circomOutputs, undefined, circomOutputsMultiCred)
      );
      checkPresentationJson(pres, Array(numReceipts).fill(pk), undefined, pp, circomOutputs, circomOutputsMultiCred);
    });

    it('with predicate checking that yearly income is less than 25000', async () => {
      // Test for a scenario where a user wants to prove that his yearly income is less than 25000 where his income comprises
      // of 12 payslip credentials, 1 for each month's.

      // If this is changed then the circuit should be changed as well
      const numPayslips = 12;

      const pkId = 'random1';
      const circuitId = 'random2';
      const r1cs = await parseR1CSFile('sum_12_less_than_public.r1cs');
      const wasm = getWasmBytes('sum_12_less_than_public.wasm');
      const snarkPk = R1CSSnarkSetup.fromParsedR1CSFile(r1cs, 12);
      const provingKey = snarkPk.decompress();
      const verifyingKey = snarkPk.getVerifyingKeyUncompressed();

      const schema = CredentialSchema.essential();
      schema.properties[SUBJECT_STR] = {
        type: 'object',
        properties: {
          fname: { type: 'string' },
          lname: { type: 'string' },
          employer: { type: 'string' },
          empId: { type: 'string' },
          salary: {
            type: 'object',
            properties: {
              paySlipId: { type: 'string' },
              year: { type: 'integer', minimum: 0 },
              month: { type: 'integer', minimum: 0 },
              amount: { type: 'number', minimum: 0.01, multipleOf: 0.01 }
            }
          }
        }
      };
      const cs = new CredentialSchema(schema);

      const maxSalary = 25000;
      const encodedMaxSalary = cs.encoder.encodeMessage('credentialSubject.salary.amount', maxSalary);

      const credentials: Credential[] = [];
      for (let i = 0; i < numPayslips; i++) {
        const builder = new CredentialBuilder();
        builder.schema = cs;
        builder.subject = {
          fname: 'John',
          lname: 'Smith',
          employer: 'Acme Corp',
          empId: 'e-123-987-1',
          salary: {
            paySlipId: 'e-123-987-1-22-' + (i + 1).toString(),
            year: 2022,
            month: i + 1,
            amount: Math.ceil(maxSalary / 12 - Math.random() * 100)
          }
        };
        expect(builder.subject.salary.amount).toBeLessThan(maxSalary);
        credentials.push(builder.sign(sk));
        verifyCred(credentials[i], pk, sk);
      }

      const builder = new PresentationBuilder();
      const attrRefs: [number, string][] = [];

      for (let i = 0; i < numPayslips; i++) {
        builder.addCredential(credentials[i], pk);
        builder.markAttributesRevealed(i, new Set<string>(['credentialSubject.salary.year']));
        builder.markAttributesRevealed(i, new Set<string>(['credentialSubject.salary.month']));
        attrRefs.push([i, 'credentialSubject.salary.amount']);
      }
      builder.enforceCircomPredicateAcrossMultipleCredentials(
        [['in', attrRefs]],
        [['max', encodedMaxSalary]],
        circuitId,
        pkId,
        r1cs,
        wasm,
        provingKey
      );

      const pres = builder.finalize();

      const pp = new Map();
      pp.set(pkId, verifyingKey);
      pp.set(PresentationBuilder.r1csParamId(circuitId), getR1CS(r1cs));
      pp.set(PresentationBuilder.wasmParamId(circuitId), wasm);

      const circomOutputsMultiCred: Uint8Array[][] = [];
      circomOutputsMultiCred.push([generateFieldElementFromNumber(1)]);
      checkResult(
        pres.verify(Array(numPayslips).fill(pk), undefined, pp, undefined, undefined, circomOutputsMultiCred)
      );
      checkPresentationJson(pres, Array(numPayslips).fill(pk), undefined, pp, undefined, circomOutputsMultiCred);
    });

    it('with predicate checking that difference between total assets and total liabilities is more than 10000', async () => {
      // Test for a scenario where a user have 20 assets and liabilities, in different credentials. The user
      // proves that the sum of his assets is greater than sum of liabilities by 10000 without revealing actual values of either.

      const numAssetCredentials = 4; // Circuit supports 20 assets, and each asset above has 5 values so 4 credentials (5*4=20)
      const numLiabilityCredentials = 5; // Circuit supports 20 liabilities, and each liability above has 4 values so 5 credentials (5*4=20)

      const pkId = 'random1';
      const circuitId = 'random2';
      const r1cs = await parseR1CSFile('difference_of_array_sum_20_20.r1cs');
      const wasm = getWasmBytes('difference_of_array_sum_20_20.wasm');
      const snarkPk = R1CSSnarkSetup.fromParsedR1CSFile(r1cs, 40);
      const provingKey = snarkPk.decompress();
      const verifyingKey = snarkPk.getVerifyingKeyUncompressed();

      const assetSchema = CredentialSchema.essential();
      assetSchema.properties[SUBJECT_STR] = {
        type: 'object',
        properties: {
          fname: { type: 'string' },
          lname: { type: 'string' },
          id: { type: 'string' },
          assets: {
            type: 'object',
            properties: {
              id1: { type: 'integer', minimum: 0 },
              id2: { type: 'integer', minimum: 0 },
              id3: { type: 'integer', minimum: 0 },
              id4: { type: 'integer', minimum: 0 },
              id5: { type: 'integer', minimum: 0 }
            }
          }
        }
      };
      const assetCs = new CredentialSchema(assetSchema);

      const liabSchema = CredentialSchema.essential();
      liabSchema.properties[SUBJECT_STR] = {
        type: 'object',
        properties: {
          fname: { type: 'string' },
          lname: { type: 'string' },
          id: { type: 'string' },
          liabilities: {
            type: 'object',
            properties: {
              id1: { type: 'integer', minimum: 0 },
              id2: { type: 'integer', minimum: 0 },
              id3: { type: 'integer', minimum: 0 },
              id4: { type: 'integer', minimum: 0 }
            }
          }
        }
      };
      const liabCs = new CredentialSchema(liabSchema);

      const minDiff = 10000;
      const encodedMinDiff = assetCs.encoder.encodeMessage('credentialSubject.assets.id1', minDiff);

      const assetCreds: Credential[] = [];
      for (let i = 0; i < numAssetCredentials; i++) {
        const builder = new CredentialBuilder();
        builder.schema = assetCs;
        builder.subject = {
          fname: 'John',
          lname: 'Smith',
          id: `aid-${i}`,
          assets: {
            id1: (i + 1) * 10000,
            id2: (i + 2) * 10000,
            id3: (i + 3) * 10000,
            id4: (i + 4) * 10000,
            id5: (i + 5) * 10000
          }
        };
        assetCreds.push(builder.sign(sk));
        verifyCred(assetCreds[i], pk, sk);
      }

      const liabCreds: Credential[] = [];
      for (let i = 0; i < numLiabilityCredentials; i++) {
        const builder = new CredentialBuilder();
        builder.schema = liabCs;
        builder.subject = {
          fname: 'John',
          lname: 'Smith',
          id: `lid-${i}`,
          liabilities: {
            id1: (i + 1) * 100,
            id2: (i + 2) * 100,
            id3: (i + 3) * 100,
            id4: (i + 4) * 100
          }
        };
        liabCreds.push(builder.sign(sk));
        verifyCred(liabCreds[i], pk, sk);
      }

      const builder = new PresentationBuilder();
      const assetAttrRefs: [number, string][] = [];
      const liabAttrRefs: [number, string][] = [];
      for (let i = 0; i < numAssetCredentials; i++) {
        builder.addCredential(assetCreds[i], pk);
        for (let j = 0; j < 5; j++) {
          assetAttrRefs.push([i, `credentialSubject.assets.id${j + 1}`]);
        }
      }
      for (let i = 0; i < numLiabilityCredentials; i++) {
        builder.addCredential(liabCreds[i], pk);
        for (let j = 0; j < 4; j++) {
          liabAttrRefs.push([numAssetCredentials + i, `credentialSubject.liabilities.id${j + 1}`]);
        }
      }

      builder.enforceCircomPredicateAcrossMultipleCredentials(
        [
          ['inA', assetAttrRefs],
          ['inB', liabAttrRefs]
        ],
        [['min', encodedMinDiff]],
        circuitId,
        pkId,
        r1cs,
        wasm,
        provingKey
      );

      const pres = builder.finalize();

      const pp = new Map();
      pp.set(pkId, verifyingKey);
      pp.set(PresentationBuilder.r1csParamId(circuitId), getR1CS(r1cs));
      pp.set(PresentationBuilder.wasmParamId(circuitId), wasm);

      const circomOutputsMultiCred: Uint8Array[][] = [];
      circomOutputsMultiCred.push([generateFieldElementFromNumber(1)]);
      checkResult(
        pres.verify(
          Array(numAssetCredentials + numLiabilityCredentials).fill(pk),
          undefined,
          pp,
          undefined,
          undefined,
          circomOutputsMultiCred
        )
      );

      checkPresentationJson(pres, Array(numAssetCredentials + numLiabilityCredentials).fill(pk), undefined, pp, undefined, circomOutputsMultiCred);
    });
  }
);
