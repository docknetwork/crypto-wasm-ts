import { initializeWasm } from '@docknetwork/crypto-wasm';
import { checkResult, stringToBytes } from '../../utils';
import {
  CompositeProofG1,
  createWitnessEqualityMetaStatement,
  Encoder,
  encodeRevealedMsgs,
  getAdaptedSignatureParamsForMessages,
  getIndicesForMsgNames,
  getRevealedAndUnrevealed,
  isValidMsgStructure,
  BBSKeypair,
  MetaStatements,
  ProofSpecG1,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses,
  BBSSignatureParams
} from '../../../src';
import {
  attributes1,
  attributes1Struct,
  attributes2,
  attributes2Struct,
  attributes3,
  attributes3Struct,
  defaultEncoder
} from './data-and-encoder';
import { checkMapsEqual, signedToHex } from './index';

describe('Signing and proof of knowledge of BBS+ signature', () => {
  // NOTE: The following tests contain a lot of duplicated code but that is intentional as this code is for illustration purpose.

  beforeAll(async () => {
    // Load the WASM module
    await initializeWasm();
  });

  it('signing and proof of knowledge of a signature', () => {
    // This test check that a single signature can be produced and verified and proof of knowledge of signature can be
    // done while revealing only some attributes (selective-disclosure). Nested attributes are separated by a "dot" (.)

    const label = stringToBytes('Sig params label - this is public');
    // Message count shouldn't matter as `label` is known
    let params = BBSSignatureParams.generate(1, label);
    const keypair = BBSKeypair.generate(params);
    const sk = keypair.secretKey;
    const pk = keypair.publicKey;

    // The encoder has to be known and agreed upon by all system participants, i.e. signer, prover and verifier.
    const encoder = new Encoder(undefined, defaultEncoder);

    let i = 1;
    for (const [attributes, attributesStruct, revealedAttributeNames] of [
      [attributes1, attributes1Struct, ['fname', 'country']],
      [attributes2, attributes2Struct, ['lname', 'location.country', 'physical.weight']],
      [
        attributes3,
        attributes3Struct,
        ['fname', 'lessSensitive.department.name', 'lessSensitive.department.location.name']
      ]
    ]) {
      expect(isValidMsgStructure(attributes, attributesStruct)).toEqual(true);

      const signed = BBSSignatureParams.signMessageObject(attributes, sk, label, encoder);
      checkResult(BBSSignatureParams.verifyMessageObject(attributes, signed.signature, pk, label, encoder));

      // For debugging
      console.log(signedToHex(signed));

      const revealedNames = new Set<string>();
      // @ts-ignore
      revealedAttributeNames.forEach((n: string) => {
        revealedNames.add(n);
      });

      // Both prover and verifier can independently create this struct
      const sigParams = getAdaptedSignatureParamsForMessages(params, attributesStruct);

      // Prover prepares messages it wishes to reveal and hide.

      const [revealedMsgs, unrevealedMsgs, revealedMsgsRaw] = getRevealedAndUnrevealed(
        attributes,
        revealedNames,
        encoder
      );

      // `revealedMsgsRaw` contains the messages being revealed without the values being encoded. The idea is for the
      // verifier to encode it independently.
      if (i == 1) {
        expect(revealedMsgsRaw).toEqual({ fname: 'John', country: 'USA' });
      }

      if (i == 2) {
        expect(revealedMsgsRaw).toEqual({
          lname: 'Smith',
          location: {
            country: 'USA'
          },
          physical: {
            weight: 210
          }
        });
      }

      if (i == 3) {
        expect(revealedMsgsRaw).toEqual({
          fname: 'John',
          lessSensitive: {
            department: {
              name: 'Random',
              location: {
                name: 'Somewhere'
              }
            }
          }
        });
      }

      const statement1 = Statement.bbsSignature(sigParams, pk, revealedMsgs, false);
      const statementsProver = new Statements();
      statementsProver.add(statement1);

      // The prover should independently construct this `ProofSpec`
      const proofSpecProver = new ProofSpecG1(statementsProver, new MetaStatements());
      expect(proofSpecProver.isValid()).toEqual(true);

      const witness1 = Witness.bbsSignature(signed.signature, unrevealedMsgs, false);
      const witnesses = new Witnesses();
      witnesses.add(witness1);

      const proof = CompositeProofG1.generate(proofSpecProver, witnesses);
      // For debugging
      console.log(proof.hex);

      // Verifier independently encodes revealed messages
      const revealedMsgsFromVerifier = encodeRevealedMsgs(revealedMsgsRaw, attributesStruct, encoder);
      checkMapsEqual(revealedMsgs, revealedMsgsFromVerifier);

      const statement2 = Statement.bbsSignature(sigParams, pk, revealedMsgsFromVerifier, false);
      const statementsVerifier = new Statements();
      statementsVerifier.add(statement2);

      // The verifier should independently construct this `ProofSpec`
      const proofSpecVerifier = new ProofSpecG1(statementsVerifier, new MetaStatements());
      expect(proofSpecVerifier.isValid()).toEqual(true);

      checkResult(proof.verify(proofSpecVerifier));

      i++;
    }
  });

  it('signing and proof of knowledge of 2 signatures', () => {
    // This test check that 2 signatures can be produced and verified and proof of knowledge of both signatures can be
    // done while revealing only some attributes (selective-disclosure) from each signature.
    // Nested attributes are separated by a "dot" (.)

    // 1st signer's setup
    const label1 = stringToBytes('Sig params label 1');
    // Message count shouldn't matter as `label1` is known
    let params1 = BBSSignatureParams.generate(1, label1);
    const keypair1 = BBSKeypair.generate(params1);
    const sk1 = keypair1.secretKey;
    const pk1 = keypair1.publicKey;

    // 2nd signer's setup
    const label2 = stringToBytes('Sig params label 2');
    // Message count shouldn't matter as `label2` is known
    let params2 = BBSSignatureParams.generate(1, label2);
    const keypair2 = BBSKeypair.generate(params2);
    const sk2 = keypair2.secretKey;
    const pk2 = keypair2.publicKey;

    const encoder = new Encoder(undefined, defaultEncoder);

    // Sign and verify all signatures
    const signed1 = BBSSignatureParams.signMessageObject(attributes1, sk1, label1, encoder);
    checkResult(BBSSignatureParams.verifyMessageObject(attributes1, signed1.signature, pk1, label1, encoder));

    const signed2 = BBSSignatureParams.signMessageObject(attributes2, sk2, label2, encoder);
    checkResult(BBSSignatureParams.verifyMessageObject(attributes2, signed2.signature, pk2, label2, encoder));

    // Reveal
    // - first name ("fname" attribute) from both sets of signed attributes
    // - attributes "BMI" and "country" from 1st signed attribute set
    // - attributes "location.country", "physical.BMI" and "score" from 2nd signed attribute set

    const revealedNames1 = new Set<string>();
    revealedNames1.add('fname');
    revealedNames1.add('BMI');
    revealedNames1.add('country');

    const revealedNames2 = new Set<string>();
    revealedNames2.add('fname');
    revealedNames2.add('location.country');
    revealedNames2.add('physical.BMI');
    revealedNames2.add('score');

    // Both prover and verifier can independently create this struct
    const sigParams1 = getAdaptedSignatureParamsForMessages(params1, attributes1Struct);
    const sigParams2 = getAdaptedSignatureParamsForMessages(params2, attributes2Struct);

    const [revealedMsgs1, unrevealedMsgs1, revealedMsgsRaw1] = getRevealedAndUnrevealed(
      attributes1,
      revealedNames1,
      encoder
    );
    expect(revealedMsgsRaw1).toEqual({ fname: 'John', BMI: 23.25, country: 'USA' });

    const statement1 = Statement.bbsSignature(sigParams1, pk1, revealedMsgs1, false);

    const [revealedMsgs2, unrevealedMsgs2, revealedMsgsRaw2] = getRevealedAndUnrevealed(
      attributes2,
      revealedNames2,
      encoder
    );
    expect(revealedMsgsRaw2).toEqual({
      fname: 'John',
      location: {
        country: 'USA'
      },
      physical: {
        BMI: 23.25
      },
      score: -13.5
    });

    const statement2 = Statement.bbsSignature(sigParams2, pk2, revealedMsgs2, false);

    const statementsProver = new Statements();
    statementsProver.add(statement1);
    statementsProver.add(statement2);

    // The prover should independently construct this `ProofSpec`
    const proofSpecProver = new ProofSpecG1(statementsProver, new MetaStatements());
    expect(proofSpecProver.isValid()).toEqual(true);

    const witness1 = Witness.bbsSignature(signed1.signature, unrevealedMsgs1, false);
    const witness2 = Witness.bbsSignature(signed2.signature, unrevealedMsgs2, false);
    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);

    const proof = CompositeProofG1.generate(proofSpecProver, witnesses);

    // Verifier independently encodes revealed messages
    const revealedMsgs1FromVerifier = encodeRevealedMsgs(revealedMsgsRaw1, attributes1Struct, encoder);
    checkMapsEqual(revealedMsgs1, revealedMsgs1FromVerifier);
    const revealedMsgs2FromVerifier = encodeRevealedMsgs(revealedMsgsRaw2, attributes2Struct, encoder);
    checkMapsEqual(revealedMsgs2, revealedMsgs2FromVerifier);

    const statement3 = Statement.bbsSignature(sigParams1, pk1, revealedMsgs1FromVerifier, false);
    const statement4 = Statement.bbsSignature(sigParams2, pk2, revealedMsgs2FromVerifier, false);
    const statementsVerifier = new Statements();
    statementsVerifier.add(statement3);
    statementsVerifier.add(statement4);

    // The verifier should independently construct this `ProofSpec`
    const proofSpecVerifier = new ProofSpecG1(statementsVerifier, new MetaStatements());
    expect(proofSpecVerifier.isValid()).toEqual(true);

    checkResult(proof.verify(proofSpecVerifier));
  });

  it('signing and proof of knowledge of 3 signatures and attribute equality', () => {
    // This test check that a multiple signatures created by different signers can be verified and proof of knowledge of
    // signatures can be done selective-disclosure while also proving equality between some of the hidden attributes.

    // 1st signer's setup
    const label1 = stringToBytes('Sig params label 1');
    // Message count shouldn't matter as `label1` is known
    let params1 = BBSSignatureParams.generate(1, label1);
    const keypair1 = BBSKeypair.generate(params1);
    const sk1 = keypair1.secretKey;
    const pk1 = keypair1.publicKey;

    // 2nd signer's setup
    const label2 = stringToBytes('Sig params label 2');
    // Message count shouldn't matter as `label2` is known
    let params2 = BBSSignatureParams.generate(1, label2);
    const keypair2 = BBSKeypair.generate(params2);
    const sk2 = keypair2.secretKey;
    const pk2 = keypair2.publicKey;

    // 3rd signer's setup
    const label3 = stringToBytes('Sig params label 3');
    // Message count shouldn't matter as `label3` is known
    let params3 = BBSSignatureParams.generate(1, label3);
    const keypair3 = BBSKeypair.generate(params3);
    const sk3 = keypair3.secretKey;
    const pk3 = keypair3.publicKey;

    const encoder = new Encoder(undefined, defaultEncoder);

    // Sign and verify all signatures
    const signed1 = BBSSignatureParams.signMessageObject(attributes1, sk1, label1, encoder);
    checkResult(BBSSignatureParams.verifyMessageObject(attributes1, signed1.signature, pk1, label1, encoder));

    const signed2 = BBSSignatureParams.signMessageObject(attributes2, sk2, label2, encoder);
    checkResult(BBSSignatureParams.verifyMessageObject(attributes2, signed2.signature, pk2, label2, encoder));

    const signed3 = BBSSignatureParams.signMessageObject(attributes3, sk3, label3, encoder);
    checkResult(BBSSignatureParams.verifyMessageObject(attributes3, signed3.signature, pk3, label3, encoder));

    // Reveal
    // - first name ("fname" attribute) from all 3 sets of signed attributes
    // - attributes "BMI" and "country" from 1st signed attribute set
    // - attributes "location.country" and "physical.BMI" from 2nd signed attribute set
    // - attributes "lessSensitive.location.country", "lessSensitive.department.name", "lessSensitive.department.location.name" and "rank" from 3rd signed attribute set

    // Prove equality in zero knowledge of
    // - last name ("lname" attribute), Social security number ("SSN" attribute) and city in all 3 sets of signed attributes
    // - attributes "email", "score", "height" and "weight" in 1st and 2nd sets of signed attributes
    // - attributes "user-id" and "employee-id" in 2nd and 3rd set of attributes

    const revealedNames1 = new Set<string>();
    revealedNames1.add('fname');
    revealedNames1.add('BMI');
    revealedNames1.add('country');

    const revealedNames2 = new Set<string>();
    revealedNames2.add('fname');
    revealedNames2.add('location.country');
    revealedNames2.add('physical.BMI');

    const revealedNames3 = new Set<string>();
    revealedNames3.add('fname');
    revealedNames3.add('lessSensitive.location.country');
    revealedNames3.add('lessSensitive.department.name');
    revealedNames3.add('lessSensitive.department.location.name');
    revealedNames3.add('rank');

    // Both prover and verifier can independently create this struct
    const sigParams1 = getAdaptedSignatureParamsForMessages(params1, attributes1Struct);
    const sigParams2 = getAdaptedSignatureParamsForMessages(params2, attributes2Struct);
    const sigParams3 = getAdaptedSignatureParamsForMessages(params3, attributes3Struct);

    const [revealedMsgs1, unrevealedMsgs1, revealedMsgsRaw1] = getRevealedAndUnrevealed(
      attributes1,
      revealedNames1,
      encoder
    );
    expect(revealedMsgsRaw1).toEqual({ fname: 'John', BMI: 23.25, country: 'USA' });

    const statement1 = Statement.bbsSignature(sigParams1, pk1, revealedMsgs1, false);

    const [revealedMsgs2, unrevealedMsgs2, revealedMsgsRaw2] = getRevealedAndUnrevealed(
      attributes2,
      revealedNames2,
      encoder
    );
    expect(revealedMsgsRaw2).toEqual({
      fname: 'John',
      location: {
        country: 'USA'
      },
      physical: {
        BMI: 23.25
      }
    });

    const statement2 = Statement.bbsSignature(sigParams2, pk2, revealedMsgs2, false);

    const [revealedMsgs3, unrevealedMsgs3, revealedMsgsRaw3] = getRevealedAndUnrevealed(
      attributes3,
      revealedNames3,
      encoder
    );
    expect(revealedMsgsRaw3).toEqual({
      fname: 'John',
      lessSensitive: {
        location: {
          country: 'USA'
        },
        department: {
          name: 'Random',
          location: {
            name: 'Somewhere'
          }
        }
      },
      rank: 6
    });

    const statement3 = Statement.bbsSignature(sigParams3, pk3, revealedMsgs3, false);

    const statementsProver = new Statements();
    const sIdx1 = statementsProver.add(statement1);
    const sIdx2 = statementsProver.add(statement2);
    const sIdx3 = statementsProver.add(statement3);

    // Construct new `MetaStatement`s to enforce attribute equality

    // One approach is to get indices for attribute names and then construct a `WitnessEqualityMetaStatement` as follows
    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(sIdx1, getIndicesForMsgNames(['lname'], attributes1Struct)[0]);
    witnessEq1.addWitnessRef(sIdx2, getIndicesForMsgNames(['lname'], attributes2Struct)[0]);
    witnessEq1.addWitnessRef(sIdx3, getIndicesForMsgNames(['lname'], attributes3Struct)[0]);

    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(sIdx1, getIndicesForMsgNames(['city'], attributes1Struct)[0]);
    witnessEq2.addWitnessRef(sIdx2, getIndicesForMsgNames(['location.city'], attributes2Struct)[0]);
    witnessEq2.addWitnessRef(sIdx3, getIndicesForMsgNames(['lessSensitive.location.city'], attributes3Struct)[0]);

    // Another approach is to construct `WitnessEqualityMetaStatement` directly as follows
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
        m.set(sIdx1, [['email'], attributes1Struct]);
        m.set(sIdx2, [['sensitive.email'], attributes2Struct]);
        return m;
      })()
    );

    const witnessEq5 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx1, [['score'], attributes1Struct]);
        m.set(sIdx2, [['score'], attributes2Struct]);
        return m;
      })()
    );

    const witnessEq6 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx1, [['height'], attributes1Struct]);
        m.set(sIdx2, [['physical.height'], attributes2Struct]);
        return m;
      })()
    );

    const witnessEq7 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx1, [['weight'], attributes1Struct]);
        m.set(sIdx2, [['physical.weight'], attributes2Struct]);
        return m;
      })()
    );

    const witnessEq9 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx2, [['sensitive.user-id'], attributes2Struct]);
        m.set(sIdx3, [['sensitive.employee-id'], attributes3Struct]);
        return m;
      })()
    );

    // NOTE: Both of the above approaches are in-efficient where they repeatedly flatten the same objects. An efficient way
    // would be to flatten the objects just once and get indices for all names but the above approach is simpler to code with.

    const metaStmtsProver = new MetaStatements();
    metaStmtsProver.addWitnessEquality(witnessEq1);
    metaStmtsProver.addWitnessEquality(witnessEq2);
    metaStmtsProver.addWitnessEquality(witnessEq3);
    metaStmtsProver.addWitnessEquality(witnessEq4);
    metaStmtsProver.addWitnessEquality(witnessEq5);
    metaStmtsProver.addWitnessEquality(witnessEq6);
    metaStmtsProver.addWitnessEquality(witnessEq7);
    metaStmtsProver.addWitnessEquality(witnessEq9);

    // The prover should independently construct this `ProofSpec`
    const proofSpecProver = new ProofSpecG1(statementsProver, metaStmtsProver);
    expect(proofSpecProver.isValid()).toEqual(true);

    const witness1 = Witness.bbsSignature(signed1.signature, unrevealedMsgs1, false);
    const witness2 = Witness.bbsSignature(signed2.signature, unrevealedMsgs2, false);
    const witness3 = Witness.bbsSignature(signed3.signature, unrevealedMsgs3, false);
    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);
    witnesses.add(witness3);

    const proof = CompositeProofG1.generate(proofSpecProver, witnesses);

    // Verifier independently encodes revealed messages
    const revealedMsgs1FromVerifier = encodeRevealedMsgs(revealedMsgsRaw1, attributes1Struct, encoder);
    checkMapsEqual(revealedMsgs1, revealedMsgs1FromVerifier);
    const revealedMsgs2FromVerifier = encodeRevealedMsgs(revealedMsgsRaw2, attributes2Struct, encoder);
    checkMapsEqual(revealedMsgs2, revealedMsgs2FromVerifier);
    const revealedMsgs3FromVerifier = encodeRevealedMsgs(revealedMsgsRaw3, attributes3Struct, encoder);
    checkMapsEqual(revealedMsgs3, revealedMsgs3FromVerifier);

    const statement4 = Statement.bbsSignature(sigParams1, pk1, revealedMsgs1FromVerifier, false);
    const statement5 = Statement.bbsSignature(sigParams2, pk2, revealedMsgs2FromVerifier, false);
    const statement6 = Statement.bbsSignature(sigParams3, pk3, revealedMsgs3FromVerifier, false);
    const statementsVerifier = new Statements();
    const sIdx4 = statementsVerifier.add(statement4);
    const sIdx5 = statementsVerifier.add(statement5);
    const sIdx6 = statementsVerifier.add(statement6);

    // Similarly for verifier
    const witnessEq10 = new WitnessEqualityMetaStatement();
    witnessEq10.addWitnessRef(sIdx4, getIndicesForMsgNames(['lname'], attributes1Struct)[0]);
    witnessEq10.addWitnessRef(sIdx5, getIndicesForMsgNames(['lname'], attributes2Struct)[0]);
    witnessEq10.addWitnessRef(sIdx6, getIndicesForMsgNames(['lname'], attributes3Struct)[0]);

    const witnessEq11 = new WitnessEqualityMetaStatement();
    witnessEq11.addWitnessRef(sIdx4, getIndicesForMsgNames(['city'], attributes1Struct)[0]);
    witnessEq11.addWitnessRef(sIdx5, getIndicesForMsgNames(['location.city'], attributes2Struct)[0]);
    witnessEq11.addWitnessRef(sIdx6, getIndicesForMsgNames(['lessSensitive.location.city'], attributes3Struct)[0]);

    const witnessEq12 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx4, [['SSN'], attributes1Struct]);
        m.set(sIdx5, [['sensitive.SSN'], attributes2Struct]);
        m.set(sIdx6, [['sensitive.SSN'], attributes3Struct]);
        return m;
      })()
    );

    const witnessEq13 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx4, [['email'], attributes1Struct]);
        m.set(sIdx5, [['sensitive.email'], attributes2Struct]);
        return m;
      })()
    );

    const witnessEq14 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx4, [['score'], attributes1Struct]);
        m.set(sIdx5, [['score'], attributes2Struct]);
        return m;
      })()
    );

    const witnessEq15 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx4, [['height'], attributes1Struct]);
        m.set(sIdx5, [['physical.height'], attributes2Struct]);
        return m;
      })()
    );

    const witnessEq16 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx4, [['weight'], attributes1Struct]);
        m.set(sIdx5, [['physical.weight'], attributes2Struct]);
        return m;
      })()
    );

    const witnessEq18 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx5, [['sensitive.user-id'], attributes2Struct]);
        m.set(sIdx6, [['sensitive.employee-id'], attributes3Struct]);
        return m;
      })()
    );

    const metaStmtsVerifier = new MetaStatements();
    metaStmtsVerifier.addWitnessEquality(witnessEq10);
    metaStmtsVerifier.addWitnessEquality(witnessEq11);
    metaStmtsVerifier.addWitnessEquality(witnessEq12);
    metaStmtsVerifier.addWitnessEquality(witnessEq13);
    metaStmtsVerifier.addWitnessEquality(witnessEq14);
    metaStmtsVerifier.addWitnessEquality(witnessEq15);
    metaStmtsVerifier.addWitnessEquality(witnessEq16);
    metaStmtsVerifier.addWitnessEquality(witnessEq18);

    // The verifier should independently construct this `ProofSpec`
    const proofSpecVerifier = new ProofSpecG1(statementsVerifier, metaStmtsVerifier);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    checkResult(proof.verify(proofSpecVerifier));
  });
});
