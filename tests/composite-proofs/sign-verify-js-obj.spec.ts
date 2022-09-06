import {
  createWitnessEqualityMetaStatement,
  encodeRevealedMsgs,
  getAdaptedSignatureParamsForMessages,
  getRevealedAndUnrevealed,
  getSigParamsOfRequiredSize,
  signMessageObject,
  SigParamsGetter,
  verifyMessageObject
} from '../../src/sign-verify-js-objs';
import { initializeWasm } from '@docknetwork/crypto-wasm';
import { stringToBytes } from '../utils';
import {
  Accumulator,
  AccumulatorSecretKey,
  BoundCheckSnarkSetup,
  CompositeProofG1,
  EncodeFunc,
  Encoder,
  flattenObjectToKeyValuesList,
  getIndicesForMsgNames,
  IAccumulatorState,
  KeypairG2,
  MetaStatements,
  PositiveAccumulator,
  ProofSpecG1,
  QuasiProofSpecG1,
  SaverChunkedCommitmentGens,
  SaverDecryptor,
  SaverEncryptionGens,
  SetupParam,
  SignatureG1,
  SignatureParamsG1,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses,
  WitnessUpdatePublicInfo
} from '../../src';
import { InMemoryState } from '../../src/accumulator/in-memory-persistence';

describe('Utils', () => {
  beforeAll(async () => {
    // Load the WASM module
    await initializeWasm();
  });

  it('flattening works', () => {
    const msgs1 = { foo: 'Foo1', 'bar-0': 'Bar0', bar: 'Bar', grault: 'aGrault', corge: 'Corge', waldo: 'Waldo' };
    const [keys1, vals1] = flattenObjectToKeyValuesList(msgs1);
    expect(keys1.length).toEqual(vals1.length);
    expect(keys1).toEqual(['bar', 'bar-0', 'corge', 'foo', 'grault', 'waldo']);
    expect(vals1).toEqual(['Bar', 'Bar0', 'Corge', 'Foo1', 'aGrault', 'Waldo']);

    const msgs2 = { foo: 'Foo1', bar: 'Bar1', baz: { foo0: 'Foo10', bar: 'Bar4' } };
    const [keys2, vals2] = flattenObjectToKeyValuesList(msgs2);
    expect(keys2.length).toEqual(vals2.length);
    expect(keys2).toEqual(['bar', 'baz.bar', 'baz.foo0', 'foo']);
    expect(vals2).toEqual(['Bar1', 'Bar4', 'Foo10', 'Foo1']);

    const msgs3 = { foo: 'Foo1', bar: 'Bar10', baz: { foo0: 'Foo', bar: 'Bar4' }, axe: ['foo', 'bar', 1] };
    const [keys3, vals3] = flattenObjectToKeyValuesList(msgs3);
    expect(keys3.length).toEqual(vals3.length);
    expect(keys3).toEqual(['axe.0', 'axe.1', 'axe.2', 'bar', 'baz.bar', 'baz.foo0', 'foo']);
    expect(vals3).toEqual(['foo', 'bar', 1, 'Bar10', 'Bar4', 'Foo', 'Foo1']);
  });

  it('Signature params getter', () => {
    const params1 = SignatureParamsG1.generate(2);

    expect(() => getSigParamsOfRequiredSize(1, params1)).toThrow();
    expect(() => getSigParamsOfRequiredSize(3, params1)).toThrow();
    expect(() => getSigParamsOfRequiredSize(2, params1)).not.toThrow();
    expect(() => getSigParamsOfRequiredSize(1, stringToBytes('some label'))).not.toThrow();
    expect(() => getSigParamsOfRequiredSize(2, stringToBytes('some label'))).not.toThrow();
    expect(() => getSigParamsOfRequiredSize(3, stringToBytes('some label'))).not.toThrow();

    const params2 = SignatureParamsG1.generate(2, stringToBytes('label2'));
    expect(() => getSigParamsOfRequiredSize(1, params2)).not.toThrow();
    expect(() => getSigParamsOfRequiredSize(2, params2)).not.toThrow();
    expect(() => getSigParamsOfRequiredSize(3, params2)).not.toThrow();

    const pg1 = new SigParamsGetter();
    expect(() => pg1.getSigParamsOfRequiredSize(2)).toThrow();
    expect(() => pg1.getSigParamsOfRequiredSize(1, params1)).toThrow();
    expect(() => pg1.getSigParamsOfRequiredSize(3, params1)).toThrow();
    expect(() => pg1.getSigParamsOfRequiredSize(2, params1)).not.toThrow();
    expect(() => pg1.getSigParamsOfRequiredSize(1, stringToBytes('some label'))).not.toThrow();
    expect(() => pg1.getSigParamsOfRequiredSize(2, stringToBytes('some label'))).not.toThrow();
    expect(() => pg1.getSigParamsOfRequiredSize(3, stringToBytes('some label'))).not.toThrow();

    const pg2 = new SigParamsGetter(stringToBytes('a label'));
    expect(() => pg2.getSigParamsOfRequiredSize(2)).not.toThrow();
    expect(() => pg2.getSigParamsOfRequiredSize(5)).not.toThrow();
  });

  it('encoder works', () => {
    expect(() => new Encoder()).toThrow();
    expect(() => new Encoder(new Map<string, EncodeFunc>())).toThrow();

    const encoders1 = new Map<string, EncodeFunc>();
    encoders1.set('foo', Encoder.positiveIntegerEncoder());
    const encoder1 = new Encoder(encoders1);

    // Throws for unknown message name when no default encoder
    expect(() => encoder1.encodeMessage('bar', 6)).toThrow();
    expect(() => encoder1.encodeMessageObject({ bar: 6, foo: 10 })).toThrow();

    // Throws for known message name but invalid value
    expect(() => encoder1.encodeMessage('foo', 6.5)).toThrow();
    expect(() => encoder1.encodeMessageObject({ foo: 6.5 })).toThrow();

    expect(() => encoder1.encodeMessage('foo', 6)).not.toThrow();
    expect(() => encoder1.encodeMessageObject({ foo: 6 })).not.toThrow();

    const defaultEncoder = (v: unknown) => {
      // @ts-ignore
      return SignatureG1.encodeMessageForSigning(stringToBytes(v.toString()));
    };
    const encoder2 = new Encoder(undefined, defaultEncoder);
    expect(() => encoder2.encodeMessage('bar', 6)).not.toThrow();
    expect(() => encoder2.encodeMessageObject({ bar: 6 })).not.toThrow();

    const encoder3 = new Encoder(encoders1, defaultEncoder);
    // Throws for known message name but invalid value even with default encoder
    expect(() => encoder3.encodeMessage('foo', 6.5)).toThrow();
    expect(() => encoder3.encodeMessageObject({ bar: 10, foo: 6.5 })).toThrow();

    encoders1.set('bar', Encoder.integerEncoder(-100));

    const encoder4 = new Encoder(encoders1, defaultEncoder);

    // Throws when message is not an integer
    expect(() => encoder4.encodeMessage('bar', 2.6)).toThrow();
    expect(() => encoder4.encodeMessage('bar', -2.6)).toThrow();
    expect(() => encoder4.encodeMessage('bar', 'Bar1')).toThrow();
    expect(() => encoder4.encodeMessageObject({ bar: 2.6 })).toThrow();
    expect(() => encoder4.encodeMessageObject({ bar: -2.6 })).toThrow();
    expect(() => encoder4.encodeMessageObject({ bar: 'Bar1' })).toThrow();

    // Does not throw when positive integers
    expect(() => encoder4.encodeMessage('bar', 2)).not.toThrow();
    expect(() => encoder4.encodeMessageObject({ bar: 2 })).not.toThrow();

    // Throws when message is not a below the specified minimum
    expect(() => encoder4.encodeMessage('bar', -102)).toThrow();
    expect(() => encoder4.encodeMessageObject({ bar: -102 })).toThrow();

    expect(() => encoder4.encodeMessage('bar', -100)).not.toThrow();
    expect(() => encoder4.encodeMessageObject({ bar: -100 })).not.toThrow();

    // Does not throw no specific encoder is defined and thus default encoder is used
    expect(() => encoder4.encodeMessage('foo1', -102)).not.toThrow();
    expect(() => encoder4.encodeMessage('foo1', 2.6)).not.toThrow();
    expect(() => encoder4.encodeMessageObject({ foo1: -102, baz1: 'Bar1' })).not.toThrow();
    expect(() => encoder4.encodeMessageObject({ foo1: -102, baz1: 'Bar1', barfoo: -2.6 })).not.toThrow();

    encoders1.set('baz', Encoder.positiveDecimalNumberEncoder(3));

    const encoder5 = new Encoder(encoders1, defaultEncoder);

    // Throws when message is a negative number or other invalid type
    expect(() => encoder5.encodeMessage('baz', -2.6)).toThrow();
    expect(() => encoder5.encodeMessage('baz', -2)).toThrow();
    expect(() => encoder5.encodeMessage('baz', '-2.6')).toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: -2.6 })).toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: -2 })).toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: '-2.6' })).toThrow();

    // Throws when message has more decimal places than intended
    expect(() => encoder5.encodeMessage('baz', 2.1234)).toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: 2.1234 })).toThrow();

    // Does not throw when message has expected number of decimal places
    expect(() => encoder5.encodeMessage('baz', 2.0)).not.toThrow();
    expect(() => encoder5.encodeMessage('baz', 2.1)).not.toThrow();
    expect(() => encoder5.encodeMessage('baz', 2.12)).not.toThrow();
    expect(() => encoder5.encodeMessage('baz', 2.13)).not.toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: 2.0 })).not.toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: 2.0 })).not.toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: 2.12 })).not.toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: 2.13 })).not.toThrow();

    // Does not throw when positive integers
    expect(() => encoder5.encodeMessage('baz', 2)).not.toThrow();
    expect(() => encoder5.encodeMessageObject({ baz: 2 })).not.toThrow();

    // Does not throw no specific encoder is defined and thus default encoder is used
    expect(() => encoder5.encodeMessage('foo1', -2)).not.toThrow();
    expect(() => encoder5.encodeMessage('foo1', 2.1234)).not.toThrow();
    expect(() => encoder5.encodeMessageObject({ foo1: -2 })).not.toThrow();
    expect(() => encoder5.encodeMessageObject({ foo1: 2.1234 })).not.toThrow();

    encoders1.set('waldo', Encoder.decimalNumberEncoder(-1000, 2));

    const encoder6 = new Encoder(encoders1, defaultEncoder);

    // Throws when message is below the intended minimum or has more decimal places than intended
    for (const v of [-1001, -999.234, 0.056, 2.123, -1002.123]) {
      expect(() => encoder6.encodeMessage('waldo', v)).toThrow();
      expect(() => encoder6.encodeMessageObject({ waldo: v })).toThrow();
    }

    // Does not throw for valid values
    for (const v of [-1000, -999, -100.1, -40.0, -5.01, -1, 0, 1, 1.2, 1.45, 100, 200.9, 300.0, 300.1, 300.2]) {
      expect(() => encoder6.encodeMessage('waldo', v)).not.toThrow();
      expect(() => encoder6.encodeMessageObject({ waldo: v })).not.toThrow();
    }
  });
});

describe('Signing and proof of signature', () => {
  // NOTE: The following tests contain a lot of duplicated code but that is intentional as this code is for illustration purpose.

  // 1st attribute set. This is a flat JS object.
  const attributes1 = {
    fname: 'John',
    lname: 'Smith',
    email: 'john.smith@example.com',
    SSN: '123-456789-0',
    'user-id': 'user:123-xyz-#',
    country: 'USA',
    city: 'New York',
    timeOfBirth: 1662010849619,
    height: 181.5,
    weight: 210,
    BMI: 23.25,
    score: -13.5
  };

  // This is the structure of `attributes1`. This does not contain any attribute values but contains the names with the
  // same kind of nesting as `attributes1`. For any attribute set, this should be known to all system participants, i.e. signer,
  // prover and verifier.
  const attributes1Struct = {
    fname: undefined,
    lname: undefined,
    email: undefined,
    SSN: undefined,
    'user-id': undefined,
    country: undefined,
    city: undefined,
    timeOfBirth: undefined,
    height: undefined,
    weight: undefined,
    BMI: undefined,
    score: undefined
  };

  // 2nd attribute set. This is a nested JS object with 1 level of nesting.
  const attributes2 = {
    fname: 'John',
    lname: 'Smith',
    sensitive: {
      email: 'john.smith@example.com',
      SSN: '123-456789-0',
      'user-id': 'user:123-xyz-#'
    },
    location: {
      country: 'USA',
      city: 'New York'
    },
    timeOfBirth: 1662010849619,
    physical: {
      height: 181.5,
      weight: 210,
      BMI: 23.25
    },
    score: -13.5
  };

  // This is the structure of `attributes2`. Similar to `attributes1Struct`, does not contain attribute values but the names
  // and the structure of `attributes2`
  const attributes2Struct = {
    fname: undefined,
    lname: undefined,
    sensitive: {
      email: undefined,
      SSN: undefined,
      'user-id': undefined
    },
    location: {
      country: undefined,
      city: undefined
    },
    timeOfBirth: undefined,
    physical: {
      height: undefined,
      weight: undefined,
      BMI: undefined
    },
    score: undefined
  };

  // 3rd attribute set. This is an even more nested JS object with many levels of nesting.
  const attributes3 = {
    fname: 'John',
    lname: 'Smith',
    sensitive: {
      email: 'john.smith@acme.com',
      phone: '801009801',
      SSN: '123-456789-0',
      'employee-id': 'user:123-xyz-#'
    },
    lessSensitive: {
      location: {
        country: 'USA',
        city: 'New York'
      },
      department: {
        name: 'Random',
        location: {
          name: 'Somewhere',
          geo: {
            lat: -23.658,
            long: 2.556
          }
        }
      }
    },
    rank: 6
  };

  // This is the structure of `attributes3`.
  const attributes3Struct = {
    fname: undefined,
    lname: undefined,
    sensitive: {
      email: undefined,
      phone: undefined,
      SSN: undefined,
      'employee-id': undefined
    },
    lessSensitive: {
      location: {
        country: undefined,
        city: undefined
      },
      department: {
        name: undefined,
        location: {
          name: undefined,
          geo: {
            lat: undefined,
            long: undefined
          }
        }
      }
    },
    rank: undefined
  };

  beforeAll(async () => {
    // Load the WASM module
    await initializeWasm();
  });

  const defaultEncoder = (v: unknown) => {
    // @ts-ignore
    return SignatureG1.encodeMessageForSigning(stringToBytes(v.toString()));
  };

  // Create an encoder for attributes with various kinds of values.
  const encoders = new Map<string, EncodeFunc>();
  encoders.set('timeOfBirth', Encoder.positiveIntegerEncoder());
  encoders.set('weight', Encoder.positiveIntegerEncoder());
  encoders.set('physical.weight', Encoder.positiveIntegerEncoder());

  // height contains at most 1 decimal place
  encoders.set('height', Encoder.positiveDecimalNumberEncoder(1));
  encoders.set('physical.height', Encoder.positiveDecimalNumberEncoder(1));

  // BMI contains at most 2 decimal place
  encoders.set('BMI', Encoder.positiveDecimalNumberEncoder(2));
  encoders.set('physical.BMI', Encoder.positiveDecimalNumberEncoder(2));

  // score contains at most 1 decimal place and its minimum value is -100
  encoders.set('score', Encoder.decimalNumberEncoder(-100, 1));

  // latitude contains at most 3 decimal places (in this example) and its minimum value is -90
  encoders.set('lessSensitive.department.location.geo.lat', Encoder.decimalNumberEncoder(-90, 3));

  // longitude contains at most 3 decimal places (in this example) and its minimum value is -180
  encoders.set('lessSensitive.department.location.geo.long', Encoder.decimalNumberEncoder(-180, 3));

  encoders.set('SSN', (v: unknown) => {
    // @ts-ignore
    return SignatureG1.reversibleEncodeStringMessageForSigning(v);
  });
  encoders.set('sensitive.SSN', (v: unknown) => {
    // @ts-ignore
    return SignatureG1.reversibleEncodeStringMessageForSigning(v);
  });

  const globalEncoder = new Encoder(encoders, defaultEncoder);

  // Prefill the given accumulator with `totalMembers` members. The members are creates in a certain way for these tests
  async function prefillAccumulator(
    accumulator: Accumulator,
    secretKey: AccumulatorSecretKey,
    state: IAccumulatorState,
    totalMembers: number
  ) {
    const members = [];
    for (let i = 1; i <= totalMembers; i++) {
      // For this test, user id is of this form
      const userId = `user:${i}-xyz-#`;
      members.push(Accumulator.encodeBytesAsAccumulatorMember(stringToBytes(userId)));
    }
    // Adding a single batch as `totalMembers` is fairly small (100s) in this test but in practice choose a reasonable
    // batch size to not take up complete system's memory
    await accumulator.addBatch(members, secretKey, state);
    // @ts-ignore
    expect(state.state.size).toEqual(totalMembers);
    return members;
  }

  it('signing and proof of knowledge of a signature', () => {
    // This test check that a single signature can be produced and verified and proof of knowledge of signature can be
    // done while revealing only some attributes (selective-disclosure). Nested attributes are separated by a "dot" (.)

    const label = stringToBytes('Sig params label - this is public');
    // Message count shouldn't matter as `label` is known
    let params = SignatureParamsG1.generate(1, label);
    const keypair = KeypairG2.generate(params);
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
      const signed = signMessageObject(attributes, sk, label, encoder);
      expect(verifyMessageObject(attributes, signed.signature, pk, label, encoder)).toBe(true);

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

      // Verifier independently encodes revealed messages
      const revealedMsgsFromVerifier = encodeRevealedMsgs(revealedMsgsRaw, attributesStruct, encoder);
      checkMapsEqual(revealedMsgs, revealedMsgsFromVerifier);

      const statement2 = Statement.bbsSignature(sigParams, pk, revealedMsgsFromVerifier, false);
      const statementsVerifier = new Statements();
      statementsVerifier.add(statement2);

      // The verifier should independently construct this `ProofSpec`
      const proofSpecVerifier = new ProofSpecG1(statementsVerifier, new MetaStatements());
      expect(proofSpecVerifier.isValid()).toEqual(true);

      expect(proof.verify(proofSpecVerifier).verified).toEqual(true);

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
    let params1 = SignatureParamsG1.generate(1, label1);
    const keypair1 = KeypairG2.generate(params1);
    const sk1 = keypair1.secretKey;
    const pk1 = keypair1.publicKey;

    // 2nd signer's setup
    const label2 = stringToBytes('Sig params label 2');
    // Message count shouldn't matter as `label2` is known
    let params2 = SignatureParamsG1.generate(1, label2);
    const keypair2 = KeypairG2.generate(params2);
    const sk2 = keypair2.secretKey;
    const pk2 = keypair2.publicKey;

    const encoder = new Encoder(undefined, defaultEncoder);

    // Sign and verify all signatures
    const signed1 = signMessageObject(attributes1, sk1, label1, encoder);
    expect(verifyMessageObject(attributes1, signed1.signature, pk1, label1, encoder)).toBe(true);

    const signed2 = signMessageObject(attributes2, sk2, label2, encoder);
    expect(verifyMessageObject(attributes2, signed2.signature, pk2, label2, encoder)).toBe(true);

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

    expect(proof.verify(proofSpecVerifier).verified).toEqual(true);
  });

  it('signing and proof of knowledge of 3 signatures and attribute equality', () => {
    // This test check that a multiple signatures created by different signers can be verified and proof of knowledge of
    // signatures can be done selective-disclosure while also proving equality between some of the hidden attributes.

    // 1st signer's setup
    const label1 = stringToBytes('Sig params label 1');
    // Message count shouldn't matter as `label1` is known
    let params1 = SignatureParamsG1.generate(1, label1);
    const keypair1 = KeypairG2.generate(params1);
    const sk1 = keypair1.secretKey;
    const pk1 = keypair1.publicKey;

    // 2nd signer's setup
    const label2 = stringToBytes('Sig params label 2');
    // Message count shouldn't matter as `label2` is known
    let params2 = SignatureParamsG1.generate(1, label2);
    const keypair2 = KeypairG2.generate(params2);
    const sk2 = keypair2.secretKey;
    const pk2 = keypair2.publicKey;

    // 3rd signer's setup
    const label3 = stringToBytes('Sig params label 3');
    // Message count shouldn't matter as `label3` is known
    let params3 = SignatureParamsG1.generate(1, label3);
    const keypair3 = KeypairG2.generate(params3);
    const sk3 = keypair3.secretKey;
    const pk3 = keypair3.publicKey;

    const encoder = new Encoder(undefined, defaultEncoder);

    // Sign and verify all signatures
    const signed1 = signMessageObject(attributes1, sk1, label1, encoder);
    expect(verifyMessageObject(attributes1, signed1.signature, pk1, label1, encoder)).toBe(true);

    const signed2 = signMessageObject(attributes2, sk2, label2, encoder);
    expect(verifyMessageObject(attributes2, signed2.signature, pk2, label2, encoder)).toBe(true);

    const signed3 = signMessageObject(attributes3, sk3, label3, encoder);
    expect(verifyMessageObject(attributes3, signed3.signature, pk3, label3, encoder)).toBe(true);

    // Reveal
    // - first name ("fname" attribute) from all 3 sets of signed attributes
    // - attributes "BMI" and "country" from 1st signed attribute set
    // - attributes "location.country" and "physical.BMI" from 2nd signed attribute set
    // - attributes "lessSensitive.location.country", "lessSensitive.department.name", "lessSensitive.department.location.name" and "rank" from 3rd signed attribute set

    // Prove equality in zero knowledge of
    // - last name ("lname" attribute), Social security numer ("SSN" attribute) and city in all 3 sets of signed attributes
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

    expect(proof.verify(proofSpecVerifier).verified).toEqual(true);
  });

  it('signing and proof of knowledge of signatures and proof of accumulator membership', async () => {
    // This test check that 2 signatures can be produced and verified and proof of knowledge of both signatures can be
    // produced and verifier. Additionally, one of the message is also present in an accumulator and its proof of membership
    // can be done in zero-knowledge.

    // 1st signer's setup
    const label1 = stringToBytes('Sig params label 1');
    // Message count shouldn't matter as `label1` is known
    let params1 = SignatureParamsG1.generate(1, label1);
    const keypair1 = KeypairG2.generate(params1);
    const sk1 = keypair1.secretKey;
    const pk1 = keypair1.publicKey;

    // 2nd signer's setup
    const label2 = stringToBytes('Sig params label 2');
    // Message count shouldn't matter as `label2` is known
    let params2 = SignatureParamsG1.generate(1, label2);
    const keypair2 = KeypairG2.generate(params2);
    const sk2 = keypair2.secretKey;
    const pk2 = keypair2.publicKey;

    // Accumulator manager 1's setup
    const accumParams1 = PositiveAccumulator.generateParams(stringToBytes('Accumulator params 1'));
    const accumKeypair1 = PositiveAccumulator.generateKeypair(accumParams1);
    const accumulator1 = PositiveAccumulator.initialize(accumParams1);
    const accumState1 = new InMemoryState();
    const allMembers1 = await prefillAccumulator(accumulator1, accumKeypair1.secretKey, accumState1, 200);
    const provingKey1 = Accumulator.generateMembershipProvingKey(stringToBytes('Proving key1'));

    // Accumulator manager 2's setup
    const accumParams2 = PositiveAccumulator.generateParams(stringToBytes('Accumulator params 2'));
    const accumKeypair2 = PositiveAccumulator.generateKeypair(accumParams2);
    const accumulator2 = PositiveAccumulator.initialize(accumParams2);
    const accumState2 = new InMemoryState();
    const allMembers2 = await prefillAccumulator(accumulator2, accumKeypair2.secretKey, accumState2, 300);
    const provingKey2 = Accumulator.generateMembershipProvingKey(stringToBytes('Proving key2'));

    // Endoder knows how to encode the attribute being added to the accumulator.
    const encoders = new Map<string, EncodeFunc>();
    encoders.set('user-id', (v: unknown) => {
      // @ts-ignore
      return Accumulator.encodeBytesAsAccumulatorMember(stringToBytes(v));
    });
    encoders.set('sensitive.user-id', (v: unknown) => {
      // @ts-ignore
      return Accumulator.encodeBytesAsAccumulatorMember(stringToBytes(v));
    });

    const encoder = new Encoder(encoders, defaultEncoder);

    // Sign and verify all signatures

    // Signer 1 signs the attributes
    const signed1 = signMessageObject(attributes1, sk1, label1, encoder);

    // Accumulator manager 1 generates the witness for the accumulator member, i.e. attribute signed1.encodedMessages['user-id']
    // and gives the witness to the user.
    const accumWitness1 = await accumulator1.membershipWitness(
      signed1.encodedMessages['user-id'],
      accumKeypair1.secretKey,
      accumState1
    );

    expect(verifyMessageObject(attributes1, signed1.signature, pk1, label1, encoder)).toBe(true);

    // The user verifies the accumulator membership by using the witness
    let verifAccumulator1 = PositiveAccumulator.fromAccumulated(accumulator1.accumulated);
    expect(
      verifAccumulator1.verifyMembershipWitness(
        signed1.encodedMessages['user-id'],
        accumWitness1,
        accumKeypair1.publicKey,
        accumParams1
      )
    ).toEqual(true);

    // Signer 2 signs the attributes
    const signed2 = signMessageObject(attributes2, sk2, label2, encoder);

    // Accumulator manager 2 generates the witness and gives it to the user
    const accumWitness2 = await accumulator2.membershipWitness(
      signed2.encodedMessages['sensitive.user-id'],
      accumKeypair2.secretKey,
      accumState2
    );

    expect(verifyMessageObject(attributes2, signed2.signature, pk2, label2, encoder)).toBe(true);

    // The user verifies the accumulator membership by using the witness
    let verifAccumulator2 = PositiveAccumulator.fromAccumulated(accumulator2.accumulated);
    expect(
      verifAccumulator2.verifyMembershipWitness(
        signed2.encodedMessages['sensitive.user-id'],
        accumWitness2,
        accumKeypair2.publicKey,
        accumParams2
      )
    ).toEqual(true);

    // Reveal
    // - first name ("fname" attribute) from both sets of signed attributes
    // - attribute "country" from 1st signed attribute set
    // - attributes "location.country", "physical.BMI" from 2nd signed attribute set

    // Prove in zero knowledge that SSN is equal in both attribute sets

    const revealedNames1 = new Set<string>();
    revealedNames1.add('fname');
    revealedNames1.add('country');

    const revealedNames2 = new Set<string>();
    revealedNames2.add('fname');
    revealedNames2.add('location.country');
    revealedNames2.add('physical.BMI');

    // Both prover and verifier can independently create this struct
    const sigParams1 = getAdaptedSignatureParamsForMessages(params1, attributes1Struct);
    const sigParams2 = getAdaptedSignatureParamsForMessages(params2, attributes2Struct);

    const [revealedMsgs1, unrevealedMsgs1, revealedMsgsRaw1] = getRevealedAndUnrevealed(
      attributes1,
      revealedNames1,
      encoder
    );
    const statement1 = Statement.bbsSignature(sigParams1, pk1, revealedMsgs1, false);

    const [revealedMsgs2, unrevealedMsgs2, revealedMsgsRaw2] = getRevealedAndUnrevealed(
      attributes2,
      revealedNames2,
      encoder
    );
    const statement2 = Statement.bbsSignature(sigParams2, pk2, revealedMsgs2, false);

    const statement3 = Statement.accumulatorMembership(
      accumParams1,
      accumKeypair1.publicKey,
      provingKey1,
      accumulator1.accumulated
    );

    const statement4 = Statement.accumulatorMembership(
      accumParams2,
      accumKeypair2.publicKey,
      provingKey2,
      accumulator2.accumulated
    );

    const statementsProver = new Statements();
    const sIdx1 = statementsProver.add(statement1);
    const sIdx2 = statementsProver.add(statement2);
    const sIdx3 = statementsProver.add(statement3);
    const sIdx4 = statementsProver.add(statement4);

    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(sIdx1, getIndicesForMsgNames(['user-id'], attributes1Struct)[0]);
    witnessEq1.addWitnessRef(sIdx3, 0);
    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(sIdx2, getIndicesForMsgNames(['sensitive.user-id'], attributes2Struct)[0]);
    witnessEq2.addWitnessRef(sIdx4, 0);
    const witnessEq3 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx1, [['SSN'], attributes1Struct]);
        m.set(sIdx2, [['sensitive.SSN'], attributes2Struct]);
        return m;
      })()
    );

    const metaStmtsProver = new MetaStatements();
    metaStmtsProver.addWitnessEquality(witnessEq1);
    metaStmtsProver.addWitnessEquality(witnessEq2);
    metaStmtsProver.addWitnessEquality(witnessEq3);

    // The prover should independently construct this `ProofSpec`
    const proofSpecProver = new ProofSpecG1(statementsProver, metaStmtsProver);
    expect(proofSpecProver.isValid()).toEqual(true);

    const witness1 = Witness.bbsSignature(signed1.signature, unrevealedMsgs1, false);
    const witness2 = Witness.bbsSignature(signed2.signature, unrevealedMsgs2, false);
    const witness3 = Witness.accumulatorMembership(signed1.encodedMessages['user-id'], accumWitness1);
    const witness4 = Witness.accumulatorMembership(signed2.encodedMessages['sensitive.user-id'], accumWitness2);

    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);
    witnesses.add(witness3);
    witnesses.add(witness4);

    const proof = CompositeProofG1.generate(proofSpecProver, witnesses);

    // Verifier independently encodes revealed messages
    const revealedMsgs1FromVerifier = encodeRevealedMsgs(revealedMsgsRaw1, attributes1Struct, encoder);
    checkMapsEqual(revealedMsgs1, revealedMsgs1FromVerifier);
    const revealedMsgs2FromVerifier = encodeRevealedMsgs(revealedMsgsRaw2, attributes2Struct, encoder);
    checkMapsEqual(revealedMsgs2, revealedMsgs2FromVerifier);

    const statement5 = Statement.bbsSignature(sigParams1, pk1, revealedMsgs1FromVerifier, false);
    const statement6 = Statement.bbsSignature(sigParams2, pk2, revealedMsgs2FromVerifier, false);
    const statement7 = Statement.accumulatorMembership(
      accumParams1,
      accumKeypair1.publicKey,
      provingKey1,
      accumulator1.accumulated
    );
    const statement8 = Statement.accumulatorMembership(
      accumParams2,
      accumKeypair2.publicKey,
      provingKey2,
      accumulator2.accumulated
    );

    const statementsVerifier = new Statements();
    const sIdx5 = statementsVerifier.add(statement5);
    const sIdx6 = statementsVerifier.add(statement6);
    const sIdx7 = statementsVerifier.add(statement7);
    const sIdx8 = statementsVerifier.add(statement8);

    const witnessEq4 = new WitnessEqualityMetaStatement();
    witnessEq4.addWitnessRef(sIdx5, getIndicesForMsgNames(['user-id'], attributes1Struct)[0]);
    witnessEq4.addWitnessRef(sIdx7, 0);
    const witnessEq5 = new WitnessEqualityMetaStatement();
    witnessEq5.addWitnessRef(sIdx6, getIndicesForMsgNames(['sensitive.user-id'], attributes2Struct)[0]);
    witnessEq5.addWitnessRef(sIdx8, 0);
    const witnessEq6 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        m.set(sIdx5, [['SSN'], attributes1Struct]);
        m.set(sIdx6, [['sensitive.SSN'], attributes2Struct]);
        return m;
      })()
    );

    const metaStmtsVerifier = new MetaStatements();
    metaStmtsVerifier.addWitnessEquality(witnessEq4);
    metaStmtsVerifier.addWitnessEquality(witnessEq5);
    metaStmtsVerifier.addWitnessEquality(witnessEq6);

    // The verifier should independently construct this `ProofSpec`
    const proofSpecVerifier = new ProofSpecG1(statementsVerifier, metaStmtsVerifier);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    expect(proof.verify(proofSpecVerifier).verified).toEqual(true);

    // Remove members from accumulator

    // Prepare witness update info that needs to be shared with the members
    const witnessUpdInfo1 = WitnessUpdatePublicInfo.new(
      accumulator1.accumulated,
      [],
      [allMembers1[5]],
      accumKeypair1.secretKey
    );
    const witnessUpdInfo2 = WitnessUpdatePublicInfo.new(
      accumulator2.accumulated,
      [],
      [allMembers1[20]],
      accumKeypair2.secretKey
    );

    // Accumulator managers remove the member from accumulaator
    await accumulator1.remove(allMembers1[5], accumKeypair1.secretKey, accumState1);
    await accumulator2.remove(allMembers2[20], accumKeypair2.secretKey, accumState2);

    // Prover updates its witnesses
    accumWitness1.updateUsingPublicInfoPostBatchUpdate(
      signed1.encodedMessages['user-id'],
      [],
      [allMembers1[5]],
      witnessUpdInfo1
    );
    accumWitness2.updateUsingPublicInfoPostBatchUpdate(
      signed2.encodedMessages['sensitive.user-id'],
      [],
      [allMembers2[20]],
      witnessUpdInfo2
    );

    // The witnesses are still valid. Proof can be created as above
    verifAccumulator1 = PositiveAccumulator.fromAccumulated(accumulator1.accumulated);
    expect(
      verifAccumulator1.verifyMembershipWitness(
        signed1.encodedMessages['user-id'],
        accumWitness1,
        accumKeypair1.publicKey,
        accumParams1
      )
    ).toEqual(true);

    verifAccumulator2 = PositiveAccumulator.fromAccumulated(accumulator2.accumulated);
    expect(
      verifAccumulator2.verifyMembershipWitness(
        signed2.encodedMessages['sensitive.user-id'],
        accumWitness2,
        accumKeypair2.publicKey,
        accumParams2
      )
    ).toEqual(true);
  });

  it('signing and proof of knowledge of signature, verifiable encryption and range proof', () => {
    // This test check in addition to proof of knowledge of signature, one of the attribute is verifiably encrypted for a
    // 3rd-party and a proof that an attribute satisfies bounds (range proof) can also be created.

    const label = stringToBytes('Sig params label - this is public');
    // Message count shouldn't matter as `label` is known
    let params = SignatureParamsG1.generate(1, label);
    const keypair = KeypairG2.generate(params);
    const sk = keypair.secretKey;
    const pk = keypair.publicKey;

    const signed = signMessageObject(attributes1, sk, label, globalEncoder);
    expect(verifyMessageObject(attributes1, signed.signature, pk, label, globalEncoder)).toBe(true);

    // Setup for decryptor
    const chunkBitSize = 16;
    const encGens = SaverEncryptionGens.generate();
    // `chunkBitSize` is optional, it will default to reasonable good value.
    const [saverSnarkPk, saverSk, encryptionKey, decryptionKey] = SaverDecryptor.setup(encGens, chunkBitSize);
    const saverEncGens = encGens.decompress();
    const saverProvingKey = saverSnarkPk.decompress();
    const saverVerifyingKey = saverSnarkPk.getVerifyingKeyUncompressed();
    const saverEk = encryptionKey.decompress();
    const saverDk = decryptionKey.decompress();

    console.info('Saver setup done');

    // Verifier creates SNARK proving and verification key
    const spk = BoundCheckSnarkSetup();
    const snarkProvingKey = spk.decompress();
    const snarkVerifyingKey = spk.getVerifyingKeyUncompressed();

    console.info('Bound check setup done');

    // The lower and upper bounds of attribute "timeOfBirth"
    const timeMin = 1662010819619;
    const timeMax = 1662011149654;

    // Verifier creates these parameters
    const gens = SaverChunkedCommitmentGens.generate(stringToBytes('some label'));
    const commGens = gens.decompress();

    // Reveal first name ("fname" attribute), last name ("lname") and country
    // Prove that "SSN" is verifiably encrypted
    // Prove that "timeOfBirth" satisfies the given bounds in zero knowledge, i.e. without revealing timeOfBirth

    const revealedNames = new Set<string>();
    revealedNames.add('fname');
    revealedNames.add('lname');
    revealedNames.add('country');

    // Both prover and verifier can independently create this struct
    const sigParams = getAdaptedSignatureParamsForMessages(params, attributes1Struct);

    const [revealedMsgs, unrevealedMsgs, revealedMsgsRaw] = getRevealedAndUnrevealed(
      attributes1,
      revealedNames,
      globalEncoder
    );
    expect(revealedMsgsRaw).toEqual({ fname: 'John', lname: 'Smith', country: 'USA' });

    const statement1 = Statement.bbsSignature(sigParams, pk, revealedMsgs, false);
    const statement2 = Statement.saverProver(saverEncGens, commGens, saverEk, saverProvingKey, chunkBitSize);
    const statement3 = Statement.boundCheckProver(timeMin, timeMax, snarkProvingKey);

    const statementsProver = new Statements();
    const sIdx1 = statementsProver.add(statement1);
    const sIdx2 = statementsProver.add(statement2);
    const sIdx3 = statementsProver.add(statement3);

    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(sIdx1, getIndicesForMsgNames(['SSN'], attributes1Struct)[0]);
    witnessEq1.addWitnessRef(sIdx2, 0);

    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(sIdx1, getIndicesForMsgNames(['timeOfBirth'], attributes1Struct)[0]);
    witnessEq2.addWitnessRef(sIdx3, 0);

    const metaStmtsProver = new MetaStatements();
    metaStmtsProver.addWitnessEquality(witnessEq1);
    metaStmtsProver.addWitnessEquality(witnessEq2);

    // The prover should independently construct this `ProofSpec`
    const proofSpecProver = new QuasiProofSpecG1(statementsProver, metaStmtsProver);

    const witness1 = Witness.bbsSignature(signed.signature, unrevealedMsgs, false);
    const witness2 = Witness.saver(signed.encodedMessages['SSN']);
    const witness3 = Witness.boundCheckLegoGroth16(signed.encodedMessages['timeOfBirth']);
    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);
    witnesses.add(witness3);

    const proof = CompositeProofG1.generateUsingQuasiProofSpec(proofSpecProver, witnesses);

    // Verifier independently encodes revealed messages
    const revealedMsgsFromVerifier = encodeRevealedMsgs(revealedMsgsRaw, attributes1Struct, globalEncoder);
    checkMapsEqual(revealedMsgs, revealedMsgsFromVerifier);

    const statement4 = Statement.bbsSignature(sigParams, pk, revealedMsgsFromVerifier, false);
    const statement5 = Statement.saverVerifier(saverEncGens, commGens, saverEk, saverVerifyingKey, chunkBitSize);
    const statement6 = Statement.boundCheckVerifier(timeMin, timeMax, snarkVerifyingKey);

    const verifierStatements = new Statements();
    const sIdx4 = verifierStatements.add(statement4);
    const sIdx5 = verifierStatements.add(statement5);
    const sIdx6 = verifierStatements.add(statement6);

    const witnessEq3 = new WitnessEqualityMetaStatement();
    witnessEq3.addWitnessRef(sIdx4, getIndicesForMsgNames(['SSN'], attributes1Struct)[0]);
    witnessEq3.addWitnessRef(sIdx5, 0);

    const witnessEq4 = new WitnessEqualityMetaStatement();
    witnessEq4.addWitnessRef(sIdx4, getIndicesForMsgNames(['timeOfBirth'], attributes1Struct)[0]);
    witnessEq4.addWitnessRef(sIdx6, 0);

    const metaStmtsVerifier = new MetaStatements();
    metaStmtsVerifier.addWitnessEquality(witnessEq3);
    metaStmtsVerifier.addWitnessEquality(witnessEq4);

    const verifierProofSpec = new QuasiProofSpecG1(verifierStatements, metaStmtsVerifier);
    expect(proof.verifyUsingQuasiProofSpec(verifierProofSpec).verified).toEqual(true);

    // Verifier extracts the ciphertext
    const ciphertext = proof.getSaverCiphertext(sIdx5);

    // Decryptor gets the ciphertext from the verifier and decrypts it
    const decrypted = SaverDecryptor.decryptCiphertext(ciphertext, saverSk, saverDk, saverVerifyingKey, chunkBitSize);
    expect(decrypted.message).toEqual(signed.encodedMessages['SSN']);

    // Decryptor shares the decryption result with verifier which the verifier can check for correctness.
    expect(
      ciphertext.verifyDecryption(decrypted, saverDk, saverVerifyingKey, saverEncGens, chunkBitSize).verified
    ).toEqual(true);

    // Message can be successfully decoded to the original string
    const decoded = SignatureG1.reversibleDecodeStringMessageForSigning(signed.encodedMessages['SSN']);
    expect(decoded).toEqual(attributes1['SSN']);
  });

  it('signing and proof of knowledge of signatures and range proofs', () => {
    // This test check that a multiple signatures created by different signers can be verified and proof of knowledge of
    // signatures can be done selective-disclosure while also proving equality between some of the hidden attributes.
    // In addition, it checks that bounds of several attributes can be proven in zero knowledge. Some attributes have negative
    // values, some have decimal and some both

    // 1st signer's setup
    const label1 = stringToBytes('Sig params label 1');
    // Message count shouldn't matter as `label1` is known
    let params1 = SignatureParamsG1.generate(1, label1);
    const keypair1 = KeypairG2.generate(params1);
    const sk1 = keypair1.secretKey;
    const pk1 = keypair1.publicKey;

    // 2nd signer's setup
    const label2 = stringToBytes('Sig params label 2');
    // Message count shouldn't matter as `label2` is known
    let params2 = SignatureParamsG1.generate(1, label2);
    const keypair2 = KeypairG2.generate(params2);
    const sk2 = keypair2.secretKey;
    const pk2 = keypair2.publicKey;

    // 3rd signer's setup
    const label3 = stringToBytes('Sig params label 3');
    // Message count shouldn't matter as `label3` is known
    let params3 = SignatureParamsG1.generate(1, label3);
    const keypair3 = KeypairG2.generate(params3);
    const sk3 = keypair3.secretKey;
    const pk3 = keypair3.publicKey;

    // Sign and verify all signatures
    const signed1 = signMessageObject(attributes1, sk1, label1, globalEncoder);
    expect(verifyMessageObject(attributes1, signed1.signature, pk1, label1, globalEncoder)).toBe(true);

    const signed2 = signMessageObject(attributes2, sk2, label2, globalEncoder);
    expect(verifyMessageObject(attributes2, signed2.signature, pk2, label2, globalEncoder)).toBe(true);

    const signed3 = signMessageObject(attributes3, sk3, label3, globalEncoder);
    expect(verifyMessageObject(attributes3, signed3.signature, pk3, label3, globalEncoder)).toBe(true);

    // Verifier creates SNARK proving and verification key
    const pk = BoundCheckSnarkSetup();
    const snarkProvingKey = pk.decompress();
    const snarkVerifyingKey = pk.getVerifyingKeyUncompressed();

    // The lower and upper bounds of attributes involved in the bound check
    const timeMin = 1662010819619;
    const timeMax = 1662011149654;
    const weightMin = 60;
    const weightMax = 600;
    const heightMin = 1000;
    const heightMax = 2400;
    const bmiMin = 1000;
    const bmiMax = 4000;
    const scoreMin = 0;
    const scoreMax = 2000; // (100 + 100)*10
    const latMin = 0;
    const latMax = 180000; // (90 + 90)*1000
    const longMin = 0;
    const longMax = 360000; // (180 + 180)*1000

    // Reveal
    // - first name ("fname" attribute) from all 3 sets of signed attributes
    // - attribute "country" from 1st signed attribute set
    // - attribute "location.country" from 2nd signed attribute set
    // - attributes "lessSensitive.location.country", "lessSensitive.department.name" from 3rd signed attribute set

    // Prove equality in zero knowledge of last name ("lname" attribute), Social security numer ("SSN" attribute) and city in all 3 sets of signed attributes

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
    const proverSetupParams = [];
    proverSetupParams.push(SetupParam.legosnarkProvingKeyUncompressed(snarkProvingKey));

    const [revealedMsgs1, unrevealedMsgs1, revealedMsgsRaw1] = getRevealedAndUnrevealed(
      attributes1,
      revealedNames1,
      globalEncoder
    );
    expect(revealedMsgsRaw1).toEqual({ fname: 'John', country: 'USA' });

    const statement1 = Statement.bbsSignature(sigParams1, pk1, revealedMsgs1, false);

    const [revealedMsgs2, unrevealedMsgs2, revealedMsgsRaw2] = getRevealedAndUnrevealed(
      attributes2,
      revealedNames2,
      globalEncoder
    );
    expect(revealedMsgsRaw2).toEqual({ fname: 'John', location: { country: 'USA' } });

    const statement2 = Statement.bbsSignature(sigParams2, pk2, revealedMsgs2, false);

    const [revealedMsgs3, unrevealedMsgs3, revealedMsgsRaw3] = getRevealedAndUnrevealed(
      attributes3,
      revealedNames3,
      globalEncoder
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

    const statement3 = Statement.bbsSignature(sigParams3, pk3, revealedMsgs3, false);

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

    const witness1 = Witness.bbsSignature(signed1.signature, unrevealedMsgs1, false);
    const witness2 = Witness.bbsSignature(signed2.signature, unrevealedMsgs2, false);
    const witness3 = Witness.bbsSignature(signed3.signature, unrevealedMsgs3, false);

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

    const verifierSetupParams = [];
    verifierSetupParams.push(SetupParam.legosnarkVerifyingKeyUncompressed(snarkVerifyingKey));

    // Verifier independently encodes revealed messages
    const revealedMsgs1FromVerifier = encodeRevealedMsgs(revealedMsgsRaw1, attributes1Struct, globalEncoder);
    checkMapsEqual(revealedMsgs1, revealedMsgs1FromVerifier);
    const revealedMsgs2FromVerifier = encodeRevealedMsgs(revealedMsgsRaw2, attributes2Struct, globalEncoder);
    checkMapsEqual(revealedMsgs2, revealedMsgs2FromVerifier);
    const revealedMsgs3FromVerifier = encodeRevealedMsgs(revealedMsgsRaw3, attributes3Struct, globalEncoder);
    checkMapsEqual(revealedMsgs3, revealedMsgs3FromVerifier);

    const statement11 = Statement.bbsSignature(sigParams1, pk1, revealedMsgs1FromVerifier, false);
    const statement12 = Statement.bbsSignature(sigParams2, pk2, revealedMsgs2FromVerifier, false);
    const statement13 = Statement.bbsSignature(sigParams3, pk3, revealedMsgs3FromVerifier, false);

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

    expect(proof.verify(proofSpecVerifier).verified).toEqual(true);
  });
});

function checkMapsEqual(mapA: Map<unknown, unknown>, mapB: Map<unknown, unknown>) {
  expect(mapA.size).toEqual(mapB.size);
  for (const key of mapA.keys()) {
    expect(mapA.get(key)).toEqual(mapB.get(key));
  }
}
