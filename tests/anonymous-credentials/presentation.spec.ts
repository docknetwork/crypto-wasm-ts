import {
  Accumulator,
  AccumulatorPublicKey,
  AccumulatorSecretKey,
  BBSPlusPublicKeyG2,
  BBSPlusSecretKey,
  BoundCheckSnarkSetup,
  IAccumulatorState,
  KeypairG2,
  LegoProvingKeyUncompressed,
  LegoVerifyingKeyUncompressed,
  MembershipWitness,
  PositiveAccumulator,
  SaverChunkedCommitmentGens,
  SaverCiphertext,
  SaverDecryptionKeyUncompressed,
  SaverDecryptor,
  SaverEncryptionKeyUncompressed,
  SaverProvingKeyUncompressed,
  SaverVerifyingKeyUncompressed,
  SignatureParamsG1
} from '../../src';
import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  Credential,
  CredentialSchema,
  dockAccumulatorParams,
  dockSaverEncryptionGens,
  dockSaverEncryptionGensUncompressed,
  MEM_CHECK_STR,
  PresentationBuilder,
  REV_ID_STR,
  SIGNATURE_PARAMS_LABEL_BYTES,
  STATUS_STR,
  SUBJECT_STR
} from '../../src/anonymous-credentials';
import { checkResult, stringToBytes } from '../utils';
import { InMemoryState } from '../../src/accumulator/in-memory-persistence';

// Prefill the given accumulator with `totalMembers` members. The members are creates in a certain way for these tests
async function prefillAccumulator(
  accumulator: Accumulator,
  secretKey: AccumulatorSecretKey,
  state: IAccumulatorState,
  credSchema: CredentialSchema,
  memberValPrefix: string,
  memberNameInSchema: string,
  totalMembers: number
) {
  const members: Uint8Array[] = [];
  for (let i = 1; i <= totalMembers; i++) {
    // For this test, user id is of this form
    const userId = `${memberValPrefix}${i}`;
    members.push(credSchema.encoder.encodeMessage(memberNameInSchema, userId));
  }
  // Adding a single batch as `totalMembers` is fairly small (100s) in this test but in practice choose a reasonable
  // batch size to not take up complete system's memory
  await accumulator.addBatch(members, secretKey, state);
  return members;
}

describe('Presentation creation and verification', () => {
  let sk1: BBSPlusSecretKey, pk1: BBSPlusPublicKeyG2;
  let sk2: BBSPlusSecretKey, pk2: BBSPlusPublicKeyG2;
  let sk3: BBSPlusSecretKey, pk3: BBSPlusPublicKeyG2;
  let sk4: BBSPlusSecretKey, pk4: BBSPlusPublicKeyG2;

  let credential1: Credential;
  let credential2: Credential;
  let credential3: Credential;
  let credential4: Credential;

  let accumulator3: PositiveAccumulator;
  let accumulator3Pk: AccumulatorPublicKey;
  let accumulator3Witness: MembershipWitness;

  let accumulator4: PositiveAccumulator;
  let accumulator4Pk: AccumulatorPublicKey;
  let accumulator4Witness: MembershipWitness;

  let boundCheckProvingKey: LegoProvingKeyUncompressed;
  let boundCheckVerifyingKey: LegoVerifyingKeyUncompressed;

  const chunkBitSize = 16;
  let saverSk: SaverProvingKeyUncompressed;
  let saverProvingKey: SaverProvingKeyUncompressed;
  let saverVerifyingKey: SaverVerifyingKeyUncompressed;
  let saverEk: SaverEncryptionKeyUncompressed;
  let saverDk: SaverDecryptionKeyUncompressed;

  function setupBoundCheck() {
    if (boundCheckProvingKey === undefined) {
      const pk = BoundCheckSnarkSetup();
      boundCheckProvingKey = pk.decompress();
      boundCheckVerifyingKey = pk.getVerifyingKeyUncompressed();
    }
  }

  function setupSaver() {
    if (saverProvingKey === undefined) {
      const encGens = dockSaverEncryptionGens();
      const [saverSnarkPk, saverSec, encryptionKey, decryptionKey] = SaverDecryptor.setup(encGens, chunkBitSize);
      saverSk = saverSec;
      saverProvingKey = saverSnarkPk.decompress();
      saverVerifyingKey = saverSnarkPk.getVerifyingKeyUncompressed();
      saverEk = encryptionKey.decompress();
      saverDk = decryptionKey.decompress();
    }
  }

  beforeAll(async () => {
    await initializeWasm();
    const params = SignatureParamsG1.generate(1, SIGNATURE_PARAMS_LABEL_BYTES);
    const keypair1 = KeypairG2.generate(params);
    const keypair2 = KeypairG2.generate(params);
    const keypair3 = KeypairG2.generate(params);
    const keypair4 = KeypairG2.generate(params);
    sk1 = keypair1.sk;
    pk1 = keypair1.pk;
    sk2 = keypair2.sk;
    pk2 = keypair2.pk;
    sk3 = keypair3.sk;
    pk3 = keypair3.pk;
    sk4 = keypair4.sk;
    pk4 = keypair4.pk;

    const schema1 = CredentialSchema.bare();
    schema1[SUBJECT_STR] = {
      fname: { type: 'string' },
      lname: { type: 'string' },
      email: { type: 'string' },
      SSN: { type: 'stringReversible', compress: false },
      userId: { type: 'stringReversible', compress: true },
      country: { type: 'string' },
      city: { type: 'string' },
      timeOfBirth: { type: 'positiveInteger' },
      height: { type: 'positiveDecimalNumber', decimalPlaces: 1 },
      weight: { type: 'positiveDecimalNumber', decimalPlaces: 1 },
      BMI: { type: 'positiveDecimalNumber', decimalPlaces: 2 },
      score: { type: 'decimalNumber', decimalPlaces: 1, minimum: -100 },
      secret: { type: 'string' }
    };
    const credSchema1 = new CredentialSchema(schema1);
    credential1 = new Credential();
    credential1.schema = credSchema1;
    credential1.issuerPubKey = 'did:dock:some-issuer-did-123';
    credential1.subject = {
      fname: 'John',
      lname: 'Smith',
      email: 'john.smith@example.com',
      SSN: '123-456789-0',
      userId: 'user:123-xyz-#',
      country: 'USA',
      city: 'New York',
      timeOfBirth: 1662010849619,
      height: 181.5,
      weight: 210.4,
      BMI: 23.25,
      score: -13.5,
      secret: 'my-secret-that-wont-tell-anyone'
    };
    credential1.sign(sk1);
    checkResult(credential1.verify(pk1));

    const schema2 = CredentialSchema.bare();
    schema2[SUBJECT_STR] = {
      fname: { type: 'string' },
      lname: { type: 'string' },
      sensitive: {
        secret: { type: 'string' },
        email: { type: 'string' },
        SSN: { type: 'stringReversible', compress: false },
        userId: { type: 'stringReversible', compress: true }
      },
      location: {
        country: { type: 'string' },
        city: { type: 'string' }
      },
      timeOfBirth: { type: 'positiveInteger' },
      physical: {
        height: { type: 'positiveDecimalNumber', decimalPlaces: 1 },
        weight: { type: 'positiveDecimalNumber', decimalPlaces: 1 },
        BMI: { type: 'positiveDecimalNumber', decimalPlaces: 2 }
      },
      score: { type: 'decimalNumber', decimalPlaces: 1, minimum: -100 }
    };
    const credSchema2 = new CredentialSchema(schema2);
    credential2 = new Credential();
    credential2.schema = credSchema2;
    credential2.issuerPubKey = 'did:dock:some-issuer-did-124';
    credential2.subject = {
      fname: 'John',
      lname: 'Smith',
      sensitive: {
        secret: 'my-secret-that-wont-tell-anyone',
        email: 'john.smith@example.com',
        SSN: '123-456789-0',
        userId: 'user:123-xyz-#'
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
    credential2.sign(sk2);
    checkResult(credential2.verify(pk2));

    const schema3 = CredentialSchema.bare();
    schema3[SUBJECT_STR] = {
      fname: { type: 'string' },
      lname: { type: 'string' },
      sensitive: {
        very: {
          secret: { type: 'string' }
        },
        email: { type: 'string' },
        phone: { type: 'string' },
        SSN: { type: 'stringReversible', compress: false }
      },
      lessSensitive: {
        location: {
          country: { type: 'string' },
          city: { type: 'string' }
        },
        department: {
          name: { type: 'string' },
          location: {
            name: { type: 'string' },
            geo: {
              lat: { type: 'decimalNumber', decimalPlaces: 3, minimum: -90 },
              long: { type: 'decimalNumber', decimalPlaces: 3, minimum: -180 }
            }
          }
        }
      },
      rank: { type: 'positiveInteger' }
    };
    schema3[STATUS_STR] = {
      $registryId: { type: 'string' },
      $revocationCheck: { type: 'string' },
      $revocationId: { type: 'string' }
    };

    const credSchema3 = new CredentialSchema(schema3);
    credential3 = new Credential();
    credential3.schema = credSchema3;
    credential3.issuerPubKey = 'did:dock:some-issuer-did-125';
    credential3.subject = {
      fname: 'John',
      lname: 'Smith',
      sensitive: {
        very: {
          secret: 'my-secret-that-wont-tell-anyone'
        },
        email: 'john.smith@acme.com',
        phone: '801009801',
        SSN: '123-456789-0'
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
    credential3.setCredentialStatus('dock:accumulator:accumId123', MEM_CHECK_STR, 'user:A-123');
    credential3.sign(sk3);
    checkResult(credential3.verify(pk3));

    const accumKeypair3 = PositiveAccumulator.generateKeypair(dockAccumulatorParams());
    accumulator3Pk = accumKeypair3.publicKey;
    accumulator3 = PositiveAccumulator.initialize(dockAccumulatorParams());
    const accumState3 = new InMemoryState();
    const allMembers3 = await prefillAccumulator(
      accumulator3,
      accumKeypair3.secretKey,
      accumState3,
      credSchema3,
      'user:A-',
      `${STATUS_STR}.${REV_ID_STR}`,
      200
    );
    accumulator3Witness = await accumulator3.membershipWitness(allMembers3[122], accumKeypair3.secretKey, accumState3);
    let verifAccumulator3 = PositiveAccumulator.fromAccumulated(accumulator3.accumulated);
    expect(
      verifAccumulator3.verifyMembershipWitness(
        allMembers3[122],
        accumulator3Witness,
        accumulator3Pk,
        dockAccumulatorParams()
      )
    ).toEqual(true);

    const schema4 = CredentialSchema.bare();
    schema4[SUBJECT_STR] = {
      fname: { type: 'string' },
      lname: { type: 'string' },
      sensitive: {
        email: { type: 'string' },
        SSN: { type: 'stringReversible', compress: false }
      },
      education: {
        studentId: { type: 'string' },
        university: {
          name: { type: 'string' },
          registrationNumber: { type: 'string' }
        },
        transcript: {
          rank: { type: 'positiveInteger' },
          CGPA: { type: 'positiveDecimalNumber', decimalPlaces: 2 },
          scores: {
            english: { type: 'positiveInteger' },
            mathematics: { type: 'positiveInteger' },
            science: { type: 'positiveInteger' },
            history: { type: 'positiveInteger' },
            geography: { type: 'positiveInteger' }
          }
        }
      }
    };
    schema4[STATUS_STR] = {
      $registryId: { type: 'string' },
      $revocationCheck: { type: 'string' },
      $revocationId: { type: 'string' }
    };

    const credSchema4 = new CredentialSchema(schema4);
    credential4 = new Credential();
    credential4.schema = credSchema4;
    credential4.issuerPubKey = 'did:dock:some-issuer-did-126';
    credential4.subject = {
      fname: 'John',
      lname: 'Smith',
      sensitive: {
        email: 'john.smith@example.edu',
        SSN: '123-456789-0'
      },
      education: {
        studentId: 's-22-123450',
        university: {
          name: 'Example University',
          registrationNumber: 'XYZ-123-789'
        },
        transcript: {
          rank: 100,
          CGPA: 2.57,
          scores: {
            english: 60,
            mathematics: 70,
            science: 50,
            history: 45,
            geography: 40
          }
        }
      }
    };
    credential4.setCredentialStatus('dock:accumulator:accumId124', MEM_CHECK_STR, 'tran:2022-YZ4-250');
    credential4.sign(sk4);
    checkResult(credential4.verify(pk4));

    const accumKeypair4 = PositiveAccumulator.generateKeypair(dockAccumulatorParams());
    accumulator4Pk = accumKeypair4.publicKey;
    accumulator4 = PositiveAccumulator.initialize(dockAccumulatorParams());
    const accumState4 = new InMemoryState();
    const allMembers4 = await prefillAccumulator(
      accumulator4,
      accumKeypair4.secretKey,
      accumState4,
      credSchema4,
      'tran:2022-YZ4-',
      `${STATUS_STR}.${REV_ID_STR}`,
      300
    );
    accumulator4Witness = await accumulator4.membershipWitness(allMembers4[249], accumKeypair4.secretKey, accumState4);
    let verifAccumulator4 = PositiveAccumulator.fromAccumulated(accumulator4.accumulated);
    expect(
      verifAccumulator4.verifyMembershipWitness(
        allMembers4[249],
        accumulator4Witness,
        accumulator4Pk,
        dockAccumulatorParams()
      )
    ).toEqual(true);
  });

  it('from a flat credential - `credential1`', () => {
    const builder1 = new PresentationBuilder();
    expect(builder1.addCredential(credential1, pk1)).toEqual(0);
    builder1.markAttributesRevealed(0, new Set<string>(['fname', 'lname']));
    const pres1 = builder1.finalize();

    expect(pres1.spec.credentials.length).toEqual(1);
    expect(pres1.spec.credentials[0].revealedAttributes).toEqual({
      fname: 'John',
      lname: 'Smith'
    });
    expect(pres1.spec.credentials[0].status).not.toBeDefined();

    checkResult(pres1.verify([pk1]));
  });

  it('from a nested credential - `credential2`', () => {
    const builder2 = new PresentationBuilder();
    expect(builder2.addCredential(credential2, pk2)).toEqual(0);
    builder2.markAttributesRevealed(0, new Set<string>(['fname', 'location.country', 'physical.BMI']));
    const pres2 = builder2.finalize();

    expect(pres2.spec.credentials.length).toEqual(1);
    expect(pres2.spec.credentials[0].revealedAttributes).toEqual({
      fname: 'John',
      location: { country: 'USA' },
      physical: { BMI: 23.25 }
    });
    expect(pres2.spec.credentials[0].status).not.toBeDefined();

    checkResult(pres2.verify([pk2]));
  });

  it('from a nested credential with credential status - `credential3`', () => {
    const builder3 = new PresentationBuilder();
    expect(builder3.addCredential(credential3, pk3)).toEqual(0);
    builder3.markAttributesRevealed(
      0,
      new Set<string>(['fname', 'lessSensitive.location.country', 'lessSensitive.department.location.name'])
    );
    builder3.addAccumInfoForCredStatus(0, accumulator3Witness, accumulator3.accumulated, accumulator3Pk, {
      blockNo: 2010334
    });
    const pres3 = builder3.finalize();
    expect(pres3.spec.credentials[0].revealedAttributes).toEqual({
      fname: 'John',
      lessSensitive: { location: { country: 'USA' }, department: { location: { name: 'Somewhere' } } }
    });
    expect(pres3.spec.credentials[0].status).toEqual({
      $registryId: 'dock:accumulator:accumId123',
      $revocationCheck: 'membership',
      accumulated: accumulator3.accumulated,
      extra: { blockNo: 2010334 }
    });

    const acc = new Map();
    acc.set(0, [accumulator3.accumulated, accumulator3Pk]);
    checkResult(pres3.verify([pk3], acc));
  });

  it('from 2 credentials, `credential1` and `credential2`, and prove some attributes equal', () => {
    const builder4 = new PresentationBuilder();
    expect(builder4.addCredential(credential1, pk1)).toEqual(0);
    expect(builder4.addCredential(credential2, pk2)).toEqual(1);

    builder4.markAttributesRevealed(0, new Set<string>(['fname', 'lname']));
    builder4.markAttributesRevealed(1, new Set<string>(['fname', 'location.country', 'physical.BMI']));

    builder4.markAttributesEqual([0, 'SSN'], [1, 'sensitive.SSN']);
    builder4.markAttributesEqual([0, 'city'], [1, 'location.city']);
    builder4.markAttributesEqual([0, 'height'], [1, 'physical.height']);

    const pres4 = builder4.finalize();

    expect(pres4.spec.credentials.length).toEqual(2);
    expect(pres4.spec.credentials[0].revealedAttributes).toEqual({
      fname: 'John',
      lname: 'Smith'
    });
    expect(pres4.spec.credentials[1].revealedAttributes).toEqual({
      fname: 'John',
      location: { country: 'USA' },
      physical: { BMI: 23.25 }
    });

    // Public keys in wrong order
    expect(pres4.verify([pk2, pk1]).verified).toEqual(false);

    checkResult(pres4.verify([pk1, pk2]));
  });

  it('from 2 credentials, both having credential status', () => {
    const builder5 = new PresentationBuilder();
    expect(builder5.addCredential(credential3, pk3)).toEqual(0);
    expect(builder5.addCredential(credential4, pk4)).toEqual(1);

    builder5.markAttributesRevealed(
      0,
      new Set<string>(['fname', 'lessSensitive.location.country', 'lessSensitive.department.location.name'])
    );
    builder5.markAttributesRevealed(
      1,
      new Set<string>(['education.university.name', 'education.university.registrationNumber'])
    );

    builder5.markAttributesEqual([0, 'sensitive.SSN'], [1, 'sensitive.SSN']);
    builder5.markAttributesEqual([0, 'lname'], [1, 'lname']);

    builder5.addAccumInfoForCredStatus(0, accumulator3Witness, accumulator3.accumulated, accumulator3Pk, {
      blockNo: 2010334
    });
    builder5.addAccumInfoForCredStatus(1, accumulator4Witness, accumulator4.accumulated, accumulator4Pk, {
      blockNo: 2010340
    });

    const pres5 = builder5.finalize();

    expect(pres5.spec.credentials.length).toEqual(2);
    expect(pres5.spec.credentials[0].revealedAttributes).toEqual({
      fname: 'John',
      lessSensitive: { location: { country: 'USA' }, department: { location: { name: 'Somewhere' } } }
    });
    expect(pres5.spec.credentials[1].revealedAttributes).toEqual({
      education: { university: { name: 'Example University', registrationNumber: 'XYZ-123-789' } }
    });
    expect(pres5.spec.credentials[0].status).toEqual({
      $registryId: 'dock:accumulator:accumId123',
      $revocationCheck: 'membership',
      accumulated: accumulator3.accumulated,
      extra: { blockNo: 2010334 }
    });
    expect(pres5.spec.credentials[1].status).toEqual({
      $registryId: 'dock:accumulator:accumId124',
      $revocationCheck: 'membership',
      accumulated: accumulator4.accumulated,
      extra: { blockNo: 2010340 }
    });

    const acc = new Map();
    acc.set(0, [accumulator3.accumulated, accumulator3Pk]);
    acc.set(1, [accumulator4.accumulated, accumulator4Pk]);
    checkResult(pres5.verify([pk3, pk4], acc));
  });

  it('from multiple credentials, some having credential status (revocable) and some not', () => {
    const builder6 = new PresentationBuilder();
    expect(builder6.addCredential(credential1, pk1)).toEqual(0);
    expect(builder6.addCredential(credential2, pk2)).toEqual(1);
    expect(builder6.addCredential(credential3, pk3)).toEqual(2);
    expect(builder6.addCredential(credential4, pk4)).toEqual(3);

    builder6.markAttributesRevealed(0, new Set<string>(['fname', 'lname']));
    builder6.markAttributesRevealed(1, new Set<string>(['fname', 'location.country', 'physical.BMI']));
    builder6.markAttributesRevealed(
      2,
      new Set<string>(['fname', 'lessSensitive.location.country', 'lessSensitive.department.location.name'])
    );
    builder6.markAttributesRevealed(
      3,
      new Set<string>(['education.university.name', 'education.university.registrationNumber'])
    );

    builder6.markAttributesEqual([0, 'SSN'], [1, 'sensitive.SSN']);
    builder6.markAttributesEqual([0, 'city'], [1, 'location.city']);
    builder6.markAttributesEqual([0, 'height'], [1, 'physical.height']);
    builder6.markAttributesEqual([2, 'sensitive.SSN'], [3, 'sensitive.SSN']);
    builder6.markAttributesEqual([2, 'lname'], [3, 'lname']);

    builder6.addAccumInfoForCredStatus(2, accumulator3Witness, accumulator3.accumulated, accumulator3Pk, {
      blockNo: 2010334
    });
    builder6.addAccumInfoForCredStatus(3, accumulator4Witness, accumulator4.accumulated, accumulator4Pk, {
      blockNo: 2010340
    });

    const pres6 = builder6.finalize();

    expect(pres6.spec.credentials.length).toEqual(4);
    expect(pres6.spec.credentials[0].revealedAttributes).toEqual({
      fname: 'John',
      lname: 'Smith'
    });
    expect(pres6.spec.credentials[1].revealedAttributes).toEqual({
      fname: 'John',
      location: { country: 'USA' },
      physical: { BMI: 23.25 }
    });
    expect(pres6.spec.credentials[2].revealedAttributes).toEqual({
      fname: 'John',
      lessSensitive: { location: { country: 'USA' }, department: { location: { name: 'Somewhere' } } }
    });
    expect(pres6.spec.credentials[3].revealedAttributes).toEqual({
      education: { university: { name: 'Example University', registrationNumber: 'XYZ-123-789' } }
    });

    const acc = new Map();
    acc.set(2, [accumulator3.accumulated, accumulator3Pk]);
    acc.set(3, [accumulator4.accumulated, accumulator4Pk]);
    checkResult(pres6.verify([pk1, pk2, pk3, pk4], acc));
  });

  it('from credentials and proving bounds on attributes', () => {
    setupBoundCheck();

    const pkId = 'random';

    // ------------------- Presentation with 1 credential -----------------------------------------
    const builder7 = new PresentationBuilder();
    expect(builder7.addCredential(credential1, pk1)).toEqual(0);

    builder7.markAttributesRevealed(0, new Set<string>(['fname', 'lname']));

    const [minTime, maxTime] = [1662010838000, 1662010856123];
    // @ts-ignore
    expect(minTime).toBeLessThan(credential1.subject['timeOfBirth']);
    // @ts-ignore
    expect(maxTime).toBeGreaterThan(credential1.subject['timeOfBirth']);
    builder7.enforceBounds(0, 'timeOfBirth', minTime, maxTime, pkId, boundCheckProvingKey);

    const [minBMI, maxBMI] = [10, 40];
    // @ts-ignore
    expect(minBMI).toBeLessThan(credential1.subject['BMI']);
    // @ts-ignore
    expect(maxBMI).toBeGreaterThan(credential1.subject['BMI']);
    builder7.enforceBounds(0, 'BMI', minBMI, maxBMI, pkId);

    const [minScore, maxScore] = [-40.5, 60.7];
    // @ts-ignore
    expect(minScore).toBeLessThan(credential1.subject['score']);
    // @ts-ignore
    expect(maxScore).toBeGreaterThan(credential1.subject['score']);
    builder7.enforceBounds(0, 'score', minScore, maxScore, pkId);

    const pres1 = builder7.finalize();

    expect(pres1.spec.credentials.length).toEqual(1);
    expect(pres1.spec.credentials[0].revealedAttributes).toEqual({
      fname: 'John',
      lname: 'Smith'
    });
    expect(pres1.spec.credentials[0].bounds).toEqual({
      timeOfBirth: {
        min: minTime,
        max: maxTime,
        paramId: pkId
      },
      BMI: {
        min: minBMI,
        max: maxBMI,
        paramId: pkId
      },
      score: {
        min: minScore,
        max: maxScore,
        paramId: pkId
      }
    });

    const pp = new Map();
    pp.set(pkId, boundCheckVerifyingKey);
    checkResult(pres1.verify([pk1], undefined, pp));

    // ---------------------------------- Presentation with 3 credentials ---------------------------------

    const builder8 = new PresentationBuilder();
    expect(builder8.addCredential(credential1, pk1)).toEqual(0);
    expect(builder8.addCredential(credential2, pk2)).toEqual(1);
    expect(builder8.addCredential(credential3, pk3)).toEqual(2);

    builder8.markAttributesRevealed(0, new Set<string>(['fname', 'lname']));
    builder8.markAttributesRevealed(1, new Set<string>(['fname', 'location.country']));
    builder8.markAttributesRevealed(
      2,
      new Set<string>(['fname', 'lessSensitive.location.country', 'lessSensitive.department.location.name'])
    );

    builder8.markAttributesEqual([0, 'SSN'], [1, 'sensitive.SSN'], [2, 'sensitive.SSN']);
    builder8.markAttributesEqual([0, 'timeOfBirth'], [1, 'timeOfBirth']);
    builder8.markAttributesEqual([0, 'BMI'], [1, 'physical.BMI']);
    builder8.markAttributesEqual([0, 'score'], [1, 'score']);

    builder8.addAccumInfoForCredStatus(2, accumulator3Witness, accumulator3.accumulated, accumulator3Pk, {
      blockNo: 2010334
    });

    builder8.enforceBounds(0, 'timeOfBirth', minTime, maxTime, pkId, boundCheckProvingKey);
    builder8.enforceBounds(0, 'BMI', minBMI, maxBMI, pkId);
    builder8.enforceBounds(0, 'score', minScore, maxScore, pkId);

    const [minLat, maxLat] = [-30, 50];
    // @ts-ignore
    expect(minLat).toBeLessThan(credential3.subject.lessSensitive.department.location.geo.lat);
    // @ts-ignore
    expect(maxLat).toBeGreaterThan(credential3.subject.lessSensitive.department.location.geo.lat);
    builder8.enforceBounds(2, 'lessSensitive.department.location.geo.lat', minLat, maxLat, pkId);

    const [minLong, maxLong] = [-10, 85];
    // @ts-ignore
    expect(minLong).toBeLessThan(credential3.subject.lessSensitive.department.location.geo.long);
    // @ts-ignore
    expect(maxLong).toBeGreaterThan(credential3.subject.lessSensitive.department.location.geo.long);
    builder8.enforceBounds(2, 'lessSensitive.department.location.geo.long', minLong, maxLong, pkId);

    const pres2 = builder8.finalize();

    expect(pres2.spec.credentials[0].bounds).toEqual({
      timeOfBirth: {
        min: minTime,
        max: maxTime,
        paramId: pkId
      },
      BMI: {
        min: minBMI,
        max: maxBMI,
        paramId: pkId
      },
      score: {
        min: minScore,
        max: maxScore,
        paramId: pkId
      }
    });

    expect(pres2.spec.credentials[2].bounds).toEqual({
      lessSensitive: {
        department: {
          location: {
            geo: {
              lat: {
                min: minLat,
                max: maxLat,
                paramId: pkId
              },
              long: {
                min: minLong,
                max: maxLong,
                paramId: pkId
              }
            }
          }
        }
      }
    });
    expect(pres2.spec.credentials[2].status).toEqual({
      $registryId: 'dock:accumulator:accumId123',
      $revocationCheck: 'membership',
      accumulated: accumulator3.accumulated,
      extra: { blockNo: 2010334 }
    });

    const acc = new Map();
    acc.set(2, [accumulator3.accumulated, accumulator3Pk]);

    const pp1 = new Map();
    pp1.set(pkId, boundCheckVerifyingKey);
    checkResult(pres2.verify([pk1, pk2, pk3], acc, pp1));
  });

  it('from credentials and encryption of attributes', () => {
    // Setup for decryptor
    setupSaver();

    // ------------------- Presentation with 1 credential -----------------------------------------

    const gens = SaverChunkedCommitmentGens.generate(stringToBytes('some nonce'));
    const commGens = gens.decompress();

    const commGensId = 'random-1';
    const ekId = 'random-2';
    const snarkPkId = 'random-3';

    const builder9 = new PresentationBuilder();
    expect(builder9.addCredential(credential1, pk1)).toEqual(0);

    builder9.markAttributesRevealed(0, new Set<string>(['fname', 'lname']));
    builder9.verifiablyEncrypt(0, 'SSN', chunkBitSize, commGensId, ekId, snarkPkId, commGens, saverEk, saverProvingKey);

    const pres1 = builder9.finalize();

    expect(pres1.spec.credentials[0].verifiableEncryptions).toEqual({
      SSN: {
        chunkBitSize,
        commitmentGensId: commGensId,
        encryptionKeyId: ekId,
        snarkKeyId: snarkPkId
      }
    });

    // @ts-ignore
    expect(pres1.attributeCiphertexts.size).toEqual(1);
    // @ts-ignore
    expect(pres1.attributeCiphertexts.get(0)).toBeDefined();

    const pp = new Map();
    pp.set(commGensId, commGens);
    pp.set(ekId, saverEk);
    pp.set(snarkPkId, saverVerifyingKey);
    checkResult(pres1.verify([pk1], undefined, pp));

    // Decryptor gets the ciphertext from the verifier and decrypts it
    const ciphertext = pres1.attributeCiphertexts?.get(0)?.SSN as SaverCiphertext;
    const decrypted = SaverDecryptor.decryptCiphertext(ciphertext, saverSk, saverDk, saverVerifyingKey, chunkBitSize);
    expect(decrypted.message).toEqual(
      // @ts-ignore
      credential1.schema?.encoder.encodeMessage(`${SUBJECT_STR}.SSN`, credential1.subject['SSN'])
    );

    // Decryptor shares the decryption result with verifier which the verifier can check for correctness.
    expect(
      ciphertext.verifyDecryption(
        decrypted,
        saverDk,
        saverVerifyingKey,
        dockSaverEncryptionGensUncompressed(),
        chunkBitSize
      ).verified
    ).toEqual(true);

    // ---------------------------------- Presentation with 3 credentials ---------------------------------

    const gensNew = SaverChunkedCommitmentGens.generate(stringToBytes('another nonce'));
    const commGensNew = gensNew.decompress();

    const builder10 = new PresentationBuilder();
    expect(builder10.addCredential(credential1, pk1)).toEqual(0);
    expect(builder10.addCredential(credential2, pk2)).toEqual(1);
    expect(builder10.addCredential(credential3, pk3)).toEqual(2);

    builder10.markAttributesRevealed(0, new Set<string>(['fname', 'lname']));
    builder10.markAttributesRevealed(1, new Set<string>(['fname', 'location.country']));
    builder10.markAttributesRevealed(
      2,
      new Set<string>(['fname', 'lessSensitive.location.country', 'lessSensitive.department.location.name'])
    );

    builder10.markAttributesEqual([0, 'SSN'], [1, 'sensitive.SSN'], [2, 'sensitive.SSN']);
    builder10.markAttributesEqual([0, 'userId'], [1, 'sensitive.userId']);

    builder10.addAccumInfoForCredStatus(2, accumulator3Witness, accumulator3.accumulated, accumulator3Pk, {
      blockNo: 2010334
    });

    builder10.verifiablyEncrypt(
      0,
      'SSN',
      chunkBitSize,
      commGensId,
      ekId,
      snarkPkId,
      commGensNew,
      saverEk,
      saverProvingKey
    );
    builder10.verifiablyEncrypt(1, 'sensitive.userId', chunkBitSize, commGensId, ekId, snarkPkId);

    const pres2 = builder10.finalize();

    expect(pres2.spec.credentials[0].verifiableEncryptions).toEqual({
      SSN: {
        chunkBitSize,
        commitmentGensId: commGensId,
        encryptionKeyId: ekId,
        snarkKeyId: snarkPkId
      }
    });
    expect(pres2.spec.credentials[1].verifiableEncryptions).toEqual({
      sensitive: {
        userId: {
          chunkBitSize,
          commitmentGensId: commGensId,
          encryptionKeyId: ekId,
          snarkKeyId: snarkPkId
        }
      }
    });
    expect(pres2.spec.credentials[2].status).toEqual({
      $registryId: 'dock:accumulator:accumId123',
      $revocationCheck: 'membership',
      accumulated: accumulator3.accumulated,
      extra: { blockNo: 2010334 }
    });

    const acc = new Map();
    acc.set(2, [accumulator3.accumulated, accumulator3Pk]);

    const pp1 = new Map();
    pp1.set(commGensId, commGensNew);
    pp1.set(ekId, saverEk);
    pp1.set(snarkPkId, saverVerifyingKey);

    checkResult(pres2.verify([pk1, pk2, pk3], acc, pp1));

    // @ts-ignore
    expect(pres2.attributeCiphertexts.size).toEqual(2);
    // @ts-ignore
    expect(pres2.attributeCiphertexts.get(0)).toBeDefined();
    // @ts-ignore
    expect(pres2.attributeCiphertexts.get(1)).toBeDefined();

    const ciphertext1 = pres2.attributeCiphertexts?.get(0)?.SSN as SaverCiphertext;
    const decrypted1 = SaverDecryptor.decryptCiphertext(ciphertext1, saverSk, saverDk, saverVerifyingKey, chunkBitSize);
    expect(decrypted1.message).toEqual(
      // @ts-ignore
      credential1.schema?.encoder.encodeMessage(`${SUBJECT_STR}.SSN`, credential1.subject['SSN'])
    );

    // Decryptor shares the decryption result with verifier which the verifier can check for correctness.
    expect(
      ciphertext1.verifyDecryption(
        decrypted1,
        saverDk,
        saverVerifyingKey,
        dockSaverEncryptionGensUncompressed(),
        chunkBitSize
      ).verified
    ).toEqual(true);

    // @ts-ignore
    const ciphertext2 = pres2.attributeCiphertexts?.get(1).sensitive.userId as SaverCiphertext;
    const decrypted2 = SaverDecryptor.decryptCiphertext(ciphertext2, saverSk, saverDk, saverVerifyingKey, chunkBitSize);
    expect(decrypted2.message).toEqual(
      credential2.schema?.encoder.encodeMessage(
        `${SUBJECT_STR}.sensitive.userId`,
        // @ts-ignore
        credential2.subject['sensitive']['userId']
      )
    );

    // Decryptor shares the decryption result with verifier which the verifier can check for correctness.
    expect(
      ciphertext2.verifyDecryption(
        decrypted2,
        saverDk,
        saverVerifyingKey,
        dockSaverEncryptionGensUncompressed(),
        chunkBitSize
      ).verified
    ).toEqual(true);
  });

  it('from credentials with proving bounds on attributes and encryption of some attributes', () => {
    setupBoundCheck();
    setupSaver();

    const boundCheckSnarkId = 'random';
    const commGensId = 'random-1';
    const ekId = 'random-2';
    const snarkPkId = 'random-3';

    const gens = SaverChunkedCommitmentGens.generate(stringToBytes('a new nonce'));
    const commGens = gens.decompress();

    const builder11 = new PresentationBuilder();
    expect(builder11.addCredential(credential1, pk1)).toEqual(0);
    expect(builder11.addCredential(credential2, pk2)).toEqual(1);
    expect(builder11.addCredential(credential3, pk3)).toEqual(2);

    builder11.markAttributesRevealed(0, new Set<string>(['fname', 'lname']));
    builder11.markAttributesRevealed(1, new Set<string>(['fname', 'location.country']));
    builder11.markAttributesRevealed(
      2,
      new Set<string>(['fname', 'lessSensitive.location.country', 'lessSensitive.department.location.name'])
    );

    builder11.markAttributesEqual([0, 'SSN'], [1, 'sensitive.SSN'], [2, 'sensitive.SSN']);
    builder11.markAttributesEqual([0, 'timeOfBirth'], [1, 'timeOfBirth']);
    builder11.markAttributesEqual([0, 'BMI'], [1, 'physical.BMI']);
    builder11.markAttributesEqual([0, 'score'], [1, 'score']);
    builder11.markAttributesEqual([0, 'userId'], [1, 'sensitive.userId']);

    builder11.addAccumInfoForCredStatus(2, accumulator3Witness, accumulator3.accumulated, accumulator3Pk, {
      blockNo: 2010334
    });

    const [minTime, maxTime] = [1662010838000, 1662010856123];
    // @ts-ignore
    expect(minTime).toBeLessThan(credential1.subject['timeOfBirth']);
    // @ts-ignore
    expect(maxTime).toBeGreaterThan(credential1.subject['timeOfBirth']);
    builder11.enforceBounds(0, 'timeOfBirth', minTime, maxTime, boundCheckSnarkId, boundCheckProvingKey);

    const [minBMI, maxBMI] = [10, 40];
    // @ts-ignore
    expect(minBMI).toBeLessThan(credential1.subject['BMI']);
    // @ts-ignore
    expect(maxBMI).toBeGreaterThan(credential1.subject['BMI']);
    builder11.enforceBounds(0, 'BMI', minBMI, maxBMI, boundCheckSnarkId);

    const [minScore, maxScore] = [-40.5, 60.7];
    // @ts-ignore
    expect(minScore).toBeLessThan(credential1.subject['score']);
    // @ts-ignore
    expect(maxScore).toBeGreaterThan(credential1.subject['score']);
    builder11.enforceBounds(0, 'score', minScore, maxScore, boundCheckSnarkId);

    const [minLat, maxLat] = [-30, 50];
    // @ts-ignore
    expect(minLat).toBeLessThan(credential3.subject.lessSensitive.department.location.geo.lat);
    // @ts-ignore
    expect(maxLat).toBeGreaterThan(credential3.subject.lessSensitive.department.location.geo.lat);
    builder11.enforceBounds(2, 'lessSensitive.department.location.geo.lat', minLat, maxLat, boundCheckSnarkId);

    const [minLong, maxLong] = [-10, 85];
    // @ts-ignore
    expect(minLong).toBeLessThan(credential3.subject.lessSensitive.department.location.geo.long);
    // @ts-ignore
    expect(maxLong).toBeGreaterThan(credential3.subject.lessSensitive.department.location.geo.long);
    builder11.enforceBounds(2, 'lessSensitive.department.location.geo.long', minLong, maxLong, boundCheckSnarkId);

    builder11.verifiablyEncrypt(
      0,
      'SSN',
      chunkBitSize,
      commGensId,
      ekId,
      snarkPkId,
      commGens,
      saverEk,
      saverProvingKey
    );
    builder11.verifiablyEncrypt(1, 'sensitive.userId', chunkBitSize, commGensId, ekId, snarkPkId);

    const pres1 = builder11.finalize();

    expect(pres1.spec.credentials[0].bounds).toEqual({
      timeOfBirth: {
        min: minTime,
        max: maxTime,
        paramId: boundCheckSnarkId
      },
      BMI: {
        min: minBMI,
        max: maxBMI,
        paramId: boundCheckSnarkId
      },
      score: {
        min: minScore,
        max: maxScore,
        paramId: boundCheckSnarkId
      }
    });
    expect(pres1.spec.credentials[0].verifiableEncryptions).toEqual({
      SSN: {
        chunkBitSize,
        commitmentGensId: commGensId,
        encryptionKeyId: ekId,
        snarkKeyId: snarkPkId
      }
    });

    expect(pres1.spec.credentials[2].bounds).toEqual({
      lessSensitive: {
        department: {
          location: {
            geo: {
              lat: {
                min: minLat,
                max: maxLat,
                paramId: boundCheckSnarkId
              },
              long: {
                min: minLong,
                max: maxLong,
                paramId: boundCheckSnarkId
              }
            }
          }
        }
      }
    });
    expect(pres1.spec.credentials[1].verifiableEncryptions).toEqual({
      sensitive: {
        userId: {
          chunkBitSize,
          commitmentGensId: commGensId,
          encryptionKeyId: ekId,
          snarkKeyId: snarkPkId
        }
      }
    });
    expect(pres1.spec.credentials[2].status).toEqual({
      $registryId: 'dock:accumulator:accumId123',
      $revocationCheck: 'membership',
      accumulated: accumulator3.accumulated,
      extra: { blockNo: 2010334 }
    });

    const acc = new Map();
    acc.set(2, [accumulator3.accumulated, accumulator3Pk]);

    const pp = new Map();
    pp.set(boundCheckSnarkId, boundCheckVerifyingKey);
    pp.set(commGensId, commGens);
    pp.set(ekId, saverEk);
    pp.set(snarkPkId, saverVerifyingKey);
    checkResult(pres1.verify([pk1, pk2, pk3], acc, pp));
  });
});
