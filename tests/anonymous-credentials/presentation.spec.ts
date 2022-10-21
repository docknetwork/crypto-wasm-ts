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
  PositiveAccumulator, randomFieldElement, SaverChunkedCommitmentGens,
  SaverDecryptionKeyUncompressed,
  SaverDecryptor,
  SaverEncryptionKeyUncompressed,
  SaverProvingKeyUncompressed,
  SaverVerifyingKeyUncompressed,
  SignatureParamsG1
} from '../../src';
import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  CredentialBuilder,
  Credential,
  CredentialSchema,
  dockAccumulatorParams,
  dockSaverEncryptionGens,
  MEM_CHECK_STR,
  PresentationBuilder,
  REV_ID_STR,
  SIGNATURE_PARAMS_LABEL_BYTES,
  STATUS_STR,
  SUBJECT_STR, dockSaverEncryptionGensUncompressed
} from '../../src/anonymous-credentials';
import { areUint8ArraysEqual, checkResult, stringToBytes } from '../utils';
import { InMemoryState } from '../../src/accumulator/in-memory-persistence';
import { getExampleSchema } from './utils';
import { Presentation } from '../../src/anonymous-credentials/presentation';

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
  let credential5: Credential;
  let credential6: Credential;

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

    const schema1 = getExampleSchema(9);
    const credSchema1 = new CredentialSchema(schema1);
    const builder1 = new CredentialBuilder();
    builder1.schema = credSchema1;
    builder1.subject = {
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
    credential1 = builder1.sign(sk1);
    checkResult(credential1.verify(pk1));

    const schema2 = getExampleSchema(11);
    const credSchema2 = new CredentialSchema(schema2);
    const builder2 = new CredentialBuilder();
    builder2.schema = credSchema2;
    builder2.subject = {
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
    credential2 = builder2.sign(sk2);
    checkResult(credential2.verify(pk2));

    const schema3 = getExampleSchema(5);

    const credSchema3 = new CredentialSchema(schema3);
    const builder3 = new CredentialBuilder();
    builder3.schema = credSchema3;
    builder3.subject = {
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
    builder3.setCredentialStatus('dock:accumulator:accumId123', MEM_CHECK_STR, 'user:A-123');
    credential3 = builder3.sign(sk3);
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

    const schema4 = getExampleSchema(10);

    const credSchema4 = new CredentialSchema(schema4);
    const builder4 = new CredentialBuilder();
    builder4.schema = credSchema4;
    builder4.subject = {
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
    builder4.setCredentialStatus('dock:accumulator:accumId124', MEM_CHECK_STR, 'tran:2022-YZ4-250');
    credential4 = builder4.sign(sk4);
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

    const schema5 = CredentialSchema.essential();
    const subjectItem = {
        type: 'object',
        properties: {
          name: {type: "string"},
          location: {
            type: 'object',
            properties: {
              name: {type: "string"},
              geo: {
                type: 'object',
                properties: {
                  lat: {type: "decimalNumber", decimalPlaces: 3, minimum: -90},
                  long: {type: "decimalNumber", decimalPlaces: 3, minimum: -180}
                }
              }
            }
          }
        }
    };

    schema5.properties[SUBJECT_STR] = {
      type: 'array',
      items: [
        subjectItem,
        subjectItem,
        subjectItem
      ]
    };
    const credSchema5 = new CredentialSchema(schema5);
    const builder5 = new CredentialBuilder();
    builder5.schema = credSchema5;
    builder5.subject = [
      {
        name: 'Random',
        location: {
          name: 'Somewhere',
          geo: {
            lat: -23.658,
            long: 2.556
          }
        }
      },
      {
        name: 'Random-1',
        location: {
          name: 'Somewhere-1',
          geo: {
            lat: 35.01,
            long: -40.987
          }
        }
      },
      {
        name: 'Random-2',
        location: {
          name: 'Somewhere-2',
          geo: {
            lat: -67.0,
            long: -10.12
          }
        }
      }
    ];
    credential5 = builder5.sign(sk1);
    checkResult(credential5.verify(pk1));

    const schema6 = CredentialSchema.essential();
    const subjectItem2 = {
      type: 'object',
      properties: {
        name: {type: "string"},
        location: {
          type: 'object',
          properties: {
            name: {type: "string"},
            geo: {
              lat: {type: "decimalNumber", decimalPlaces: 3, minimum: -90},
              long: {type: "decimalNumber", decimalPlaces: 3, minimum: -180}
            },
          }
        }
      }
    };
    schema6.properties[SUBJECT_STR] = {
      type: 'array',
      items: [
        subjectItem2,
        subjectItem2,
        subjectItem2
      ]
    };
    schema6.properties['issuer'] = {
      type: 'object',
      properties: {
        name: {type: "string"},
        desc: {type: "string"},
        logo: {type: "string"}
      }
    };
    schema6.properties['issuanceDate'] = {type: "positiveInteger"};
    schema6.properties['expirationDate'] = {type: "positiveInteger"};

    const credSchema6 = new CredentialSchema(schema6);
    const builder6 = new CredentialBuilder();
    builder6.schema = credSchema6;
    builder6.subject = [
      {
        name: 'Random',
        location: {
          name: 'Somewhere',
          geo: {
            lat: -23.658,
            long: 2.556
          }
        }
      },
      {
        name: 'Random-1',
        location: {
          name: 'Somewhere-1',
          geo: {
            lat: 35.01,
            long: -40.987
          }
        }
      },
      {
        name: 'Random-2',
        location: {
          name: 'Somewhere-2',
          geo: {
            lat: -67.0,
            long: -10.12
          }
        }
      }
    ];
    builder6.setTopLevelField('issuer', {
      name: "An issuer",
      desc: "Just an issuer",
      logo: "https://images.example-issuer.com/logo.png"
    });
    builder6.setTopLevelField('issuanceDate', 1662010849700);
    builder6.setTopLevelField('expirationDate', 1662011950934);
    credential6 = builder6.sign(sk1);
    checkResult(credential6.verify(pk1));
  });

  it('from a flat credential - `credential1`', () => {
    const builder1 = new PresentationBuilder();
    expect(builder1.addCredential(credential1, pk1)).toEqual(0);
    builder1.markAttributesRevealed(0, new Set<string>(['credentialSubject.fname', 'credentialSubject.lname']));
    const pres1 = builder1.finalize();

    expect(pres1.spec.credentials.length).toEqual(1);
    expect(pres1.spec.credentials[0].revealedAttributes).toEqual({
      credentialSubject: {
        fname: 'John',
        lname: 'Smith'
      }
    });
    expect(pres1.spec.credentials[0].status).not.toBeDefined();

    expect(pres1.context).not.toBeDefined();
    expect(pres1.nonce).not.toBeDefined();

    checkResult(pres1.verify([pk1]));

    const presJson = pres1.toJSON();
    const recreatedPres = Presentation.fromJSON(presJson);
    checkResult(recreatedPres.verify([pk1]));
    expect(presJson).toEqual(recreatedPres.toJSON());
  });

  it('from with context and nonce', () => {
    const ctx = 'Test context: Someeee   vverrryyyyyy  longgggg   contexxxxttttt .............';
    const nonce = randomFieldElement();

    const builder1 = new PresentationBuilder();
    expect(builder1.addCredential(credential1, pk1)).toEqual(0);
    builder1.markAttributesRevealed(0, new Set<string>(['credentialSubject.fname', 'credentialSubject.lname']));

    builder1.context = ctx;
    let pres = builder1.finalize();
    expect(pres.context).toEqual(ctx);
    expect(pres.nonce).not.toBeDefined();
    checkResult(pres.verify([pk1]));

    const builder2 = new PresentationBuilder();
    expect(builder2.addCredential(credential1, pk1)).toEqual(0);
    builder2.markAttributesRevealed(0, new Set<string>(['credentialSubject.fname', 'credentialSubject.lname']));

    builder2.context = ctx;
    builder2.nonce = nonce;
    pres = builder2.finalize();
    expect(pres.context).toEqual(ctx);
    expect(areUint8ArraysEqual(pres.nonce as Uint8Array, nonce)).toEqual(true);
    checkResult(pres.verify([pk1]));

    const builder3 = new PresentationBuilder();
    expect(builder3.addCredential(credential1, pk1)).toEqual(0);
    builder3.markAttributesRevealed(0, new Set<string>(['credentialSubject.fname', 'credentialSubject.lname']));

    builder3.nonce = nonce;
    pres = builder3.finalize();
    expect(pres.context).not.toBeDefined();
    expect(areUint8ArraysEqual(pres.nonce as Uint8Array, nonce)).toEqual(true);
    checkResult(pres.verify([pk1]));
  });

  it('from a nested credential - `credential2`', () => {
    const builder2 = new PresentationBuilder();
    expect(builder2.addCredential(credential2, pk2)).toEqual(0);
    builder2.markAttributesRevealed(0, new Set<string>(['credentialSubject.fname', 'credentialSubject.location.country', 'credentialSubject.physical.BMI']));
    const pres2 = builder2.finalize();

    expect(pres2.spec.credentials.length).toEqual(1);
    expect(pres2.spec.credentials[0].revealedAttributes).toEqual({
      credentialSubject: {
        fname: 'John',
        location: { country: 'USA' },
        physical: { BMI: 23.25 }
      }
    });
    expect(pres2.spec.credentials[0].status).not.toBeDefined();

    checkResult(pres2.verify([pk2]));

    const presJson = pres2.toJSON();
    const recreatedPres = Presentation.fromJSON(presJson);
    checkResult(recreatedPres.verify([pk2]));
    expect(presJson).toEqual(recreatedPres.toJSON());
  });

  it('from a nested credential with credential status - `credential3`', () => {
    const builder3 = new PresentationBuilder();
    expect(builder3.addCredential(credential3, pk3)).toEqual(0);
    builder3.markAttributesRevealed(
      0,
      new Set<string>(['credentialSubject.fname', 'credentialSubject.lessSensitive.location.country', 'credentialSubject.lessSensitive.department.location.name'])
    );
    builder3.addAccumInfoForCredStatus(0, accumulator3Witness, accumulator3.accumulated, accumulator3Pk, {
      blockNo: 2010334
    });
    const pres3 = builder3.finalize();
    expect(pres3.spec.credentials[0].revealedAttributes).toEqual({
      credentialSubject: {
        fname: 'John',
        lessSensitive: { location: { country: 'USA' }, department: { location: { name: 'Somewhere' } } }
      }
    });
    expect(pres3.spec.getStatus(0)).toEqual({
      $registryId: 'dock:accumulator:accumId123',
      $revocationCheck: 'membership',
      accumulated: accumulator3.accumulated,
      extra: { blockNo: 2010334 }
    });

    const acc = new Map();
    acc.set(0, accumulator3Pk);
    checkResult(pres3.verify([pk3], acc));

    const presJson = pres3.toJSON();
    const recreatedPres = Presentation.fromJSON(presJson);
    checkResult(recreatedPres.verify([pk3], acc));
    expect(presJson).toEqual(recreatedPres.toJSON());
  });

  it('from 2 credentials, `credential1` and `credential2`, and prove some attributes equal', () => {
    const builder4 = new PresentationBuilder();
    expect(builder4.addCredential(credential1, pk1)).toEqual(0);
    expect(builder4.addCredential(credential2, pk2)).toEqual(1);

    builder4.markAttributesRevealed(0, new Set<string>(['credentialSubject.fname', 'credentialSubject.lname']));
    builder4.markAttributesRevealed(1, new Set<string>(['credentialSubject.fname', 'credentialSubject.location.country', 'credentialSubject.physical.BMI']));

    builder4.markAttributesEqual([0, 'credentialSubject.SSN'], [1, 'credentialSubject.sensitive.SSN']);
    builder4.markAttributesEqual([0, 'credentialSubject.city'], [1, 'credentialSubject.location.city']);
    builder4.markAttributesEqual([0, 'credentialSubject.height'], [1, 'credentialSubject.physical.height']);

    const pres4 = builder4.finalize();

    expect(pres4.spec.credentials.length).toEqual(2);
    expect(pres4.spec.credentials[0].revealedAttributes).toEqual({
      credentialSubject: {
        fname: 'John',
        lname: 'Smith'
      }
    });
    expect(pres4.spec.credentials[1].revealedAttributes).toEqual({
      credentialSubject: {
        fname: 'John',
        location: { country: 'USA' },
        physical: { BMI: 23.25 }
      }
    });

    // Public keys in wrong order
    expect(pres4.verify([pk2, pk1]).verified).toEqual(false);

    checkResult(pres4.verify([pk1, pk2]));

    const presJson = pres4.toJSON();
    const recreatedPres = Presentation.fromJSON(presJson);
    checkResult(recreatedPres.verify([pk1, pk2]));
    expect(presJson).toEqual(recreatedPres.toJSON());
  });

  it('from 2 credentials, both having credential status', () => {
    const builder5 = new PresentationBuilder();
    expect(builder5.addCredential(credential3, pk3)).toEqual(0);
    expect(builder5.addCredential(credential4, pk4)).toEqual(1);

    builder5.markAttributesRevealed(
      0,
      new Set<string>(['credentialSubject.fname', 'credentialSubject.lessSensitive.location.country', 'credentialSubject.lessSensitive.department.location.name'])
    );
    builder5.markAttributesRevealed(
      1,
      new Set<string>(['credentialSubject.education.university.name', 'credentialSubject.education.university.registrationNumber'])
    );

    builder5.markAttributesEqual([0, 'credentialSubject.sensitive.SSN'], [1, 'credentialSubject.sensitive.SSN']);
    builder5.markAttributesEqual([0, 'credentialSubject.lname'], [1, 'credentialSubject.lname']);

    builder5.addAccumInfoForCredStatus(0, accumulator3Witness, accumulator3.accumulated, accumulator3Pk, {
      blockNo: 2010334
    });
    builder5.addAccumInfoForCredStatus(1, accumulator4Witness, accumulator4.accumulated, accumulator4Pk, {
      blockNo: 2010340
    });

    const pres5 = builder5.finalize();

    expect(pres5.spec.credentials.length).toEqual(2);
    expect(pres5.spec.credentials[0].revealedAttributes).toEqual({
      credentialSubject: {
        fname: 'John',
        lessSensitive: { location: { country: 'USA' }, department: { location: { name: 'Somewhere' } } }
      }
    });
    expect(pres5.spec.credentials[1].revealedAttributes).toEqual({
      credentialSubject: {
        education: { university: { name: 'Example University', registrationNumber: 'XYZ-123-789' } }
      }
    });
    expect(pres5.spec.getStatus(0)).toEqual({
      $registryId: 'dock:accumulator:accumId123',
      $revocationCheck: 'membership',
      accumulated: accumulator3.accumulated,
      extra: { blockNo: 2010334 }
    });
    expect(pres5.spec.getStatus(1)).toEqual({
      $registryId: 'dock:accumulator:accumId124',
      $revocationCheck: 'membership',
      accumulated: accumulator4.accumulated,
      extra: { blockNo: 2010340 }
    });

    const acc = new Map();
    acc.set(0, accumulator3Pk);
    acc.set(1, accumulator4Pk);
    checkResult(pres5.verify([pk3, pk4], acc));

    const presJson = pres5.toJSON();
    const recreatedPres = Presentation.fromJSON(presJson);
    checkResult(recreatedPres.verify([pk3, pk4], acc));
    expect(presJson).toEqual(recreatedPres.toJSON());
  });

  it('from multiple credentials, some having credential status (revocable) and some not', () => {
    const builder6 = new PresentationBuilder();
    expect(builder6.addCredential(credential1, pk1)).toEqual(0);
    expect(builder6.addCredential(credential2, pk2)).toEqual(1);
    expect(builder6.addCredential(credential3, pk3)).toEqual(2);
    expect(builder6.addCredential(credential4, pk4)).toEqual(3);

    builder6.markAttributesRevealed(0, new Set<string>(['credentialSubject.fname', 'credentialSubject.lname']));
    builder6.markAttributesRevealed(1, new Set<string>(['credentialSubject.fname', 'credentialSubject.location.country', 'credentialSubject.physical.BMI']));
    builder6.markAttributesRevealed(
      2,
      new Set<string>(['credentialSubject.fname', 'credentialSubject.lessSensitive.location.country', 'credentialSubject.lessSensitive.department.location.name'])
    );
    builder6.markAttributesRevealed(
      3,
      new Set<string>(['credentialSubject.education.university.name', 'credentialSubject.education.university.registrationNumber'])
    );

    builder6.markAttributesEqual([0, 'credentialSubject.SSN'], [1, 'credentialSubject.sensitive.SSN']);
    builder6.markAttributesEqual([0, 'credentialSubject.city'], [1, 'credentialSubject.location.city']);
    builder6.markAttributesEqual([0, 'credentialSubject.height'], [1, 'credentialSubject.physical.height']);
    builder6.markAttributesEqual([2, 'credentialSubject.sensitive.SSN'], [3, 'credentialSubject.sensitive.SSN']);
    builder6.markAttributesEqual([2, 'credentialSubject.lname'], [3, 'credentialSubject.lname']);

    builder6.addAccumInfoForCredStatus(2, accumulator3Witness, accumulator3.accumulated, accumulator3Pk, {
      blockNo: 2010334
    });
    builder6.addAccumInfoForCredStatus(3, accumulator4Witness, accumulator4.accumulated, accumulator4Pk, {
      blockNo: 2010340
    });

    const pres6 = builder6.finalize();

    expect(pres6.spec.credentials.length).toEqual(4);
    expect(pres6.spec.credentials[0].revealedAttributes).toEqual({
      credentialSubject: {
        fname: 'John',
        lname: 'Smith'
      }
    });
    expect(pres6.spec.credentials[1].revealedAttributes).toEqual({
      credentialSubject: {
        fname: 'John',
        location: { country: 'USA' },
        physical: { BMI: 23.25 }
      }
    });
    expect(pres6.spec.credentials[2].revealedAttributes).toEqual({
      credentialSubject: {
        fname: 'John',
        lessSensitive: { location: { country: 'USA' }, department: { location: { name: 'Somewhere' } } }
      }
    });
    expect(pres6.spec.credentials[3].revealedAttributes).toEqual({
      credentialSubject: {
        education: { university: { name: 'Example University', registrationNumber: 'XYZ-123-789' } }
      }
    });

    expect(pres6.spec.getStatus(2)).toEqual({
      $registryId: 'dock:accumulator:accumId123',
      $revocationCheck: 'membership',
      accumulated: accumulator3.accumulated,
      extra: { blockNo: 2010334 }
    });
    expect(pres6.spec.getStatus(3)).toEqual({
      $registryId: 'dock:accumulator:accumId124',
      $revocationCheck: 'membership',
      accumulated: accumulator4.accumulated,
      extra: { blockNo: 2010340 }
    });

    const acc = new Map();
    acc.set(2, accumulator3Pk);
    acc.set(3, accumulator4Pk);
    checkResult(pres6.verify([pk1, pk2, pk3, pk4], acc));

    const presJson = pres6.toJSON();
    const recreatedPres = Presentation.fromJSON(presJson);
    checkResult(recreatedPres.verify([pk1, pk2, pk3, pk4], acc));
    expect(presJson).toEqual(recreatedPres.toJSON());
  });

  it('from credentials and proving bounds on attributes', () => {
    setupBoundCheck();

    const pkId = 'random';

    // ------------------- Presentation with 1 credential -----------------------------------------
    const builder7 = new PresentationBuilder();
    expect(builder7.addCredential(credential1, pk1)).toEqual(0);

    builder7.markAttributesRevealed(0, new Set<string>(['credentialSubject.fname', 'credentialSubject.lname']));

    const [minTime, maxTime] = [1662010838000, 1662010856123];
    // @ts-ignore
    expect(minTime).toBeLessThan(credential1.subject['timeOfBirth']);
    // @ts-ignore
    expect(maxTime).toBeGreaterThan(credential1.subject['timeOfBirth']);
    builder7.enforceBounds(0, 'credentialSubject.timeOfBirth', minTime, maxTime, pkId, boundCheckProvingKey);

    const [minBMI, maxBMI] = [10, 40];
    // @ts-ignore
    expect(minBMI).toBeLessThan(credential1.subject['BMI']);
    // @ts-ignore
    expect(maxBMI).toBeGreaterThan(credential1.subject['BMI']);
    builder7.enforceBounds(0, 'credentialSubject.BMI', minBMI, maxBMI, pkId);

    const [minScore, maxScore] = [-40.5, 60.7];
    // @ts-ignore
    expect(minScore).toBeLessThan(credential1.subject['score']);
    // @ts-ignore
    expect(maxScore).toBeGreaterThan(credential1.subject['score']);
    builder7.enforceBounds(0, 'credentialSubject.score', minScore, maxScore, pkId);

    const pres1 = builder7.finalize();

    expect(pres1.spec.credentials.length).toEqual(1);
    expect(pres1.spec.credentials[0].revealedAttributes).toEqual({
      credentialSubject: {
        fname: 'John',
        lname: 'Smith'
      }
    });
    expect(pres1.spec.credentials[0].bounds).toEqual({
      credentialSubject: {
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
      }
    });

    const pp = new Map();
    pp.set(pkId, boundCheckVerifyingKey);
    checkResult(pres1.verify([pk1], undefined, pp));

    const presJson = pres1.toJSON();
    const recreatedPres = Presentation.fromJSON(presJson);
    checkResult(recreatedPres.verify([pk1], undefined, pp));
    expect(presJson).toEqual(recreatedPres.toJSON());

    // ---------------------------------- Presentation with 3 credentials ---------------------------------

    const builder8 = new PresentationBuilder();
    expect(builder8.addCredential(credential1, pk1)).toEqual(0);
    expect(builder8.addCredential(credential2, pk2)).toEqual(1);
    expect(builder8.addCredential(credential3, pk3)).toEqual(2);

    builder8.markAttributesRevealed(0, new Set<string>(['credentialSubject.fname', 'credentialSubject.lname']));
    builder8.markAttributesRevealed(1, new Set<string>(['credentialSubject.fname', 'credentialSubject.location.country']));
    builder8.markAttributesRevealed(
      2,
      new Set<string>(['credentialSubject.fname', 'credentialSubject.lessSensitive.location.country', 'credentialSubject.lessSensitive.department.location.name'])
    );

    builder8.markAttributesEqual([0, 'credentialSubject.SSN'], [1, 'credentialSubject.sensitive.SSN'], [2, 'credentialSubject.sensitive.SSN']);
    builder8.markAttributesEqual([0, 'credentialSubject.timeOfBirth'], [1, 'credentialSubject.timeOfBirth']);
    builder8.markAttributesEqual([0, 'credentialSubject.BMI'], [1, 'credentialSubject.physical.BMI']);
    builder8.markAttributesEqual([0, 'credentialSubject.score'], [1, 'credentialSubject.score']);

    builder8.addAccumInfoForCredStatus(2, accumulator3Witness, accumulator3.accumulated, accumulator3Pk, {
      blockNo: 2010334
    });

    builder8.enforceBounds(0, 'credentialSubject.timeOfBirth', minTime, maxTime, pkId, boundCheckProvingKey);
    builder8.enforceBounds(0, 'credentialSubject.BMI', minBMI, maxBMI, pkId);
    builder8.enforceBounds(0, 'credentialSubject.score', minScore, maxScore, pkId);

    const [minLat, maxLat] = [-30, 50];
    // @ts-ignore
    expect(minLat).toBeLessThan(credential3.subject.lessSensitive.department.location.geo.lat);
    // @ts-ignore
    expect(maxLat).toBeGreaterThan(credential3.subject.lessSensitive.department.location.geo.lat);
    builder8.enforceBounds(2, 'credentialSubject.lessSensitive.department.location.geo.lat', minLat, maxLat, pkId);

    const [minLong, maxLong] = [-10, 85];
    // @ts-ignore
    expect(minLong).toBeLessThan(credential3.subject.lessSensitive.department.location.geo.long);
    // @ts-ignore
    expect(maxLong).toBeGreaterThan(credential3.subject.lessSensitive.department.location.geo.long);
    builder8.enforceBounds(2, 'credentialSubject.lessSensitive.department.location.geo.long', minLong, maxLong, pkId);

    const pres2 = builder8.finalize();

    expect(pres2.spec.credentials[0].bounds).toEqual({
      credentialSubject: {
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
      }
    });

    expect(pres2.spec.credentials[2].bounds).toEqual({
      credentialSubject: {
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
      }
    });
    expect(pres2.spec.getStatus(2)).toEqual({
      $registryId: 'dock:accumulator:accumId123',
      $revocationCheck: 'membership',
      accumulated: accumulator3.accumulated,
      extra: { blockNo: 2010334 }
    });

    const acc = new Map();
    acc.set(2, accumulator3Pk);

    const pp1 = new Map();
    pp1.set(pkId, boundCheckVerifyingKey);
    checkResult(pres2.verify([pk1, pk2, pk3], acc, pp1));

    const presJson2 = pres2.toJSON();
    const recreatedPres2 = Presentation.fromJSON(presJson2);
    checkResult(recreatedPres2.verify([pk1, pk2, pk3], acc, pp1));
    expect(presJson2).toEqual(recreatedPres2.toJSON());
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

    builder9.markAttributesRevealed(0, new Set<string>(['credentialSubject.fname', 'credentialSubject.lname']));
    builder9.verifiablyEncrypt(0, 'credentialSubject.SSN', chunkBitSize, commGensId, ekId, snarkPkId, commGens, saverEk, saverProvingKey);

    const pres1 = builder9.finalize();

    expect(pres1.spec.credentials[0].verifiableEncryptions).toEqual({
      credentialSubject: {
        SSN: {
          chunkBitSize,
          commitmentGensId: commGensId,
          encryptionKeyId: ekId,
          snarkKeyId: snarkPkId
        }
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

    const presJson = pres1.toJSON();
    const recreatedPres = Presentation.fromJSON(presJson);
    checkResult(recreatedPres.verify([pk1], undefined, pp));
    expect(presJson).toEqual(recreatedPres.toJSON());

    // Decryptor gets the ciphertext from the verifier and decrypts it
    // @ts-ignore
    const ciphertext = pres1.attributeCiphertexts?.get(0).credentialSubject.SSN as SaverCiphertext;
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

    builder10.markAttributesRevealed(0, new Set<string>(['credentialSubject.fname', 'credentialSubject.lname']));
    builder10.markAttributesRevealed(1, new Set<string>(['credentialSubject.fname', 'credentialSubject.location.country']));
    builder10.markAttributesRevealed(
      2,
      new Set<string>(['credentialSubject.fname', 'credentialSubject.lessSensitive.location.country', 'credentialSubject.lessSensitive.department.location.name'])
    );

    builder10.markAttributesEqual([0, 'credentialSubject.SSN'], [1, 'credentialSubject.sensitive.SSN'], [2, 'credentialSubject.sensitive.SSN']);
    builder10.markAttributesEqual([0, 'credentialSubject.userId'], [1, 'credentialSubject.sensitive.userId']);

    builder10.addAccumInfoForCredStatus(2, accumulator3Witness, accumulator3.accumulated, accumulator3Pk, {
      blockNo: 2010334
    });

    builder10.verifiablyEncrypt(
      0,
      'credentialSubject.SSN',
      chunkBitSize,
      commGensId,
      ekId,
      snarkPkId,
      commGensNew,
      saverEk,
      saverProvingKey
    );
    builder10.verifiablyEncrypt(1, 'credentialSubject.sensitive.userId', chunkBitSize, commGensId, ekId, snarkPkId);

    const pres2 = builder10.finalize();

    expect(pres2.spec.credentials[0].verifiableEncryptions).toEqual({
      credentialSubject: {
        SSN: {
          chunkBitSize,
          commitmentGensId: commGensId,
          encryptionKeyId: ekId,
          snarkKeyId: snarkPkId
        }
      }
    });
    expect(pres2.spec.credentials[1].verifiableEncryptions).toEqual({
      credentialSubject: {
        sensitive: {
          userId: {
            chunkBitSize,
            commitmentGensId: commGensId,
            encryptionKeyId: ekId,
            snarkKeyId: snarkPkId
          }
        }
      }
    });
    expect(pres2.spec.getStatus(2)).toEqual({
      $registryId: 'dock:accumulator:accumId123',
      $revocationCheck: 'membership',
      accumulated: accumulator3.accumulated,
      extra: { blockNo: 2010334 }
    });

    const acc = new Map();
    acc.set(2, accumulator3Pk);

    const pp1 = new Map();
    pp1.set(commGensId, commGensNew);
    pp1.set(ekId, saverEk);
    pp1.set(snarkPkId, saverVerifyingKey);

    checkResult(pres2.verify([pk1, pk2, pk3], acc, pp1));

    const presJson2 = pres2.toJSON();
    const recreatedPres2 = Presentation.fromJSON(presJson2);
    checkResult(recreatedPres2.verify([pk1, pk2, pk3], acc, pp1));
    expect(presJson2).toEqual(recreatedPres2.toJSON());

    // @ts-ignore
    expect(pres2.attributeCiphertexts.size).toEqual(2);
    // @ts-ignore
    expect(pres2.attributeCiphertexts.get(0)).toBeDefined();
    // @ts-ignore
    expect(pres2.attributeCiphertexts.get(1)).toBeDefined();

    // @ts-ignore
    const ciphertext1 = pres2.attributeCiphertexts?.get(0).credentialSubject.SSN as SaverCiphertext;
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
    const ciphertext2 = pres2.attributeCiphertexts?.get(1).credentialSubject.sensitive.userId as SaverCiphertext;
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

    builder11.markAttributesRevealed(0, new Set<string>(['credentialSubject.fname', 'credentialSubject.lname']));
    builder11.markAttributesRevealed(1, new Set<string>(['credentialSubject.fname', 'credentialSubject.location.country']));
    builder11.markAttributesRevealed(
      2,
      new Set<string>(['credentialSubject.fname', 'credentialSubject.lessSensitive.location.country', 'credentialSubject.lessSensitive.department.location.name'])
    );

    builder11.markAttributesEqual([0, 'credentialSubject.SSN'], [1, 'credentialSubject.sensitive.SSN'], [2, 'credentialSubject.sensitive.SSN']);
    builder11.markAttributesEqual([0, 'credentialSubject.timeOfBirth'], [1, 'credentialSubject.timeOfBirth']);
    builder11.markAttributesEqual([0, 'credentialSubject.BMI'], [1, 'credentialSubject.physical.BMI']);
    builder11.markAttributesEqual([0, 'credentialSubject.score'], [1, 'credentialSubject.score']);
    builder11.markAttributesEqual([0, 'credentialSubject.userId'], [1, 'credentialSubject.sensitive.userId']);

    builder11.addAccumInfoForCredStatus(2, accumulator3Witness, accumulator3.accumulated, accumulator3Pk, {
      blockNo: 2010334
    });

    const [minTime, maxTime] = [1662010838000, 1662010856123];
    // @ts-ignore
    expect(minTime).toBeLessThan(credential1.subject['timeOfBirth']);
    // @ts-ignore
    expect(maxTime).toBeGreaterThan(credential1.subject['timeOfBirth']);
    builder11.enforceBounds(0, 'credentialSubject.timeOfBirth', minTime, maxTime, boundCheckSnarkId, boundCheckProvingKey);

    const [minBMI, maxBMI] = [10, 40];
    // @ts-ignore
    expect(minBMI).toBeLessThan(credential1.subject['BMI']);
    // @ts-ignore
    expect(maxBMI).toBeGreaterThan(credential1.subject['BMI']);
    builder11.enforceBounds(0, 'credentialSubject.BMI', minBMI, maxBMI, boundCheckSnarkId);

    const [minScore, maxScore] = [-40.5, 60.7];
    // @ts-ignore
    expect(minScore).toBeLessThan(credential1.subject['score']);
    // @ts-ignore
    expect(maxScore).toBeGreaterThan(credential1.subject['score']);
    builder11.enforceBounds(0, 'credentialSubject.score', minScore, maxScore, boundCheckSnarkId);

    const [minLat, maxLat] = [-30, 50];
    // @ts-ignore
    expect(minLat).toBeLessThan(credential3.subject.lessSensitive.department.location.geo.lat);
    // @ts-ignore
    expect(maxLat).toBeGreaterThan(credential3.subject.lessSensitive.department.location.geo.lat);
    builder11.enforceBounds(2, 'credentialSubject.lessSensitive.department.location.geo.lat', minLat, maxLat, boundCheckSnarkId);

    const [minLong, maxLong] = [-10, 85];
    // @ts-ignore
    expect(minLong).toBeLessThan(credential3.subject.lessSensitive.department.location.geo.long);
    // @ts-ignore
    expect(maxLong).toBeGreaterThan(credential3.subject.lessSensitive.department.location.geo.long);
    builder11.enforceBounds(2, 'credentialSubject.lessSensitive.department.location.geo.long', minLong, maxLong, boundCheckSnarkId);

    builder11.verifiablyEncrypt(
      0,
      'credentialSubject.SSN',
      chunkBitSize,
      commGensId,
      ekId,
      snarkPkId,
      commGens,
      saverEk,
      saverProvingKey
    );
    builder11.verifiablyEncrypt(1, 'credentialSubject.sensitive.userId', chunkBitSize, commGensId, ekId, snarkPkId);

    const pres1 = builder11.finalize();

    expect(pres1.spec.credentials[0].bounds).toEqual({
      credentialSubject: {
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
      }
    });
    expect(pres1.spec.credentials[0].verifiableEncryptions).toEqual({
      credentialSubject: {
        SSN: {
          chunkBitSize,
          commitmentGensId: commGensId,
          encryptionKeyId: ekId,
          snarkKeyId: snarkPkId
        }
      }
    });

    expect(pres1.spec.credentials[2].bounds).toEqual({
      credentialSubject: {
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
      }
    });
    expect(pres1.spec.credentials[1].verifiableEncryptions).toEqual({
      credentialSubject: {
        sensitive: {
          userId: {
            chunkBitSize,
            commitmentGensId: commGensId,
            encryptionKeyId: ekId,
            snarkKeyId: snarkPkId
          }
        }
      }
    });
    expect(pres1.spec.getStatus(2)).toEqual({
      $registryId: 'dock:accumulator:accumId123',
      $revocationCheck: 'membership',
      accumulated: accumulator3.accumulated,
      extra: { blockNo: 2010334 }
    });

    const acc = new Map();
    acc.set(2, accumulator3Pk);

    const pp = new Map();
    pp.set(boundCheckSnarkId, boundCheckVerifyingKey);
    pp.set(commGensId, commGens);
    pp.set(ekId, saverEk);
    pp.set(snarkPkId, saverVerifyingKey);
    checkResult(pres1.verify([pk1, pk2, pk3], acc, pp));

    const presJson = pres1.toJSON();
    const recreatedPres = Presentation.fromJSON(presJson);
    checkResult(recreatedPres.verify([pk1, pk2, pk3], acc, pp));
    expect(presJson).toEqual(recreatedPres.toJSON());
  });

  it('from a credential with subject as an array `credential5`', () => {
    const builder1 = new PresentationBuilder();
    expect(builder1.addCredential(credential5, pk1)).toEqual(0);
    builder1.markAttributesRevealed(0, new Set<string>(['credentialSubject.0.name', 'credentialSubject.1.name', 'credentialSubject.1.location.name', 'credentialSubject.2.location.name']));
    const pres1 = builder1.finalize();

    expect(pres1.spec.credentials.length).toEqual(1);
    expect(pres1.spec.credentials[0].revealedAttributes).toEqual({
      credentialSubject: [
        {
          name: 'Random'
        },
        {
          name: 'Random-1',
          location: {
            name: 'Somewhere-1',
          }
        },
        {
          location: {
            name: 'Somewhere-2',
          }
        }
      ]
    });

    checkResult(pres1.verify([pk1]));

    setupBoundCheck();

    const boundCheckSnarkId = 'random';

    const builder2 = new PresentationBuilder();
    expect(builder2.addCredential(credential5, pk1)).toEqual(0);
    builder2.markAttributesRevealed(0, new Set<string>(['credentialSubject.0.name', 'credentialSubject.1.name', 'credentialSubject.1.location.name', 'credentialSubject.2.location.name']));

    const [minLat0, maxLat0] = [-30, 50];
    // @ts-ignore
    expect(minLat0).toBeLessThan(credential5.subject[0].location.geo.lat);
    // @ts-ignore
    expect(maxLat0).toBeGreaterThan(credential5.subject[0].location.geo.lat);
    builder2.enforceBounds(0, 'credentialSubject.0.location.geo.lat', minLat0, maxLat0, boundCheckSnarkId, boundCheckProvingKey);

    const [minLong0, maxLong0] = [1, 10.5];
    // @ts-ignore
    expect(minLong0).toBeLessThan(credential5.subject[0].location.geo.long);
    // @ts-ignore
    expect(maxLong0).toBeGreaterThan(credential5.subject[0].location.geo.long);
    builder2.enforceBounds(0, 'credentialSubject.0.location.geo.long', minLong0, maxLong0, boundCheckSnarkId);

    const [minLat1, maxLat1] = [25.6, 50];
    // @ts-ignore
    expect(minLat1).toBeLessThan(credential5.subject[1].location.geo.lat);
    // @ts-ignore
    expect(maxLat1).toBeGreaterThan(credential5.subject[1].location.geo.lat);
    builder2.enforceBounds(0, 'credentialSubject.1.location.geo.lat', minLat1, maxLat1, boundCheckSnarkId);

    const [minLong1, maxLong1] = [-50.1, 0];
    // @ts-ignore
    expect(minLong1).toBeLessThan(credential5.subject[1].location.geo.long);
    // @ts-ignore
    expect(maxLong1).toBeGreaterThan(credential5.subject[1].location.geo.long);
    builder2.enforceBounds(0, 'credentialSubject.1.location.geo.long', minLong1, maxLong1, boundCheckSnarkId);

    const [minLat2, maxLat2] = [-70, -60];
    // @ts-ignore
    expect(minLat2).toBeLessThan(credential5.subject[2].location.geo.lat);
    // @ts-ignore
    expect(maxLat2).toBeGreaterThan(credential5.subject[2].location.geo.lat);
    builder2.enforceBounds(0, 'credentialSubject.2.location.geo.lat', minLat2, maxLat2, boundCheckSnarkId);

    const [minLong2, maxLong2] = [-10.5, -5];
    // @ts-ignore
    expect(minLong2).toBeLessThan(credential5.subject[2].location.geo.long);
    // @ts-ignore
    expect(maxLong2).toBeGreaterThan(credential5.subject[2].location.geo.long);
    builder2.enforceBounds(0, 'credentialSubject.2.location.geo.long', minLong2, maxLong2, boundCheckSnarkId);

    const pres2 = builder2.finalize();

    expect(pres2.spec.credentials[0].revealedAttributes).toEqual({
      credentialSubject: [
        {
          name: 'Random'
        },
        {
          name: 'Random-1',
          location: {
            name: 'Somewhere-1',
          }
        },
        {
          location: {
            name: 'Somewhere-2',
          }
        }
      ]
    });
    expect(pres2.spec.credentials[0].bounds).toEqual({
      credentialSubject: [
        {
          location: {
            geo: {
              lat: {
                min: minLat0,
                max: maxLat0,
                paramId: boundCheckSnarkId
              },
              long: {
                min: minLong0,
                max: maxLong0,
                paramId: boundCheckSnarkId
              }
            }
          }
        },
        {
          location: {
            geo: {
              lat: {
                min: minLat1,
                max: maxLat1,
                paramId: boundCheckSnarkId
              },
              long: {
                min: minLong1,
                max: maxLong1,
                paramId: boundCheckSnarkId
              }
            }
          }
        },
        {
          location: {
            geo: {
              lat: {
                min: minLat2,
                max: maxLat2,
                paramId: boundCheckSnarkId
              },
              long: {
                min: minLong2,
                max: maxLong2,
                paramId: boundCheckSnarkId
              }
            }
          }
        }
      ]
    });

    const pp = new Map();
    pp.set(boundCheckSnarkId, boundCheckVerifyingKey);
    checkResult(pres2.verify([pk1], undefined, pp));

    const presJson = pres2.toJSON();
    const recreatedPres = Presentation.fromJSON(presJson);
    checkResult(recreatedPres.verify([pk1], undefined, pp));
    expect(presJson).toEqual(recreatedPres.toJSON());
  });

  it('from a credential with subject as an array and top-level custom fields `credential6`', () => {
    const builder1 = new PresentationBuilder();
    expect(builder1.addCredential(credential6, pk1)).toEqual(0);
    builder1.markAttributesRevealed(0, new Set<string>(['credentialSubject.0.name', 'credentialSubject.1.name', 'credentialSubject.1.location.name', 'credentialSubject.2.location.name', 'issuer.desc']));
    const pres1 = builder1.finalize();

    expect(pres1.spec.credentials.length).toEqual(1);
    expect(pres1.spec.credentials[0].revealedAttributes).toEqual({
      credentialSubject: [
        {
          name: 'Random'
        },
        {
          name: 'Random-1',
          location: {
            name: 'Somewhere-1',
          }
        },
        {
          location: {
            name: 'Somewhere-2',
          }
        }
      ],
      issuer: {
        desc: 'Just an issuer'
      }
    });

    checkResult(pres1.verify([pk1]));

    setupBoundCheck();

    const boundCheckSnarkId = 'random';

    const builder2 = new PresentationBuilder();
    expect(builder2.addCredential(credential6, pk1)).toEqual(0);
    builder2.markAttributesRevealed(0, new Set<string>(['credentialSubject.0.name', 'credentialSubject.1.name', 'credentialSubject.1.location.name', 'credentialSubject.2.location.name', 'issuer.desc']));

    const [minIssuanceDate, maxIssuanceDate] = [1662010848700, 1662010849900];
    // @ts-ignore
    expect(minIssuanceDate).toBeLessThan(credential6.getTopLevelField('issuanceDate'));
    // @ts-ignore
    expect(maxIssuanceDate).toBeGreaterThan(credential6.getTopLevelField('issuanceDate'));
    builder2.enforceBounds(0, 'issuanceDate', minIssuanceDate, maxIssuanceDate, boundCheckSnarkId, boundCheckProvingKey);

    const [minExpDate, maxExpDate] = [1662011940000, 1662011980000];
    // @ts-ignore
    expect(minExpDate).toBeLessThan(credential6.getTopLevelField('expirationDate'));
    // @ts-ignore
    expect(maxExpDate).toBeGreaterThan(credential6.getTopLevelField('expirationDate'));
    builder2.enforceBounds(0, 'expirationDate', minExpDate, maxExpDate, boundCheckSnarkId);

    const pres2 = builder2.finalize();
    expect(pres2.spec.credentials[0].revealedAttributes).toEqual({
      credentialSubject: [
        {
          name: 'Random'
        },
        {
          name: 'Random-1',
          location: {
            name: 'Somewhere-1',
          }
        },
        {
          location: {
            name: 'Somewhere-2',
          }
        }
      ],
      issuer: {
        desc: 'Just an issuer'
      }
    });
    expect(pres2.spec.credentials[0].bounds).toEqual({
      issuanceDate: {
        min: minIssuanceDate,
        max: maxIssuanceDate,
        paramId: boundCheckSnarkId
      },
      expirationDate: {
        min: minExpDate,
        max: maxExpDate,
        paramId: boundCheckSnarkId
      }
    });

    const pp = new Map();
    pp.set(boundCheckSnarkId, boundCheckVerifyingKey);
    checkResult(pres2.verify([pk1], undefined, pp));

    const presJson = pres2.toJSON();
    const recreatedPres = Presentation.fromJSON(presJson);
    checkResult(recreatedPres.verify([pk1], undefined, pp));
    expect(presJson).toEqual(recreatedPres.toJSON());
  })
});
