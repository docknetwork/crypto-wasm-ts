import { BBSPlusPublicKeyG2, BBSPlusSecretKey, KeypairG2, SignatureParamsG1 } from '../../src';
import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  Credential,
  CredentialSchema,
  MEM_CHECK_STR,
  PresentationBuilder, SIGNATURE_PARAMS_LABEL_BYTES,
  STATUS_STR,
  SUBJECT_STR
} from '../../src/anonymous-credentials';
import { checkResult } from '../utils';

describe('Presentation creation and verification', () => {
  let sk1: BBSPlusSecretKey, pk1: BBSPlusPublicKeyG2;
  let sk2: BBSPlusSecretKey, pk2: BBSPlusPublicKeyG2;
  let sk3: BBSPlusSecretKey, pk3: BBSPlusPublicKeyG2;

  let credential1: Credential;
  let credential2: Credential;
  let credential3: Credential;

  beforeAll(async () => {
    await initializeWasm();
    const params = SignatureParamsG1.generate(1, SIGNATURE_PARAMS_LABEL_BYTES);
    const keypair1 = KeypairG2.generate(params);
    const keypair2 = KeypairG2.generate(params);
    const keypair3 = KeypairG2.generate(params);
    sk1 = keypair1.sk;
    pk1 = keypair1.pk;
    sk2 = keypair2.sk;
    pk2 = keypair2.pk;
    sk3 = keypair3.sk;
    pk3 = keypair3.pk;

    const schema1 = CredentialSchema.bare();
    schema1[SUBJECT_STR] = {
      fname: {type: "string"},
      lname: {type: "string"},
      email: {type: "string"},
      SSN: {type: "stringReversible", compress: false},
      userId: {type: "stringReversible", compress: true},
      country: {type: "string"},
      city: {type: "string"},
      timeOfBirth: {type: "positiveInteger"},
      height: {type: "positiveDecimalNumber", decimalPlaces: 1},
      weight: {type: "positiveDecimalNumber", decimalPlaces: 1},
      BMI: {type: "positiveDecimalNumber", decimalPlaces: 2},
      score: {type: "decimalNumber", decimalPlaces: 1, minimum: -100},
      secret: {type: "string"}
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
      fname: {type: "string"},
      lname: {type: "string"},
      sensitive: {
        secret: {type: "string"},
        email: {type: "string"},
        SSN: {type: "stringReversible", compress: false},
        userId: {type: "stringReversible", compress: true},
      },
      location: {
        country: {type: "string"},
        city: {type: "string"},
      },
      timeOfBirth: {type: "positiveInteger"},
      physical: {
        height: {type: "positiveDecimalNumber", decimalPlaces: 1},
        weight: {type: "positiveDecimalNumber", decimalPlaces: 1},
        BMI: {type: "positiveDecimalNumber", decimalPlaces: 2},
      },
      score: {type: "decimalNumber", decimalPlaces: 1, minimum: -100},
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
      fname: {type: "string"},
      lname: {type: "string"},
      sensitive: {
        very: {
          secret: {type: "string"}
        },
        email: {type: "string"},
        phone: {type: "string"},
        SSN: {type: "stringReversible", compress: false},
      },
      lessSensitive: {
        location: {
          country: {type: "string"},
          city: {type: "string"}
        },
        department: {
          name: {type: "string"},
          location: {
            name: {type: "string"},
            geo: {
              lat: {type: "decimalNumber", decimalPlaces: 3, minimum: -90},
              long: {type: "decimalNumber", decimalPlaces: 3, minimum: -180}
            }
          }
        }
      },
      rank: {type: "positiveInteger"}
    };
    schema3[STATUS_STR] = {
      $registryId: {type: "string"},
      $revocationCheck: {type: "string"},
      employeeId: {type: "string"}
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
        SSN: '123-456789-0',
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
    credential3.setCredentialStatus('dock:accumulator:accumId123', MEM_CHECK_STR, 'employeeId', 'user:123-xyz-#')
    credential3.sign(sk3);
    checkResult(credential3.verify(pk3));
    // TODO: Create accumulator for above
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
      physical: { BMI: 23.25 },
    });
    checkResult(pres2.verify([pk2]));
  });

  it('from a nested credential with credential status - `credential3`', () => {
    const builder3 = new PresentationBuilder();
    expect(builder3.addCredential(credential3, pk3)).toEqual(0);
    builder3.markAttributesRevealed(0, new Set<string>(['fname', 'lessSensitive.location.country', 'lessSensitive.department.location.name']));
    // TODO:
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
      physical: { BMI: 23.25 },
    });

    // Public keys in wrong order
    expect(pres4.verify([pk2, pk1]).verified).toEqual(false);

    checkResult(pres4.verify([pk1, pk2]));
  });
});
