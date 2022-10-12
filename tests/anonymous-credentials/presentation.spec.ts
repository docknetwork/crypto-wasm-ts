import { BBSPlusPublicKeyG2, BBSPlusSecretKey, KeypairG2, SignatureParamsG1 } from '../../src';
import { initializeWasm } from '@docknetwork/crypto-wasm';
import { Credential, CredentialSchema, MEM_CHECK_STR, STATUS_STR, SUBJECT_STR } from '../../src/anonymous-credentials';
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
    const params = SignatureParamsG1.generate(1, Credential.getLabelBytes());
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

  it('from a single credential', () => {

  });
});