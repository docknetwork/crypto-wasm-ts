import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  Credential,
  CredentialBuilder,
  CredentialSchema,
  MEM_CHECK_STR, REGISTRY_ID_STR, REV_CHECK_STR, REV_ID_STR,
  SIGNATURE_PARAMS_LABEL_BYTES,
  SUBJECT_STR
} from '../../src/anonymous-credentials';
import { BBSPlusPublicKeyG2, BBSPlusSecretKey, KeypairG2, SignatureParamsG1 } from '../../src';
import { checkResult } from '../utils';
import { getExampleSchema } from './utils';
import * as jsonld from 'jsonld';

describe('CredentialBuilder signing and verification', () => {
  let sk: BBSPlusSecretKey, pk: BBSPlusPublicKeyG2;

  beforeAll(async () => {
    await initializeWasm();
    const params = SignatureParamsG1.generate(1, SIGNATURE_PARAMS_LABEL_BYTES);
    const keypair = KeypairG2.generate(params);
    sk = keypair.sk;
    pk = keypair.pk;
  });

  function checkJsonConvForCred(cred: Credential, pk: BBSPlusPublicKeyG2): Credential {
    // This to/from JSON can be abstracted into a class and then testing will lead to less duplicated code
    const credJson = cred.toJSON();
    const recreatedCred = Credential.fromJSON(credJson);
    checkResult(recreatedCred.verify(pk));
    expect(credJson).toEqual(recreatedCred.toJSON());
    expect(recreatedCred.schema.version).toEqual(cred.schema.version);
    expect(recreatedCred.schema.schema).toEqual(cred.schema.schema);
    return recreatedCred;
  }

  it('for a flat (no-nesting) credential', () => {
    const schema = CredentialSchema.essential();
    schema[SUBJECT_STR] = {
      fname: { type: 'string' },
      lname: { type: 'string' }
    };
    const credSchema = new CredentialSchema(schema);

    const builder = new CredentialBuilder();
    builder.schema = credSchema;

    builder.subject = { fname: 'John', lastName: 'Smith' };
    expect(() => builder.sign(sk)).toThrow();

    builder.subject = { fname: 'John', lname: 'Smith' };
    const cred = builder.sign(sk);

    checkResult(cred.verify(pk));
    const recreatedCred = checkJsonConvForCred(cred, pk);
    expect(recreatedCred.subject).toEqual({ fname: 'John', lname: 'Smith' });
  });

  it('for credential with nesting', () => {
    const schema = CredentialSchema.essential();
    schema[SUBJECT_STR] = {
      fname: { type: 'string' },
      lname: { type: 'string' },
      sensitive: {
        email: { type: 'string' },
        phone: { type: 'string' },
        SSN: { type: 'stringReversible', compress: false }
      }
    };
    const credSchema = new CredentialSchema(schema);

    const builder = new CredentialBuilder();
    builder.schema = credSchema;

    builder.subject = {
      fname: 'John',
      lname: 'Smith',
      sensitive: {
        secret: 'my-secret-that-wont-tell-anyone',
        email: 'john.smith@example.com',
        SSN: '123-456789-0'
      }
    };
    expect(() => builder.sign(sk)).toThrow();

    builder.subject = {
      fname: 'John',
      lname: 'Smith',
      sensitive: {
        phone: '810-1234567',
        email: 'john.smith@example.com',
        SSN: '123-456789-0'
      }
    };
    const cred = builder.sign(sk);

    checkResult(cred.verify(pk));
    const recreatedCred = checkJsonConvForCred(cred, pk);
    expect(recreatedCred.subject).toEqual({
      fname: 'John',
      lname: 'Smith',
      sensitive: {
        phone: '810-1234567',
        email: 'john.smith@example.com',
        SSN: '123-456789-0'
      }
    });
  });

  it('for credential with numeric fields', () => {
    const schema = getExampleSchema(8);
    const credSchema = new CredentialSchema(schema);

    const builder = new CredentialBuilder();
    builder.schema = credSchema;

    builder.subject = {
      fname: 'John',
      lname: 'Smith',
      sensitive: {
        phone: '810-1234567',
        email: 'john.smith@example.com',
        SSN: '123-456789-0'
      },
      timeOfBirth: 1662010849619
    };
    // Throw when some fields missing
    expect(() => builder.sign(sk)).toThrow();

    builder.subject = {
      fname: 'John',
      lname: 'Smith',
      sensitive: {
        phone: '810-1234567',
        email: 'john.smith@example.com',
        SSN: '123-456789-0'
      },
      timeOfBirth: 1662010849619,
      physical: {
        height: 181.5,
        weight: 210,
        BMI: 23.25
      }
    };
    const cred = builder.sign(sk);

    checkResult(cred.verify(pk));
    const recreatedCred = checkJsonConvForCred(cred, pk);
    expect(recreatedCred.subject).toEqual({
      fname: 'John',
      lname: 'Smith',
      sensitive: {
        phone: '810-1234567',
        email: 'john.smith@example.com',
        SSN: '123-456789-0'
      },
      timeOfBirth: 1662010849619,
      physical: {
        height: 181.5,
        weight: 210,
        BMI: 23.25
      }
    });
  });

  it('for credential with credential status', () => {
    const schema = getExampleSchema(5);
    const credSchema = new CredentialSchema(schema);

    const builder = new CredentialBuilder();
    builder.schema = credSchema;

    builder.subject = {
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
    builder.setCredentialStatus('dock:accumulator:accumId123', MEM_CHECK_STR, 'user:A-123');
    const cred = builder.sign(sk);

    checkResult(cred.verify(pk));
    const recreatedCred = checkJsonConvForCred(cred, pk);
    expect(recreatedCred.subject).toEqual({
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
    });
    expect(recreatedCred.credentialStatus).toEqual({
      [REGISTRY_ID_STR]: 'dock:accumulator:accumId123',
      [REV_CHECK_STR]: MEM_CHECK_STR,
      [REV_ID_STR]: 'user:A-123'
    })
    // In practice there will be an accumulator as well
  });

  it('for credential with top level fields', () => {
    const schema = getExampleSchema(7);
    const credSchema = new CredentialSchema(schema);

    const builder = new CredentialBuilder();
    builder.schema = credSchema;

    builder.subject = [
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
    builder.setTopLevelField('issuer', {
      name: "An issuer",
      desc: "Just an issuer",
      logo: "https://images.example-issuer.com/logo.png"
    });
    builder.setTopLevelField('issuanceDate', 1662010849700);
    builder.setTopLevelField('expirationDate', 1662011950934);

    const cred = builder.sign(sk);

    checkResult(cred.verify(pk));
    checkJsonConvForCred(cred, pk);
  })

  it('json-ld validation', async () => {
    const schema = getExampleSchema(8);
    const credSchema = new CredentialSchema(schema);

    const builder = new CredentialBuilder();
    builder.schema = credSchema;
    builder.subject = {
      fname: 'John',
      lname: 'Smith',
      sensitive: {
        phone: '810-1234567',
        email: 'john.smith@example.com',
        SSN: '123-456789-0'
      },
      timeOfBirth: 1662010849619,
      physical: {
        height: 181.5,
        weight: 210,
        BMI: 23.25
      }
    };
    const cred = builder.sign(sk);

    const credWithCtx = cred.prepareForJsonLd();
    let normalized = await jsonld.normalize(credWithCtx);
    expect(normalized).not.toEqual("");

    const credWithoutCtx = cred.prepareForJson();
    normalized = await jsonld.normalize(credWithoutCtx);
    expect(normalized).toEqual("");
  })
});
