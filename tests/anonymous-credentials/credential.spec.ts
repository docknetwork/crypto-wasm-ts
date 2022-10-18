import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  Credential,
  CredentialSchema,
  MEM_CHECK_STR,
  SIGNATURE_PARAMS_LABEL_BYTES,
  STATUS_STR,
  SUBJECT_STR
} from '../../src/anonymous-credentials';
import { BBSPlusPublicKeyG2, BBSPlusSecretKey, KeypairG2, SignatureParamsG1 } from '../../src';
import { checkResult } from '../utils';

describe('Credential signing and verification', () => {
  let sk: BBSPlusSecretKey, pk: BBSPlusPublicKeyG2;

  beforeAll(async () => {
    await initializeWasm();
    const params = SignatureParamsG1.generate(1, SIGNATURE_PARAMS_LABEL_BYTES);
    const keypair = KeypairG2.generate(params);
    sk = keypair.sk;
    pk = keypair.pk;
  });

  it('for a flat (no-nesting) credential', () => {
    const credSchema = CredentialSchema.fromJSON(JSON.stringify({
      "$schema": "http://json-schema.org/draft-07/schema#",
      "$metadata": {
        "version": 1
      },
      "$id": "test",
      "type": "object",
      "properties": {
        "credentialSubject": {
          "type": "object",
          "properties": {
            "fname": {
              "type": "string"
            },
            "lname": {
              "type": "string"
            }
          },
          "required": []
        }
      }
    }));

    const cred = new Credential();
    cred.schema = credSchema;
    cred.issuerPubKey = 'did:dock:some-issuer-did-123';

    // TODO: restore
    // cred.subject = { fname: 'John', lastName: 'Smith' };
    // expect(() => cred.sign(sk)).toThrow();

    cred.subject = { fname: 'John', lname: 'Smith' };
    cred.sign(sk);

    checkResult(cred.verify(pk));

    const credJson = cred.toJSON();
  });

  it('for credential with nesting', () => {
    const credSchema = CredentialSchema.fromJSON(JSON.stringify({
      "$schema": "http://json-schema.org/draft-07/schema#",
      "$id": "test",
      "type": "object",
      "properties": {
        "credentialSubject": {
          "type": "object",
          "properties": {
            "fname": {
              "type": "string"
            },
            "lname": {
              "type": "string"
            },
            "sensitive": {
              "type": "object",
              "properties": {
                "email": {
                  "type": "string"
                },
                "phone": {
                  "type": "string"
                },
                "SSN": {
                  "type": "stringReversible",
                  "compress": false
                }
              }
            }
          },
          "required": []
        }
      }
    }));

    const cred = new Credential();
    cred.schema = credSchema;
    cred.issuerPubKey = 'did:dock:some-issuer-did-123';

    // TODO: fixme when theres actual json schema validation instead of just checking for property names
    // cred.subject = {
    //   fname: 'John',
    //   lname: 'Smith',
    //   sensitive: {
    //     secret: 'my-secret-that-wont-tell-anyone',
    //     email: 'john.smith@example.com',
    //     SSN: '123-456789-0'
    //   }
    // };
    // expect(() => cred.sign(sk)).toThrow();

    cred.subject = {
      fname: 'John',
      lname: 'Smith',
      sensitive: {
        phone: '810-1234567',
        email: 'john.smith@example.com',
        SSN: '123-456789-0'
      }
    };
    cred.sign(sk);

    checkResult(cred.verify(pk));
  });

  it('for credential with numeric fields', () => {
    // TODO: use jsonschema multipleOf instead of decimalPlaces
    const credSchema = CredentialSchema.fromJSON(JSON.stringify({
      "$schema": "http://json-schema.org/draft-07/schema#",
      "$id": "test",
      "type": "object",
      "properties": {
        "credentialSubject": {
          "type": "object",
          "properties": {
            "fname": {
              "type": "string"
            },
            "lname": {
              "type": "string"
            },
            "timeOfBirth": {
              "type": "positiveInteger"
            },
            "sensitive": {
              "type": "object",
              "properties": {
                "email": {
                  "type": "string"
                },
                "phone": {
                  "type": "string"
                },
                "SSN": {
                  "type": "stringReversible",
                  "compress": false
                }
              }
            }
          },
          "physical": {
            "type": "object",
            "properties": {
              "height": {"type": "positiveDecimalNumber", "decimalPlaces": 1},
              "weight": {"type": "positiveDecimalNumber", "decimalPlaces": 1},
              "BMI": {"type": "positiveDecimalNumber", "decimalPlaces": 2}
            }
          },
          "required": []
        }
      }
    }));

    const cred = new Credential();
    cred.schema = credSchema;
    cred.issuerPubKey = 'did:dock:some-issuer-did-123';

    cred.subject = {
      fname: 'John',
      lname: 'Smith',
      sensitive: {
        phone: '810-1234567',
        email: 'john.smith@example.com',
        SSN: '123-456789-0'
      },
      timeOfBirth: 1662010849619
    };
    // TODO: Fix me by checking conformity to schema
    // expect(() => cred.sign(sk)).toThrow();

    cred.subject = {
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
    cred.sign(sk);

    checkResult(cred.verify(pk));
  });

  it('for credential with credential status', () => {
    const schema: any = CredentialSchema.bare();
    schema.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        lname: { type: 'string' },
        sensitive: {
          type: 'object',
          properties: {
            very: {
              type: 'object',
              properties: {
                secret: { type: 'string' }
              }
            },
            email: { type: 'string' },
            phone: { type: 'string' },
            SSN: { type: 'stringReversible', compress: false }
          }
        },
        lessSensitive: {
          type: 'object',
          properties: {
            location: {
              type: 'object',
              properties: {
                country: { type: 'string' },
                city: { type: 'string' }
              }
            },
            department: {
              type: 'object',
              properties: {
                name: { type: 'string' },
                location: {
                  name: { type: 'string' },
                  geo: {
                    type: 'object',
                    properties: {
                      lat: { type: 'decimalNumber', decimalPlaces: 3, minimum: -90 },
                      long: { type: 'decimalNumber', decimalPlaces: 3, minimum: -180 }
                    }
                  }
                }
              }
            }
          }
        },
        rank: { type: 'positiveInteger' }
      }
    };
    schema.properties[STATUS_STR] = {
      type: 'object',
      properties: {
        $registryId: { type: 'string' },
        $revocationCheck: { type: 'string' },
        $revocationId: { type: 'string' }
      }
    };
    const credSchema = new CredentialSchema(schema);

    const cred = new Credential();
    cred.schema = credSchema;
    cred.issuerPubKey = 'did:dock:some-issuer-did-123';

    cred.subject = {
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
    cred.setCredentialStatus('dock:accumulator:accumId123', MEM_CHECK_STR, 'user:A-123');
    cred.sign(sk);

    checkResult(cred.verify(pk));

    // In practice there will be an accumulator as well
  });
});