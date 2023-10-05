import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  CredentialSchema,
  MEM_CHECK_STR,
  ID_STR,
  REV_CHECK_STR,
  REV_ID_STR,
  SCHEMA_STR,
  VB_ACCUMULATOR_22,
  SUBJECT_STR,
  TYPE_STR, IEmbeddedJsonSchema, META_SCHEMA_STR, DefaultSchemaParsingOpts, IJsonSchema
} from '../../src';
import { checkResult } from '../utils';
import { checkEmbeddedSchema, checkSchemaFromJson, getExampleBuilder, getExampleSchema } from './utils';
import * as jsonld from 'jsonld';
import { validate } from 'jsonschema';
import {
  SecretKey,
  KeyPair,
  PublicKey,
  SignatureParams,
  Credential,
  CredentialBuilder,
  SignatureLabelBytes,
  Scheme
} from '../scheme';

describe(`${Scheme} Credential signing and verification`, () => {
  let sk: SecretKey, pk: PublicKey;

  beforeAll(async () => {
    await initializeWasm();
    const params = SignatureParams.generate(100, SignatureLabelBytes);
    const keypair = KeyPair.generate(params);
    sk = keypair.sk;
    pk = keypair.pk;
  });

  function checkJsonConvForCred(cred: Credential, pk: PublicKey): Credential {
    const credJson = cred.toJSON();
    // Check that the credential JSON contains the schema in JSON-schema format
    checkSchemaFromJson(credJson[SCHEMA_STR], cred.schema);

    // The recreated credential should verify
    const recreatedCred = Credential.fromJSON(credJson);
    checkResult(recreatedCred.verify(pk));

    // The JSON representation of original and recreated credential should be same
    expect(credJson).toEqual(recreatedCred.toJSON());
    expect(recreatedCred.schema.version).toEqual(cred.schema.version);
    expect(recreatedCred.schema.schema).toEqual(cred.schema.schema);
    expect(recreatedCred.schema.jsonSchema).toEqual(cred.schema.jsonSchema);
    return recreatedCred;
  }

  function checkSigningVerificationAndSerialization(builder: CredentialBuilder, sk: SecretKey, pk: PublicKey) {
    expect(() => builder.sign(sk)).toThrow();
    expect(() => builder.sign(sk, undefined, { requireSameFieldsAsSchema: true })).toThrow();

    const cred = builder.sign(sk, undefined, { requireSameFieldsAsSchema: false });

    checkResult(cred.verify(pk));

    const recreatedCred = checkJsonConvForCred(cred, pk);
    expect(recreatedCred.subject).toEqual(builder.subject);
    checkResult(recreatedCred.verify(pk));
  }

  function checkCredSerz(withSchemaRef: boolean, num: number, allNonEmbeddedSchemas: IJsonSchema[], fullJsonSchema: IEmbeddedJsonSchema) {
    let builder: CredentialBuilder;
    if (withSchemaRef) {
      builder = getExampleBuilder(num, allNonEmbeddedSchemas);
    } else {
      builder = getExampleBuilder(num);
    }

    const ns = CredentialSchema.generateAppropriateSchema(
      builder.serializeForSigning(),
      builder.schema as CredentialSchema
    );

    checkEmbeddedSchema(withSchemaRef, ns, fullJsonSchema);
    checkSigningVerificationAndSerialization(builder, sk, pk);
  }

  it('for a flat (no-nesting) credential', () => {
    const schema = CredentialSchema.essential();
    schema.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        lname: { type: 'string' }
      }
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

    // The credential JSON should be valid as per the JSON schema
    let res = validate(cred.toJSON(), schema);
    expect(res.valid).toEqual(true);

    // The credential JSON fails to validate for an incorrect schema
    schema.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        lname: { type: 'number' }
      }
    };
    res = validate(cred.toJSON(), schema);
    expect(res.valid).toEqual(false);

    // NOTE: Probably makes sense to always have `required` as true in each object. Also to disallow extra keys.
  });

  it('for credential with nesting', async () => {
    const schema = CredentialSchema.essential();
    schema.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        lname: { type: 'string' },
        sensitive: {
          type: 'object',
          properties: {
            email: { type: 'string' },
            phone: { type: 'string' },
            SSN: { $ref: '#/definitions/encryptableString' }
          }
        }
      }
    };

    const schemaRef = 'https://example.com?hash=abc123ff';
    async function schemaGetter(ref: string): Promise<IEmbeddedJsonSchema> {
      return schema;
    }
    const nonEmbeddedSchema = {
      $id: schemaRef,
      [META_SCHEMA_STR]: 'http://json-schema.org/draft-07/schema#',
      type: 'object',
    };

    async function check(withSchemaRef: boolean) {
      let credSchema;
      if (withSchemaRef) {
        credSchema = await CredentialSchema.newSchemaFromExternal(nonEmbeddedSchema, schemaGetter);
      } else {
        credSchema = new CredentialSchema(schema);
      }
      const builder = new CredentialBuilder();
      builder.schema = credSchema;

      // Subject attributes not same as schema
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

      expect(recreatedCred.schema.getEmbeddedJsonSchema()).toEqual(schema);
      if (withSchemaRef) {
        expect(recreatedCred.schema.jsonSchema).toEqual(nonEmbeddedSchema);
        expect(recreatedCred.schema.fullJsonSchema).toEqual(schema);
      } else {
        expect(recreatedCred.schema.jsonSchema).toEqual(schema);
        expect(recreatedCred.schema.fullJsonSchema).not.toBeDefined();
      }
    }

    await check(true);
    await check(false);
  });

  it('for credential with boolean fields', () => {
    const schema = CredentialSchema.essential();
    schema.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        isbool: { type: 'boolean' }
      }
    };
    const credSchema = new CredentialSchema(schema);

    const builder = new CredentialBuilder();
    builder.schema = credSchema;

    builder.subject = { fname: 'John', isnotbool: true };
    expect(() => builder.sign(sk)).toThrow();

    builder.subject = { fname: 'John', isbool: "not a bool" };
    expect(() => builder.sign(sk)).toThrow();

    builder.subject = { fname: 'John', isbool: true };
    const cred = builder.sign(sk);

    checkResult(cred.verify(pk));
    const recreatedCred = checkJsonConvForCred(cred, pk);
    expect(recreatedCred.subject).toEqual({ fname: 'John', isbool: true });

    // The credential JSON should be valid as per the JSON schema
    let res = validate(cred.toJSON(), schema);
    expect(res.valid).toEqual(true);

    // The credential JSON fails to validate for an incorrect schema
    schema.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        isbool: { type: 'number' }
      }
    };
    res = validate(cred.toJSON(), schema);
    expect(res.valid).toEqual(false);
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

  it('for credential with date-time fields', () => {
    const schema = CredentialSchema.essential();
    schema.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        isDateTime: { type: 'string', format: 'date-time' }
      }
    };
    const credSchema = new CredentialSchema(schema);

    const builder = new CredentialBuilder();
    builder.schema = credSchema;

    builder.subject = { fname: 'John', isNotDateTime: true };
    expect(() => builder.sign(sk)).toThrow();

    builder.subject = { fname: 'John', isDateTime: 'not a valid date' };
    expect(() => builder.sign(sk)).toThrow();

    builder.subject = { fname: 'John', isDateTime: '2023-09-14T19:26:40.488Z' };
    const cred = builder.sign(sk);

    checkResult(cred.verify(pk));
    const recreatedCred = checkJsonConvForCred(cred, pk);
    expect(recreatedCred.subject).toEqual({ fname: 'John', isDateTime: '2023-09-14T19:26:40.488Z' });

    // The credential JSON should be valid as per the JSON schema
    let res = validate(cred.toJSON(), schema);
    expect(res.valid).toEqual(true);

    // Check negative date-time values
    const builderNegative = new CredentialBuilder();
    builderNegative.schema = credSchema;
    builderNegative.subject = { fname: 'John', isDateTime: '1800-09-14T19:26:40.488Z' };
    const credNegative = builderNegative.sign(sk);

    checkResult(credNegative.verify(pk));
    const recreatedCredNegative = checkJsonConvForCred(credNegative, pk);
    expect(recreatedCredNegative.subject).toEqual({ fname: 'John', isDateTime: '1800-09-14T19:26:40.488Z' });

    // The credential JSON fails to validate for an incorrect schema
    schema.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        isDateTime: { type: 'number' }
      }
    };
    res = validate(cred.toJSON(), schema);
    expect(res.valid).toEqual(false);
  });

  it('for credential with date fields', () => {
    const schema = CredentialSchema.essential();
    schema.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        isDateTime: { type: 'string', format: 'date' }
      }
    };
    const credSchema = new CredentialSchema(schema);

    const builder = new CredentialBuilder();
    builder.schema = credSchema;

    builder.subject = { fname: 'John', isNotDateTime: true };
    expect(() => builder.sign(sk)).toThrow();

    builder.subject = { fname: 'John', isDateTime: 'not a valid date' };
    expect(() => builder.sign(sk)).toThrow();

    builder.subject = { fname: 'John', isDateTime: '2023-09-14' };
    const cred = builder.sign(sk);

    checkResult(cred.verify(pk));
    const recreatedCred = checkJsonConvForCred(cred, pk);
    expect(recreatedCred.subject).toEqual({ fname: 'John', isDateTime: '2023-09-14' });

    // The credential JSON should be valid as per the JSON schema
    let res = validate(cred.toJSON(), schema);
    expect(res.valid).toEqual(true);

    // The credential JSON fails to validate for an incorrect schema
    schema.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        isDateTime: { type: 'number' }
      }
    };
    res = validate(cred.toJSON(), schema);
    expect(res.valid).toEqual(false);
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
      [ID_STR]: 'dock:accumulator:accumId123',
      [REV_CHECK_STR]: MEM_CHECK_STR,
      [REV_ID_STR]: 'user:A-123',
      [TYPE_STR]: VB_ACCUMULATOR_22
    });
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
      name: 'An issuer',
      desc: 'Just an issuer',
      logo: 'https://images.example-issuer.com/logo.png'
    });
    builder.setTopLevelField('issuanceDate', 1662010849700);
    builder.setTopLevelField('expirationDate', 1662011950934);

    const cred = builder.sign(sk);

    checkResult(cred.verify(pk));
    checkJsonConvForCred(cred, pk);
  });

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

    const credWithCtx = cred.toJSONWithJsonLdContext();
    let normalized = await jsonld.normalize(credWithCtx);
    expect(normalized).not.toEqual('');

    const credWithoutCtx = cred.toJSON();
    normalized = await jsonld.normalize(credWithoutCtx);
    expect(normalized).toEqual('');
  });

  it('for credential with relaxed schema validation', () => {
    // The schema does not match the credential exactly
    const schemaRefs = ['https://example.com?hash=abc123ff', 'https://example.com?hash=12345', 'https://example.com?hash=aaffbbdd55', 'blob:dock:9fedcba12'];
    const nonEmbeddedSchema = {
      $id: schemaRefs[0],
      [META_SCHEMA_STR]: 'http://json-schema.org/draft-07/schema#',
      type: 'object',
    };

    function check(withSchemaRef: boolean) {
      // With bare minimum schema
      const builder0 = new CredentialBuilder();
      builder0.subject = {
        fname: 'John',
        lname: 'Smith',
        city: 'NY',
        education: { university: 'Example', major: 'Nothing' }
      };
      if (withSchemaRef) {
        builder0.schema = new CredentialSchema(nonEmbeddedSchema, { useDefaults: true }, true, undefined, CredentialSchema.essential());
      } else {
        builder0.schema = new CredentialSchema(CredentialSchema.essential(), { useDefaults: true });
      }
      checkSigningVerificationAndSerialization(builder0, sk, pk);

      const ns0 = CredentialSchema.generateAppropriateSchema(
        builder0.serializeForSigning(),
        builder0.schema as CredentialSchema
      );
      const fullJsonSchema0 = {
        $schema: 'http://json-schema.org/draft-07/schema#',
        type: 'object',
        properties: {
          credentialSubject: {
            type: 'object',
            properties: {
              fname: { type: 'string' },
              lname: { type: 'string' },
              city: { type: 'string' },
              education: {
                type: 'object',
                properties: { university: { type: 'string' }, major: { type: 'string' } }
              }
            }
          },
          cryptoVersion: { type: 'string' },
          credentialSchema: { type: 'string' },
          proof: CredentialSchema.essential().properties.proof
        },
        definitions: {
          encryptableString: { type: 'string' },
          encryptableCompString: { type: 'string' }
        }
      };

      checkEmbeddedSchema(withSchemaRef, ns0, fullJsonSchema0, nonEmbeddedSchema);

      const allNonEmbeddedSchemas = [
        {
          $id: schemaRefs[0],
          [META_SCHEMA_STR]: 'http://json-schema.org/draft-07/schema#',
          type: 'object',
        },
        {
          $id: schemaRefs[1],
          [META_SCHEMA_STR]: 'http://json-schema.org/draft-07/schema#',
          type: 'object',
        },
        {
          $id: schemaRefs[2],
          [META_SCHEMA_STR]: 'http://json-schema.org/draft-07/schema#',
          type: 'object',
        },
        {
          $id: schemaRefs[3],
          [META_SCHEMA_STR]: 'http://json-schema.org/draft-07/schema#',
          type: 'object',
        }
      ];

      const fullJsonSchema = {
        $schema: 'http://json-schema.org/draft-07/schema#',
        type: 'object',
        properties: {
          credentialSubject: {
            type: 'object',
            properties: {
              fname: { type: 'string' },
              lname: { type: 'string' },
              city: { type: 'string' },
              education: {
                type: 'object',
                properties: { university: { type: 'string' }, major: { type: 'string' } }
              }
            }
          },
          cryptoVersion: { type: 'string' },
          credentialSchema: { type: 'string' },
          proof: CredentialSchema.essential().properties.proof
        },
        definitions: {
          encryptableString: { type: 'string' },
          encryptableCompString: { type: 'string' }
        }
      };

      checkCredSerz(withSchemaRef, 1, allNonEmbeddedSchemas, fullJsonSchema)

      const fullJsonSchema1 = {
        $schema: 'http://json-schema.org/draft-07/schema#',
        type: 'object',
        properties: {
          credentialSubject: {
            type: 'object',
            properties: {
              fname: { type: 'string' },
              lname: { type: 'string' },
              city: { type: 'string' },
              education: {
                type: 'object',
                properties: { university: { type: 'string' }, major: { type: 'string' } }
              },
              someArr: {
                type: 'array',
                items: [
                  { type: 'string' },
                  { type: 'string' },
                  { type: 'integer', minimum: -4294967295 },
                  { type: 'string' }
                ]
              }
            }
          },
          cryptoVersion: { type: 'string' },
          credentialSchema: { type: 'string' },
          proof: CredentialSchema.essential().properties.proof
        },
        definitions: {
          encryptableString: { type: 'string' },
          encryptableCompString: { type: 'string' }
        }
      };

      checkCredSerz(withSchemaRef, 2, allNonEmbeddedSchemas, fullJsonSchema1)

      const fullJsonSchema2 = {
        $schema: 'http://json-schema.org/draft-07/schema#',
        type: 'object',
        properties: {
          credentialSubject: {
            type: 'object',
            properties: {
              fname: { type: 'string' },
              lname: { type: 'string' },
              city: { type: 'string' },
              education: {
                type: 'object',
                properties: {
                  university: { type: 'string' },
                  major: { type: 'string' },
                  location: {
                    type: 'object',
                    properties: {
                      name: { type: 'string' },
                      lat: {
                        type: 'number',
                        minimum: -4294967295,
                        multipleOf: 0.01
                      },
                      long: {
                        type: 'number',
                        minimum: -4294967295,
                        multipleOf: 0.001
                      }
                    }
                  }
                }
              }
            }
          },
          cryptoVersion: { type: 'string' },
          credentialSchema: { type: 'string' },
          proof: CredentialSchema.essential().properties.proof
        },
        definitions: {
          encryptableString: { type: 'string' },
          encryptableCompString: { type: 'string' }
        }
      };

      checkCredSerz(withSchemaRef, 3, allNonEmbeddedSchemas, fullJsonSchema2)

      const fullJsonSchema3 = {
        $schema: 'http://json-schema.org/draft-07/schema#',
        type: 'object',
        properties: {
          credentialSubject: {
            type: 'object',
            properties: {
              fname: { type: 'string' },
              lname: { type: 'string' },
              education: {
                type: 'object',
                properties: {
                  university: { type: 'string' },
                  major: { type: 'string' },
                  location: {
                    type: 'object',
                    properties: {
                      name: { type: 'string' },
                      lat: {
                        type: 'number',
                        minimum: -4294967295,
                        multipleOf: 0.01
                      },
                      long: {
                        type: 'number',
                        minimum: -4294967295,
                        multipleOf: 0.001
                      }
                    }
                  }
                }
              },
              city: { type: 'string' }
            }
          },
          cryptoVersion: { type: 'string' },
          credentialSchema: { type: 'string' },
          proof: CredentialSchema.essential().properties.proof
        },
        definitions: {
          encryptableString: { type: 'string' },
          encryptableCompString: { type: 'string' }
        }
      };

      checkCredSerz(withSchemaRef, 4, allNonEmbeddedSchemas, fullJsonSchema3)

      // With top level fields
      const fullJsonSchema4 = {
        $schema: 'http://json-schema.org/draft-07/schema#',
        type: 'object',
        properties: {
          credentialSubject: {
            type: 'object',
            properties: {
              fname: { type: 'string' },
              lname: { type: 'string' },
              education: {
                type: 'object',
                properties: {
                  university: { type: 'string' },
                  major: { type: 'string' },
                  location: {
                    type: 'object',
                    properties: {
                      name: { type: 'string' },
                      lat: {
                        type: 'number',
                        minimum: -4294967295,
                        multipleOf: 0.01
                      },
                      long: {
                        type: 'number',
                        minimum: -4294967295,
                        multipleOf: 0.001
                      }
                    }
                  }
                }
              },
              city: { type: 'string' }
            }
          },
          cryptoVersion: { type: 'string' },
          credentialSchema: { type: 'string' },
          proof: CredentialSchema.essential().properties.proof,
          issuer: {
            type: 'object',
            properties: {
              name: { type: 'string' },
              location: {
                type: 'object',
                properties: { city: { type: 'string' }, state: { type: 'string' } }
              }
            }
          },
          issuanceDate: { type: 'string', format: 'date' },
          types: {
            type: 'array',
            items: [{ type: 'string' }, { type: 'string' }]
          }
        },
        definitions: {
          encryptableString: { type: 'string' },
          encryptableCompString: { type: 'string' }
        }
      };

      checkCredSerz(withSchemaRef, 5, allNonEmbeddedSchemas, fullJsonSchema4)

      // Credential with array of objects and schema has extra fields which would be removed
      const fullJsonSchema5 = {
        $schema: 'http://json-schema.org/draft-07/schema#',
        type: 'object',
        properties: {
          credentialSubject: {
            type: 'object',
            properties: {
              fname: { type: 'string' },
              lname: { type: 'string' },
              city: { type: 'string' },
              universities: {
                type: 'array',
                items: [
                  {
                    type: 'object',
                    properties: {
                      university: { type: 'string' },
                      major: { type: 'string' },
                      location: {
                        type: 'object',
                        properties: {
                          name: { type: 'string' },
                          lat: {
                            type: 'number',
                            minimum: -4294967295,
                            multipleOf: 0.01
                          },
                          long: {
                            type: 'number',
                            minimum: -4294967295,
                            multipleOf: 0.001
                          }
                        }
                      }
                    }
                  },
                  {
                    type: 'object',
                    properties: {
                      university: { type: 'string' },
                      major: { type: 'string' },
                      location: {
                        type: 'object',
                        properties: {
                          name: { type: 'string' },
                          lat: { type: 'integer', minimum: -4294967295 },
                          long: {
                            type: 'number',
                            minimum: -4294967295,
                            multipleOf: 0.1
                          }
                        }
                      }
                    }
                  }
                ]
              }
            }
          },
          cryptoVersion: { type: 'string' },
          credentialSchema: { type: 'string' },
          proof: CredentialSchema.essential().properties.proof
        },
        definitions: {
          encryptableString: { type: 'string' },
          encryptableCompString: { type: 'string' }
        }
      };

      checkCredSerz(withSchemaRef, 6, allNonEmbeddedSchemas, fullJsonSchema5)

      // Credential with array of object, string and array and schema has extra fields which would be removed
      const fullJsonSchema6 = {
        $schema: 'http://json-schema.org/draft-07/schema#',
        type: 'object',
        properties: {
          credentialSubject: {
            type: 'object',
            properties: {
              fname: { type: 'string' },
              lname: { type: 'string' },
              city: { type: 'string' },
              universities: {
                type: 'array',
                items: [
                  {
                    type: 'object',
                    properties: {
                      university: { type: 'string' },
                      major: { type: 'string' },
                      location: {
                        type: 'object',
                        properties: {
                          name: { type: 'string' },
                          lat: {
                            type: 'number',
                            minimum: -4294967295,
                            multipleOf: 0.01
                          },
                          long: {
                            type: 'number',
                            minimum: -4294967295,
                            multipleOf: 0.001
                          }
                        }
                      }
                    }
                  },
                  {
                    type: 'array',
                    items: [
                      { type: 'string' },
                      { type: 'string' },
                      {
                        type: 'object',
                        properties: { foo: { type: 'string' }, bar: { type: 'string' } }
                      }
                    ]
                  },
                  { type: 'string' }
                ]
              }
            }
          },
          cryptoVersion: { type: 'string' },
          credentialSchema: { type: 'string' },
          proof: CredentialSchema.essential().properties.proof
        },
        definitions: {
          encryptableString: { type: 'string' },
          encryptableCompString: { type: 'string' }
        }
      };

      checkCredSerz(withSchemaRef, 7, allNonEmbeddedSchemas, fullJsonSchema6)

      // Some fields missing and some extra in credential
      const fullJsonSchema7 = {
        $schema: 'http://json-schema.org/draft-07/schema#',
        type: 'object',
        properties: {
          credentialSubject: {
            type: 'object',
            properties: {
              education: {
                type: 'object',
                properties: {
                  major: { type: 'string' },
                  location: {
                    type: 'object',
                    properties: {
                      name: { type: 'string' },
                      lat: {
                        type: 'number',
                        minimum: -4294967295,
                        multipleOf: 0.01
                      },
                      long: {
                        type: 'number',
                        minimum: -4294967295,
                        multipleOf: 0.001
                      }
                    }
                  }
                }
              },
              city: { type: 'string' }
            }
          },
          cryptoVersion: { type: 'string' },
          credentialSchema: { type: 'string' },
          proof: CredentialSchema.essential().properties.proof
        },
        definitions: {
          encryptableString: { type: 'string' },
          encryptableCompString: { type: 'string' }
        }
      };

      checkCredSerz(withSchemaRef, 8, allNonEmbeddedSchemas, fullJsonSchema7)

      const fullJsonSchema8 = {
        $schema: 'http://json-schema.org/draft-07/schema#',
        type: 'object',
        properties: {
          credentialSubject: {
            type: 'object',
            properties: {
              education: {
                type: 'object',
                properties: {
                  major: { type: 'string' },
                  location: {
                    type: 'object',
                    properties: {
                      name: { type: 'string' },
                      lat: {
                        type: 'number',
                        minimum: -4294967295,
                        multipleOf: 0.01
                      },
                      long: {
                        type: 'number',
                        minimum: -4294967295,
                        multipleOf: 0.001
                      }
                    }
                  }
                }
              }
            }
          },
          cryptoVersion: { type: 'string' },
          credentialSchema: { type: 'string' },
          proof: CredentialSchema.essential().properties.proof
        },
        definitions: {
          encryptableString: { type: 'string' },
          encryptableCompString: { type: 'string' }
        }
      };

      checkCredSerz(withSchemaRef, 9, allNonEmbeddedSchemas, fullJsonSchema8)

      const fullJsonSchema9 = {
        $schema: 'http://json-schema.org/draft-07/schema#',
        $id: 'https://ld.dock.io/examples/resident-card-schema.json',
        title: 'Resident Card Example',
        type: 'object',
        properties: {
          credentialSubject: {
            type: 'object',
            properties: {
              givenName: { title: 'Given Name', type: 'string' },
              familyName: { title: 'Family Name', type: 'string' },
              lprNumber: { title: 'LPR Number', type: 'integer', minimum: 0 },
              id: { type: 'string' },
              type: {
                type: 'array',
                items: [{ type: 'string' }, { type: 'string' }]
              }
            },
            required: []
          },
          cryptoVersion: { type: 'string' },
          credentialSchema: { type: 'string' },
          proof: CredentialSchema.essential().properties.proof,
          '@context': {
            type: 'array',
            items: [{ type: 'string' }, { type: 'string' }, { type: 'string' }]
          },
          id: { type: 'string' },
          type: {
            type: 'array',
            items: [{ type: 'string' }, { type: 'string' }]
          },
          identifier: { type: 'string' },
          name: { type: 'string' },
          description: { type: 'string' }
        }
      };

      checkCredSerz(withSchemaRef, 10, allNonEmbeddedSchemas, fullJsonSchema9)

      const fullJsonSchema10 = {
        '$schema': 'http://json-schema.org/draft-07/schema#',
        type: 'object',
        properties: {
          credentialSubject: {
            type: 'object',
            properties: {
              fname: { type: 'string' },
              isbool: { type: 'boolean' },
            }
          },
          cryptoVersion: { type: 'string' },
          credentialSchema: { type: 'string' },
          proof: CredentialSchema.essential().properties.proof,
        },
        definitions: {
          encryptableString: { type: 'string' },
          encryptableCompString: { type: 'string' }
        }
      };

      checkCredSerz(withSchemaRef, 11, allNonEmbeddedSchemas, fullJsonSchema10)
    }

    check(false);
    check(true);
  });
});
