import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  CRYPTO_VERSION_STR,
  CredentialSchema,
  DefaultSchemaParsingOpts,
  META_SCHEMA_STR,
  ID_STR,
  REV_CHECK_STR,
  REV_ID_STR,
  SCHEMA_STR,
  STATUS_STR,
  SUBJECT_STR,
  ValueType,
  VERSION_STR,
  TYPE_STR
} from '../../src';
import { getExampleSchema } from './utils';

describe('Credential Schema', () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it('JSON-schema $ref expansion with schema defined definitions', () => {
    const jsonSchema = {
      type: 'object',
      definitions: {
        customDefinition: { type: 'integer', minimum: -256 }
      },
      properties: {
        credentialSubject: {
          type: 'object',
          properties: {
            customField: { $ref: '#/definitions/customDefinition' }
          }
        }
      }
    };
    const schema = CredentialSchema.convertToInternalSchemaObj(jsonSchema, DefaultSchemaParsingOpts);
    expect(schema).toEqual({
      credentialSubject: {
        customField: { type: 'integer', minimum: -256 }
      }
    });
  });

  it('JSON-schema $ref expansion with override definitions', () => {
    const jsonSchema = {
      type: 'object',
      definitions: {
        encryptableString: { type: 'string' }
      },
      properties: {
        // cryptoVersion: {type: 'string'},
        // credentialSchema: CredentialSchema.schemaAsJsonSchema(),
        credentialSubject: {
          type: 'object',
          properties: {
            SSN: { $ref: '#/definitions/encryptableString' },
            userId: { $ref: '#/definitions/encryptableCompString' }
          }
        }
      }
    };
    const schema = CredentialSchema.convertToInternalSchemaObj(jsonSchema, DefaultSchemaParsingOpts);
    expect(schema).toEqual({
      credentialSubject: {
        SSN: { type: 'stringReversible', compress: false },
        userId: { type: 'stringReversible', compress: true }
      }
    });
  });

  it('Parse JSON-schema syntax', () => {
    const jsonSchema = {
      type: 'object',
      properties: {
        credentialSubject: {
          type: 'object',
          properties: {
            SSN: { $ref: '#/definitions/encryptableString' },
            userId: { $ref: '#/definitions/encryptableCompString' },
            bool: {type: 'boolean'},
            vision: { type: 'integer', minimum: -20 },
            longitude: { type: 'number', minimum: -180, multipleOf: 0.001 },
            time: { type: 'integer', minimum: 0 },
            weight: { type: 'number', minimum: 25, multipleOf: 0.1 }
          }
        }
      }
    };
    const schema = CredentialSchema.convertToInternalSchemaObj(jsonSchema, DefaultSchemaParsingOpts);
    expect(schema).toEqual({
      credentialSubject: {
        SSN: { type: 'stringReversible', compress: false },
        userId: { type: 'stringReversible', compress: true },
        bool: { type: 'boolean' },
        vision: { type: 'integer', minimum: -20 },
        longitude: { type: 'decimalNumber', minimum: -180, decimalPlaces: 3 },
        time: { type: 'positiveInteger' },
        weight: { type: 'positiveDecimalNumber', decimalPlaces: 1 }
      }
    });

    const jsonSchema1 = {
      type: 'object',
      properties: {
        credentialSubject: {
          type: 'object',
          properties: {
            sensitive: {
              type: 'object',
              properties: {
                SSN: { $ref: '#/definitions/encryptableString' },
                userId: { $ref: '#/definitions/encryptableCompString' }
              }
            },
            longitude: { type: 'number', minimum: -180, multipleOf: 0.001 },
            time: { type: 'integer', minimum: 0 },
            physical: {
              type: 'object',
              properties: {
                l1: {
                  type: 'object',
                  properties: {
                    vision: { type: 'integer', minimum: -20 }
                  }
                },
                l2: {
                  type: 'object',
                  properties: {
                    weight: { type: 'number', minimum: 25, multipleOf: 0.1 }
                  }
                }
              }
            }
          }
        }
      }
    };
    const schema1 = CredentialSchema.convertToInternalSchemaObj(jsonSchema1, DefaultSchemaParsingOpts);
    expect(schema1).toEqual({
      credentialSubject: {
        sensitive: {
          SSN: { type: 'stringReversible', compress: false },
          userId: { type: 'stringReversible', compress: true }
        },
        longitude: { type: 'decimalNumber', minimum: -180, decimalPlaces: 3 },
        time: { type: 'positiveInteger' },
        physical: {
          l1: { vision: { type: 'integer', minimum: -20 } },
          l2: {
            weight: { type: 'positiveDecimalNumber', decimalPlaces: 1 }
          }
        }
      }
    });
  });

  it('needs version, schema and subject fields', () => {
    const schema1 = {
      [META_SCHEMA_STR]: 'http://json-schema.org/draft-07/schema#',
      type: 'object',
      properties: {}
    };

    // @ts-ignore
    expect(() => new CredentialSchema(schema1)).toThrow();

    schema1.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' }
      }
    };
    // @ts-ignore
    const cs1 = new CredentialSchema(schema1);
    expect(cs1.schema[SUBJECT_STR]).toEqual({
      fname: { type: 'string' }
    });
    expect(cs1.toJSON()[VERSION_STR]).toEqual(CredentialSchema.VERSION);
    expect(cs1.hasStatus()).toEqual(false);
  });

  it('is valid schema validation', () => {
    // @ts-ignore
    expect(() => new CredentialSchema({})).toThrow();

    const essentialProps = CredentialSchema.essential(false);
    const schema1: any = {
      ...essentialProps,
      $metadata: {
        version: 1
      },
      properties: {
        ...essentialProps.properties,
        [SUBJECT_STR]: {
          type: 'object',
          properties: {
            fname: { type: 'string' }
          }
        }
      }
    };
    const cs1 = new CredentialSchema(schema1);
    expect(cs1.schema).toEqual({
      [SUBJECT_STR]: {
        fname: { type: 'string' }
      },
      proof: {
        type: { type: 'string' }
      }
    });
    expect(cs1.jsonSchema).toEqual({
      [META_SCHEMA_STR]: 'http://json-schema.org/draft-07/schema#',
      $metadata: {
        version: 1
      },
      type: 'object',
      properties: {
        [SUBJECT_STR]: {
          type: 'object',
          properties: {
            fname: { type: 'string' }
          }
        },
        proof: CredentialSchema.essential().properties.proof
      }
    });
    expect(cs1.hasStatus()).toEqual(false);
  });

  it('parsing options', () => {
    const schema = getExampleSchema(1);

    const cs1 = new CredentialSchema(schema, {
      useDefaults: true,
      defaultMinimumInteger: -10,
      defaultDecimalPlaces: 1
    });
    expect(cs1.parsingOptions).toEqual({ useDefaults: true, defaultMinimumInteger: -10, defaultDecimalPlaces: 1 });

    const cs2 = new CredentialSchema(schema, { useDefaults: true });
    expect(cs2.parsingOptions).toEqual({
      useDefaults: true,
      defaultMinimumInteger: DefaultSchemaParsingOpts.defaultMinimumInteger,
      defaultDecimalPlaces: DefaultSchemaParsingOpts.defaultDecimalPlaces
    });

    const cs3 = new CredentialSchema(schema, { useDefaults: true, defaultDecimalPlaces: 3 });
    expect(cs3.parsingOptions).toEqual({
      useDefaults: true,
      defaultMinimumInteger: DefaultSchemaParsingOpts.defaultMinimumInteger,
      defaultDecimalPlaces: 3
    });

    const cs4 = new CredentialSchema(schema, { useDefaults: true, defaultMinimumInteger: -50 });
    expect(cs4.parsingOptions).toEqual({
      useDefaults: true,
      defaultMinimumInteger: -50,
      defaultDecimalPlaces: DefaultSchemaParsingOpts.defaultDecimalPlaces
    });
  });

  it('validation of boolean type', () => {
    const schema2 = CredentialSchema.essential();
    schema2.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        isbool: { type: 'boolean' }
      }
    };
    const cs = new CredentialSchema(schema2, {useDefaults: true});
    expect(cs.schema[SUBJECT_STR]).toEqual({
      fname: { type: 'string' },
      isbool: { type: 'boolean' },
    });
    expect(cs.jsonSchema.properties[SUBJECT_STR]).toEqual({
      type: 'object',
      properties: {
        fname: { type: 'string' },
        isbool: { type: 'boolean' },
      }
    });
  });

  it('validation of numeric types', () => {
    const schema2 = CredentialSchema.essential();
    schema2.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'random string' }
      }
    };
    expect(() => new CredentialSchema(schema2)).toThrow();

    expect(() =>
      CredentialSchema.typeOfName('score', [
        ['fname', 'score'],
        [{ type: 'string' }, { type: 'random string' }]
      ])
    ).toThrow();

    schema2.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer' }
      }
    };
    expect(() => new CredentialSchema(schema2)).toThrow();

    schema2.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer' }
      }
    };
    expect(() => new CredentialSchema(schema2)).toThrow();

    let cs = new CredentialSchema(schema2, { useDefaults: true });
    expect(cs.schema[SUBJECT_STR]).toEqual({
      fname: { type: 'string' },
      score: { type: 'integer', minimum: DefaultSchemaParsingOpts.defaultMinimumInteger }
    });
    expect(cs.jsonSchema.properties[SUBJECT_STR]).toEqual({
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer' }
      }
    });

    cs = new CredentialSchema(schema2, { useDefaults: true, defaultMinimumInteger: -100 });
    expect(cs.schema[SUBJECT_STR]).toEqual({
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 }
    });
    expect(cs.jsonSchema.properties[SUBJECT_STR]).toEqual({
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer' }
      }
    });

    schema2.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 }
      }
    };
    const cs2 = new CredentialSchema(schema2);
    expect(cs2.schema[SUBJECT_STR]).toEqual({
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 }
    });
    expect(cs2.jsonSchema.properties[SUBJECT_STR]).toEqual({
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 }
      }
    });

    const schema3 = schema2;

    schema3.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        long: { type: 'number' }
      }
    };
    expect(() => new CredentialSchema(schema3)).toThrow();

    cs = new CredentialSchema(schema3, { useDefaults: true });
    expect(cs.schema[SUBJECT_STR]).toEqual({
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 },
      long: {
        type: 'decimalNumber',
        minimum: DefaultSchemaParsingOpts.defaultMinimumInteger,
        decimalPlaces: DefaultSchemaParsingOpts.defaultDecimalPlaces
      }
    });
    expect(cs.jsonSchema.properties[SUBJECT_STR]).toEqual({
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        long: { type: 'number' }
      }
    });

    cs = new CredentialSchema(schema3, { useDefaults: true, defaultMinimumInteger: -200, defaultDecimalPlaces: 5 });
    expect(cs.schema[SUBJECT_STR]).toEqual({
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 },
      long: { type: 'decimalNumber', minimum: -200, decimalPlaces: 5 }
    });
    expect(cs.jsonSchema.properties[SUBJECT_STR]).toEqual({
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        long: { type: 'number' }
      }
    });

    schema3.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        long: { type: 'number', minimum: -200 }
      }
    };
    expect(() => new CredentialSchema(schema3)).toThrow();

    cs = new CredentialSchema(schema3, { useDefaults: true });
    expect(cs.schema[SUBJECT_STR]).toEqual({
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 },
      long: { type: 'decimalNumber', minimum: -200, decimalPlaces: DefaultSchemaParsingOpts.defaultDecimalPlaces }
    });
    expect(cs.jsonSchema.properties[SUBJECT_STR]).toEqual({
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        long: { type: 'number', minimum: -200 }
      }
    });

    cs = new CredentialSchema(schema3, { useDefaults: true, defaultDecimalPlaces: 2 });
    expect(cs.schema[SUBJECT_STR]).toEqual({
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 },
      long: { type: 'decimalNumber', minimum: -200, decimalPlaces: 2 }
    });
    expect(cs.jsonSchema.properties[SUBJECT_STR]).toEqual({
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        long: { type: 'number', minimum: -200 }
      }
    });

    schema3.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        long: { type: 'number', minimum: 0, multipleOf: 0.01 }
      }
    };
    const cs3 = new CredentialSchema(schema3);
    expect(cs3.schema[SUBJECT_STR]).toEqual({
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 },
      long: { type: 'positiveDecimalNumber', decimalPlaces: 2 }
    });
    expect(cs3.jsonSchema.properties[SUBJECT_STR]).toEqual({
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        long: { type: 'number', minimum: 0, multipleOf: 0.01 }
      }
    });

    const schema4 = schema2;

    schema4.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        lat: { type: 'number' }
      }
    };
    expect(() => new CredentialSchema(schema4)).toThrow();

    cs = new CredentialSchema(schema4, { useDefaults: true });
    expect(cs.schema[SUBJECT_STR]).toEqual({
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 },
      lat: {
        type: 'decimalNumber',
        minimum: DefaultSchemaParsingOpts.defaultMinimumInteger,
        decimalPlaces: DefaultSchemaParsingOpts.defaultDecimalPlaces
      }
    });
    expect(cs.jsonSchema.properties[SUBJECT_STR]).toEqual({
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        lat: { type: 'number' }
      }
    });

    schema4.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        lat: { type: 'number', multipleOf: 0.001 }
      }
    };
    expect(() => new CredentialSchema(schema4)).toThrow();

    cs = new CredentialSchema(schema4, { useDefaults: true });
    expect(cs.schema[SUBJECT_STR]).toEqual({
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 },
      lat: { type: 'decimalNumber', minimum: DefaultSchemaParsingOpts.defaultMinimumInteger, decimalPlaces: 3 }
    });
    expect(cs.jsonSchema.properties[SUBJECT_STR]).toEqual({
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        lat: { type: 'number', multipleOf: 0.001 }
      }
    });

    cs = new CredentialSchema(schema4, { useDefaults: true, defaultMinimumInteger: -90 });
    expect(cs.schema[SUBJECT_STR]).toEqual({
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 },
      lat: { type: 'decimalNumber', minimum: -90, decimalPlaces: 3 }
    });
    expect(cs.jsonSchema.properties[SUBJECT_STR]).toEqual({
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        lat: { type: 'number', multipleOf: 0.001 }
      }
    });

    schema4.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        lat: { type: 'number', multipleOf: 0.002, minimum: -90 }
      }
    };
    expect(() => new CredentialSchema(schema4)).toThrow();

    schema4.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        lat: { type: 'number', multipleOf: 0.001, minimum: -90 }
      }
    };

    const cs4 = new CredentialSchema(schema4);
    expect(cs4.schema[SUBJECT_STR]).toEqual({
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 },
      lat: { type: 'decimalNumber', decimalPlaces: 3, minimum: -90 }
    });
    expect(cs4.jsonSchema.properties[SUBJECT_STR]).toEqual({
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        lat: { type: 'number', multipleOf: 0.001, minimum: -90 }
      }
    });
  });

  it('validation of credential status', () => {
    const schema4 = CredentialSchema.essential();
    schema4.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 }
      }
    };

    schema4.properties[STATUS_STR] = {
      type: 'object',
      properties: {
        [ID_STR]: { type: 'integer', minimum: -100 }
      }
    };

    expect(() => new CredentialSchema(schema4)).toThrow();

    schema4.properties[STATUS_STR]['properties'][ID_STR] = { type: 'string' };
    schema4.properties[STATUS_STR]['properties'][REV_CHECK_STR] = { type: 'string' };
    expect(() => new CredentialSchema(schema4)).toThrow();

    schema4.properties[STATUS_STR]['properties'][REV_ID_STR] = { type: 'string' };
    schema4.properties[STATUS_STR]['properties'][TYPE_STR] = { type: 'string' };
    const cs4 = new CredentialSchema(schema4);
    // @ts-ignore
    expect(cs4.schema[STATUS_STR][ID_STR]).toEqual({ type: 'string' });
    // @ts-ignore
    expect(cs4.schema[STATUS_STR][REV_CHECK_STR]).toEqual({ type: 'string' });
    // @ts-ignore
    expect(cs4.schema[STATUS_STR][REV_ID_STR]).toEqual({ type: 'string' });
    // @ts-ignore
    expect(cs4.schema[STATUS_STR][TYPE_STR]).toEqual({ type: 'string' });

    // @ts-ignore
    expect(cs4.jsonSchema.properties[STATUS_STR].properties[ID_STR]).toEqual({ type: 'string' });
    // @ts-ignore
    expect(cs4.jsonSchema.properties[STATUS_STR].properties[REV_CHECK_STR]).toEqual({ type: 'string' });
    // @ts-ignore
    expect(cs4.jsonSchema.properties[STATUS_STR].properties[REV_ID_STR]).toEqual({ type: 'string' });
    // @ts-ignore
    expect(cs4.jsonSchema.properties[STATUS_STR].properties[TYPE_STR]).toEqual({ type: 'string' });

    expect(cs4.hasStatus()).toEqual(true);
  });

  it('validation of some more schemas', () => {
    for (let i = 1; i <= 11; i++) {
      const schema = getExampleSchema(i);
      const cs = new CredentialSchema(schema);
      expect(cs.jsonSchema.properties[SUBJECT_STR]).toEqual(schema.properties[SUBJECT_STR]);
      if (schema.properties[STATUS_STR] === undefined) {
        expect(cs.schema[STATUS_STR]).not.toBeDefined();
        expect(cs.jsonSchema.properties[STATUS_STR]).not.toBeDefined();
        expect(cs.hasStatus()).toEqual(false);
      } else {
        expect(cs.schema[STATUS_STR]).toBeDefined();
        expect(cs.jsonSchema.properties[STATUS_STR]).toEqual(schema.properties[STATUS_STR]);
        expect(cs.hasStatus()).toEqual(true);
      }
    }
  });

  it('flattening', () => {
    const cs1 = new CredentialSchema(getExampleSchema(1));
    expect(cs1.flatten()).toEqual([
      [SCHEMA_STR, `${SUBJECT_STR}.fname`, CRYPTO_VERSION_STR, 'proof.type'],
      [{ type: 'string' }, { type: 'string' }, { type: 'string' }, { type: 'string' }]
    ]);

    const cs2 = new CredentialSchema(getExampleSchema(2));
    expect(cs2.flatten()).toEqual([
      [SCHEMA_STR, `${SUBJECT_STR}.fname`, `${SUBJECT_STR}.score`, CRYPTO_VERSION_STR, 'proof.type'],
      [
        { type: 'string' },
        { type: 'string' },
        { type: 'integer', minimum: -100 },
        { type: 'string' },
        { type: 'string' }
      ]
    ]);

    const cs3 = new CredentialSchema(getExampleSchema(3));
    expect(cs3.flatten()).toEqual([
      [
        SCHEMA_STR,
        `${SUBJECT_STR}.fname`,
        `${SUBJECT_STR}.long`,
        `${SUBJECT_STR}.score`,
        CRYPTO_VERSION_STR,
        'proof.type'
      ],
      [
        { type: 'string' },
        { type: 'string' },
        { type: 'positiveDecimalNumber', decimalPlaces: 2 },
        { type: 'integer', minimum: -100 },
        { type: 'string' },
        { type: 'string' }
      ]
    ]);

    const cs4 = new CredentialSchema(getExampleSchema(4));
    expect(cs4.flatten()).toEqual([
      [
        SCHEMA_STR,
        `${STATUS_STR}.${ID_STR}`,
        `${STATUS_STR}.${REV_CHECK_STR}`,
        `${STATUS_STR}.${REV_ID_STR}`,
        `${STATUS_STR}.${TYPE_STR}`,
        `${SUBJECT_STR}.fname`,
        `${SUBJECT_STR}.score`,
        CRYPTO_VERSION_STR,
        'proof.type'
      ],
      [
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'integer', minimum: -100 },
        { type: 'string' },
        { type: 'string' }
      ]
    ]);

    const cs5 = new CredentialSchema(getExampleSchema(5));
    expect(cs5.flatten()).toEqual([
      [
        SCHEMA_STR,
        `${STATUS_STR}.${ID_STR}`,
        `${STATUS_STR}.${REV_CHECK_STR}`,
        `${STATUS_STR}.${REV_ID_STR}`,
        `${STATUS_STR}.${TYPE_STR}`,
        `${SUBJECT_STR}.fname`,
        `${SUBJECT_STR}.lessSensitive.department.location.geo.lat`,
        `${SUBJECT_STR}.lessSensitive.department.location.geo.long`,
        `${SUBJECT_STR}.lessSensitive.department.location.name`,
        `${SUBJECT_STR}.lessSensitive.department.name`,
        `${SUBJECT_STR}.lessSensitive.location.city`,
        `${SUBJECT_STR}.lessSensitive.location.country`,
        `${SUBJECT_STR}.lname`,
        `${SUBJECT_STR}.rank`,
        `${SUBJECT_STR}.sensitive.SSN`,
        `${SUBJECT_STR}.sensitive.email`,
        `${SUBJECT_STR}.sensitive.phone`,
        `${SUBJECT_STR}.sensitive.very.secret`,
        CRYPTO_VERSION_STR,
        'proof.type'
      ],
      [
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { decimalPlaces: 3, minimum: -90, type: 'decimalNumber' },
        { decimalPlaces: 3, minimum: -180, type: 'decimalNumber' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'positiveInteger' },
        { compress: false, type: 'stringReversible' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' }
      ]
    ]);
  });

  it('to and from JSON', () => {
    for (let i = 1; i <= 12; i++) {
      const schema = getExampleSchema(i);
      const cs = new CredentialSchema(schema);
      const j = cs.toJSON();
      expect(CredentialSchema.asEmbeddedJsonSchema(cs.jsonSchema)).toEqual(j[ID_STR]);
      expect(CredentialSchema.extractJsonSchemaFromEmbedded(j[ID_STR])).toEqual(cs.jsonSchema);
      const recreatedCs = CredentialSchema.fromJSON(j);
      expect(j).toEqual(recreatedCs.toJSON());
      expect(cs.version).toEqual(recreatedCs.version);
      expect(cs.jsonSchema).toEqual(recreatedCs.jsonSchema);
      expect(cs.schema).toEqual(recreatedCs.schema);
      expect(
        // @ts-ignore
        JSON.stringify(Array.from(cs.encoder.encoders?.keys())) ===
          // @ts-ignore
          JSON.stringify(Array.from(recreatedCs.encoder.encoders?.keys()))
      ).toEqual(true);
      // TODO: Test encoding functions are same as well, this can be done in the credentials suite by using a deserialized schema
    }

    // version should match what was in JSON and not what's in `CredentialSchema` class
    const cs1 = new CredentialSchema(getExampleSchema(1));
    const j1 = cs1.toJSON();
    j1[VERSION_STR] = '91.329.68';
    const recreatedCs1 = CredentialSchema.fromJSON(j1);
    expect(recreatedCs1.version).toEqual('91.329.68');
    expect(recreatedCs1.version).not.toEqual(CredentialSchema.VERSION);
  });

  it('check type', () => {
    const schema = CredentialSchema.essential();
    schema.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        SSN: { $ref: '#/definitions/encryptableString' },
        userId: { $ref: '#/definitions/encryptableCompString' },
        timeOfBirth: { type: 'integer', minimum: 0 },
        xyz: { type: 'integer', minimum: -10 },
        BMI: { type: 'number', minimum: 0, multipleOf: 0.01 },
        score: { type: 'number', multipleOf: 0.1, minimum: -100 }
      }
    };
    const cs = new CredentialSchema(schema);

    expect(() => cs.typeOfName(`${SUBJECT_STR}.x`)).toThrow();
    expect(() => cs.typeOfName('fname')).toThrow();
    expect(cs.typeOfName(`${SUBJECT_STR}.fname`)).toEqual({ type: ValueType.Str });
    expect(cs.typeOfName(`${SUBJECT_STR}.SSN`)).toEqual({ type: ValueType.RevStr, compress: false });
    expect(cs.typeOfName(`${SUBJECT_STR}.userId`)).toEqual({ type: ValueType.RevStr, compress: true });
    expect(cs.typeOfName(`${SUBJECT_STR}.timeOfBirth`)).toEqual({ type: ValueType.PositiveInteger });
    expect(cs.typeOfName(`${SUBJECT_STR}.xyz`)).toEqual({ type: ValueType.Integer, minimum: -10 });
    expect(cs.typeOfName(`${SUBJECT_STR}.BMI`)).toEqual({ type: ValueType.PositiveNumber, decimalPlaces: 2 });
    expect(cs.typeOfName(`${SUBJECT_STR}.score`)).toEqual({ type: ValueType.Number, minimum: -100, decimalPlaces: 1 });
  });

  it('subject as an array', () => {
    const schema6 = getExampleSchema(6);
    const cs6 = new CredentialSchema(schema6);
    expect(cs6.jsonSchema.properties[SUBJECT_STR]).toEqual(schema6.properties[SUBJECT_STR]);

    expect(cs6.flatten()).toEqual([
      [
        SCHEMA_STR,
        `${SUBJECT_STR}.0.location.geo.lat`,
        `${SUBJECT_STR}.0.location.geo.long`,
        `${SUBJECT_STR}.0.location.name`,
        `${SUBJECT_STR}.0.name`,
        `${SUBJECT_STR}.1.location.geo.lat`,
        `${SUBJECT_STR}.1.location.geo.long`,
        `${SUBJECT_STR}.1.location.name`,
        `${SUBJECT_STR}.1.name`,
        `${SUBJECT_STR}.2.location.geo.lat`,
        `${SUBJECT_STR}.2.location.geo.long`,
        `${SUBJECT_STR}.2.location.name`,
        `${SUBJECT_STR}.2.name`,
        CRYPTO_VERSION_STR,
        'proof.type'
      ],
      [
        { type: 'string' },
        { type: 'decimalNumber', decimalPlaces: 3, minimum: -90 },
        { type: 'decimalNumber', decimalPlaces: 3, minimum: -180 },
        { type: 'string' },
        { type: 'string' },
        { type: 'decimalNumber', decimalPlaces: 3, minimum: -90 },
        { type: 'decimalNumber', decimalPlaces: 3, minimum: -180 },
        { type: 'string' },
        { type: 'string' },
        { type: 'decimalNumber', decimalPlaces: 3, minimum: -90 },
        { type: 'decimalNumber', decimalPlaces: 3, minimum: -180 },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' }
      ]
    ]);
  });

  it('custom top level fields', () => {
    const schema7 = getExampleSchema(7);
    const cs7 = new CredentialSchema(schema7);
    expect(cs7.jsonSchema.properties[SUBJECT_STR]).toEqual(schema7.properties[SUBJECT_STR]);
    expect(cs7.jsonSchema.properties['issuer']).toEqual(schema7.properties['issuer']);
    expect(cs7.jsonSchema.properties['issuanceDate']).toEqual(schema7.properties['issuanceDate']);
    expect(cs7.jsonSchema.properties['expirationDate']).toEqual(schema7.properties['expirationDate']);

    expect(cs7.flatten()).toEqual([
      [
        SCHEMA_STR,
        `${SUBJECT_STR}.0.location.geo.lat`,
        `${SUBJECT_STR}.0.location.geo.long`,
        `${SUBJECT_STR}.0.location.name`,
        `${SUBJECT_STR}.0.name`,
        `${SUBJECT_STR}.1.location.geo.lat`,
        `${SUBJECT_STR}.1.location.geo.long`,
        `${SUBJECT_STR}.1.location.name`,
        `${SUBJECT_STR}.1.name`,
        `${SUBJECT_STR}.2.location.geo.lat`,
        `${SUBJECT_STR}.2.location.geo.long`,
        `${SUBJECT_STR}.2.location.name`,
        `${SUBJECT_STR}.2.name`,
        CRYPTO_VERSION_STR,
        'expirationDate',
        'issuanceDate',
        'issuer.desc',
        'issuer.logo',
        'issuer.name',
        'proof.type'
      ],
      [
        { type: 'string' },
        { type: 'decimalNumber', decimalPlaces: 3, minimum: -90 },
        { type: 'decimalNumber', decimalPlaces: 3, minimum: -180 },
        { type: 'string' },
        { type: 'string' },
        { type: 'decimalNumber', decimalPlaces: 3, minimum: -90 },
        { type: 'decimalNumber', decimalPlaces: 3, minimum: -180 },
        { type: 'string' },
        { type: 'string' },
        { type: 'decimalNumber', decimalPlaces: 3, minimum: -90 },
        { type: 'decimalNumber', decimalPlaces: 3, minimum: -180 },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'positiveInteger' },
        { type: 'positiveInteger' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' }
      ]
    ]);
  });

  it('creating JSON-LD context', () => {
    const schema9 = getExampleSchema(9);
    const cs9 = new CredentialSchema(schema9);
    const ctx9 = cs9.getJsonLdContext();
    expect(ctx9['@context'][0]).toEqual({ '@version': 1.1 });
    expect(ctx9['@context'][1]).toEqual({
      dk: 'https://ld.dock.io/credentials#',
      credentialSchema: 'dk:credentialSchema',
      cryptoVersion: 'dk:cryptoVersion',
      credentialSubject: 'dk:credentialSubject',
      BMI: 'dk:BMI',
      SSN: 'dk:SSN',
      city: 'dk:city',
      country: 'dk:country',
      email: 'dk:email',
      fname: 'dk:fname',
      height: 'dk:height',
      lname: 'dk:lname',
      score: 'dk:score',
      secret: 'dk:secret',
      timeOfBirth: 'dk:timeOfBirth',
      userId: 'dk:userId',
      weight: 'dk:weight',
      proof: 'dk:proof',
      type: 'dk:type'
    });

    const schema5 = getExampleSchema(5);
    const cs5 = new CredentialSchema(schema5);
    const ctx5 = cs5.getJsonLdContext();
    expect(ctx5['@context'][0]).toEqual({ '@version': 1.1 });
    expect(ctx5['@context'][1]).toEqual({
      dk: 'https://ld.dock.io/credentials#',
      credentialSchema: 'dk:credentialSchema',
      cryptoVersion: 'dk:cryptoVersion',
      id: 'dk:id',
      revocationCheck: 'dk:revocationCheck',
      revocationId: 'dk:revocationId',
      credentialStatus: 'dk:credentialStatus',
      credentialSubject: 'dk:credentialSubject',
      fname: 'dk:fname',
      lessSensitive: 'dk:lessSensitive',
      department: 'dk:department',
      location: 'dk:location',
      geo: 'dk:geo',
      lat: 'dk:lat',
      long: 'dk:long',
      name: 'dk:name',
      city: 'dk:city',
      country: 'dk:country',
      lname: 'dk:lname',
      rank: 'dk:rank',
      sensitive: 'dk:sensitive',
      SSN: 'dk:SSN',
      email: 'dk:email',
      phone: 'dk:phone',
      type: 'dk:type',
      very: 'dk:very',
      secret: 'dk:secret',
      proof: 'dk:proof'
    });

    const schema7 = getExampleSchema(7);
    const cs7 = new CredentialSchema(schema7);
    const ctx7 = cs7.getJsonLdContext();
    expect(ctx7['@context'][0]).toEqual({ '@version': 1.1 });
    expect(ctx7['@context'][1]).toEqual({
      '0': 'dk:0',
      '1': 'dk:1',
      '2': 'dk:2',
      dk: 'https://ld.dock.io/credentials#',
      credentialSchema: 'dk:credentialSchema',
      cryptoVersion: 'dk:cryptoVersion',
      credentialSubject: 'dk:credentialSubject',
      location: 'dk:location',
      geo: 'dk:geo',
      lat: 'dk:lat',
      long: 'dk:long',
      name: 'dk:name',
      expirationDate: 'dk:expirationDate',
      issuanceDate: 'dk:issuanceDate',
      issuer: 'dk:issuer',
      desc: 'dk:desc',
      logo: 'dk:logo',
      proof: 'dk:proof',
      type: 'dk:type'
    });
  });

  it('extracing json from embedded', () => {
    const jsonData = { hello: 'world', buyDock: true };

    let dataStr = JSON.stringify(jsonData);
    let dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);
    let parsed = CredentialSchema.extractJsonSchemaFromEmbedded(dataUri);
    expect(parsed).toEqual(jsonData);

    dataUri = 'data:application/json;,' + encodeURIComponent(dataStr);
    parsed = CredentialSchema.extractJsonSchemaFromEmbedded(dataUri);
    expect(parsed).toEqual(jsonData);
  });
});
