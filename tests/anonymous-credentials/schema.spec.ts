import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  CRED_VERSION_STR,
  CredentialSchema,
  REGISTRY_ID_STR,
  REV_CHECK_STR,
  REV_ID_STR,
  SCHEMA_STR,
  STATUS_STR,
  SUBJECT_STR, ValueType,
  VERSION_STR
} from '../../src/anonymous-credentials';

describe('Credential Schema', () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it('is valid schema validation', () => {
    expect(() => new CredentialSchema({})).toThrow();

    const schema1: any = {
      "$schema": "http://json-schema.org/draft-07/schema#",
      "$metadata": {
        "version": 1
      },
      properties: {
        credentialSubject: {
          type: 'object',
          properties: {
            fname: { type: 'string' }
          }
        }
      },
    };
    const cs1 = new CredentialSchema(schema1);
    expect(cs1.properties[SUBJECT_STR].properties.fname).toEqual({ type: 'string' });
  });

  it('validation of numeric types', () => {
    const schema2: any = CredentialSchema.bare();
    schema2.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'random string' },
      },
    };
    expect(() => new CredentialSchema(schema2)).toThrow();

    schema2.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer' }
      },
    };
    expect(() => new CredentialSchema(schema2)).toThrow();

    schema2.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 }
      },
    };
    const cs2 = new CredentialSchema(schema2);
    expect(cs2.schema.properties[SUBJECT_STR]).toEqual({
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
      }
    });

    const schema3: any = schema2;

    schema3.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        long: { type: 'positiveDecimalNumber' }
      },
    };
    expect(() => new CredentialSchema(schema3)).toThrow();

    schema3.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        long: { type: 'positiveDecimalNumber', minimum: -200 }
      },
    };
    expect(() => new CredentialSchema(schema3)).toThrow();

    schema3.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        long: { type: 'positiveDecimalNumber', decimalPlaces: 2 }
      }
    };
    const cs3 = new CredentialSchema(schema3);
    expect(cs3.schema.properties[SUBJECT_STR]).toEqual({
      type: 'object',
      properties: {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        long: { type: 'positiveDecimalNumber', decimalPlaces: 2 }
      }
    });
  });

  it('validation of some more schemas', () => {
    const schema5: any = CredentialSchema.bare();
    schema5.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
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
      },
    };
    const cs5 = new CredentialSchema(schema5);
    expect(cs5.schema.properties[SUBJECT_STR]).toEqual(schema5.properties[SUBJECT_STR]);
    expect(cs5.schema.properties[STATUS_STR]).not.toBeDefined();

    const schema6: any = CredentialSchema.bare();
    schema6.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
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
      }
    };
    schema6.properties[STATUS_STR] = {
      type: 'object',
      properties: {
        $registryId: { type: 'string' },
        $revocationCheck: { type: 'string' },
        $revocationId: { type: 'string' }
      }
    };

    const cs6 = new CredentialSchema(schema6);
    expect(cs6.schema.properties[SUBJECT_STR]).toEqual(schema6.properties[SUBJECT_STR]);
    expect(cs6.schema.properties[STATUS_STR]).toEqual(schema6.properties[STATUS_STR]);
  });

  function getSchema(num) {
    const schema: any = CredentialSchema.bare();
    schema[CRED_VERSION_STR] = { type: 'string' };
    schema[SCHEMA_STR] = { type: 'string' };
    switch (num) {
      case 1:
        schema.properties[SUBJECT_STR] = {
          type: 'object',
          properties: {
            fname: { type: 'string' }
          },
        };
        break;
      case 2:
        schema.properties[SUBJECT_STR] = {
          type: 'object',
          properties: {
            fname: { type: 'string' },
            score: { type: 'integer', minimum: -100 }
          }
        };
        break;
      case 3:
        schema.properties[SUBJECT_STR] = {
          type: 'object',
          properties: {
            fname: { type: 'string' },
            score: { type: 'integer', minimum: -100 },
            long: { type: 'positiveDecimalNumber', decimalPlaces: 2 }
          }
        };
        break;
      case 4:
        schema.properties[SUBJECT_STR] = {
          type: 'object',
          properties: {
            fname: { type: 'string' },
            score: { type: 'integer', minimum: -100 }
          }
        };
        schema.properties[STATUS_STR] = {};
        schema.properties[STATUS_STR][REGISTRY_ID_STR] = { type: 'string' };
        schema.properties[STATUS_STR][REV_CHECK_STR] = { type: 'string' };
        schema.properties[STATUS_STR][REV_ID_STR] = { type: 'string' };
        break;
      case 5:
        schema.properties[SUBJECT_STR] = {
          type: 'object',
            properties: {
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
        break;
    }
    return schema;
  }

  it('flattening', () => {
    const cs1 = new CredentialSchema(getSchema(1));
    expect(cs1.flatten()).toEqual([
      [SCHEMA_STR, CRED_VERSION_STR, `${SUBJECT_STR}.fname`],
      [{ type: 'string' }, { type: 'string' }, { type: 'string' }]
    ]);

    const cs2 = new CredentialSchema(getSchema(2));
    expect(cs2.flatten()).toEqual([
      [SCHEMA_STR, CRED_VERSION_STR, `${SUBJECT_STR}.fname`, `${SUBJECT_STR}.score`],
      [{ type: 'string' }, { type: 'string' }, { type: 'string' }, { type: 'integer', minimum: -100 }],
    ]);

    const cs3 = new CredentialSchema(getSchema(3));
    expect(cs3.flatten()).toEqual([
      [SCHEMA_STR, CRED_VERSION_STR, `${SUBJECT_STR}.fname`, `${SUBJECT_STR}.long`, `${SUBJECT_STR}.score`],
      [
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'positiveDecimalNumber', decimalPlaces: 2 },
        { type: 'integer', minimum: -100 },
      ]
    ]);

    const cs4 = new CredentialSchema(getSchema(4));
    expect(cs4.flatten()).toEqual([
      [
        SCHEMA_STR,
        `${STATUS_STR}.${REGISTRY_ID_STR}`,
        `${STATUS_STR}.${REV_CHECK_STR}`,
        `${STATUS_STR}.${REV_ID_STR}`,
        CRED_VERSION_STR,
        `${SUBJECT_STR}.fname`,
        `${SUBJECT_STR}.score`,
      ],
      [
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'integer', minimum: -100 },
      ]
    ]);

    const cs5 = new CredentialSchema(getSchema(5));
    expect(cs5.flatten()).toEqual([
      [
        SCHEMA_STR,
        `${STATUS_STR}.${REGISTRY_ID_STR}`,
        `${STATUS_STR}.${REV_CHECK_STR}`,
        `${STATUS_STR}.${REV_ID_STR}`,
        CRED_VERSION_STR,
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
        { type: 'string' }
      ]
    ]);
  });

  it('to and from JSON', () => {
    for (let i = 1; i <= 5; i++) {
      const cs = new CredentialSchema(getSchema(i));
      const j = cs.toJSON();
      const recreatedCs = CredentialSchema.fromJSON(j);
      expect(cs.version).toEqual(recreatedCs.version);
      expect(cs.schema).toEqual(recreatedCs.schema);
      expect(
        // @ts-ignore
        JSON.stringify(Array.from(cs.encoder.encoders?.keys())) === JSON.stringify(Array.from(recreatedCs.encoder.encoders?.keys()))
      ).toEqual(true);
      // TODO: Test encoding functions are same as well, this can be done in the credentials suite by using a deserialized schema
    }

    // version should match what was in JSON and not whats in `CredentialSchema` class
    const cs1 = new CredentialSchema(getSchema(1));
    const j1 = JSON.parse(cs1.toJSON());
    j1[VERSION_STR] = '91.329.68';
    const recreatedCs1 = CredentialSchema.fromJSON(JSON.stringify(j1));
    expect(recreatedCs1.version).toEqual('91.329.68');
    expect(recreatedCs1.version).not.toEqual(CredentialSchema.VERSION);
  });

  it('check type', () => {
    const schema: any = CredentialSchema.bare();
    schema.properties[SUBJECT_STR] = {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        SSN: { type: 'stringReversible', compress: false },
        userId: { type: 'stringReversible', compress: true },
        timeOfBirth: { type: 'positiveInteger' },
        xyz: { type: 'integer', minimum: -10 },
        BMI: { type: 'positiveDecimalNumber', decimalPlaces: 2 },
        score: { type: 'decimalNumber', decimalPlaces: 1, minimum: -100 },
      }
    };
    const cs = new CredentialSchema(schema);

    expect(() => cs.typeOfName(`${SUBJECT_STR}.x`)).toThrow();
    expect(() => cs.typeOfName('fname')).toThrow();
    expect(cs.typeOfName(`${SUBJECT_STR}.fname`)).toEqual({type: ValueType.Str});
    expect(cs.typeOfName(`${SUBJECT_STR}.SSN`)).toEqual({type: ValueType.RevStr, compress: false});
    expect(cs.typeOfName(`${SUBJECT_STR}.userId`)).toEqual({type: ValueType.RevStr, compress: true});
    expect(cs.typeOfName(`${SUBJECT_STR}.timeOfBirth`)).toEqual({type: ValueType.PositiveInteger});
    expect(cs.typeOfName(`${SUBJECT_STR}.xyz`)).toEqual({type: ValueType.Integer, minimum: -10});
    expect(cs.typeOfName(`${SUBJECT_STR}.BMI`)).toEqual({type: ValueType.PositiveNumber, decimalPlaces: 2});
    expect(cs.typeOfName(`${SUBJECT_STR}.score`)).toEqual({type: ValueType.Number, minimum: -100, decimalPlaces: 1});
  })
});
