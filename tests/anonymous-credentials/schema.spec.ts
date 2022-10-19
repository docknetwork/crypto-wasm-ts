import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  CRED_VERSION_STR,
  CredentialSchema,
  REGISTRY_ID_STR,
  REV_CHECK_STR,
  REV_ID_STR,
  SCHEMA_STR,
  STATUS_STR,
  SUBJECT_STR,
  ValueType,
  VERSION_STR
} from '../../src/anonymous-credentials';
import { getExampleSchema } from './utils';

describe('CredentialBuilder Schema', () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it('needs version, schema and subject fields', () => {
    const schema1 = {};

    expect(() => new CredentialSchema(schema1)).toThrow();

    schema1[SUBJECT_STR] = {
      fname: { type: 'string' }
    };
    expect(() => new CredentialSchema(schema1)).toThrow();

    schema1[CRED_VERSION_STR] = { type: 'integer' };
    expect(() => new CredentialSchema(schema1)).toThrow();

    schema1[CRED_VERSION_STR] = { type: 'string' };
    expect(() => new CredentialSchema(schema1)).toThrow();

    schema1[SCHEMA_STR] = { type: 'integer' };
    expect(() => new CredentialSchema(schema1)).toThrow();

    schema1[SCHEMA_STR] = { type: 'string' };
    const cs1 = new CredentialSchema(schema1);
    expect(cs1.schema[CRED_VERSION_STR]).toEqual({ type: 'string' });
    expect(cs1.schema[SCHEMA_STR]).toEqual({ type: 'string' });
    expect(cs1.schema[SUBJECT_STR]).toEqual({ fname: { type: 'string' } });
    expect(JSON.parse(cs1.toJSON())[VERSION_STR]).toEqual(CredentialSchema.VERSION);
  });

  it('validation of numeric types', () => {
    const schema2 = CredentialSchema.bare();
    schema2[SUBJECT_STR] = {
      fname: { type: 'string' },
      score: { type: 'random string' }
    };
    expect(() => new CredentialSchema(schema2)).toThrow();

    schema2[SUBJECT_STR] = {
      fname: { type: 'string' },
      score: { type: 'integer' }
    };
    expect(() => new CredentialSchema(schema2)).toThrow();

    schema2[SUBJECT_STR] = {
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 }
    };
    const cs2 = new CredentialSchema(schema2);
    expect(cs2.schema[SUBJECT_STR]).toEqual({ fname: { type: 'string' }, score: { type: 'integer', minimum: -100 } });

    const schema3 = schema2;

    schema3[SUBJECT_STR] = {
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 },
      long: { type: 'positiveDecimalNumber' }
    };
    expect(() => new CredentialSchema(schema3)).toThrow();

    schema3[SUBJECT_STR] = {
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 },
      long: { type: 'positiveDecimalNumber', minimum: -200 }
    };
    expect(() => new CredentialSchema(schema3)).toThrow();

    schema3[SUBJECT_STR] = {
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 },
      long: { type: 'positiveDecimalNumber', decimalPlaces: 2 }
    };
    const cs3 = new CredentialSchema(schema3);
    expect(cs3.schema[SUBJECT_STR]).toEqual({
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 },
      long: { type: 'positiveDecimalNumber', decimalPlaces: 2 }
    });
  });

  it('validation of credential status', () => {
    const schema4 = CredentialSchema.bare();
    schema4[SUBJECT_STR] = {
      fname: { type: 'string' },
      score: { type: 'integer', minimum: -100 }
    };

    schema4[STATUS_STR] = {};
    schema4[STATUS_STR][REGISTRY_ID_STR] = { type: 'integer', minimum: -100 };

    expect(() => new CredentialSchema(schema4)).toThrow();

    schema4[STATUS_STR][REGISTRY_ID_STR] = { type: 'string' };
    schema4[STATUS_STR][REV_CHECK_STR] = { type: 'string' };
    expect(() => new CredentialSchema(schema4)).toThrow();

    schema4[STATUS_STR][REV_ID_STR] = { type: 'string' };
    const cs4 = new CredentialSchema(schema4);
    expect(cs4.schema[STATUS_STR][REGISTRY_ID_STR]).toEqual({ type: 'string' });
    expect(cs4.schema[STATUS_STR][REV_CHECK_STR]).toEqual({ type: 'string' });
    expect(cs4.schema[STATUS_STR][REV_ID_STR]).toEqual({ type: 'string' });
  });

  it('validation of some more schemas', () => {
    const schema5 = getExampleSchema(9);
    const cs5 = new CredentialSchema(schema5);
    expect(cs5.schema[SUBJECT_STR]).toEqual(schema5[SUBJECT_STR]);
    expect(cs5.schema[STATUS_STR]).not.toBeDefined();

    const schema6 = getExampleSchema(5);

    const cs6 = new CredentialSchema(schema6);
    expect(cs6.schema[SUBJECT_STR]).toEqual(schema6[SUBJECT_STR]);
    expect(cs6.schema[STATUS_STR]).toEqual(schema6[STATUS_STR]);
  });


  it('flattening', () => {
    const cs1 = new CredentialSchema(getExampleSchema(1));
    expect(cs1.flatten()).toEqual([
      [SCHEMA_STR, `${SUBJECT_STR}.fname`, CRED_VERSION_STR],
      [{ type: 'string' }, { type: 'string' }, { type: 'string' }]
    ]);

    const cs2 = new CredentialSchema(getExampleSchema(2));
    expect(cs2.flatten()).toEqual([
      [SCHEMA_STR, `${SUBJECT_STR}.fname`, `${SUBJECT_STR}.score`, CRED_VERSION_STR],
      [{ type: 'string' }, { type: 'string' }, { type: 'integer', minimum: -100 }, { type: 'string' }]
    ]);

    const cs3 = new CredentialSchema(getExampleSchema(3));
    expect(cs3.flatten()).toEqual([
      [SCHEMA_STR, `${SUBJECT_STR}.fname`, `${SUBJECT_STR}.long`, `${SUBJECT_STR}.score`, CRED_VERSION_STR],
      [
        { type: 'string' },
        { type: 'string' },
        { type: 'positiveDecimalNumber', decimalPlaces: 2 },
        { type: 'integer', minimum: -100 },
        { type: 'string' }
      ]
    ]);

    const cs4 = new CredentialSchema(getExampleSchema(4));
    expect(cs4.flatten()).toEqual([
      [
        SCHEMA_STR,
        `${STATUS_STR}.${REGISTRY_ID_STR}`,
        `${STATUS_STR}.${REV_CHECK_STR}`,
        `${STATUS_STR}.${REV_ID_STR}`,
        `${SUBJECT_STR}.fname`,
        `${SUBJECT_STR}.score`,
        CRED_VERSION_STR
      ],
      [
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'string' },
        { type: 'integer', minimum: -100 },
        { type: 'string' }
      ]
    ]);

    const cs5 = new CredentialSchema(getExampleSchema(5));
    expect(cs5.flatten()).toEqual([
      [
        SCHEMA_STR,
        `${STATUS_STR}.${REGISTRY_ID_STR}`,
        `${STATUS_STR}.${REV_CHECK_STR}`,
        `${STATUS_STR}.${REV_ID_STR}`,
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
        CRED_VERSION_STR
      ],
      [
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
        { type: 'string' }
      ]
    ]);
  });

  it('to and from JSON', () => {
    for (let i = 1; i <= 5; i++) {
      const cs = new CredentialSchema(getExampleSchema(i));
      const j = cs.toJSON();
      const recreatedCs = CredentialSchema.fromJSON(j);
      expect(cs.version).toEqual(recreatedCs.version);
      expect(cs.schema).toEqual(recreatedCs.schema);
      expect(
        // @ts-ignore
        JSON.stringify(Array.from(cs.encoder.encoders?.keys())) ===
        // @ts-ignore
          JSON.stringify(Array.from(recreatedCs.encoder.encoders?.keys()))
      ).toEqual(true);
      // TODO: Test encoding functions are same as well, this can be done in the credentials suite by using a deserialized schema
    }

    // version should match what was in JSON and not whats in `CredentialSchema` class
    const cs1 = new CredentialSchema(getExampleSchema(1));
    const j1 = JSON.parse(cs1.toJSON());
    j1[VERSION_STR] = '91.329.68';
    const recreatedCs1 = CredentialSchema.fromJSON(JSON.stringify(j1));
    expect(recreatedCs1.version).toEqual('91.329.68');
    expect(recreatedCs1.version).not.toEqual(CredentialSchema.VERSION);
  });

  it('check type', () => {
    const schema = CredentialSchema.bare();
    schema[SUBJECT_STR] = {
      fname: { type: 'string' },
      SSN: { type: 'stringReversible', compress: false },
      userId: { type: 'stringReversible', compress: true },
      timeOfBirth: { type: 'positiveInteger' },
      xyz: { type: 'integer', minimum: -10 },
      BMI: { type: 'positiveDecimalNumber', decimalPlaces: 2 },
      score: { type: 'decimalNumber', decimalPlaces: 1, minimum: -100 }
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
    expect(cs6.schema[SUBJECT_STR]).toEqual(schema6[SUBJECT_STR]);

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
        CRED_VERSION_STR
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
        { type: 'string' }
      ]
    ]);
  });

  it('custom top level fields', () => {
    const schema7 = getExampleSchema(7);
    const cs7 = new CredentialSchema(schema7);
    expect(cs7.schema[SUBJECT_STR]).toEqual(schema7[SUBJECT_STR]);
    expect(cs7.schema['issuer']).toEqual(schema7['issuer']);
    expect(cs7.schema['issuanceDate']).toEqual(schema7['issuanceDate']);
    expect(cs7.schema['expirationDate']).toEqual(schema7['expirationDate']);

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
        CRED_VERSION_STR,
        'expirationDate',
        'issuanceDate',
        'issuer.desc',
        'issuer.logo',
        'issuer.name'
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
        { type: 'string' }
      ]
    ]);
  });
});
