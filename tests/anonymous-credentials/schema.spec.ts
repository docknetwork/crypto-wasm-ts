import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  CRED_VERSION_STR,
  CredentialSchema,
  SCHEMA_STR,
  SUBJECT_STR,
  VERSION_STR
} from '../../src/anonymous-credentials';

describe('Credential Schema validation', () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it('needs version, schema and subject fields', () => {
    const schema1 = {};

    expect(() => new CredentialSchema(schema1)).toThrow();

    schema1[SUBJECT_STR] = {
      fname: {type: "string"},
    };
    expect(() => new CredentialSchema(schema1)).toThrow();

    schema1[CRED_VERSION_STR] = {type: "integer"};
    expect(() => new CredentialSchema(schema1)).toThrow();

    schema1[CRED_VERSION_STR] = {type: "string"};
    expect(() => new CredentialSchema(schema1)).toThrow();

    schema1[SCHEMA_STR] = {type: "integer"};
    expect(() => new CredentialSchema(schema1)).toThrow();

    schema1[SCHEMA_STR] = {type: "string"};
    const cs1 = new CredentialSchema(schema1);
    expect(cs1.schema[CRED_VERSION_STR]).toEqual({ type: 'string' })
    expect(cs1.schema[SCHEMA_STR]).toEqual({ type: 'string' })
    expect(cs1.schema[SUBJECT_STR]).toEqual({ fname: { type: 'string' } });
    expect(JSON.parse(cs1.toJSON())[VERSION_STR]).toEqual(CredentialSchema.VERSION);
  })

  it('validation of numeric types', () => {
    const schema2 = {};
    schema2[CRED_VERSION_STR] = {type: "string"};
    schema2[SCHEMA_STR] = {type: "string"};
    schema2[SUBJECT_STR] = {
      fname: {type: "string"},
      score: {type: "random string"},
    };
    expect(() => new CredentialSchema(schema2)).toThrow();

    schema2[SUBJECT_STR] = {
      fname: {type: "string"},
      score: {type: "integer"},
    };
    expect(() => new CredentialSchema(schema2)).toThrow();

    schema2[SUBJECT_STR] = {
      fname: {type: "string"},
      score: {type: "integer", minimum: -100},
    };
    const cs2 = new CredentialSchema(schema2);
    expect(cs2.schema[SUBJECT_STR]).toEqual({ fname: { type: 'string' }, score: {type: "integer", minimum: -100} });

    const schema3 = schema2;

    schema3[SUBJECT_STR] = {
      fname: {type: "string"},
      score: {type: "integer", minimum: -100},
      long: {type: "positiveDecimalNumber"},
    };
    expect(() => new CredentialSchema(schema3)).toThrow();

    schema3[SUBJECT_STR] = {
      fname: {type: "string"},
      score: {type: "integer", minimum: -100},
      long: {type: "positiveDecimalNumber", minimum: -200},
    };
    expect(() => new CredentialSchema(schema3)).toThrow();

    schema3[SUBJECT_STR] = {
      fname: {type: "string"},
      score: {type: "integer", minimum: -100},
      long: {type: "positiveDecimalNumber", decimalPlaces: 2},
    };
    const cs3 = new CredentialSchema(schema3);
    expect(cs3.schema[SUBJECT_STR]).toEqual({ fname: { type: 'string' }, score: {type: "integer", minimum: -100}, long: {type: "positiveDecimalNumber", decimalPlaces: 2} });
  });
});