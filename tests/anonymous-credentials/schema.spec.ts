import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  CRED_VERSION_STR,
  CredentialSchema, REGISTRY_ID_STR, REV_CHECK_STR,
  SCHEMA_STR, STATUS_STR,
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
    const schema2 = CredentialSchema.bare();
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

  it('validation of credential status', () => {
    const schema4 = CredentialSchema.bare();
    schema4[SUBJECT_STR] = {
      fname: {type: "string"},
      score: {type: "integer", minimum: -100},
    };

    schema4[STATUS_STR] = {};
    schema4[STATUS_STR][REGISTRY_ID_STR] = {type: "integer", minimum: -100};

    expect(() => new CredentialSchema(schema4)).toThrow();

    schema4[STATUS_STR][REGISTRY_ID_STR] = {type: "string"};
    schema4[STATUS_STR][REV_CHECK_STR] = {type: "string"};
    const cs4 = new CredentialSchema(schema4);
    expect(cs4.schema[STATUS_STR][REGISTRY_ID_STR]).toEqual({type: "string"} );
    expect(cs4.schema[STATUS_STR][REV_CHECK_STR]).toEqual({type: "string"} );
  })

  it('validation of some more schemas', () => {
    const schema5 = CredentialSchema.bare();
    schema5[SUBJECT_STR] = {
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
    const cs5 = new CredentialSchema(schema5);
    expect(cs5.schema[SUBJECT_STR]).toEqual(schema5[SUBJECT_STR]);
    expect(cs5.schema[STATUS_STR]).not.toBeDefined();

    const schema6 = CredentialSchema.bare();
    schema6[SUBJECT_STR] = {
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
    schema6[STATUS_STR] = {
      $registryId: {type: "string"},
      $revocationCheck: {type: "string"},
      employeeId: {type: "string"}
    };

    const cs6 = new CredentialSchema(schema6);
    expect(cs6.schema[SUBJECT_STR]).toEqual(schema6[SUBJECT_STR]);
    expect(cs6.schema[STATUS_STR]).toEqual(schema6[STATUS_STR]);
  })
});