import { Versioned } from './versioned';
import { EncodeFunc, Encoder } from '../bbs-plus';
import { isPositiveInteger } from '../util';
import {
  CRED_VERSION_STR,
  REGISTRY_ID_STR,
  REV_CHECK_STR, REV_ID_STR,
  SCHEMA_STR,
  STATUS_STR,
  StringOrObject,
  SUBJECT_STR,
  VERSION_STR
} from './types-and-consts';
import { flatten } from 'flat';
import b58 from 'bs58';

/**
 Some example schemas

 {
  $credentialVersion: {type: "string"},
  $credentialSchema: {type: "string"},
  $credentialSubject: {
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
  }
 }

 {
  $credentialVersion: {type: "string"},
  $credentialSchema: {type: "string"},
  $credentialSubject: {
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
  },
  $credentialStatus: {
    $registryId: {type: "string"},
    $revocationCheck: {type: "string"},
    $revocationId: {type: "string"},
  }
 }
 */
export class CredentialSchema extends Versioned {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.0.1';

  private static readonly STR_TYPE = 'string';
  private static readonly STR_REV_TYPE = 'stringReversible';
  private static readonly POSITIVE_INT_TYPE = 'positiveInteger';
  private static readonly INT_TYPE = 'integer';
  private static readonly POSITIVE_NUM_TYPE = 'positiveDecimalNumber';
  private static readonly NUM_TYPE = 'decimalNumber';

  // Credential subject/claims cannot have any of these names
  static RESERVED_NAMES = [CRED_VERSION_STR, SCHEMA_STR, SUBJECT_STR, STATUS_STR];

  static POSSIBLE_TYPES = new Set<string>([
    this.STR_TYPE,
    this.STR_REV_TYPE,
    this.POSITIVE_INT_TYPE,
    this.INT_TYPE,
    this.POSITIVE_NUM_TYPE,
    this.NUM_TYPE
  ]);

  schema: object;
  // @ts-ignore
  encoder: Encoder;

  constructor(schema: StringOrObject) {
    // This functions flattens schema object twice but the repetition can be avoid. Keeping this deliberately to keep
    // the code clear.
    const schem = typeof schema === 'string' ? JSON.parse(schema) : schema;
    CredentialSchema.validate(schem);

    super(CredentialSchema.VERSION);
    this.schema = schem;
    this.initEncoder();
  }

  initEncoder() {
    const defaultEncoder = Encoder.defaultEncodeFunc();
    const encoders = new Map<string, EncodeFunc>();
    const [names, values] = this.flatten();
    for (let i = 0; i < names.length; i++) {
      const value = values[i] as object;
      let f: EncodeFunc;
      switch (value['type']) {
        case CredentialSchema.STR_REV_TYPE:
          f = Encoder.reversibleEncoderString(value['compress']);
          break;
        case CredentialSchema.POSITIVE_INT_TYPE:
          f = Encoder.positiveIntegerEncoder();
          break;
        case CredentialSchema.INT_TYPE:
          f = Encoder.integerEncoder(value['minimum']);
          break;
        case CredentialSchema.POSITIVE_NUM_TYPE:
          f = Encoder.positiveDecimalNumberEncoder(value['decimalPlaces']);
          break;
        case CredentialSchema.NUM_TYPE:
          f = Encoder.decimalNumberEncoder(value['minimum'], value['decimalPlaces']);
          break;
        default:
          f = defaultEncoder;
      }
      encoders.set(names[i], f);
    }

    // Intentionally not supplying default encoder as we already know the schema
    this.encoder = new Encoder(encoders);
  }

  /**
   * Encode a sub-structure of the subject
   * @param subject
   */
  encodeSubject(subject: object): Map<number, Uint8Array> {
    const encoded = new Map<number, Uint8Array>();
    const [names] = CredentialSchema.flattenSchemaObj(this.schema);
    Object.entries(flatten(subject) as object).forEach(([k, v]) => {
      const n = `${SUBJECT_STR}.${k}`;
      const i = names.indexOf(n);
      if (i === -1) {
        throw new Error(`Attribute name ${n} not found in schema`);
      }
      encoded.set(i, this.encoder.encodeMessage(n, v));
    });
    return encoded;
  }

  static validate(schema: object) {
    // Following 2 fields could have been implicit but being explicit for clarity
    this.validateStringType(schema, CRED_VERSION_STR);
    this.validateStringType(schema, SCHEMA_STR);

    if (schema[SUBJECT_STR] === undefined) {
      throw new Error(`Schema did not contain top level key ${SUBJECT_STR}`);
    }
    this.validateGeneric(schema[SUBJECT_STR]);

    if (schema[STATUS_STR] !== undefined) {
      this.validateStringType(schema[STATUS_STR], REGISTRY_ID_STR);
      this.validateStringType(schema[STATUS_STR], REV_CHECK_STR);
      this.validateStringType(schema[STATUS_STR], REV_ID_STR);
      // Not validating anything else as the field name denoting the registry member could be anything
    }
  }

  static validateGeneric(schema: object) {
    const [names, values] = this.flattenSchemaObj(schema);
    for (let i = 0; i < names.length; i++) {
      if (typeof values[i] !== 'object') {
        throw new Error(`Schema value for ${names[i]} should have been an object type but was ${typeof values[i]}`);
      }

      const value = values[i] as object;
      const objKeys = Object.keys(value);

      if (objKeys.indexOf('type') < 0) {
        throw new Error(`Schema value for ${names[i]} should have a "type" field`);
      }
      if (!CredentialSchema.POSSIBLE_TYPES.has(value['type'])) {
        throw new Error(`Schema value for ${names[i]} had an unknown "type" field ${value['type']}`);
      }

      switch (value['type']) {
        case this.STR_REV_TYPE:
          if (typeof value['compress'] !== 'boolean') {
            throw new Error(`Schema value for ${names[i]} expected boolean but found ${value['compress']}`);
          }
          break;
        case this.INT_TYPE:
          if (!Number.isInteger(value['minimum'])) {
            throw new Error(`Schema value for ${names[i]} expected integer but found ${value['minimum']}`);
          }
          break;
        case this.POSITIVE_NUM_TYPE:
          if (!isPositiveInteger(value['decimalPlaces'])) {
            throw new Error(
              `Schema value for ${names[i]} expected maximum decimal places as a positive integer but was ${value['decimalPlaces']}`
            );
          }
          break;
        case this.NUM_TYPE:
          if (!Number.isInteger(value['minimum']) || !isPositiveInteger(value['decimalPlaces'])) {
            throw new Error(
              `Schema value for ${names[i]} expected an integer as a minimum values and maximum decimal places as a positive integer but were ${value['minimum']} and ${value['decimalPlaces']} respectively`
            );
          }
          break;
        default:
          break;
      }
    }
  }

  static bare(): object {
    const schema = {};
    schema[CRED_VERSION_STR] = { type: 'string' };
    schema[SCHEMA_STR] = { type: 'string' };
    return schema;
  }

  forCredential(): object {
    return { $version: this.version, ...this.schema };
  }

  flatten(): [string[], unknown[]] {
    return CredentialSchema.flattenSchemaObj(this.schema);
  }

  toJSON(): string {
    return JSON.stringify(this.forCredential());
  }

  static fromJSON(j: string): CredentialSchema {
    const { $version, ...schema } = JSON.parse(j);
    const credSchema = new CredentialSchema(schema);
    credSchema.version = $version;
    return credSchema;
  }

  static flattenSchemaObj(schema: object): [string[], unknown[]] {
    const flattened = {};
    const temp = flatten(schema) as object;
    for (const k of Object.keys(temp)) {
      // taken from https://stackoverflow.com/a/5555607
      const name = k.substring(0, k.lastIndexOf('.'));
      const t = k.substring(k.lastIndexOf('.') + 1, k.length);

      if (flattened[name] === undefined) {
        flattened[name] = {};
      }
      flattened[name][t] = temp[k];
    }
    const keys = Object.keys(flattened).sort();
    // @ts-ignore
    const values = keys.map((k) => flattened[k]);
    return [keys, values];
  }

  private static validateStringType(schema, fieldName) {
    if (JSON.stringify(schema[fieldName], undefined, 0) !== '{"type":"string"}') {
      throw new Error(`Schema should contain a top level key ${fieldName} and its value must be {"type":"string"}`);
    }
  }
}
