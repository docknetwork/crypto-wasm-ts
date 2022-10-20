import { Versioned } from './versioned';
import { EncodeFunc, Encoder } from '../bbs-plus';
import { isPositiveInteger } from '../util';
import {
  CRED_VERSION_STR,
  FlattenedSchema,
  REGISTRY_ID_STR,
  REV_CHECK_STR,
  REV_ID_STR,
  SCHEMA_STR,
  STATUS_STR,
  StringOrObject,
  SUBJECT_STR
} from './types-and-consts';
import { flatten } from 'flat';
import { flattenTill2ndLastKey } from './util';

/**
 * Rules
 * 1. Schema must define a top level `credentialSubject` field for the subject, and it can be an array of object
 * 2. Schema must define a top level `credentialSchema` field.
 * 3. CredentialBuilder status if defined must be present as `credentialStatus` field.
 * 4. Any top level keys in the schema JSON can be created
 Some example schemas

 {
  credentialVersion: {type: "string"},
  credentialSchema: {type: "string"},
  credentialSubject: {
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
  credentialVersion: {type: "string"},
  credentialSchema: {type: "string"},
  credentialSubject: {
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
  credentialStatus: {
    $registryId: {type: "string"},
    $revocationCheck: {type: "string"},
    $revocationId: {type: "string"},
  }

  {
  credentialVersion: {type: "string"},
  credentialSchema: {type: "string"},
  credentialSubject: [
    {
      name: {type: "string"},
      location: {
        name: {type: "string"},
        geo: {
          lat: {type: "decimalNumber", decimalPlaces: 3, minimum: -90},
          long: {type: "decimalNumber", decimalPlaces: 3, minimum: -180}
        }
      }
    },
    {
      name: {type: "string"},
      location: {
        name: {type: "string"},
        geo: {
          lat: {type: "decimalNumber", decimalPlaces: 3, minimum: -90},
          long: {type: "decimalNumber", decimalPlaces: 3, minimum: -180}
        }
      }
    },
    {
      name: {type: "string"},
      location: {
        name: {type: "string"},
        geo: {
          lat: {type: "decimalNumber", decimalPlaces: 3, minimum: -90},
          long: {type: "decimalNumber", decimalPlaces: 3, minimum: -180}
        }
      }
    }
  ]
 }

 {
  credentialVersion: {type: "string"},
  credentialSchema: {type: "string"},
  credentialSubject: [
    {
      name: {type: "string"},
      location: {
        name: {type: "string"},
        geo: {
          lat: {type: "decimalNumber", decimalPlaces: 3, minimum: -90},
          long: {type: "decimalNumber", decimalPlaces: 3, minimum: -180}
        }
      }
    },
    {
      name: {type: "string"},
      location: {
        name: {type: "string"},
        geo: {
          lat: {type: "decimalNumber", decimalPlaces: 3, minimum: -90},
          long: {type: "decimalNumber", decimalPlaces: 3, minimum: -180}
        }
      }
    },
    {
      name: {type: "string"},
      location: {
        name: {type: "string"},
        geo: {
          lat: {type: "decimalNumber", decimalPlaces: 3, minimum: -90},
          long: {type: "decimalNumber", decimalPlaces: 3, minimum: -180}
        }
      }
    }
  ],
  issuer: {
    name: {type: "string"},
    desc: {type: "string"},
    logo: {type: "string"}
  },
  issuanceDate: {type: "positiveInteger"},
  expirationDate: {type: "positiveInteger"},
 }
 */

export enum ValueType {
  Str,
  RevStr,
  PositiveInteger,
  Integer,
  PositiveNumber,
  Number
}

export interface StringType {
  type: ValueType.Str;
}

export interface ReversibleStringType {
  type: ValueType.RevStr;
  compress: boolean;
}

export interface PositiveIntegerType {
  type: ValueType.PositiveInteger;
}

export interface IntegerType {
  type: ValueType.Integer;
  minimum: number;
}

export interface PositiveNumberType {
  type: ValueType.PositiveNumber;
  decimalPlaces: number;
}

export interface NumberType {
  type: ValueType.Number;
  minimum: number;
  decimalPlaces: number;
}

export type ValueTypes =
  | StringType
  | ReversibleStringType
  | PositiveIntegerType
  | IntegerType
  | PositiveNumberType
  | NumberType;

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

  // CredentialBuilder subject/claims cannot have any of these names
  static RESERVED_NAMES = new Set([CRED_VERSION_STR, SCHEMA_STR, SUBJECT_STR, STATUS_STR]);

  static POSSIBLE_TYPES = new Set<string>([
    this.STR_TYPE,
    this.STR_REV_TYPE,
    this.POSITIVE_INT_TYPE,
    this.INT_TYPE,
    this.POSITIVE_NUM_TYPE,
    this.NUM_TYPE,
    'object',
    'array',
  ]);

  schema: any;
  // @ts-ignore
  encoder: Encoder;

  constructor(schema: StringOrObject) {
    // This functions flattens schema object twice but the repetition can be avoided. Keeping this deliberately for code clarity.
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
      const value = values[i];
      let f: EncodeFunc;
      switch (value['type']) {
        case CredentialSchema.STR_REV_TYPE:
          f = Encoder.reversibleEncoderString(value['compress']);
          break;
        case CredentialSchema.POSITIVE_INT_TYPE:
          f = Encoder.positiveIntegerEncoder();
          break;
        case CredentialSchema.INT_TYPE:
          f = Encoder.integerEncoder(value['minimum'] || 0);
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
    this.encoder = new Encoder(encoders, defaultEncoder);
  }

  /**
   * Encode a sub-structure of the subject
   * @param subject
   * @param flattenedSchema
   */
  encodeSubject(subject: object, flattenedSchema?: [string[], unknown[]]): Map<number, Uint8Array> {
    const encoded = new Map<number, Uint8Array>();
    const [names] = flattenedSchema === undefined ? this.flatten() : flattenedSchema[0];
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

  static validate(schema: any) {
    if (typeof schema.properties !== 'object') {
      throw new Error(`Schema must have top level properties object`);
    }

    const schemaStatus = schema.properties[STATUS_STR];
    if (schemaStatus !== undefined) {
      this.validateStringType(schemaStatus.properties, REGISTRY_ID_STR);
      this.validateStringType(schemaStatus.properties, REV_CHECK_STR);
      this.validateStringType(schemaStatus.properties, REV_ID_STR);
    }

    if (schema.properties[SUBJECT_STR] === undefined) {
      throw new Error(`Schema properties did not contain top level key ${SUBJECT_STR}`);
    }
    this.validateGeneric(schema);
  }

  static validateGeneric(schema: object) {
    const [names, values] = this.flattenSchemaObj(schema);
    for (let i = 0; i < names.length; i++) {
      if (typeof values[i] !== 'object') {
        throw new Error(`Schema value for ${names[i]} should have been an object type but was ${typeof values[i]}`);
      }

      const value: any = values[i];

      if (typeof value.type === 'undefined') {
        throw new Error(`Schema value for ${names[i]} should have a "type" field`);
      }

      if (!CredentialSchema.POSSIBLE_TYPES.has(value['type'])) {
        throw new Error(`Schema value for ${names[i]} had an unknown "type" field ${value['type']}`);
      }

      switch (value['type']) {
        case this.STR_REV_TYPE:
          if (typeof value['compress'] !== 'boolean') {
            throw new Error(`Schema value for ${names[i]} expected boolean compress but found ${value['compress']}`);
          }
          break;
        case this.INT_TYPE:
          if (!Number.isInteger(value['minimum'])) {
            throw new Error(`Schema value for ${names[i]} expected integer minimum but found ${value['minimum']}`);
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

  get properties(): object {
    return this.schema.properties;
  }

  typeOfName(name: string, flattenedSchema?: FlattenedSchema): ValueTypes {
    return CredentialSchema.typeOfName(name, flattenedSchema === undefined ? this.flatten() : flattenedSchema);
  }

  static typeOfName(name: string, flattenedSchema: FlattenedSchema): ValueTypes {
    const [names, values] = flattenedSchema;
    const nameIdx = names.indexOf(name);
    try {
      return this.typeOfValue(values[nameIdx]);
    } catch (e) {
      // @ts-ignore
      throw new Error(`${e.message} for name ${name}`);
    }
  }

  static typeOfValue(value: object): ValueTypes {
    const typ = value['type'];
    switch (typ) {
      case CredentialSchema.STR_TYPE:
        return { type: ValueType.Str };
      case CredentialSchema.STR_REV_TYPE:
        return { type: ValueType.RevStr, compress: value['compress'] };
      case CredentialSchema.POSITIVE_INT_TYPE:
        return { type: ValueType.PositiveInteger };
      case CredentialSchema.INT_TYPE:
        return { type: ValueType.Integer, minimum: value['minimum'] };
      case CredentialSchema.POSITIVE_NUM_TYPE:
        return { type: ValueType.PositiveNumber, decimalPlaces: value['decimalPlaces'] };
      case CredentialSchema.NUM_TYPE:
        return {
          type: ValueType.Number,
          minimum: value['minimum'],
          decimalPlaces: value['decimalPlaces']
        };
      default:
        throw new Error(`Unknown type ${typ}`);
    }
  }

  // TODO: proper typedef for root schema instead of any
  static essential(): any {
    return {
      $schema: 'http://json-schema.org/draft-07/schema#',
      $metadata: {
        version: 1
      },
      type: 'object',
      properties: {
        [CRED_VERSION_STR]: { type: 'string' },
        [SCHEMA_STR]: { type: 'string' },
        [SUBJECT_STR]: {
          type: 'object',
          properties: {
            id: { type: 'string' }
          }
        }
      }
    };
  }

  forCredential(): object {
    return { $version: this.version, ...this.schema };
  }

  flatten(): FlattenedSchema {
    return CredentialSchema.flattenSchemaObj(this.schema);
  }

  hasStatus(): boolean {
    return this.properties[STATUS_STR] !== undefined;
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

  getJsonLdContext(): object {
    const txt = 'schema:Text';
    const num = 'schema:Number';
    const int = 'schema:Integer';

    let ctx = {
      schema: 'http://schema.org/',
      [CRED_VERSION_STR]: txt, // Since our version is per semver
      [SCHEMA_STR]: txt
    };

    if (this.hasStatus()) {
      ctx = {
        ...ctx,
        ...{
          [STATUS_STR]: {
            [REGISTRY_ID_STR]: txt,
            [REV_CHECK_STR]: txt,
            [REV_ID_STR]: txt
          }
        }
      };
    }

    const flattened = this.flatten();

    const seen = new Set<string>();
    seen.add(SCHEMA_STR);
    seen.add(CRED_VERSION_STR);

    for (const name of flattened[0]) {
      if (
        [
          SCHEMA_STR,
          CRED_VERSION_STR,
          `${STATUS_STR}.${REGISTRY_ID_STR}`,
          `${STATUS_STR}.${REV_CHECK_STR}`,
          `${STATUS_STR}.${REV_ID_STR}`
        ].indexOf(name) > 0
      ) {
        continue;
      }
      let current = ctx;
      const nameParts = name.split('.');
      for (let j = 0; j < nameParts.length - 1; j++) {
        if (current[nameParts[j]] === undefined) {
          current[nameParts[j]] = {};
        }
        current = current[nameParts[j]];
      }
      switch (this.typeOfName(name, flattened).type) {
        case ValueType.Str:
          current[nameParts[nameParts.length - 1]] = txt;
          break;
        case ValueType.RevStr:
          current[nameParts[nameParts.length - 1]] = txt;
          break;
        case ValueType.PositiveInteger:
          current[nameParts[nameParts.length - 1]] = int;
          break;
        case ValueType.Integer:
          current[nameParts[nameParts.length - 1]] = int;
          break;
        case ValueType.PositiveNumber:
          current[nameParts[nameParts.length - 1]] = num;
          break;
        case ValueType.Number:
          current[nameParts[nameParts.length - 1]] = num;
          break;
      }
    }

    return {
      '@context': [
        {
          '@version': 1.1
        },
        ctx
      ]
    };
  }

  static flattenJSONSchema(node: any) {
    if (typeof node.type !== 'string') {
      throw new Error('Schema node must have type field that is a string');
    }

    if (node.type === 'object') {
      if (typeof node.properties !== 'undefined') {
        const result: object = {};
        const keys = Object.keys(node.properties);
        keys.forEach((k) => {
          const value = node.properties[k];

          let insVal = {};
          if (value.type === 'object') {
            if (typeof value.properties === 'object') {
              insVal = CredentialSchema.flattenJSONSchema(value);
            } else {
              throw new Error(`${k} must have properties field that is an object`);
            }
          } else if (value.type === 'array') {
            if (Array.isArray(value.items)) {
              insVal = value.items.map((i) => CredentialSchema.flattenJSONSchema(i));
            } else {
              throw new Error('No indefinite length array support');
            }
          } else {
            insVal = value;
          }

          result[k] = insVal;
        });
        return result;
      } else {
        throw new Error('Schema object must have properties object');
      }
    } else if (node.type === 'array') {
      return node.items.map((i) => CredentialSchema.flattenJSONSchema(i));
    } else {
      return node;
    }
  }

  static flattenSchemaObj(schema: any): FlattenedSchema {
    const resultObj = CredentialSchema.flattenJSONSchema(schema);
    return flattenTill2ndLastKey(resultObj);
  }

  private static validateStringType(schema, fieldName) {
    if (JSON.stringify(schema[fieldName], undefined, 0) !== '{"type":"string"}') {
      throw new Error(`Schema should contain a top level key ${fieldName} and its value must be {"type":"string"}`);
    }
  }
}
