import pointer from 'json-pointer';
import stringify from 'json-stringify-deterministic';
import _ from 'lodash';
import { Versioned } from './versioned';
import { EncodeFunc, Encoder } from '../encoder';
import { isPositiveInteger } from '../util';
import {
  CRYPTO_VERSION_STR,
  EMPTY_SCHEMA_ID,
  FlattenedSchema,
  FULL_SCHEMA_STR,
  ID_STR,
  JSON_SCHEMA_STR,
  REV_CHECK_STR,
  REV_ID_STR,
  SCHEMA_DETAILS_STR,
  SCHEMA_FIELDS,
  SCHEMA_PROPS_STR,
  SCHEMA_STR,
  SCHEMA_TYPE_STR,
  STATUS_STR,
  SUBJECT_STR,
  TYPE_STR,
  VERSION_STR
} from './types-and-consts';
import { flattenTill2ndLastKey, isValueDate, isValueDateTime } from './util';
import semver from 'semver/preload';

/**
 * Rules
 * 1. Schema must define a top level `credentialSubject` field for the subject, and it can be an object or array of object
 * 2. Credential status if defined must be present as `credentialStatus` field.
 * 3. Any top level keys in the schema JSON can be created
 Some example schemas

 {
  '$schema': 'http://json-schema.org/draft-07/schema#',
  type: 'object',
  properties: {
    credentialSubject: {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        lname: { type: 'string' },
        email: { type: 'string' },
        SSN: { '$ref': '#/definitions/encryptableString' },
        userId: { '$ref': '#/definitions/encryptableCompString' },
        country: { type: 'string' },
        city: { type: 'string' },
        timeOfBirth: { type: 'integer', minimum: 0 },
        height: { type: 'number', minimum: 0, multipleOf: 0.1 },
        weight: { type: 'number', minimum: 0, multipleOf: 0.1 },
        BMI: { type: 'number', minimum: 0, multipleOf: 0.01 },
        score: { type: 'number', minimum: -100, multipleOf: 0.1 },
        secret: { type: 'string' }
      }
    }
  },
  definitions: {
    encryptableString: { type: 'string' },
    encryptableCompString: { type: 'string' }
  }
}

 {
  '$schema': 'http://json-schema.org/draft-07/schema#',
  type: 'object',
  properties: {
    credentialSubject: {
      type: 'object',
      properties: {
        fname: { type: 'string' },
        lname: { type: 'string' },
        sensitive: {
          type: 'object',
          properties: {
            very: {
              type: 'object',
              properties: { secret: { type: 'string' } }
            },
            email: { type: 'string' },
            phone: { type: 'string' },
            SSN: { '$ref': '#/definitions/encryptableString' }
          }
        },
        lessSensitive: {
          type: 'object',
          properties: {
            location: {
              type: 'object',
              properties: { country: { type: 'string' }, city: { type: 'string' } }
            },
            department: {
              type: 'object',
              properties: {
                name: { type: 'string' },
                location: {
                  type: 'object',
                  properties: {
                    name: { type: 'string' },
                    geo: {
                      type: 'object',
                      properties: {
                        lat: {
                          type: 'number',
                          minimum: -90,
                          multipleOf: 0.001
                        },
                        long: {
                          type: 'number',
                          minimum: -180,
                          multipleOf: 0.001
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        },
        rank: { type: 'integer', minimum: 0 }
      }
    },
    credentialStatus: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        type: { type: 'string' },
        revocationCheck: { type: 'string' },
        revocationId: { type: 'string' }
      }
    }
  },
  definitions: {
    encryptableString: { type: 'string' },
    encryptableCompString: { type: 'string' }
  }
 }

 {
  '$schema': 'http://json-schema.org/draft-07/schema#',
  type: 'object',
  properties: {
    credentialSubject: {
      type: 'array',
      items: [
        {
          type: 'object',
          properties: {
            name: { type: 'string' },
            location: {
              type: 'object',
              properties: {
                name: { type: 'string' },
                geo: {
                  type: 'object',
                  properties: {
                    lat: { type: 'number', minimum: -90, multipleOf: 0.001 },
                    long: {
                      type: 'number',
                      minimum: -180,
                      multipleOf: 0.001
                    }
                  }
                }
              }
            }
          }
        },
        {
          type: 'object',
          properties: {
            name: { type: 'string' },
            location: {
              type: 'object',
              properties: {
                name: { type: 'string' },
                geo: {
                  type: 'object',
                  properties: {
                    lat: { type: 'number', minimum: -90, multipleOf: 0.001 },
                    long: {
                      type: 'number',
                      minimum: -180,
                      multipleOf: 0.001
                    }
                  }
                }
              }
            }
          }
        },
        {
          type: 'object',
          properties: {
            name: { type: 'string' },
            location: {
              type: 'object',
              properties: {
                name: { type: 'string' },
                geo: {
                  type: 'object',
                  properties: {
                    lat: { type: 'number', minimum: -90, multipleOf: 0.001 },
                    long: {
                      type: 'number',
                      minimum: -180,
                      multipleOf: 0.001
                    }
                  }
                }
              }
            }
          }
        }
      ]
    }
  },
  definitions: {
    encryptableString: { type: 'string' },
    encryptableCompString: { type: 'string' }
  }
 }

 {
  '$schema': 'http://json-schema.org/draft-07/schema#',
  type: 'object',
  properties: {
    credentialSubject: {
      type: 'array',
      items: [
        {
          type: 'object',
          properties: {
            name: { type: 'string' },
            location: {
              type: 'object',
              properties: {
                name: { type: 'string' },
                geo: {
                  type: 'object',
                  properties: {
                    lat: { type: 'number', minimum: -90, multipleOf: 0.001 },
                    long: {
                      type: 'number',
                      minimum: -180,
                      multipleOf: 0.001
                    }
                  }
                }
              }
            }
          }
        },
        {
          type: 'object',
          properties: {
            name: { type: 'string' },
            location: {
              type: 'object',
              properties: {
                name: { type: 'string' },
                geo: {
                  type: 'object',
                  properties: {
                    lat: { type: 'number', minimum: -90, multipleOf: 0.001 },
                    long: {
                      type: 'number',
                      minimum: -180,
                      multipleOf: 0.001
                    }
                  }
                }
              }
            }
          }
        },
        {
          type: 'object',
          properties: {
            name: { type: 'string' },
            location: {
              type: 'object',
              properties: {
                name: { type: 'string' },
                geo: {
                  type: 'object',
                  properties: {
                    lat: { type: 'number', minimum: -90, multipleOf: 0.001 },
                    long: {
                      type: 'number',
                      minimum: -180,
                      multipleOf: 0.001
                    }
                  }
                }
              }
            }
          }
        }
      ]
    },
    issuer: {
      type: 'object',
      properties: {
        name: { type: 'string' },
        desc: { type: 'string' },
        logo: { type: 'string' }
      }
    },
    issuanceDate: { type: 'integer', minimum: 0 },
    expirationDate: { type: 'integer', minimum: 0 }
  },
  definitions: {
    encryptableString: { type: 'string' },
    encryptableCompString: { type: 'string' }
  }
}
 */

export const META_SCHEMA_STR = '$schema';

export interface ISchema {
  [CRYPTO_VERSION_STR]: object;
  [SCHEMA_STR]: object;
  [SUBJECT_STR]: object | object[];
  // @ts-ignore
  [STATUS_STR]?: object;
  [key: string]: object;
}

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

export interface IJsonSchemaProperties {
  [SUBJECT_STR]: object | object[];
  // @ts-ignore
  [STATUS_STR]?: object;
  [key: string]: object;
}

/**
 * JSON schema that contains the properties
 */
export interface IEmbeddedJsonSchema {
  [META_SCHEMA_STR]: string;
  $id?: string;
  title?: string;
  type: string;
  [SCHEMA_PROPS_STR]: IJsonSchemaProperties;
  definitions?: { [key: string]: object };
}

/**
 * JSON schema that does not contain the properties but its $id property can be used to fetch the properties.
 * Intentionally not allowing `properties` key as reconciliation will be needed in case of conflict with fetched properties
 */
export interface IJsonSchema {
  [META_SCHEMA_STR]: string;
  $id: string;
  title?: string;
  type: string;
}

export interface ISchemaParsingOpts {
  /** Whether to use the default values or throw error if required parameters are not passed */
  useDefaults: boolean;
  defaultMinimumInteger: number;
  defaultMinimumDate: number;
  defaultDecimalPlaces: number;
}

export const DefaultSchemaParsingOpts: ISchemaParsingOpts = {
  useDefaults: false,
  /** Minimum value kept over a billion */
  defaultMinimumInteger: -(Math.pow(2, 32) - 1),
  defaultMinimumDate: -(Math.pow(2, 44) - 1),
  defaultDecimalPlaces: 0
};

export interface ISchemaOverrides {
  version: string;
}

export type CredVal = string | number | object | CredVal[];

export class CredentialSchema extends Versioned {
  /** Follows semver and must be updated accordingly when the logic of this class changes or the
   underlying crypto changes. */
  static VERSION = '0.5.0';

  private static readonly STR_TYPE = 'string';
  private static readonly STR_REV_TYPE = 'stringReversible';
  private static readonly POSITIVE_INT_TYPE = 'positiveInteger';
  private static readonly BOOLEAN_TYPE = 'boolean';
  private static readonly INT_TYPE = 'integer';
  private static readonly POSITIVE_NUM_TYPE = 'positiveDecimalNumber';
  private static readonly NUM_TYPE = 'decimalNumber';
  private static readonly DATETIME_TYPE = 'date-time';

  /** CredentialBuilder subject/claims cannot have any of these names */
  static RESERVED_NAMES = new Set([CRYPTO_VERSION_STR, SCHEMA_STR, SUBJECT_STR, STATUS_STR]);

  /** Implicit fields for schema version < 0.4.0 */
  static OLD_IMPLICIT_FIELDS = { [CRYPTO_VERSION_STR]: { type: 'string' }, [SCHEMA_STR]: { type: 'string' } };
  /** Implicit fields for schema version >= 0.4.0 */
  static IMPLICIT_FIELDS = {
    [CRYPTO_VERSION_STR]: { type: 'string' },
    [SCHEMA_STR]: {
      [ID_STR]: { type: 'string' },
      [TYPE_STR]: { type: 'string' },
      [VERSION_STR]: { type: 'string' },
      [SCHEMA_DETAILS_STR]: { type: 'string' }
    }
  };

  /** Custom definitions for JSON schema syntax */
  static JSON_SCHEMA_CUSTOM_DEFS = {
    encryptableString: {
      type: 'string'
    },
    encryptableCompString: {
      type: 'string'
    }
  };

  /** Custom override definitions for JSON schema syntax.
  Any refs in the jsonschema that reference these will be overwritten */
  static JSON_SCHEMA_OVERRIDE_DEFS = {
    '#/definitions/encryptableString': {
      type: CredentialSchema.STR_REV_TYPE,
      compress: false
    },
    '#/definitions/encryptableCompString': {
      type: CredentialSchema.STR_REV_TYPE,
      compress: true
    }
  };

  /** Keys to ignore from generic validation as they are already validated */
  static IGNORE_GENERIC_VALIDATION = new Set([
    CRYPTO_VERSION_STR,
    SCHEMA_STR,
    `${SCHEMA_STR}.${ID_STR}`,
    `${SCHEMA_STR}.${TYPE_STR}`,
    `${SCHEMA_STR}.${VERSION_STR}`,
    `${SCHEMA_STR}.${SCHEMA_DETAILS_STR}`,
    `${STATUS_STR}.${ID_STR}`,
    `${STATUS_STR}.${TYPE_STR}`,
    `${STATUS_STR}.${REV_CHECK_STR}`,
    `${STATUS_STR}.${REV_ID_STR}`
  ]);

  static POSSIBLE_TYPES = new Set<string>([
    this.STR_TYPE,
    this.STR_REV_TYPE,
    this.BOOLEAN_TYPE,
    this.POSITIVE_INT_TYPE,
    this.INT_TYPE,
    this.POSITIVE_NUM_TYPE,
    this.NUM_TYPE,
    this.DATETIME_TYPE
  ]);

  readonly schema: ISchema;
  readonly jsonSchema: IEmbeddedJsonSchema | IJsonSchema;
  readonly parsingOptions: ISchemaParsingOpts;
  // @ts-ignore
  encoder: Encoder;
  fullJsonSchema?: IEmbeddedJsonSchema;

  /**
   * Takes a schema object as per JSON-schema syntax (`IJsonSchema`), validates it and converts it to an internal
   * representation (`ISchema`) and stores both as the one with JSON-schema syntax is added to the credential representation.
   * @param jsonSchema - Could be a JSON schema with properties or contain an $id key which is used to fetch them
   * @param parsingOpts - Options to parse the schema like whether to use defaults and what defaults to use
   * @param addMissingParsingOpts - Whether to update `parsingOpts` for any missing options with default options. Pass false
   * when deserializing to get the exact object that was serialized which is necessary when verifying signatures
   * @param overrides - Override any properties of the schema
   * @param fullJsonSchema - When `jsonSchema` does not contain the properties, this object is expected to contain them.
   * @param useConstantTimeEncoder - Set to false when creating legacy schemas
   */
  constructor(
    jsonSchema: IEmbeddedJsonSchema | IJsonSchema,
    parsingOpts: Partial<ISchemaParsingOpts> = DefaultSchemaParsingOpts,
    addMissingParsingOpts = true,
    overrides?: Partial<ISchemaOverrides>,
    fullJsonSchema?: IEmbeddedJsonSchema,
    useConstantTimeEncoder = true
  ) {
    // This functions flattens schema object twice but the repetition can be avoided. Keeping this deliberately for code clarity.
    let pOpts;
    if (addMissingParsingOpts) {
      pOpts = { ...DefaultSchemaParsingOpts, ...parsingOpts };
    } else {
      pOpts = { ...parsingOpts };
    }

    let isEmbeddedSchema = CredentialSchema.isEmbeddedJsonSchema(jsonSchema);
    if (!isEmbeddedSchema && fullJsonSchema === undefined) {
      throw new Error('Either pass an embedded schema or the actual schema');
    }
    const schema = CredentialSchema.convertToInternalSchemaObj(
      isEmbeddedSchema ? jsonSchema : fullJsonSchema,
      pOpts,
      '',
      undefined
    ) as ISchema;
    CredentialSchema.validate(schema);

    let ct = useConstantTimeEncoder;
    if (overrides !== undefined && overrides.version !== undefined) {
      super(overrides.version);
      // For older version, a variable time message encoder was mistakenly used.
      // This is overriding the caller's intent
      ct = semver.gte(overrides.version, '0.5.0');
    } else {
      super(CredentialSchema.VERSION);
    }
    this.schema = schema;
    // This is the schema in JSON-schema format. Kept to output in credentials or in `toJSON` without converting back from
    // internal representation; trading off memory for CPU time.
    this.jsonSchema = jsonSchema;
    this.parsingOptions = pOpts;
    this.fullJsonSchema = fullJsonSchema;
    this.initEncoder(ct);
  }

  /**
   * Initialize the encoder as per the internal representation of schema, i.e. `ISchema`
   */
  initEncoder(useConstantTimeEncoder = true) {
    const defaultEncoder = useConstantTimeEncoder
      ? Encoder.defaultEncodeFuncConstantTime()
      : Encoder.defaultEncodeFunc();
    const encoders = new Map<string, EncodeFunc>();
    const [names, values] = this.flatten();
    for (let i = 0; i < names.length; i++) {
      const value = values[i];
      let f: EncodeFunc;
      switch (value['type']) {
        case CredentialSchema.BOOLEAN_TYPE:
          f = Encoder.booleanEncoder();
          break;
        case CredentialSchema.STR_REV_TYPE:
          f = Encoder.reversibleEncoderString(value['compress']);
          break;
        case CredentialSchema.DATETIME_TYPE:
          f = Encoder.dateEncoder(value['minimum']);
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
          // For other types including string type, use default encoder
          f = defaultEncoder;
      }
      encoders.set(names[i], f);
    }

    // Implicitly present fields
    encoders.set(CRYPTO_VERSION_STR, defaultEncoder);
    // In older credential format, schema was JSON string, but in new credential format, schema is an object
    if (semver.gte(this.version, '0.4.0')) {
      SCHEMA_FIELDS.forEach((s) => encoders.set(s, defaultEncoder));
    } else {
      encoders.set(SCHEMA_STR, defaultEncoder);
    }

    // Overwrite encoder of status field to not break older credentials. This needs to be fixed at some point
    if (encoders.has(`${STATUS_STR}.${REV_ID_STR}`)) {
      encoders.set(`${STATUS_STR}.${REV_ID_STR}`, Encoder.defaultEncodeFunc());
    }

    // Only supply default encoder if user requests to use defaults
    this.encoder = new Encoder(encoders, this.parsingOptions.useDefaults ? defaultEncoder : undefined);
  }

  /**
   * Validates the internal representation of schema
   * @param schema
   */
  static validate(schema: ISchema) {
    if (schema[SUBJECT_STR] === undefined) {
      throw new Error(`Schema properties did not contain top level key ${SUBJECT_STR}`);
    }

    const schemaStatus = schema[STATUS_STR];
    if (schemaStatus !== undefined) {
      this.validateStringType(schemaStatus, TYPE_STR);
      this.validateStringType(schemaStatus, ID_STR);
      this.validateStringType(schemaStatus, REV_CHECK_STR);
      this.validateStringType(schemaStatus, REV_ID_STR);
    }

    this.validateGeneric(schema, CredentialSchema.IGNORE_GENERIC_VALIDATION);
  }

  static validateGeneric(schema: object, ignoreKeys: Set<string> = new Set()) {
    const [names, values] = this.flattenSchemaObj(schema);

    for (let i = 0; i < names.length; i++) {
      if (ignoreKeys.has(names[i])) {
        continue;
      }

      if (typeof values[i] !== 'object') {
        throw new Error(`Schema value for ${names[i]} should have been an object type but was ${typeof values[i]}`);
      }

      const value: any = values[i];

      if (value.type === undefined) {
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

  typeOfName(name: string, flattenedSchema: FlattenedSchema = this.flatten()): ValueTypes {
    return CredentialSchema.typeOfName(name, flattenedSchema);
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
      case CredentialSchema.BOOLEAN_TYPE:
        return { type: ValueType.PositiveInteger };
      case CredentialSchema.DATETIME_TYPE:
        return { type: ValueType.Integer, minimum: value['minimum'] };
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

  /**
   * Essential properties of a non-embedded schema.
   * @param withDefinitions - add custom definitions as well
   */
  static essential(withDefinitions = true): IEmbeddedJsonSchema {
    const s = {
      // Currently only assuming support for draft-07 but other might work as well
      [META_SCHEMA_STR]: 'http://json-schema.org/draft-07/schema#',
      type: 'object',
      [SCHEMA_PROPS_STR]: {
        [SUBJECT_STR]: {
          type: 'object',
          properties: {
            id: {
              type: 'string'
            }
          }
        },
        proof: {
          type: 'object',
          properties: {
            type: {
              type: 'string'
            }
          }
        }
      }
    };
    if (withDefinitions) {
      s['definitions'] = this.JSON_SCHEMA_CUSTOM_DEFS;
    }
    // @ts-ignore
    return s;
  }

  static statusAsJsonSchema(): object {
    return {
      type: 'object',
      properties: {
        [ID_STR]: { type: 'string' },
        [TYPE_STR]: { type: 'string' },
        [REV_CHECK_STR]: { type: 'string' },
        [REV_ID_STR]: { type: 'string' }
      }
    };
  }

  flatten(): FlattenedSchema {
    return CredentialSchema.flattenSchemaObj(this.schema, semver.gte(this.version, '0.4.0'));
  }

  hasStatus(): boolean {
    return this.schema[STATUS_STR] !== undefined;
  }

  /**
   * Older version of toJSON, i.e. versions < 0.4.0
   */
  toJSONOlder(): object {
    const embedded = this.hasEmbeddedJsonSchema();
    const j = {
      [ID_STR]: CredentialSchema.convertToDataUri(this.jsonSchema, this.version),
      [TYPE_STR]: SCHEMA_TYPE_STR,
      parsingOptions: this.parsingOptions,
      version: this._version
    };
    if (!embedded) {
      j[FULL_SCHEMA_STR] = CredentialSchema.convertToDataUri(this.fullJsonSchema as IEmbeddedJsonSchema, this.version);
    }
    return j;
  }

  toJSON(): object {
    const j = {
      // If the JSON schema has no id, set it to an empty data uri
      [ID_STR]: this.jsonSchema['$id'] || EMPTY_SCHEMA_ID,
      [TYPE_STR]: SCHEMA_TYPE_STR,
      [VERSION_STR]: this._version
    };
    const details = {
      parsingOptions: this.parsingOptions,
      [JSON_SCHEMA_STR]: this.jsonSchema
    };
    if (!this.hasEmbeddedJsonSchema()) {
      details[FULL_SCHEMA_STR] = this.fullJsonSchema;
    }
    j[SCHEMA_DETAILS_STR] = stringify(details);
    return j;
  }

  static fromJSON(j: object): CredentialSchema {
    // @ts-ignore
    const { id, type, version } = j;
    if (type !== SCHEMA_TYPE_STR) {
      throw new Error(`Schema type was "${type}", expected: "${SCHEMA_TYPE_STR}"`);
    }
    let parsingOptions, jsonSchema, full: IEmbeddedJsonSchema | undefined;
    if (semver.lt(version, '0.4.0')) {
      // @ts-ignore
      parsingOptions = j.parsingOptions;
      const fullJsonSchema = j[FULL_SCHEMA_STR];
      jsonSchema = this.convertFromDataUri(id);
      if (fullJsonSchema !== undefined) {
        if (CredentialSchema.isEmbeddedJsonSchema(jsonSchema)) {
          throw new Error(`Actual schema was provided even when the given jsonSchema was an embedded one`);
        }
        full = this.convertFromDataUri(fullJsonSchema) as IEmbeddedJsonSchema;
        if (!CredentialSchema.isEmbeddedJsonSchema(full)) {
          throw new Error(`Expected actual schema to be an embedded one but got ${full}`);
        }
      } else {
        if (!CredentialSchema.isEmbeddedJsonSchema(jsonSchema)) {
          throw new Error(`Full json schema wasn't provided when a non-embedded schema was provided ${jsonSchema}`);
        }
      }
    } else {
      if (j[SCHEMA_DETAILS_STR] === undefined) {
        throw new Error(`Did not find key ${SCHEMA_DETAILS_STR} in schema version ${version}`);
      }
      const details = JSON.parse(j[SCHEMA_DETAILS_STR]);
      parsingOptions = details.parsingOptions;
      jsonSchema = details[JSON_SCHEMA_STR];
      full = details[FULL_SCHEMA_STR];
      if (full !== undefined) {
        if (CredentialSchema.isEmbeddedJsonSchema(jsonSchema)) {
          throw new Error(`Actual schema was provided even when the given jsonSchema was an embedded one`);
        }
        if (!CredentialSchema.isEmbeddedJsonSchema(full)) {
          throw new Error(`Expected actual schema to be an embedded one but got ${full}`);
        }
      } else {
        if (!CredentialSchema.isEmbeddedJsonSchema(jsonSchema)) {
          throw new Error(`Full json schema wasn't provided when a non-embedded schema was provided ${jsonSchema}`);
        }
      }
    }
    // For older version, a variable time message encoder was mistakenly used
    const useConstantTimeEncoder = semver.gte(version, '0.5.0');
    // Note: `parsingOptions` might still be in an incorrect format which can fail the next call
    // Note: Passing `addMissingParsingOpts` as false to recreate the exact same object that was serialized. This is important
    // when verifying signatures.
    // @ts-ignore
    return new CredentialSchema(jsonSchema, parsingOptions, false, { version }, full, useConstantTimeEncoder);
  }

  /**
   * Similar to this.fromJSON but can load an externally referenced schema if the given schema is not an embedded one.
   * @param j
   * @param schemaGetter
   */
  static async fromJSONWithPotentiallyExternalSchema(
    j: object,
    schemaGetter: (url: string) => Promise<IEmbeddedJsonSchema>
  ): Promise<CredentialSchema> {
    // @ts-ignore
    const { id, type, version } = j;
    if (type !== SCHEMA_TYPE_STR) {
      throw new Error(`Schema type was "${type}", expected: "${SCHEMA_TYPE_STR}"`);
    }
    let parsingOptions, jsonSchema, fullJsonSchema: IEmbeddedJsonSchema | undefined;
    if (version !== undefined && semver.lt(version, '0.4.0')) {
      // @ts-ignore
      parsingOptions = j.parsingOptions;
      jsonSchema = this.convertFromDataUri(id);
      if (!CredentialSchema.isEmbeddedJsonSchema(jsonSchema)) {
        // @ts-ignore
        fullJsonSchema = await schemaGetter(jsonSchema.$id);
        if (!(fullJsonSchema[SCHEMA_PROPS_STR] instanceof Object)) {
          throw new Error(
            `Expected the fetched schema to have key ${SCHEMA_PROPS_STR} set and as an Object but was ${fullJsonSchema[SCHEMA_PROPS_STR]}`
          );
        }
      }
    } else {
      // Either the version was explicitly passed or a new schema is being created (credential signing)
      if (j[SCHEMA_DETAILS_STR] === undefined) {
        throw new Error(`Did not find key ${SCHEMA_DETAILS_STR} in schema version ${version}`);
      }
      const details = JSON.parse(j[SCHEMA_DETAILS_STR]);
      parsingOptions = details.parsingOptions;
      jsonSchema = details[JSON_SCHEMA_STR];
      if (!CredentialSchema.isEmbeddedJsonSchema(jsonSchema)) {
        // @ts-ignore
        fullJsonSchema = await schemaGetter(jsonSchema.$id);
        if (!(fullJsonSchema[SCHEMA_PROPS_STR] instanceof Object)) {
          throw new Error(
            `Expected the fetched schema to have key ${SCHEMA_PROPS_STR} set and as an Object but was ${fullJsonSchema[SCHEMA_PROPS_STR]}`
          );
        }
      }
    }
    return new CredentialSchema(jsonSchema, parsingOptions, false, { version: version }, fullJsonSchema);
  }

  /**
   * Convert to a JSON string and the string is deterministic. This is important for signing
   */
  toJsonString(): string {
    // Version < 0.2.0 used JSON.stringify to create a JSON string
    return semver.lt(this.version, '0.2.0') ? JSON.stringify(this.toJSONOlder()) : stringify(this.toJSONOlder());
  }

  /**
   * Convert schema JSON to a data URI
   * @param jsonSchema
   * @param version - The schema version. This is needed as a different conversion to JSON function was used in
   * older version and backward compatibility is needed.
   */
  static convertToDataUri(jsonSchema: IEmbeddedJsonSchema | IJsonSchema, version?: string): string {
    // Old version used JSON.stringify
    const newVersion = version === undefined || semver.gte(version, '0.2.0');
    const jsonStr = newVersion ? stringify(jsonSchema) : JSON.stringify(jsonSchema);
    return `data:application/json;charset=utf-8,${encodeURIComponent(jsonStr)}`;
  }

  static convertFromDataUri(embedded: string): IEmbeddedJsonSchema | IJsonSchema {
    if (!embedded.startsWith('data:')) {
      throw new Error(`Embedded schema must be a data URI but was ${embedded}`);
    }

    // Strip new lines
    const dataUri = embedded.replace(/\r?\n/g, '');

    // split the URI up into the "metadata" and the "data" portions
    const firstComma = dataUri.indexOf(',');
    if (firstComma === -1) {
      throw new Error('Schema is a malformed data URI');
    }

    // Remove the scheme and parse metadata
    const meta = dataUri.substring(5, firstComma).split(';'); // 'data:'.length = 5

    if (meta[0] !== 'application/json') {
      throw new Error(`Expected media type application/json but was ${meta[0]}`);
    }

    const isBase64 = meta.indexOf('base64') !== -1;
    if (isBase64) {
      throw new Error('Base64 embedded JSON is not yet supported');
    }

    // Extract data string
    const dataStr = decodeURIComponent(dataUri.substring(firstComma + 1));
    return JSON.parse(dataStr);
  }

  // TODO: Revisit me. Following was an attempt to create more accurate JSON-LD context but pausing it now because
  // its not an immediate priority. When fixed, this should replace the uncommented function with same name below
  /*getJsonLdContext(): object {
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

    const innerMostNames = new Map<string, string>();

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
      const innerMostName = nameParts[nameParts.length - 1];
      switch (this.typeOfName(name, flattened).type) {
        case ValueType.Str:
          current[innerMostName] = txt;
          break;
        case ValueType.RevStr:
          current[innerMostName] = txt;
          break;
        case ValueType.PositiveInteger:
          current[innerMostName] = int;
          break;
        case ValueType.Integer:
          current[innerMostName] = int;
          break;
        case ValueType.PositiveNumber:
          current[innerMostName] = num;
          break;
        case ValueType.Number:
          current[innerMostName] = num;
          break;
      }
      innerMostNames.set(innerMostName, current[innerMostName]);
    }

    return {
      '@context': [
        {
          '@version': 1.1
        },
        ctx
      ]
    };
  }*/

  /**
   * Same as the constructor of this class but gets the JSON schema from a callback
   * @param jsonSchema - The JSON schema that contains the URL to fetch the full JSON schema, i.e. properties
   * @param schemaGetter - The callback that takes the `$id` field of `jsonSchema` and returns the full JSON schema.
   * @param parsingOpts
   * @param addMissingParsingOpts
   * @param overrides
   */
  static async newSchemaFromExternal(
    jsonSchema: IJsonSchema,
    schemaGetter: (url: string) => Promise<IEmbeddedJsonSchema>,
    parsingOpts: Partial<ISchemaParsingOpts> = DefaultSchemaParsingOpts,
    addMissingParsingOpts = true,
    overrides?: Partial<ISchemaOverrides>
  ): Promise<CredentialSchema> {
    const fullJsonSchema = await schemaGetter(jsonSchema.$id);
    return new CredentialSchema(jsonSchema, parsingOpts, addMissingParsingOpts, overrides, fullJsonSchema);
  }

  getJsonLdContext(): object {
    const terms = new Set<string>();
    terms.add(SCHEMA_STR);
    terms.add(CRYPTO_VERSION_STR);

    const ctx = {
      dk: 'https://ld.truvera.io/credentials#'
    };

    if (this.hasStatus()) {
      terms.add(ID_STR);
      terms.add(REV_CHECK_STR);
      terms.add(REV_ID_STR);
      terms.add(TYPE_STR);
    }

    const flattened = this.flatten();

    // TODO: future work here to not redefine JSON-LD terms from the W3C VC context
    for (const name of flattened[0]) {
      const nameParts = name.split('.');
      for (let j = 0; j < nameParts.length; j++) {
        terms.add(nameParts[j]);
      }
    }

    for (const term of terms) {
      ctx[term] = CredentialSchema.getDummyContextValue(term);
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

  /**
   * Returns true if the JSON schema provided during the object creation was an embedded one.
   */
  hasEmbeddedJsonSchema(): boolean {
    return this.fullJsonSchema === undefined;
  }

  /**
   * Gets the embedded JSON schema either from the one that was provided or the one that was fetched.
   */
  getEmbeddedJsonSchema(): IEmbeddedJsonSchema {
    // @ts-ignore
    return this.hasEmbeddedJsonSchema() ? this.jsonSchema : this.fullJsonSchema;
  }

  getJsonSchemaProperties(): object {
    // @ts-ignore
    return this.getEmbeddedJsonSchema().properties;
  }

  static getDummyContextValue(term: string): string {
    return `dk:${term}`;
  }

  /**
   * Convert a schema object as per JSON-schema syntax (`IJsonSchema`) to the internal representation (`ISchema`).
   * Currently, does not check if the needed JSON-schema definitions are actually present but assumes that they will be
   * already passed.
   * @param inputNode
   * @param parsingOpts
   * @param nodeKeyName - Name of the node, used for throwing more informative error message
   * @param rootObject
   */
  static convertToInternalSchemaObj(
    inputNode: any,
    parsingOpts: ISchemaParsingOpts,
    nodeKeyName = '',
    rootObject?: object
  ): object {
    // util function needed only in this func
    const createFullName = (old: string, neww: string): string => {
      return old.length === 0 ? neww : `${old}.${neww}`;
    };

    // Will either have a "type" property or will be defined using "$ref"
    let node: any = inputNode;
    const ref = inputNode.$ref;
    const rootNode = rootObject || inputNode;

    // If the node is using a ref, we should locate it with a jsonpointer
    // or use an override in case of encryptable strings
    if (ref) {
      const overrideRef = this.JSON_SCHEMA_OVERRIDE_DEFS[ref];
      if (overrideRef !== undefined) {
        return overrideRef;
      } else {
        try {
          node = { ...pointer.get(rootNode, ref.replace('#', '')) };
        } catch (e) {
          throw new Error(`Error while getting pointer ${ref} in node name ${nodeKeyName}: ${e}`);
        }
      }
    }

    const typ = node.type;

    if (typ !== undefined) {
      switch (typ) {
        case 'string':
          if (node.format === 'date' || node.format === 'date-time') {
            return this.parseDateType(node, parsingOpts);
          }
          return node;
        case 'integer':
          return this.parseIntegerType(node, parsingOpts, nodeKeyName);
        case 'boolean':
          return this.parseBooleanType();
        case 'number':
          return this.parseNumberType(node, parsingOpts, nodeKeyName);
        case 'object':
          if (node.properties !== undefined) {
            const result = {};
            Object.entries(node.properties).forEach(([k, v]) => {
              result[k] = CredentialSchema.convertToInternalSchemaObj(
                v,
                parsingOpts,
                createFullName(nodeKeyName, k),
                rootNode
              );
            });
            return result;
          } else {
            throw new Error(`Schema object key ${nodeKeyName} must have properties object`);
          }
        case 'array':
          if (Array.isArray(node.items)) {
            return node.items.map((i) =>
              CredentialSchema.convertToInternalSchemaObj(i, parsingOpts, createFullName(nodeKeyName, i), rootNode)
            );
          } else {
            throw new Error(
              `"items" field must be an array but was ${typeof node.items}. This is required because the schema should specify exactly how many items are present in the array.`
            );
          }
        default:
          throw new Error(`Unknown type for key ${nodeKeyName} in schema: ${typ}`);
      }
    } else {
      throw new Error(`Cannot parse node key ${nodeKeyName} for JSON-schema syntax: ${node}`);
    }
  }

  // Rules for parsing numeric type:
  // 1. For type integer, if minimum is provided and >=0, then it's a positive integer. If minimum is not provided its potentially
  // negative and choose a minimum if `useDefaults` is set to true in `parsingOptions` else throw error.
  // 2. For type number, if minimum is provided and >=0, then it's a positive number. If minimum is not provided its potentially
  // negative and choose a minimum if `useDefaults` is set to true in `parsingOptions` else throw error.
  // 3. For type number, if `multipleOf` is not provided, assume value of 0 if `useDefaults` is set to true in `parsingOptions`
  // else throw error.

  static parseIntegerType(node: { minimum?: number }, parsingOpts: ISchemaParsingOpts, nodeName: string): object {
    if (!parsingOpts.useDefaults && node.minimum === undefined) {
      throw new Error(`No minimum was provided for key ${nodeName}`);
    }
    const min = node.minimum !== undefined ? node.minimum : parsingOpts.defaultMinimumInteger;
    return min >= 0 ? { type: this.POSITIVE_INT_TYPE } : { type: this.INT_TYPE, minimum: min };
  }

  static parseDateType(node: { minimum?: number }, parsingOpts: ISchemaParsingOpts): object {
    const min = node.minimum !== undefined ? node.minimum : parsingOpts.defaultMinimumDate;
    return { type: this.DATETIME_TYPE, minimum: min };
  }

  static parseBooleanType(): object {
    return { type: this.BOOLEAN_TYPE };
  }

  static parseNumberType(
    node: { minimum?: number; multipleOf: number },
    parsingOpts: ISchemaParsingOpts,
    nodeName: string
  ): object {
    if (!parsingOpts.useDefaults && (node.minimum === undefined || node.multipleOf === undefined)) {
      throw new Error(`both minimum and multipleOf must be provided for key ${nodeName}`);
    }

    const min = node.minimum !== undefined ? node.minimum : parsingOpts.defaultMinimumInteger;
    const d = node.multipleOf !== undefined ? this.getDecimalPlaces(node.multipleOf) : parsingOpts.defaultDecimalPlaces;
    return min >= 0
      ? { type: this.POSITIVE_NUM_TYPE, decimalPlaces: d }
      : { type: this.NUM_TYPE, minimum: min, decimalPlaces: d };
  }

  static getDecimalPlaces(d: number): number {
    const re = /^0?\.(0*1$)/;
    const m = d.toString().match(re);
    if (m === null) {
      throw new Error(`Needed a number with a decimal point like .1, .01, .001, etc but found ${d}`);
    }
    return m[1].length;
  }

  static flattenSchemaObj(schema: object, versionGte040 = true): FlattenedSchema {
    return versionGte040
      ? flattenTill2ndLastKey({ ...this.IMPLICIT_FIELDS, ...schema })
      : flattenTill2ndLastKey({ ...this.OLD_IMPLICIT_FIELDS, ...schema });
  }

  /**
   * Generate a schema based on the credential and with the help of a schema that defines some fields. For fields with a
   * conflicting types between credential and schema, error will be thrown. For extra keys or items in schema, they will be
   * removed in the returned schema. The missing keys or items in schema will be added in the returned schema.
   * @param cred
   * @param schema
   */
  // @ts-ignore
  static generateAppropriateSchema(cred: object, schema: CredentialSchema): CredentialSchema {
    // Make `newJsonSchema` a copy of `schema.jsonSchema` as `newJsonSchema` will be updated as per the content of `cred`
    const newJsonSchema = _.cloneDeep(schema.getEmbeddedJsonSchema()) as IEmbeddedJsonSchema;
    const props = newJsonSchema.properties;
    // Update `props` and hence `newJsonSchema`
    CredentialSchema.generateFromCredential(cred, props, schema.version);
    // For older version, a variable time message encoder was mistakenly used
    const useConstantTimeEncoder = semver.gte(schema.version, '0.5.0');
    if (schema.hasEmbeddedJsonSchema()) {
      return new CredentialSchema(
        newJsonSchema,
        schema.parsingOptions,
        false,
        { version: schema.version },
        undefined,
        useConstantTimeEncoder
      );
    } else {
      return new CredentialSchema(
        schema.jsonSchema,
        schema.parsingOptions,
        false,
        { version: schema.version },
        newJsonSchema,
        useConstantTimeEncoder
      );
    }
  }

  /**
   * Get type and format of the credential value
   * @param value
   * @param schemaVersion - Schema version for which the parsing rules should apply
   * @private
   */
  private static getTypeAndFormat(value: CredVal, schemaVersion?: string): [string, string | undefined] {
    let typ = typeof value as string;
    let format: string | undefined = undefined;
    switch (typ) {
      case 'boolean':
        typ = 'boolean';
        break;
      case 'number':
        if (Number.isInteger(value)) {
          typ = 'integer';
        }
        break;
      case 'object':
        if (Array.isArray(value)) {
          typ = 'array';
        }
        break;
      default:
        typ = 'string';
        // Date-time support was added in schema version '0.0.3' so for earlier versions don't return format that
        // causes the encoding to change from string to integer
        const skipParsingDates = schemaVersion !== undefined && semver.lt(schemaVersion, '0.0.3');
        if (!skipParsingDates && isValueDateTime(value as string)) {
          format = 'date-time';
        } else if (!skipParsingDates && isValueDate(value as string)) {
          format = 'date';
        }
    }
    return [typ, format];
  }

  /**
   * Get sub-schema for the credential value
   * @param value
   * @param schemaVersion - Schema version for which the parsing rules should apply
   * @private
   */
  private static getSubschema(value: CredVal, schemaVersion?: string): object {
    const [typ, format] = CredentialSchema.getTypeAndFormat(value, schemaVersion);

    if (typ === 'boolean') {
      return { type: typ };
    }

    if (typ === 'string') {
      return format ? { type: typ, format } : { type: typ };
    }

    if (typ === 'number') {
      return {
        type: typ,
        minimum: DefaultSchemaParsingOpts.defaultMinimumInteger,
        multipleOf: 1 / Math.pow(10, value.toString().split('.')[1].length)
      };
    }

    if (typ === 'integer') {
      return { type: typ, minimum: DefaultSchemaParsingOpts.defaultMinimumInteger };
    }

    if (typ === 'object') {
      const obj = { type: typ, properties: {} };
      for (const [k, v] of Object.entries(value)) {
        obj.properties[k] = CredentialSchema.getSubschema(v, schemaVersion);
      }
      return obj;
    }

    // `typ` is array
    const items: object[] = [];
    // @ts-ignore
    value.forEach((v) => {
      items.push(CredentialSchema.getSubschema(v, schemaVersion));
    });
    return { type: typ, items };
  }

  /**
   * Update given JSON-schema properties based on the given credential object.
   * @param cred
   * @param schemaProps - These will be updated based on the credential subject.
   * @param schemaVersion - Schema version for which the schema generation logic should apply
   * @private
   */
  private static generateFromCredential(cred: object, schemaProps: object, schemaVersion?: string) {
    for (const [key, value] of Object.entries(cred)) {
      const [typ] = CredentialSchema.getTypeAndFormat(value, schemaVersion);

      if (schemaProps[key] === undefined) {
        // key not in schema
        schemaProps[key] = CredentialSchema.getSubschema(value, schemaVersion);
      } else if ('type' in schemaProps[key]) {
        // key in schema
        if (
          schemaProps[key]['type'] == 'string' ||
          schemaProps[key]['type'] == 'integer' ||
          schemaProps[key]['type'] == 'boolean' ||
          schemaProps[key]['type'] == 'number'
        ) {
          if (schemaProps[key]['type'] !== typ) {
            // If schema defines the type as "number" but credential has "integer" value then don't throw an error
            if (!(schemaProps[key]['type'] === 'number' && typ === 'integer')) {
              throw new Error(
                `Mismatch in credential and given schema type for key ${key}: ${schemaProps[key]['type']} !== ${typ}`
              );
            }
          }
        } else if (schemaProps[key]['type'] === 'array' && typ === 'array') {
          if (schemaProps[key]['items'].length < value.length) {
            // If cred has more items than schema, add the missing ones
            value.slice(schemaProps[key]['items'].length).forEach((v) => {
              schemaProps[key]['items'].push(CredentialSchema.getSubschema(v, schemaVersion));
            });
          } else if (schemaProps[key]['items'].length > value.length) {
            // If cred has less items than schema, delete those items
            schemaProps[key]['items'] = schemaProps[key]['items'].slice(0, value.length);
          }
        } else if (schemaProps[key]['type'] === 'object' && typ === 'object') {
          CredentialSchema.generateFromCredential(value, schemaProps[key][SCHEMA_PROPS_STR], schemaVersion);
        } else {
          throw new Error(
            `Incompatible types in credential and schema for key ${key}: ${schemaProps[key]['type']} !== ${typ}`
          );
        }
      } else {
        throw new Error(`Schema's key ${key} does not have type field`);
      }
    }

    // For keys in schemaProps but not in cred, they should be removed
    const sk = Object.keys(schemaProps);
    for (const k of sk) {
      if (cred[k] === undefined) {
        delete schemaProps[k];
      }
    }
  }

  private static validateStringType(schema: object, fieldName: string) {
    if (!schema[fieldName] || schema[fieldName].type !== 'string') {
      throw new Error(`Schema should contain a top level key ${fieldName} and its type must be "string"`);
    }
  }

  /**
   * Returns true if the given object is an embedded schema, i.e. it has the `properties` key set.
   * @param obj
   */
  static isEmbeddedJsonSchema(obj: IEmbeddedJsonSchema | IJsonSchema): boolean {
    return obj[SCHEMA_PROPS_STR] !== undefined;
  }
}

export function getTransformedMinMax(name: string, valTyp: ValueTypes, min: number, max: number): [number, number] {
  let transformedMin, transformedMax;
  switch (valTyp.type) {
    case ValueType.PositiveInteger:
      transformedMin = min;
      transformedMax = max;
      break;
    case ValueType.Integer:
      transformedMin = Encoder.integerToPositiveInt(valTyp.minimum)(min);
      transformedMax = Encoder.integerToPositiveInt(valTyp.minimum)(max);
      break;
    case ValueType.PositiveNumber:
      transformedMin = Encoder.positiveDecimalNumberToPositiveInt(valTyp.decimalPlaces)(min);
      transformedMax = Encoder.positiveDecimalNumberToPositiveInt(valTyp.decimalPlaces)(max);
      break;
    case ValueType.Number:
      transformedMin = Encoder.decimalNumberToPositiveInt(valTyp.minimum, valTyp.decimalPlaces)(min);
      transformedMax = Encoder.decimalNumberToPositiveInt(valTyp.minimum, valTyp.decimalPlaces)(max);
      break;
    default:
      throw new Error(`${name} should be of numeric type as per schema but was ${JSON.stringify(valTyp, null, 2)}`);
  }
  return [transformedMin, transformedMax];
}
