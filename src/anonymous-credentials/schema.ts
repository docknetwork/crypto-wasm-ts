import pointer from 'json-pointer';
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
  SUBJECT_STR,
  VERSION_STR
} from './types-and-consts';
import { flattenTill2ndLastKey } from './util';

/**
 * Rules
 * 1. Schema must define a top level `credentialSubject` field for the subject, and it can be an array of object
 * 2. Schema must define a top level `credentialSchema` field.
 * 3. Credential status if defined must be present as `credentialStatus` field.
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

export const META_SCHEMA_STR = '$schema';

export interface ISchema {
  [CRED_VERSION_STR]: object;
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
  [CRED_VERSION_STR]: object;
  [SCHEMA_STR]: object;
  [SUBJECT_STR]: object | object[];
  // @ts-ignore
  [STATUS_STR]?: object;
  [key: string]: object;
}

export interface IJsonSchema {
  [META_SCHEMA_STR]: string;
  type: string;
  properties: IJsonSchemaProperties;
  definitions?: { [key: string]: object };
}

export interface ISchemaParsingOpts {
  useDefaults: boolean;
  defaultMinimumInteger: number;
  defaultDecimalPlaces: number;
}

export const DefaultSchemaParsingOpts: ISchemaParsingOpts = {
  useDefaults: false,
  // Minimum value kept over a billion
  defaultMinimumInteger: -(Math.pow(2, 32) - 1),
  defaultDecimalPlaces: 0
};

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

  // Custom definitions for JSON schema syntax
  static JSON_SCHEMA_CUSTOM_DEFS = {
    encryptableString: {
      type: 'string'
    },
    encryptableCompString: {
      type: 'string'
    }
  };

  // Custom override definitions for JSON schema syntax
  // any refs in the jsonschema that reference these will be overwritten
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

  // Keys to ignore from generic validation as they are already validated
  static IGNORE_GENERIC_VALIDATION = new Set([
    CRED_VERSION_STR,
    SCHEMA_STR,
    `${STATUS_STR}.${REGISTRY_ID_STR}`,
    `${STATUS_STR}.${REV_CHECK_STR}`,
    `${STATUS_STR}.${REV_ID_STR}`
  ]);

  static POSSIBLE_TYPES = new Set<string>([
    this.STR_TYPE,
    this.STR_REV_TYPE,
    this.POSITIVE_INT_TYPE,
    this.INT_TYPE,
    this.POSITIVE_NUM_TYPE,
    this.NUM_TYPE
  ]);

  schema: ISchema;
  jsonSchema: IJsonSchema;
  parsingOptions: ISchemaParsingOpts;
  // @ts-ignore
  encoder: Encoder;

  /**
   * Takes a schema object as per JSON-schema syntax (`IJsonSchema`), validates it and converts it to an internal
   * representation (`ISchema`) and stores both as the one with JSON-schema syntax is added to the credential representation.
   * @param jsonSchema
   * @param parsingOpts
   */
  constructor(jsonSchema: IJsonSchema, parsingOpts: Partial<ISchemaParsingOpts> = DefaultSchemaParsingOpts) {
    // This functions flattens schema object twice but the repetition can be avoided. Keeping this deliberately for code clarity.
    const pOpts = { ...DefaultSchemaParsingOpts, ...parsingOpts };
    const schema = CredentialSchema.convertToInternalSchemaObj(jsonSchema, pOpts, '', undefined) as ISchema;
    CredentialSchema.validate(schema);

    super(CredentialSchema.VERSION);
    this.schema = schema as ISchema;
    // This is the schema in JSON-schema format. Kept to output in credentials or in `toJSON` without converting back from
    // internal representation; trading off memory for CPU time.
    this.jsonSchema = jsonSchema;
    this.parsingOptions = pOpts;
    this.initEncoder();
  }

  /**
   * Initialize the encoder as per the internal representation of schema, i.e. `ISchema`
   */
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
   * Validates the internal representation of schema
   * @param schema
   */
  static validate(schema: ISchema) {
    // Following 2 fields could have been implicit but being explicit for clarity
    this.validateStringType(schema, CRED_VERSION_STR);
    this.validateStringType(schema, SCHEMA_STR);

    const schemaStatus = schema[STATUS_STR];
    if (schemaStatus !== undefined) {
      this.validateStringType(schemaStatus, REGISTRY_ID_STR);
      this.validateStringType(schemaStatus, REV_CHECK_STR);
      this.validateStringType(schemaStatus, REV_ID_STR);
    }

    if (schema[SUBJECT_STR] === undefined) {
      throw new Error(`Schema properties did not contain top level key ${SUBJECT_STR}`);
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

  static essential(withDefinitions = true): IJsonSchema {
    const s = {
      // Currently only assuming support for draft-07 but other might work as well
      [META_SCHEMA_STR]: 'http://json-schema.org/draft-07/schema#',
      type: 'object',
      properties: {
        [CRED_VERSION_STR]: { type: 'string' },
        [SCHEMA_STR]: { type: 'string' },
        [SUBJECT_STR]: {}
      }
    };
    if (withDefinitions) {
      s['definitions'] = this.JSON_SCHEMA_CUSTOM_DEFS;
    }
    // @ts-ignore
    return s;
  }

  flatten(): FlattenedSchema {
    return CredentialSchema.flattenSchemaObj(this.schema);
  }

  hasStatus(): boolean {
    return this.schema[STATUS_STR] !== undefined;
  }

  toJSON(): object {
    return { [VERSION_STR]: this.version, ...this.jsonSchema };
  }

  static fromJSON(j: object): CredentialSchema {
    // @ts-ignore
    const { $version, ...jsonSchema } = j;
    // @ts-ignore
    const credSchema = new CredentialSchema(jsonSchema);
    credSchema.version = $version;
    return credSchema;
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

  getJsonLdContext(): object {
    const terms = new Set<string>();
    terms.add(SCHEMA_STR);
    terms.add(CRED_VERSION_STR);

    let ctx = {
      dk: 'https://ld.dock.io/credentials#'
    };

    if (this.hasStatus()) {
      terms.add(REGISTRY_ID_STR);
      terms.add(REV_CHECK_STR);
      terms.add(REV_ID_STR);
    }

    const flattened = this.flatten();

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
    nodeKeyName: string = '',
    rootObject?: object
  ): object {
    // util function needed only in this func
    const createFullName = (old: string, neww: string): string => {
      return old.length == 0 ? neww : `${old}.${neww}`;
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
          return node;
        case 'integer':
          return this.parseIntegerType(node, parsingOpts, nodeKeyName);
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
          return node.items.map((i) =>
            CredentialSchema.convertToInternalSchemaObj(i, parsingOpts, createFullName(nodeKeyName, i), rootNode)
          );
        default:
          throw new Error(`Unknown type for key ${nodeKeyName} in schema: ${typ}`);
      }
    } else {
      throw new Error(`Cannot parse node key ${nodeKeyName} for JSON-schema syntax: ${node}`);
    }
  }

  static parseIntegerType(node: { minimum?: number }, parsingOpts: ISchemaParsingOpts, nodeName: string): object {
    if (!parsingOpts.useDefaults && node.minimum === undefined) {
      throw new Error(`No minimum was provided for key ${nodeName}`);
    }
    const min = node.minimum !== undefined ? node.minimum : parsingOpts.defaultMinimumInteger;
    return min >= 0 ? { type: this.POSITIVE_INT_TYPE } : { type: this.INT_TYPE, minimum: min };
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

  static flattenSchemaObj(schema: object): FlattenedSchema {
    return flattenTill2ndLastKey(schema);
  }

  private static validateStringType(schema: object, fieldName: string) {
    if (!schema[fieldName] || schema[fieldName].type !== 'string') {
      throw new Error(`Schema should contain a top level key ${fieldName} and its type must be "string"`);
    }
  }
}
