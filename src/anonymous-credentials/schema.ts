import { Versioned } from './versioned';
import { EncodeFunc, Encoder } from '../bbs-plus';
import { isPositiveInteger } from '../util';
import {
  CRED_VERSION_STR,
  REGISTRY_ID_STR,
  REV_CHECK_STR,
  SCHEMA_STR,
  STATUS_STR,
  StringOrObject,
  SUBJECT_STR,
  VERSION_STR
} from './types-and-consts';
import { flatten } from 'flat';
import b58 from 'bs58';

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

    super(CredentialSchema.VERSION);
    this.schema = schem;
    this.initEncoder();

    // TODO: validate "schem" this is a JSON schema
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
          f = Encoder.integerEncoder(value['minimum'] || 0);
          break;
        case CredentialSchema.POSITIVE_NUM_TYPE:
          f = Encoder.positiveDecimalNumberEncoder(value['decimalPlaces']); // TODO: replace decimalPlaces with jsonschema multipleof
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
    const credSchema = new CredentialSchema(JSON.parse(j));
    return credSchema;
  }

  static processSchemaObject(node: any, result: object) {
    const keys = Object.keys(node);
    keys.forEach(k => {
      const value = node[k];

      let insVal = {};
      if (value.type === 'object') {
        CredentialSchema.processSchemaObject(value.properties, insVal);
      } else {
        insVal = value;
      }

      result[k] = insVal;
    });
  }

  static flattenSchemaObj(schema: any): [string[], unknown[]] {
    // TODO: remove this when we fix tests, should test in constructor
    if (!schema.properties) {
      return [[], []];
    }

    const resultObj = {};
    CredentialSchema.processSchemaObject(schema.properties, resultObj);

    const flattened = {};
    const temp = flatten(resultObj) as object;
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
