import { Accumulator, AccumulatorParams, MembershipProvingKey, NonMembershipProvingKey } from '../accumulator';
import {
  ACCUMULATOR_PARAMS_LABEL_BYTES,
  ACCUMULATOR_PROVING_KEY_LABEL_BYTES,
  AttributeEquality,
  FlattenedSchema,
  SAVER_ENCRYPTION_GENS_BYTES
} from './types-and-consts';
import { SaverEncryptionGens, SaverEncryptionGensUncompressed } from '../saver';
import { flatten } from 'flat';
import { PresentationSpecification } from './presentation-specification';
import { ValueType, ValueTypes } from './schema';
import { Encoder } from '../bbs-plus';
import { WitnessEqualityMetaStatement } from '../composite-proof';

export function dockAccumulatorParams(): AccumulatorParams {
  return Accumulator.generateParams(ACCUMULATOR_PARAMS_LABEL_BYTES);
}

export function dockAccumulatorMemProvingKey(): MembershipProvingKey {
  return MembershipProvingKey.generate(ACCUMULATOR_PROVING_KEY_LABEL_BYTES);
}

export function dockAccumulatorNonMemProvingKey(): NonMembershipProvingKey {
  return NonMembershipProvingKey.generate(ACCUMULATOR_PROVING_KEY_LABEL_BYTES);
}

export function dockSaverEncryptionGens(): SaverEncryptionGens {
  return SaverEncryptionGens.generate(SAVER_ENCRYPTION_GENS_BYTES);
}

export function dockSaverEncryptionGensUncompressed(): SaverEncryptionGensUncompressed {
  return SaverEncryptionGens.generate(SAVER_ENCRYPTION_GENS_BYTES).decompress();
}

export function flattenTill2ndLastKey(obj: object): [string[], object[]] {
  const flattened = {};
  const temp = flatten(obj) as object;
  for (const k of Object.keys(temp)) {
    // taken from https://stackoverflow.com/a/5555607
    const pos = k.lastIndexOf('.');
    const name = k.substring(0, pos);
    const t = k.substring(pos + 1);

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

/**
 * The context passed to the proof contains the version and the presentation spec as well. This is done to bind the
 * presentation spec and the version cryptographically to the proof.
 * @param version
 * @param presSpec
 * @param context
 */
export function buildContextForProof(
  version: string,
  presSpec: PresentationSpecification,
  context?: string | Uint8Array
): Uint8Array {
  const te = new TextEncoder();
  let ctx = Array.from(te.encode(version));
  if (context !== undefined) {
    if (typeof context === 'string') {
      ctx = ctx.concat(Array.from(te.encode(context)));
    } else {
      ctx = ctx.concat(Array.from(context));
    }
  }
  ctx = ctx.concat(Array.from(te.encode(presSpec.toJSON())));
  return new Uint8Array(ctx);
}

export function getTransformedMinMax(valTyp: ValueTypes, min: number, max: number): [number, number] {
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
      throw new Error(`${name} should be of numeric type as per schema but was ${valTyp}`);
  }
  return [transformedMin, transformedMax];
}

export function createWitEq(eql: AttributeEquality, flattenedSchemas: FlattenedSchema[]): WitnessEqualityMetaStatement {
  const witnessEq = new WitnessEqualityMetaStatement();
  for (const [cIdx, name] of eql) {
    const i = flattenedSchemas[cIdx][0].indexOf(name);
    if (i === -1) {
      throw new Error(`Attribute name ${name} was not found`);
    }
    witnessEq.addWitnessRef(cIdx, i);
  }
  return witnessEq;
}
