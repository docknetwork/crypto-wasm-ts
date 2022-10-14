import { Accumulator, AccumulatorParams, MembershipProvingKey, NonMembershipProvingKey } from '../accumulator';
import {
  ACCUMULATOR_PARAMS_LABEL_BYTES,
  ACCUMULATOR_PROVING_KEY_LABEL_BYTES,
  SAVER_ENCRYPTION_GENS_BYTES
} from './types-and-consts';
import { SaverEncryptionGens } from '../saver';
import { flatten } from 'flat';

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

export function flattenTill2ndLastKey(obj: object): [string[], unknown[]] {
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