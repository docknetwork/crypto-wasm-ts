import { Accumulator, AccumulatorParams, MembershipProvingKey, NonMembershipProvingKey } from '../accumulator';
import { ACCUMULATOR_PARAMS_LABEL_BYTES, ACCUMULATOR_PROVING_KEY_LABEL_BYTES } from './types-and-consts';

export function dockAccumulatorParams(): AccumulatorParams {
  return Accumulator.generateParams(ACCUMULATOR_PARAMS_LABEL_BYTES)
}

export function dockAccumulatorMemProvingKey(): MembershipProvingKey {
  return MembershipProvingKey.generate(ACCUMULATOR_PROVING_KEY_LABEL_BYTES)
}

export function dockAccumulatorNonMemProvingKey(): NonMembershipProvingKey {
  return NonMembershipProvingKey.generate(ACCUMULATOR_PROVING_KEY_LABEL_BYTES)
}
