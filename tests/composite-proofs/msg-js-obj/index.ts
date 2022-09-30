import { bytearrayToHex, EncodeFunc, Encoder, SignatureG1, SignedMessages } from '../../../src';
import { stringToBytes } from '../../utils';

export const defaultEncoder = (v: unknown) => {
  // @ts-ignore
  return SignatureG1.encodeMessageForSigning(stringToBytes(v.toString()));
};

// Create an encoder for attributes with various kinds of values.
const encoders = new Map<string, EncodeFunc>();
encoders.set('timeOfBirth', Encoder.positiveIntegerEncoder());
encoders.set('weight', Encoder.positiveIntegerEncoder());
encoders.set('physical.weight', Encoder.positiveIntegerEncoder());

// height contains at most 1 decimal place
encoders.set('height', Encoder.positiveDecimalNumberEncoder(1));
encoders.set('physical.height', Encoder.positiveDecimalNumberEncoder(1));

// BMI contains at most 2 decimal place
encoders.set('BMI', Encoder.positiveDecimalNumberEncoder(2));
encoders.set('physical.BMI', Encoder.positiveDecimalNumberEncoder(2));

// score contains at most 1 decimal place and its minimum value is -100
encoders.set('score', Encoder.decimalNumberEncoder(-100, 1));

// latitude contains at most 3 decimal places (in this example) and its minimum value is -90
encoders.set('lessSensitive.department.location.geo.lat', Encoder.decimalNumberEncoder(-90, 3));

// longitude contains at most 3 decimal places (in this example) and its minimum value is -180
encoders.set('lessSensitive.department.location.geo.long', Encoder.decimalNumberEncoder(-180, 3));

encoders.set('SSN', (v: unknown) => {
  // @ts-ignore
  return SignatureG1.reversibleEncodeStringForSigning(v);
});
encoders.set('sensitive.SSN', (v: unknown) => {
  // @ts-ignore
  return SignatureG1.reversibleEncodeStringForSigning(v);
});

export const GlobalEncoder = new Encoder(encoders, defaultEncoder);

export function signedToHex(signed: SignedMessages): object {
  const sig = signed.signature.hex;
  const enc = {};
  Object.keys(signed.encodedMessages).forEach((k) => {
    // @ts-ignore
    enc[k] = bytearrayToHex(signed.encodedMessages[k]);
  });
  return { encodedMessages: enc, signature: sig };
}

export function checkMapsEqual(mapA: Map<unknown, unknown>, mapB: Map<unknown, unknown>) {
  expect(mapA.size).toEqual(mapB.size);
  for (const key of mapA.keys()) {
    expect(mapA.get(key)).toEqual(mapB.get(key));
  }
}
