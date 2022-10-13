// Data used by various tests

// 1st attribute set. This is a flat JS object.
import { EncodeFunc, Encoder, SignatureG1 } from '../../../src';
import { stringToBytes } from '../../utils';

export const attributes1 = {
  fname: 'John',
  lname: 'Smith',
  email: 'john.smith@example.com',
  SSN: '123-456789-0',
  'user-id': 'user:123-xyz-#',
  country: 'USA',
  city: 'New York',
  timeOfBirth: 1662010849619,
  height: 181.5,
  weight: 210,
  BMI: 23.25,
  score: -13.5,
  secret: 'my-secret-that-wont-tell-anyone'
};

// This is the structure of `attributes1`. This does not contain any attribute values but contains the names with the
// same kind of nesting as `attributes1`. For any attribute set, this should be known to all system participants, i.e. signer,
// prover and verifier. A similar alternative of defining the structure would be to replace the "null" value with a reference
// to the encoding function for that field.
export const attributes1Struct = {
  fname: null,
  lname: null,
  email: null,
  SSN: null,
  'user-id': null,
  country: null,
  city: null,
  timeOfBirth: null,
  height: null,
  weight: null,
  BMI: null,
  score: null,
  secret: null
};

// 2nd attribute set. This is a nested JS object with 1 level of nesting.
export const attributes2 = {
  fname: 'John',
  lname: 'Smith',
  sensitive: {
    secret: 'my-secret-that-wont-tell-anyone',
    email: 'john.smith@example.com',
    SSN: '123-456789-0',
    'user-id': 'user:123-xyz-#'
  },
  location: {
    country: 'USA',
    city: 'New York'
  },
  timeOfBirth: 1662010849619,
  physical: {
    height: 181.5,
    weight: 210,
    BMI: 23.25
  },
  score: -13.5
};

// This is the structure of `attributes2`. Similar to `attributes1Struct`, does not contain attribute values but the names
// and the structure of `attributes2`
export const attributes2Struct = {
  fname: null,
  lname: null,
  sensitive: {
    secret: null,
    email: null,
    SSN: null,
    'user-id': null
  },
  location: {
    country: null,
    city: null
  },
  timeOfBirth: null,
  physical: {
    height: null,
    weight: null,
    BMI: null
  },
  score: null
};

// 3rd attribute set. This is an even more nested JS object with many levels of nesting.
export const attributes3 = {
  fname: 'John',
  lname: 'Smith',
  sensitive: {
    very: {
      secret: 'my-secret-that-wont-tell-anyone'
    },
    email: 'john.smith@acme.com',
    phone: '801009801',
    SSN: '123-456789-0',
    'employee-id': 'user:123-xyz-#'
  },
  lessSensitive: {
    location: {
      country: 'USA',
      city: 'New York'
    },
    department: {
      name: 'Random',
      location: {
        name: 'Somewhere',
        geo: {
          lat: -23.658,
          long: 2.556
        }
      }
    }
  },
  rank: 6
};

// This is the structure of `attributes3`.
export const attributes3Struct = {
  fname: null,
  lname: null,
  sensitive: {
    very: {
      secret: null
    },
    email: null,
    phone: null,
    SSN: null,
    'employee-id': null
  },
  lessSensitive: {
    location: {
      country: null,
      city: null
    },
    department: {
      name: null,
      location: {
        name: null,
        geo: {
          lat: null,
          long: null
        }
      }
    }
  },
  rank: null
};

// The default encoder
export const defaultEncoder = (v: unknown) => {
  // @ts-ignore
  return SignatureG1.encodeMessageForSigning(stringToBytes(v.toString()));
};

// Create an encoder for attributes with various kinds of values.
export const encoders = new Map<string, EncodeFunc>();

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

encoders.set('rank', Encoder.positiveIntegerEncoder());

export const GlobalEncoder = new Encoder(encoders, Encoder.defaultEncodeFunc());
