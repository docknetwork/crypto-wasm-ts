import {
  CRED_VERSION_STR,
  REGISTRY_ID_STR, REV_CHECK_STR, REV_ID_STR,
  SCHEMA_STR,
  STATUS_STR,
  SUBJECT_STR
} from '../../src/anonymous-credentials';

export function getExampleSchema(num) {
  const schema = {};
  schema[CRED_VERSION_STR] = { type: 'string' };
  schema[SCHEMA_STR] = { type: 'string' };
  switch (num) {
    case 1:
      schema[SUBJECT_STR] = {
        fname: { type: 'string' }
      };
      break;
    case 2:
      schema[SUBJECT_STR] = {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 }
      };
      break;
    case 3:
      schema[SUBJECT_STR] = {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 },
        long: { type: 'positiveDecimalNumber', decimalPlaces: 2 }
      };
      break;
    case 4:
      schema[SUBJECT_STR] = {
        fname: { type: 'string' },
        score: { type: 'integer', minimum: -100 }
      };
      schema[STATUS_STR] = {};
      schema[STATUS_STR][REGISTRY_ID_STR] = { type: 'string' };
      schema[STATUS_STR][REV_CHECK_STR] = { type: 'string' };
      schema[STATUS_STR][REV_ID_STR] = { type: 'string' };
      break;
    case 5:
      schema[SUBJECT_STR] = {
        fname: { type: 'string' },
        lname: { type: 'string' },
        sensitive: {
          very: {
            secret: { type: 'string' }
          },
          email: { type: 'string' },
          phone: { type: 'string' },
          SSN: { type: 'stringReversible', compress: false }
        },
        lessSensitive: {
          location: {
            country: { type: 'string' },
            city: { type: 'string' }
          },
          department: {
            name: { type: 'string' },
            location: {
              name: { type: 'string' },
              geo: {
                lat: { type: 'decimalNumber', decimalPlaces: 3, minimum: -90 },
                long: { type: 'decimalNumber', decimalPlaces: 3, minimum: -180 }
              }
            }
          }
        },
        rank: { type: 'positiveInteger' }
      };
      schema[STATUS_STR] = {
        $registryId: { type: 'string' },
        $revocationCheck: { type: 'string' },
        $revocationId: { type: 'string' }
      };
      break;
    case 6:
      schema[SUBJECT_STR] = [
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
      ];
      break;
    case 7:
      schema[SUBJECT_STR] = [
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
      ];
      schema['issuer'] = {
        name: {type: "string"},
        desc: {type: "string"},
        logo: {type: "string"}
      };
      schema['issuanceDate'] = {type: "positiveInteger"};
      schema['expirationDate'] = {type: "positiveInteger"};
      break;
    case 8:
      schema[SUBJECT_STR] = {
        fname: { type: 'string' },
        lname: { type: 'string' },
        sensitive: {
          email: { type: 'string' },
          phone: { type: 'string' },
          SSN: { type: 'stringReversible', compress: false }
        },
        timeOfBirth: { type: 'positiveInteger' },
        physical: {
          height: { type: 'positiveDecimalNumber', decimalPlaces: 1 },
          weight: { type: 'positiveDecimalNumber', decimalPlaces: 1 },
          BMI: { type: 'positiveDecimalNumber', decimalPlaces: 2 }
        },
      };
      break;
    case 9:
      schema[SUBJECT_STR] = {
        fname: { type: 'string' },
        lname: { type: 'string' },
        email: { type: 'string' },
        SSN: { type: 'stringReversible', compress: false },
        userId: { type: 'stringReversible', compress: true },
        country: { type: 'string' },
        city: { type: 'string' },
        timeOfBirth: { type: 'positiveInteger' },
        height: { type: 'positiveDecimalNumber', decimalPlaces: 1 },
        weight: { type: 'positiveDecimalNumber', decimalPlaces: 1 },
        BMI: { type: 'positiveDecimalNumber', decimalPlaces: 2 },
        score: { type: 'decimalNumber', decimalPlaces: 1, minimum: -100 },
        secret: { type: 'string' }
      };
      break;
    case 10:
      schema[SUBJECT_STR] = {
        fname: { type: 'string' },
        lname: { type: 'string' },
        sensitive: {
          email: { type: 'string' },
          SSN: { type: 'stringReversible', compress: false }
        },
        education: {
          studentId: { type: 'string' },
          university: {
            name: { type: 'string' },
            registrationNumber: { type: 'string' }
          },
          transcript: {
            rank: { type: 'positiveInteger' },
            CGPA: { type: 'positiveDecimalNumber', decimalPlaces: 2 },
            scores: {
              english: { type: 'positiveInteger' },
              mathematics: { type: 'positiveInteger' },
              science: { type: 'positiveInteger' },
              history: { type: 'positiveInteger' },
              geography: { type: 'positiveInteger' }
            }
          }
        }
      };
      schema[STATUS_STR] = {
        $registryId: { type: 'string' },
        $revocationCheck: { type: 'string' },
        $revocationId: { type: 'string' }
      };
      break;
    case 11:
      schema[SUBJECT_STR] = {
        fname: { type: 'string' },
        lname: { type: 'string' },
        sensitive: {
          secret: { type: 'string' },
          email: { type: 'string' },
          SSN: { type: 'stringReversible', compress: false },
          userId: { type: 'stringReversible', compress: true }
        },
        location: {
          country: { type: 'string' },
          city: { type: 'string' }
        },
        timeOfBirth: { type: 'positiveInteger' },
        physical: {
          height: { type: 'positiveDecimalNumber', decimalPlaces: 1 },
          weight: { type: 'positiveDecimalNumber', decimalPlaces: 1 },
          BMI: { type: 'positiveDecimalNumber', decimalPlaces: 2 }
        },
        score: { type: 'decimalNumber', decimalPlaces: 1, minimum: -100 }
      };
      break;
    default:
      throw Error(`Cannot find example schema number ${num}`)
  }
  return schema;
}
