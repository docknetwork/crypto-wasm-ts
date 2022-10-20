import {
  CRED_VERSION_STR,
  REGISTRY_ID_STR, REV_CHECK_STR, REV_ID_STR,
  SCHEMA_STR,
  STATUS_STR,
  SUBJECT_STR,
  CredentialSchema,
} from '../../src/anonymous-credentials';

export function getExampleSchema(num) {
  const schema: any = CredentialSchema.essential();
  schema.properties[CRED_VERSION_STR] = { type: 'string' };
  schema.properties[SCHEMA_STR] = { type: 'string' };
  switch (num) {
    case 1:
      schema.properties[SUBJECT_STR] = {
        type: 'object',
        properties: {
          fname: { type: 'string' }
        }
      };
      break;
    case 2:
      schema.properties[SUBJECT_STR] = {
        type: 'object',
        properties: {
          fname: { type: 'string' },
          score: { type: 'integer', minimum: -100 }
        }
      };
      break;
    case 3:
      schema.properties[SUBJECT_STR] = {
        type: 'object',
        properties: {
          fname: { type: 'string' },
          score: { type: 'integer', minimum: -100 },
          long: { type: 'positiveDecimalNumber', decimalPlaces: 2 }
        }
      };
      break;
    case 4:
      schema.properties[SUBJECT_STR] = {
        type: 'object',
        properties: {
          fname: { type: 'string' },
          score: { type: 'integer', minimum: -100 }
        }
      };
      schema.properties[STATUS_STR] = {
        type: 'object',
        properties: {
          [REGISTRY_ID_STR]: { type: 'string' },
          [REV_CHECK_STR]: { type: 'string' },
          [REV_ID_STR]: { type: 'string' },
        },
      };
      break;
    case 5:
      schema.properties[SUBJECT_STR] = {
        type: 'object',
        properties: {
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
                  lat: { type: 'number', decimalPlaces: 3, minimum: -90 },
                  long: { type: 'number', decimalPlaces: 3, minimum: -180 }
                }
              }
            }
          },
          rank: { type: 'positiveInteger' }
        }
      };
      schema.properties[STATUS_STR] = {
        type: 'object',
        properties: {
          $registryId: { type: 'string' },
          $revocationCheck: { type: 'string' },
          $revocationId: { type: 'string' }
        }
      };
      break;
    case 6:
      schema.properties[SUBJECT_STR] = {
        type: "array",
        items: [{
          type: "object",
          properties: {
            name: {type: "string"},
            location: {
              type: "object",
              properties: {
                name: {type: "string"},
                geo: {
                  type: "object",
                  properties: {
                    lat: {type: "number", decimalPlaces: 3, minimum: -90},
                    long: {type: "number", decimalPlaces: 3, minimum: -180}
                  }
                }
              }
            }
          }
        }, {
          type: "object",
          properties: {
            name: {type: "string"},
            location: {
              type: "object",
              properties: {
                name: {type: "string"},
                geo: {
                  type: "object",
                  properties: {
                    lat: {type: "number", decimalPlaces: 3, minimum: -90},
                    long: {type: "number", decimalPlaces: 3, minimum: -180}
                  }
                }
              }
            }
          }
        }, {
          type: "object",
          properties: {
            name: {type: "string"},
            location: {
              type: "object",
              properties: {
                name: {type: "string"},
                geo: {
                  type: "object",
                  properties: {
                    lat: {type: "number", decimalPlaces: 3, minimum: -90},
                    long: {type: "number", decimalPlaces: 3, minimum: -180}
                  }
                }
              }
            }
          }
        }]
      };
      break;
    case 7:
      schema.properties[SUBJECT_STR] = {
        type: "array",
        items: [{
          type: "object",
          properties: {
            name: {type: "string"},
            location: {
              type: "object",
              properties: {
                name: {type: "string"},
                geo: {
                  type: "object",
                  properties: {
                    lat: {type: "number", decimalPlaces: 3, minimum: -90},
                    long: {type: "number", decimalPlaces: 3, minimum: -180}
                  }
                }
              }
            }
          }
        }, {
          type: "object",
          properties: {
            name: {type: "string"},
            location: {
              type: "object",
              properties: {
                name: {type: "string"},
                geo: {
                  type: "object",
                  properties: {
                    lat: {type: "number", decimalPlaces: 3, minimum: -90},
                    long: {type: "number", decimalPlaces: 3, minimum: -180}
                  }
                }
              }
            }
          }
        }, {
          type: "object",
          properties: {
            name: {type: "string"},
            location: {
              type: "object",
              properties: {
                name: {type: "string"},
                geo: {
                  type: "object",
                  properties: {
                    lat: {type: "number", decimalPlaces: 3, minimum: -90},
                    long: {type: "number", decimalPlaces: 3, minimum: -180}
                  }
                }
              }
            }
          }
        }]
      };
      
      schema.properties['issuer'] = {
        type: 'object',
        properties: {
          name: {type: "string"},
          desc: {type: "string"},
          logo: {type: "string"}
        }
      };
      schema.properties['issuanceDate'] = {type: "positiveInteger"};
      schema.properties['expirationDate'] = {type: "positiveInteger"};
      break;
    case 8:
      schema.properties[SUBJECT_STR] = {
        type: 'object',
        properties: {
          fname: { type: 'string' },
          lname: { type: 'string' },
          sensitive: {
            type: 'object',
            properties: {
              email: { type: 'string' },
              phone: { type: 'string' },
              SSN: { type: 'stringReversible', compress: false }
            }
          },
          timeOfBirth: { type: 'positiveInteger' },
          physical: {
            height: { type: 'positiveDecimalNumber', decimalPlaces: 1 },
            weight: { type: 'positiveDecimalNumber', decimalPlaces: 1 },
            BMI: { type: 'positiveDecimalNumber', decimalPlaces: 2 }
          },
        }
      };
      break;
    case 9:
      schema.properties[SUBJECT_STR] = {
        type: 'object',
        properties: {
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
          score: { type: 'number', decimalPlaces: 1, minimum: -100 },
          secret: { type: 'string' }
        }
      };
      break;
    case 10:
      schema.properties[SUBJECT_STR] = {
        type: 'object',
        properties: {
          fname: { type: 'string' },
          lname: { type: 'string' },
          sensitive: {
            type: 'object',
            properties: {
              email: { type: 'string' },
              SSN: { type: 'stringReversible', compress: false }
            }
          },
          education: {
            type: 'object',
            properties: {
              studentId: { type: 'string' },
              university: {
                type: 'object',
                properties: {
                  name: { type: 'string' },
                  registrationNumber: { type: 'string' }
                }
              },
              transcript: {
                type: 'object',
                properties: {
                  rank: { type: 'positiveInteger' },
                  CGPA: { type: 'positiveDecimalNumber', decimalPlaces: 2 },
                  scores: {
                    type: 'object',
                    properties: {
                      english: { type: 'positiveInteger' },
                      mathematics: { type: 'positiveInteger' },
                      science: { type: 'positiveInteger' },
                      history: { type: 'positiveInteger' },
                      geography: { type: 'positiveInteger' }
                    }
                  }
                }
              }
            }
          }
        }
      };
      schema.properties[STATUS_STR] = {
        type: 'object',
        properties: {
          $registryId: { type: 'string' },
          $revocationCheck: { type: 'string' },
          $revocationId: { type: 'string' }
        }
      };
      break;
    case 11:
      schema.properties[SUBJECT_STR] = {
        type: 'object',
        properties: {
          fname: { type: 'string' },
          lname: { type: 'string' },
          sensitive: {
            type: 'object',
            properties: {
              secret: { type: 'string' },
              email: { type: 'string' },
              SSN: { type: 'stringReversible', compress: false },
              userId: { type: 'stringReversible', compress: true }
            }
          },
          location: {
            type: 'object',
            properties: {
              country: { type: 'string' },
              city: { type: 'string' }
            }
          },
          timeOfBirth: { type: 'positiveInteger' },
          physical: {
            type: 'object',
            properties: {
              height: { type: 'positiveDecimalNumber', decimalPlaces: 1 },
              weight: { type: 'positiveDecimalNumber', decimalPlaces: 1 },
              BMI: { type: 'positiveDecimalNumber', decimalPlaces: 2 }
            }
          },
          score: { type: 'number', decimalPlaces: 1, minimum: -100 }
        }
      };
      break;
    default:
      throw Error(`Cannot find example schema number ${num}`)
  }
  return schema;
}
