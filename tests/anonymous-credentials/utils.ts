import {
  CRED_VERSION_STR,
  REGISTRY_ID_STR, REV_CHECK_STR, REV_ID_STR,
  SCHEMA_STR,
  STATUS_STR,
  SUBJECT_STR,
  CredentialSchema, IJsonSchema
} from '../../src/anonymous-credentials';

export function getExampleSchema(num): IJsonSchema {
  const schema = CredentialSchema.essential();
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
          long: { "allOf": [
              { $ref: '#/definitions/positiveNumber' },
              { multipleOf: 0.01 }
            ]
          }
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
            type: 'object',
            properties: {
              very: {
                type: 'object',
                properties: {
                  secret: { type: 'string' }
                }
              },
              email: { type: 'string' },
              phone: { type: 'string' },
              SSN: { $ref: '#/definitions/encryptableString' }
            }
          },
          lessSensitive: {
            type: 'object',
            properties: {
              location: {
                type: 'object',
                properties: {
                  country: { type: 'string' },
                  city: { type: 'string' }
                },
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
                          lat: {type: 'number',minimum: -90, multipleOf: 0.001},
                          long: {type: 'number',minimum: -180, multipleOf: 0.001}
                        }
                      }
                    }
                  }
                }
              }
            }
          },
          rank: { $ref: '#/definitions/positiveInteger' }
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
      const item = {
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
                  lat: {type: 'number',minimum: -90, multipleOf: 0.001},
                  long: {type: 'number',minimum: -180, multipleOf: 0.001}
                }
              }
            }
          }
        }
      };
      schema.properties[SUBJECT_STR] = {
        type: "array",
        items: [item, item, item]
      };
      break;
    case 7:
      const item1 = {
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
                  lat: {type: 'number', minimum: -90, multipleOf: 0.001},
                  long: {type: 'number', minimum: -180, multipleOf: 0.001}
                }
              }
            }
          }
        }
      };
      schema.properties[SUBJECT_STR] = {
        type: "array",
        items: [item1, item1, item1]
      };
      
      schema.properties['issuer'] = {
        type: 'object',
        properties: {
          name: {type: "string"},
          desc: {type: "string"},
          logo: {type: "string"}
        }
      };
      schema.properties['issuanceDate'] = {$ref: "#/definitions/positiveInteger"};
      schema.properties['expirationDate'] = {$ref: "#/definitions/positiveInteger"};
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
              SSN: { $ref: '#/definitions/encryptableString' }
            }
          },
          timeOfBirth: { $ref: '#/definitions/positiveInteger' },
          physical: {
            type: 'object',
            properties: {
              height: { "allOf": [
                  { $ref: '#/definitions/positiveNumber' },
                  { multipleOf: 0.1 }
                ]
              },
              weight: { "allOf": [
                  { $ref: '#/definitions/positiveNumber' },
                  { multipleOf: 0.1 }
                ]
              },
              BMI: { "allOf": [
                  { $ref: '#/definitions/positiveNumber' },
                  { multipleOf: 0.01 }
                ]
              }
            }
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
          SSN: { $ref: '#/definitions/encryptableString' },
          userId: { $ref: '#/definitions/encryptableCompString' },
          country: { type: 'string' },
          city: { type: 'string' },
          timeOfBirth: { $ref: "#/definitions/positiveInteger" },
          height: { "allOf": [
              { $ref: '#/definitions/positiveNumber' },
              { multipleOf: 0.1 }
            ]
          },
          weight: { "allOf": [
              { $ref: '#/definitions/positiveNumber' },
              { multipleOf: 0.1 }
            ]
          },
          BMI: { "allOf": [
              { $ref: '#/definitions/positiveNumber' },
              { multipleOf: 0.01 }
            ]
          },
          score: { type: 'number', minimum: -100, multipleOf: 0.1 },
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
              SSN: { $ref: '#/definitions/encryptableString' }
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
                  rank: { $ref: '#/definitions/positiveInteger' },
                  CGPA: { "allOf": [
                      { $ref: '#/definitions/positiveNumber' },
                      { multipleOf: 0.01 }
                    ]
                  },
                  scores: {
                    type: 'object',
                    properties: {
                      english: { $ref: '#/definitions/positiveInteger' },
                      mathematics: { $ref: '#/definitions/positiveInteger' },
                      science: { $ref: '#/definitions/positiveInteger' },
                      history: { $ref: '#/definitions/positiveInteger' },
                      geography: { $ref: '#/definitions/positiveInteger' }
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
              SSN: { $ref: '#/definitions/encryptableString' },
              userId: { $ref: '#/definitions/encryptableCompString' }
            }
          },
          location: {
            type: 'object',
            properties: {
              country: { type: 'string' },
              city: { type: 'string' }
            }
          },
          timeOfBirth: { $ref: '#/definitions/positiveInteger' },
          physical: {
            type: 'object',
            properties: {
              height: { "allOf": [
                  { $ref: '#/definitions/positiveNumber' },
                  { multipleOf: 0.1 }
                ]
              },
              weight: { "allOf": [
                  { $ref: '#/definitions/positiveNumber' },
                  { multipleOf: 0.1 }
                ]
              },
              BMI: { "allOf": [
                  { $ref: '#/definitions/positiveNumber' },
                  { multipleOf: 0.01 }
                ]
              }
            }
          },
          score: { type: 'number', multipleOf: .1, minimum: -100 }
        }
      };
      break;
    default:
      throw Error(`Cannot find example schema number ${num}`)
  }
  return schema;
}
