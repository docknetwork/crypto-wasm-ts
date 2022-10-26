import {
  CRYPTO_VERSION_STR,
  ID_STR, REV_CHECK_STR, REV_ID_STR,
  SCHEMA_STR,
  STATUS_STR,
  SUBJECT_STR,
  CredentialSchema, IJsonSchema, VERSION_STR, TYPE_STR, STATUS_TYPE_STR, EMBEDDED_SCHEMA_URI_PREFIX, SCHEMA_TYPE_STR
} from '../../src/anonymous-credentials';

export function getExampleSchema(num): IJsonSchema {
  const schema = CredentialSchema.essential();
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
          long: {type: 'number', minimum: 0, multipleOf: 0.01}
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
      schema.properties[STATUS_STR] = CredentialSchema.statusAsJsonSchema();
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
          rank: { type: 'integer', minimum: 0 }
        }
      };
      schema.properties[STATUS_STR] = CredentialSchema.statusAsJsonSchema();
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
      schema.properties['issuanceDate'] = { type: 'integer', minimum: 0 };
      schema.properties['expirationDate'] = { type: 'integer', minimum: 0 };
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
          timeOfBirth: { type: 'integer', minimum: 0 },
          physical: {
            type: 'object',
            properties: {
              height: {type: 'number', minimum: 0, multipleOf: 0.1},
              weight: {type: 'number', minimum: 0, multipleOf: 0.1},
              BMI: {type: 'number', minimum: 0, multipleOf: 0.01}
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
          timeOfBirth: {type: 'integer', minimum: 0},
          height: {type: 'number', minimum: 0, multipleOf: 0.1},
          weight: {type: 'number', minimum: 0, multipleOf: 0.1},
          BMI: {type: 'number', minimum: 0, multipleOf: 0.01},
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
                  rank: {type: 'integer', minimum: 0},
                  CGPA: {type: 'number', minimum: 0, multipleOf: 0.01},
                  scores: {
                    type: 'object',
                    properties: {
                      english: {type: 'integer', minimum: 0},
                      mathematics: {type: 'integer', minimum: 0},
                      science: {type: 'integer', minimum: 0},
                      history: {type: 'integer', minimum: 0},
                      geography: {type: 'integer', minimum: 0}
                    }
                  }
                }
              }
            }
          }
        }
      };
      schema.properties[STATUS_STR] = CredentialSchema.statusAsJsonSchema();
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
          timeOfBirth: {type: 'integer', minimum: 0},
          physical: {
            type: 'object',
            properties: {
              height: {type: 'number', minimum: 0, multipleOf: 0.1},
              weight: {type: 'number', minimum: 0, multipleOf: 0.1},
              BMI: {type: 'number', minimum: 0, multipleOf: 0.01}
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

export function checkSchemaFromJson(schemaJson: string, schema: CredentialSchema) {
  let schm = JSON.parse(schemaJson);
  expect(CredentialSchema.extractJsonSchemaFromEmbedded(schm.id)).toEqual(schema.jsonSchema);
  expect(schm.parsingOptions).toEqual(schema.parsingOptions);
  expect(schm.version).toEqual(schema.version);
  expect(schm.type).toEqual(SCHEMA_TYPE_STR);
}
