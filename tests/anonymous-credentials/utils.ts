import semver from 'semver/preload';
import {
  Accumulator,
  AccumulatorPublicKey,
  AccumulatorSecretKey, AccumulatorVerificationParam,
  AttributeBoundPseudonym,
  AttributeCiphertexts, BBDT16Credential,
  CredentialSchema, CredentialVerificationParam, dockAccumulatorParams,
  dockSaverEncryptionGensUncompressed, EMPTY_SCHEMA_ID,
  IAccumulatorState,
  IEmbeddedJsonSchema,
  IJsonSchema, PositiveAccumulator,
  PredicateParamType,
  PseudonymBases, REV_ID_STR,
  SaverCiphertext,
  SaverDecryptor, SCHEMA_DETAILS_STR,
  SCHEMA_TYPE_STR,
  STATUS_STR,
  SUBJECT_STR
} from '../../src';
import { KBUniversalAccumulator } from '../../src/accumulator/kb-universal-accumulator';
import {
  Credential,
  CredentialBuilder,
  isKvac,
  KeyPair,
  Presentation,
  PublicKey,
  SecretKey,
  SignatureLabelBytes,
  SignatureParams
} from '../scheme';
import * as _ from 'lodash';
import { checkResult, stringToBytes } from '../utils';
import fs from 'fs';
import { BytearrayWrapper } from '../../src/bytearray-wrapper';
import { BBDT16MacParams, BBDT16MacSecretKey } from '../../src/bbdt16-mac';
import { InMemoryKBUniversalState, InMemoryState } from '../../src/accumulator/in-memory-persistence';

export function getExampleSchema(num): IEmbeddedJsonSchema {
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
          long: { type: 'number', minimum: 0, multipleOf: 0.01 }
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
                }
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
                          lat: { type: 'number', minimum: -90, multipleOf: 0.001 },
                          long: { type: 'number', minimum: -180, multipleOf: 0.001 }
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
                  lat: { type: 'number', minimum: -90, multipleOf: 0.001 },
                  long: { type: 'number', minimum: -180, multipleOf: 0.001 }
                }
              }
            }
          }
        }
      };
      schema.properties[SUBJECT_STR] = {
        type: 'array',
        items: [item, item, item]
      };
      break;
    case 7:
      const item1 = {
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
                  lat: { type: 'number', minimum: -90, multipleOf: 0.001 },
                  long: { type: 'number', minimum: -180, multipleOf: 0.001 }
                }
              }
            }
          }
        }
      };
      schema.properties[SUBJECT_STR] = {
        type: 'array',
        items: [item1, item1, item1]
      };

      schema.properties['issuer'] = {
        type: 'object',
        properties: {
          name: { type: 'string' },
          desc: { type: 'string' },
          logo: { type: 'string' }
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
              height: { type: 'number', minimum: 0, multipleOf: 0.1 },
              weight: { type: 'number', minimum: 0, multipleOf: 0.1 },
              BMI: { type: 'number', minimum: 0, multipleOf: 0.01 }
            }
          }
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
          timeOfBirth: { type: 'integer', minimum: 0 },
          height: { type: 'number', minimum: 0, multipleOf: 0.1 },
          weight: { type: 'number', minimum: 0, multipleOf: 0.1 },
          BMI: { type: 'number', minimum: 0, multipleOf: 0.01 },
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
                  rank: { type: 'integer', minimum: 0 },
                  CGPA: { type: 'number', minimum: 0, multipleOf: 0.01 },
                  scores: {
                    type: 'object',
                    properties: {
                      english: { type: 'integer', minimum: 0 },
                      mathematics: { type: 'integer', minimum: 0 },
                      science: { type: 'integer', minimum: 0 },
                      history: { type: 'integer', minimum: 0 },
                      geography: { type: 'integer', minimum: 0 }
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
          isbool: { type: 'boolean' },
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
          timeOfBirth: { type: 'integer', minimum: 0 },
          physical: {
            type: 'object',
            properties: {
              height: { type: 'number', minimum: 0, multipleOf: 0.1 },
              weight: { type: 'number', minimum: 0, multipleOf: 0.1 },
              BMI: { type: 'number', minimum: 0, multipleOf: 0.01 }
            }
          },
          score: { type: 'number', multipleOf: 0.1, minimum: -100 }
        }
      };
      break;
    case 12:
      schema.properties[SUBJECT_STR] = {
        type: 'object',
        properties: {
          fname: { type: 'string' },
          lname: { type: 'string' },
          education: {
            type: 'object',
            properties: {
              score1: { type: 'integer', minimum: 0 },
              score2: { type: 'integer', minimum: 0 },
              score3: { type: 'integer', minimum: 0 },
              grade: { type: 'string' }
            }
          }
        }
      };
      break;
    case 13:
      schema.properties[SUBJECT_STR] = {
        type: 'object',
        properties: {
          fname: { type: 'string' },
          lname: { type: 'string' },
          timeOfBirth: { type: 'integer', minimum: 0 },
          sensitive: {
            type: 'object',
            properties: {
              email: { type: 'string' },
              userId: { $ref: '#/definitions/encryptableCompString' }
            }
          },
        }
      };
      schema.properties[STATUS_STR] = CredentialSchema.statusAsJsonSchema();
      schema.properties['validFrom'] = { type: 'integer', minimum: 0 };
      schema.properties['validUntil'] = { type: 'integer', minimum: 0 };
      break;
    default:
      throw Error(`Cannot find example schema number ${num}`);
  }
  return schema;
}

export function getExampleBuilder(num: number, nonEmbeddedSchemas?: IJsonSchema[]): CredentialBuilder {
  let credSchema: CredentialSchema, credSchema1: CredentialSchema, credSchema2: CredentialSchema, credSchema3: CredentialSchema;

  const schema = CredentialSchema.essential();
  schema.properties[SUBJECT_STR] = {
    type: 'object',
    properties: {
      fname: { type: 'string' },
      lname: { type: 'string' }
    }
  };

  const schema1 = CredentialSchema.essential();
  schema1.properties[SUBJECT_STR] = {
    type: 'object',
    properties: {
      fname: { type: 'string' },
      lname: { type: 'string' },
      someNumber: { type: 'number', minimum: 0.01, multipleOf: 0.01 },
      someInteger: { type: 'integer', minimum: -100}
    }
  };

  const schema2 = {
    $schema: 'http://json-schema.org/draft-07/schema#',
    $id: 'https://ld.dock.io/examples/resident-card-schema.json',
    title: 'Resident Card Example',
    type: 'object',
    properties: {
      credentialSubject: {
        type: 'object',
        properties: {
          givenName: {
            title: 'Given Name',
            type: 'string'
          },
          familyName: {
            title: 'Family Name',
            type: 'string'
          },
          lprNumber: {
            title: 'LPR Number',
            type: 'integer',
            minimum: 0
          }
        },
        required: []
      }
    }
  };

  const schema3 = CredentialSchema.essential();
  schema.properties[SUBJECT_STR] = {
    type: 'object',
    properties: {
      fname: { type: 'string' },
      isbool: { type: 'boolean' }
    }
  };

  if (nonEmbeddedSchemas === undefined) {
    credSchema = new CredentialSchema(schema, { useDefaults: true });
    credSchema1 = new CredentialSchema(schema1, { useDefaults: true });
    credSchema2 = new CredentialSchema(schema2, { useDefaults: true });
    credSchema3 = new CredentialSchema(schema3, { useDefaults: true });
  } else {
    credSchema = new CredentialSchema(nonEmbeddedSchemas[0], { useDefaults: true }, true, undefined, schema);
    credSchema1 = new CredentialSchema(nonEmbeddedSchemas[1], { useDefaults: true }, true, undefined, schema1);
    credSchema2 = new CredentialSchema(nonEmbeddedSchemas[2], { useDefaults: true }, true, undefined, schema2);
    credSchema3 = new CredentialSchema(nonEmbeddedSchemas[3], { useDefaults: true }, true, undefined, schema3);
  }

  const builder = new CredentialBuilder();
  switch (num) {
    case 1:
      builder.schema = credSchema;
      builder.subject = {
        fname: 'John',
        lname: 'Smith',
        city: 'NY',
        education: { university: 'Example', major: 'Nothing' }
      };
      break;
    case 2:
      builder.schema = credSchema;
      builder.subject = {
        fname: 'John',
        lname: 'Smith',
        city: 'NY',
        education: { university: 'Example', major: 'Nothing' },
        someArr: ['exampleItem', 'exampleItem2', 4, 'exampleItem3']
      };
      break;
    case 3:
      builder.schema = credSchema;
      builder.subject = {
        fname: 'John',
        lname: 'Smith',
        city: 'NY',
        education: { university: 'Example', major: 'Nothing', location: { name: 'xyz', lat: 2.12, long: 23.109 } }
      };
      break;
    case 4:
      builder.schema = credSchema1;
      builder.subject = {
        fname: 'John',
        lname: 'Smith',
        city: 'NY',
        education: { university: 'Example', major: 'Nothing', location: { name: 'xyz', lat: 2.12, long: 23.109 } }
      };
      break;
    case 5:
      builder.schema = credSchema1;
      builder.subject = {
        fname: 'John',
        lname: 'Smith',
        city: 'NY',
        education: { university: 'Example', major: 'Nothing', location: { name: 'xyz', lat: 2.12, long: 23.109 } }
      };
      builder.setTopLevelField('issuer', { name: 'Someone', location: { city: 'NYC', state: 'NY' } });
      builder.setTopLevelField('issuanceDate', '2000-03-28');
      builder.setTopLevelField('types', ['T1', 'T2']);
      break;
    case 6:
      builder.schema = credSchema1;
      builder.subject = {
        fname: 'John',
        lname: 'Smith',
        city: 'NY',
        universities: [
          { university: 'Example', major: 'Nothing', location: { name: 'xyz', lat: 2.12, long: 23.109 } },
          { university: 'Example1', major: 'Nothing again', location: { name: 'abc', lat: 50, long: -40.6 } }
        ]
      };
      break;
    case 7:
      builder.schema = credSchema1;
      builder.subject = {
        fname: 'John',
        lname: 'Smith',
        city: 'NY',
        universities: [
          { university: 'Example', major: 'Nothing', location: { name: 'xyz', lat: 2.12, long: 23.109 } },
          ['foo', 'bar', { foo: 'bar', bar: 'baz' }],
          'Something else'
        ]
      };
      break;
    case 8:
      builder.schema = credSchema1;
      builder.subject = {
        city: 'NY',
        education: { major: 'Nothing', location: { name: 'xyz', lat: 2.12, long: 23.109 } }
      };
      break;
    case 9:
      builder.schema = credSchema1;
      builder.subject = { education: { major: 'Nothing', location: { name: 'xyz', lat: 2.12, long: 23.109 } } };
      break;
    case 10:
      const unsignedCred = {
        '@context': [
          'https://www.w3.org/2018/credentials/v1',
          'https://w3id.org/citizenship/v1',
          'https://ld.dock.io/security/bbs/v1'
        ],
        id: 'https://issuer.oidp.uscis.gov/credentials/83627465',
        type: ['VerifiableCredential', 'PermanentResidentCard'],
        identifier: '83627465',
        name: 'Permanent Resident Card',
        description: 'Government of Example Permanent Resident Card.',
        credentialSubject: {
          id: 'did:example:b34ca6cd37bbf23',
          type: ['PermanentResident', 'Person'],
          givenName: 'JOHN',
          familyName: 'SMITH',
          lprNumber: 1234
        }
      };
      builder.schema = credSchema2;
      builder.subject = unsignedCred.credentialSubject;
      for (const k of ['@context', 'id', 'type', 'identifier', 'name', 'description']) {
        builder.setTopLevelField(k, unsignedCred[k]);
      }
      break;
    case 11:
      builder.schema = credSchema3;
      builder.subject = { fname: 'John', isbool: true };
      break;
    case 12:
      builder.schema = credSchema1;
      builder.subject = {
        fname: 'John',
        lname: 'Smith',
        education: { university: 'Example' },
        someNumber: 2,  // Deliberately specifying the number without the dot (.)
        someInteger: 5,
      };
      break;
    default:
      throw new Error(`Cannot find builder number ${num}`);
  }
  return builder;
}

export function checkSchemaFromJson(schemaJson: string, schema: CredentialSchema) {
  let schm = semver.gte(schema.version, '0.4.0') ? schemaJson : JSON.parse(schemaJson);
  if (semver.gte(schema.version, '0.4.0')) {
    const details = JSON.parse(schm[SCHEMA_DETAILS_STR]);
    expect(details.jsonSchema).toEqual(schema.jsonSchema);
    if (schema.jsonSchema['$id'] !== undefined) {
      expect(schm.id).toEqual(schema.jsonSchema['$id']);
    } else {
      expect(schm.id).toEqual(EMPTY_SCHEMA_ID);
    }
  } else {
    expect(CredentialSchema.convertFromDataUri(schm.id)).toEqual(schema.jsonSchema);
    expect(schm.parsingOptions).toEqual(schema.parsingOptions);
  }
  expect(schm.version).toEqual(schema.version);
  expect(schm.type).toEqual(SCHEMA_TYPE_STR);
}

// Prefill the given accumulator with `totalMembers` members. The members are creates in a certain way for these tests
export async function prefillAccumulator<T>(
  accumulator: Accumulator<T>,
  secretKey: AccumulatorSecretKey,
  state: IAccumulatorState,
  credSchema: CredentialSchema,
  memberValPrefix: string,
  memberNameInSchema: string,
  totalMembers: number
) {
  const members: Uint8Array[] = [];
  for (let i = 1; i <= totalMembers; i++) {
    // For this test, user id is of this form
    const userId = `${memberValPrefix}${i}`;
    members.push(credSchema.encoder.encodeMessage(memberNameInSchema, userId));
  }
  // Adding a single batch as `totalMembers` is fairly small (100s) in this test but in practice choose a reasonable
  // batch size to not take up complete system's memory
  await accumulator.addBatch(members, secretKey, state);
  return members;
}

/**
 * Check if the ciphertexts of the given attribute included in the presentation can be decrypted correctly. Returns the number of ciphertexts checked
 * @param credential
 * @param ciphertexts
 * @param attrName
 * @param saverSk
 * @param saverDk
 * @param saverVerifyingKey
 * @param chunkBitSize
 */
export function checkCiphertext(
  credential: Credential | { schema: CredentialSchema; subject: object | object[] },
  ciphertexts: AttributeCiphertexts,
  attrName: string,
  saverSk,
  saverDk,
  saverVerifyingKey,
  chunkBitSize
): number {
  // Decryptor gets the ciphertext from the verifier and decrypts it
  // @ts-ignore
  let cts = _.get(ciphertexts, `${SUBJECT_STR}.${attrName}`) as (SaverCiphertext | SaverCiphertext[]);
  if (!Array.isArray(cts)) {
    cts = [cts];
  }
  cts.forEach((ciphertext) => {
    let decrypted = SaverDecryptor.decryptCiphertext(ciphertext, saverSk, saverDk, saverVerifyingKey, chunkBitSize);
    expect(decrypted.message).toEqual(
      credential.schema?.encoder.encodeMessageConstantTime(`${SUBJECT_STR}.${attrName}`, _.get(credential.subject, attrName))
    );

    // Decryptor shares the decryption result with verifier which the verifier can check for correctness.
    expect(
      ciphertext.verifyDecryption(
        decrypted,
        saverDk,
        saverVerifyingKey,
        dockSaverEncryptionGensUncompressed(),
        chunkBitSize
      ).verified
    ).toEqual(true);
  });
  return cts.length
}

export function getDecodedBoundedPseudonym(
  credentials:
    | Credential[]
    | {
        schema: CredentialSchema;
        subject: object | object[];
      }[],
  attributesNames: string[],
  basesForAttributes: Uint8Array[],
  baseForSecretKey?: Uint8Array,
  secretKey?: Uint8Array
): [string, string[], string | undefined] {
  expect(attributesNames.length).toEqual(credentials.length);
  expect(attributesNames.length).toEqual(basesForAttributes.length);
  const basesForAttributesDecoded = PseudonymBases.decodeBasesForAttributes(basesForAttributes);
  const baseForSecretKeyDecoded =
    baseForSecretKey !== undefined ? PseudonymBases.decodeBaseForSecretKey(baseForSecretKey) : undefined;
  const attributes: Uint8Array[] = [];
  for (let i = 0; i < attributesNames.length; i++) {
    attributes.push(
      credentials[i].schema.encoder.encodeMessageConstantTime(
        `${SUBJECT_STR}.${attributesNames[i]}`,
        _.get(credentials[i].subject, attributesNames[i])
      )
    );
  }
  const expectedBoundedPseudonym = AttributeBoundPseudonym.new(
    basesForAttributes,
    attributes,
    baseForSecretKey,
    secretKey
  );
  const decodedBoundedPseudonym = PseudonymBases.decode(expectedBoundedPseudonym.value);
  return [decodedBoundedPseudonym, basesForAttributesDecoded, baseForSecretKeyDecoded];
}

/**
 * Converts the given presentation to JSON and then creates a new presentation by parsing that JSON and checks that the
 * new presentation can be verified and the JSON representation of old and new presentation is same. Returns the new
 * presentation
 * @param pres - Presentation to be converted to JSON
 * @param pks
 * @param accumulatorPublicKeys
 * @param predicateParams
 * @param circomOutputs
 * @param circomOutputsMultiCred
 * @returns The new presentation created from deserializing the serialized presentation
 */
export function checkPresentationJson(
  pres: Presentation,
  pks: Map<number, CredentialVerificationParam> | CredentialVerificationParam[],
  accumulatorPublicKeys?: Map<number, AccumulatorVerificationParam>,
  predicateParams?: Map<string, PredicateParamType>,
  circomOutputs?: Map<number, Uint8Array[][]>,
  // TODO: Rename
  circomOutputsMultiCred?: Uint8Array[][]
): Presentation {
  const presJson = pres.toJSON();
  const recreatedPres = Presentation.fromJSON(presJson);
  checkResult(recreatedPres.verify(pks, accumulatorPublicKeys, predicateParams, circomOutputs, undefined, circomOutputsMultiCred));
  expect(presJson).toEqual(recreatedPres.toJSON());
  return recreatedPres;
}

/**
 * Function used to write serialized params, keys, schemas, credentials and presentations which are later used for testing
 * backward compatibility. This is usually called in tests when new versions of these objects are created
 * @param obj
 * @param fileName
 */
export function writeSerializedObject(obj: any, fileName: string) {
  let objBytes;
  if (obj instanceof BytearrayWrapper) {
    objBytes = obj.value;
  } else if (typeof obj.toBytes === 'function') {
    objBytes = obj.toBytes();
  } else if (typeof obj.toJSON === 'function') {
    objBytes = Buffer.from(JSON.stringify(obj.toJSON()), 'utf8');
  } else {
    throw new Error(`Invalid object provided: ${obj}`);
  }

  fs.writeFileSync(`${__dirname}/serialized-objects/${fileName}`, new Uint8Array(objBytes));

  return obj;
}

export function assertSerializedObject(obj: any, fileName: string) {
  const { constructor } = obj;
  const path = `${__dirname}/serialized-objects/${fileName}`;

  if (constructor instanceof (BytearrayWrapper.prototype as any)) {
    const bytes = new Uint8Array(fs.readFileSync(path));

    expect([...bytes]).toEqual([...obj.value]);
  } else {
    const str = fs.readFileSync(path, 'utf8');
    const json = JSON.parse(str);

    expect(constructor.fromJSON(json)).toEqual(obj);
  }

  return obj;
}

export function checkEmbeddedSchema(withSchemaRef: boolean, schema: CredentialSchema, fullJsonSchema: IEmbeddedJsonSchema, nonEmbeddedSchema?: IJsonSchema) {
  if (withSchemaRef) {
    expect(schema.fullJsonSchema).toEqual(fullJsonSchema);
    if (nonEmbeddedSchema !== undefined) {
      expect(schema.jsonSchema).toEqual(nonEmbeddedSchema);
    }
  } else {
    expect(schema.jsonSchema).toEqual(fullJsonSchema);
    expect(schema.fullJsonSchema).not.toBeDefined();
  }
}

export function getKeys(seed?: string): [SecretKey, PublicKey] {
  const params = SignatureParams.generate(100, SignatureLabelBytes);
  const s = seed ? stringToBytes(seed) : undefined;
  const isKvac = params instanceof BBDT16MacParams;
  const keypair = !isKvac ? KeyPair.generate(params, s) : undefined;
  const sk = !isKvac ? keypair.sk : BBDT16MacSecretKey.generate(s);
  const pk = !isKvac ? keypair.pk : undefined;
  return [sk, pk];
}

export function verifyCred(cred: Credential, pk: PublicKey, sk: SecretKey) {
  const isKvac = cred instanceof BBDT16Credential;
  checkResult(!isKvac ? cred.verify(pk) : cred.verifyUsingSecretKey(sk));
}

export async function setupPrefilledAccum(totalMembers: number, memberIdx: number, memberValPrefix: string, schema: CredentialSchema, seed?: Uint8Array) {
  const kp = PositiveAccumulator.generateKeypair(dockAccumulatorParams(), seed);
  const sk = kp.secretKey;
  const pk = kp.publicKey;
  const accumulator = PositiveAccumulator.initialize(dockAccumulatorParams());
  const state = new InMemoryState();
  const allMembers = await prefillAccumulator<Uint8Array>(
    accumulator,
    sk,
    state,
    schema,
    memberValPrefix,
    `${STATUS_STR}.${REV_ID_STR}`,
    totalMembers
  );
  const witness = await accumulator.membershipWitness(
    allMembers[memberIdx],
    kp.secretKey,
    state
  );
  const verifAccumulator = PositiveAccumulator.fromAccumulated(accumulator.accumulated);
  expect(
    verifAccumulator.verifyMembershipWitness(
      allMembers[memberIdx],
      witness,
      pk,
      dockAccumulatorParams()
    )
  ).toEqual(true);
  return [sk, pk, accumulator, witness]
}

export async function setupKBUniAccumulator(
  totalMembers: number, memberValPrefix: string, schema: CredentialSchema, seed?: Uint8Array
) {
  const kp = KBUniversalAccumulator.generateKeypair(dockAccumulatorParams(), seed);
  const sk = kp.secretKey;
  const pk = kp.publicKey;
  const state = new InMemoryKBUniversalState();
  const domain: Uint8Array[] = [];
  for (let i = 1; i <= totalMembers; i++) {
    const userId = `${memberValPrefix}${i}`;
    domain.push(schema.encoder.encodeMessage(`${STATUS_STR}.${REV_ID_STR}`, userId));
  }
  const accumulator = await KBUniversalAccumulator.initialize(domain, dockAccumulatorParams(), sk, state);
  return [sk, pk, accumulator, domain, state]
}
