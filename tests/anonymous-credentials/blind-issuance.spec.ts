import { generateFieldElementFromNumber, initializeWasm } from 'crypto-wasm-new';
import {
  AccumulatorPublicKey,
  AccumulatorSecretKey,
  BBSBlindedCredential,
  BBSBlindedCredentialRequestBuilder,
  BBSPlusBlindedCredential,
  BBSPlusBlindedCredentialRequestBuilder,
  BlindedCredential,
  BlindedCredentialRequestBuilder,
  CredentialSchema,
  dockAccumulatorParams,
  dockSaverEncryptionGens,
  getR1CS,
  LegoProvingKeyUncompressed,
  LegoVerifyingKeyUncompressed,
  MEM_CHECK_STR,
  VBMembershipWitness,
  PositiveAccumulator,
  PredicateParamType,
  PresentationBuilder,
  PseudonymBases,
  R1CSSnarkSetup,
  REV_ID_STR,
  SaverChunkedCommitmentKey,
  SaverDecryptionKeyUncompressed,
  SaverDecryptor,
  SaverEncryptionKeyUncompressed,
  SaverProvingKeyUncompressed,
  SaverSecretKey,
  SaverVerifyingKeyUncompressed,
  STATUS_STR,
  VB_ACCUMULATOR_22,
  SUBJECT_STR,
  TYPE_STR,
  BoundCheckProtocol,
  VerifiableEncryptionProtocol,
  BoundCheckBppParams,
  BoundCheckSmcParams,
  BoundCheckBppParamsUncompressed,
  BoundCheckSmcParamsUncompressed,
  BoundCheckSmcWithKVProverParamsUncompressed,
  BoundCheckSmcWithKVVerifierParamsUncompressed,
  BoundCheckSmcWithKVSetup,
  DefaultSchemaParsingOpts,
  META_SCHEMA_STR,
  InequalityProtocol,
  CredentialVerificationParam,
  BBDT16BlindedCredentialRequestBuilder,
  BBDT16BlindedCredential, BlindedCredentialBuilder,
  CredentialBuilder as CB
} from '../../src';
import {
  SignatureParams,
  SecretKey,
  PublicKey,
  Credential,
  Scheme,
  isBBS,
  isPS, isKvac, CredentialBuilder
} from '../scheme';

import {
  checkCiphertext,
  getDecodedBoundedPseudonym,
  getExampleSchema,
  getKeys,
  prefillAccumulator,
  verifyCred
} from './utils';
import {
  checkResult,
  getBoundCheckSnarkKeys,
  getWasmBytes,
  parseR1CSFile,
  readByteArrayFromFile,
  stringToBytes
} from '../utils';
import { flatten, unflatten } from 'flat';
import { InMemoryState } from '../../src/accumulator/in-memory-persistence';
import { BBDT16BlindedCredentialRequest, BBSBlindedCredentialRequest, BBSPlusBlindedCredentialRequest, BlindedCredentialRequest } from '../../src';

const loadSnarkSetupFromFiles = true;

function finalize(reqBuilder) {
  let req, blinding;
  if (isBBS()) {
    req = reqBuilder.finalize();
  } else {
    const temp = reqBuilder.finalize();
    req = temp[0];
    blinding = temp[1];
  }
  return [req, blinding];
}

function newReqBuilder(
  schema: CredentialSchema,
  subjectToBlind: object
): BlindedCredentialRequestBuilder<SignatureParams> {
  const reqBuilder = isKvac() ? new BBDT16BlindedCredentialRequestBuilder() : isBBS() ? new BBSBlindedCredentialRequestBuilder() : new BBSPlusBlindedCredentialRequestBuilder();
  reqBuilder.schema = schema;
  reqBuilder.subjectToBlind = subjectToBlind;
  return reqBuilder;
}

function checkBlindedAttributes(req, blindedSubject, hasBlindedStatus = false) {
  const expectedBlindedAttributes = {};
  for (const name of Object.keys(flatten({ [SUBJECT_STR]: blindedSubject }))) {
    expectedBlindedAttributes[name] = null;
  }
  if (hasBlindedStatus) {
    expectedBlindedAttributes[`${STATUS_STR}.${REV_ID_STR}`] = null;
  }
  expect(req.blindedAttributes).toEqual(unflatten(expectedBlindedAttributes));
}

function checkReqJson(
  req: BlindedCredentialRequest,
  pks: Map<number, CredentialVerificationParam> | CredentialVerificationParam[],
  accumulatorPublicKeys?: Map<number, AccumulatorPublicKey>,
  predicateParams?: Map<string, PredicateParamType>,
  circomOutputs?: Map<number, Uint8Array[][]>,
  blindedAttributesCircomOutputs?: Uint8Array[][]
) {
  const reqJson = req.toJSON();
  const recreatedReq = isKvac() ? BBDT16BlindedCredentialRequest.fromJSON(reqJson) : isBBS()
    ? BBSBlindedCredentialRequest.fromJSON(reqJson)
    : BBSPlusBlindedCredentialRequest.fromJSON(reqJson);
  checkResult(
    recreatedReq.verify(pks, accumulatorPublicKeys, predicateParams, circomOutputs, blindedAttributesCircomOutputs)
  );
  expect(recreatedReq.toJSON()).toEqual(reqJson);
}

function checkBlindedCredJson(blindedCred: BlindedCredential<any>, sk: SecretKey, pk: PublicKey, blindedSubject: object, blinding?: Uint8Array, blindedStatus?: object, blindedTopLevelFields?: Map<string, unknown>) {
  const credJson = blindedCred.toJSON();
  const recreatedCred = isKvac() ? BBDT16BlindedCredential.fromJSON(credJson) : isBBS() ? BBSBlindedCredential.fromJSON(credJson) : BBSPlusBlindedCredential.fromJSON(credJson);
  // @ts-ignore
  const cred = isBBS()
    ? // @ts-ignore
      recreatedCred.toCredential(blindedSubject, blindedStatus, blindedTopLevelFields)
    // @ts-ignore
    : recreatedCred.toCredential(blindedSubject, blinding, blindedStatus, blindedTopLevelFields);
  verifyCred(cred, pk, sk);
  expect(recreatedCred.toJSON()).toEqual(credJson);
}

// Skip the tests if PS signatures are used as blind sigs are not integrated yet
const skipIfPS = isPS() ? describe.skip : describe;

skipIfPS.each([true, false])(`${Scheme} Blind issuance of credentials with withSchemaRef=%s`, (withSchemaRef) => {
  let sk1: SecretKey, pk1: PublicKey;
  let sk2: SecretKey, pk2: PublicKey;
  let sk3: SecretKey, pk3: PublicKey;

  let schema1: CredentialSchema;
  let schema2: CredentialSchema;
  let schema3: CredentialSchema;

  let credential1: Credential;
  let credential2: Credential;
  let credential3: Credential;

  let accumulator1: PositiveAccumulator;
  let accumulator1Pk: AccumulatorPublicKey;
  let accumulator1Sk: AccumulatorSecretKey;
  let accumulator1Members: Uint8Array[];
  let accumulator1State: InMemoryState;
  let accumulator1Witness: VBMembershipWitness;

  let boundCheckProvingKey: LegoProvingKeyUncompressed;
  let boundCheckVerifyingKey: LegoVerifyingKeyUncompressed;

  const chunkBitSize = 16;
  let saverSk: SaverProvingKeyUncompressed;
  let saverProvingKey: SaverProvingKeyUncompressed;
  let saverVerifyingKey: SaverVerifyingKeyUncompressed;
  let saverEk: SaverEncryptionKeyUncompressed;
  let saverDk: SaverDecryptionKeyUncompressed;

  let boundCheckBppParams: BoundCheckBppParamsUncompressed;
  let boundCheckSmcParams: BoundCheckSmcParamsUncompressed;
  let boundCheckSmcKVProverParams: BoundCheckSmcWithKVProverParamsUncompressed;
  let boundCheckSmcKVVerifierParams: BoundCheckSmcWithKVVerifierParamsUncompressed;

  const nonEmbeddedSchema = {
    $id: 'https://example.com?hash=abc123ff',
    [META_SCHEMA_STR]: 'http://json-schema.org/draft-07/schema#',
    type: 'object'
  };

  function setupBoundCheck() {
    if (boundCheckProvingKey === undefined) {
      [boundCheckProvingKey, boundCheckVerifyingKey] = getBoundCheckSnarkKeys(loadSnarkSetupFromFiles);
    }
  }

  function setupSaver() {
    if (saverProvingKey === undefined) {
      if (loadSnarkSetupFromFiles) {
        saverSk = new SaverSecretKey(readByteArrayFromFile('snark-setups/saver-secret-key-16.bin'));
        saverProvingKey = new SaverProvingKeyUncompressed(
          readByteArrayFromFile('snark-setups/saver-proving-key-16-uncompressed.bin')
        );
        saverVerifyingKey = new SaverVerifyingKeyUncompressed(
          readByteArrayFromFile('snark-setups/saver-verifying-key-16-uncompressed.bin')
        );
        saverEk = new SaverEncryptionKeyUncompressed(
          readByteArrayFromFile('snark-setups/saver-encryption-key-16-uncompressed.bin')
        );
        saverDk = new SaverDecryptionKeyUncompressed(
          readByteArrayFromFile('snark-setups/saver-decryption-key-16-uncompressed.bin')
        );
      } else {
        const encGens = dockSaverEncryptionGens();
        const [saverSnarkPk, saverSec, encryptionKey, decryptionKey] = SaverDecryptor.setup(encGens, chunkBitSize);
        saverSk = saverSec;
        saverProvingKey = saverSnarkPk.decompress();
        saverVerifyingKey = saverSnarkPk.getVerifyingKeyUncompressed();
        saverEk = encryptionKey.decompress();
        saverDk = decryptionKey.decompress();
      }
    }
  }

  function setupBoundCheckBpp() {
    if (boundCheckBppParams === undefined) {
      const p = new BoundCheckBppParams(stringToBytes('Bulletproofs++ testing'));
      boundCheckBppParams = p.decompress();
    }
  }

  function setupBoundCheckSmc() {
    if (boundCheckSmcParams === undefined) {
      const p = new BoundCheckSmcParams(stringToBytes('set-membership check based range proof testing'));
      boundCheckSmcParams = p.decompress();
    }
  }

  function setupBoundCheckSmcWithKV() {
    if (boundCheckSmcKVProverParams === undefined) {
      const p = BoundCheckSmcWithKVSetup(
        stringToBytes('set-membership check based range proof with keyed verification testing')
      );
      boundCheckSmcKVProverParams = p[0];
      boundCheckSmcKVVerifierParams = p[1];
    }
  }

  beforeAll(async () => {
    await initializeWasm();
    [sk1, pk1] = getKeys('seed1');

    if (withSchemaRef) {
      schema1 = new CredentialSchema(
        nonEmbeddedSchema,
        DefaultSchemaParsingOpts,
        true,
        undefined,
        getExampleSchema(10)
      );
    } else {
      schema1 = new CredentialSchema(getExampleSchema(10));
    }

    const accumKeypair1 = PositiveAccumulator.generateKeypair(
      dockAccumulatorParams(),
      stringToBytes('secret-seed-for-accum')
    );
    accumulator1Pk = accumKeypair1.publicKey;
    accumulator1Sk = accumKeypair1.secretKey;
    accumulator1 = PositiveAccumulator.initialize(dockAccumulatorParams());
    accumulator1State = new InMemoryState();
    accumulator1Members = await prefillAccumulator<Uint8Array>(
      accumulator1,
      accumKeypair1.secretKey,
      accumulator1State,
      schema1,
      'tran:2022-YZ4-',
      `${STATUS_STR}.${REV_ID_STR}`,
      300
    );

    [sk2, pk2] = getKeys('seed2');

    if (withSchemaRef) {
      schema2 = new CredentialSchema(nonEmbeddedSchema, DefaultSchemaParsingOpts, true, undefined, getExampleSchema(9));
    } else {
      schema2 = new CredentialSchema(getExampleSchema(9));
    }

    [sk3, pk3] = getKeys();

    if (withSchemaRef) {
      schema3 = new CredentialSchema(nonEmbeddedSchema, DefaultSchemaParsingOpts, true, undefined, getExampleSchema(7));
    } else {
      schema3 = new CredentialSchema(getExampleSchema(7));
    }
  });

  it('BlindedCredentialBuilder version should be same as CredentialBuilder version', () => {
    expect(BlindedCredentialBuilder.VERSION).toEqual(CB.VERSION)
  })

  it('should be able to request a credential when some attributes are blinded', async () => {
    const blindedSubject = {
      sensitive: {
        email: 'john.smith@example.com',
        SSN: '123-456789-0'
      },
      education: {
        studentId: 's-22-123450',
        university: {
          registrationNumber: 'XYZ-123-789'
        }
      }
    };
    const reqBuilder = newReqBuilder(schema1, blindedSubject);

    const inEqualEmail = 'alice@example.com';
    const inEqualEmail2 = 'bob@example.com';
    const inEqualSsn = '1234';
    reqBuilder.enforceInequalityOnBlindedAttribute('credentialSubject.sensitive.email', inEqualEmail);
    reqBuilder.enforceInequalityOnBlindedAttribute('credentialSubject.sensitive.email', inEqualEmail2);
    reqBuilder.enforceInequalityOnBlindedAttribute('credentialSubject.sensitive.SSN', inEqualSsn);

    const [req, blinding] = finalize(reqBuilder);

    expect(req.presentation.spec.blindCredentialRequest.attributeInequalities).toEqual({
      credentialSubject: {
        sensitive: {
          email: [
            { inEqualTo: inEqualEmail, protocol: InequalityProtocol.Uprove },
            { inEqualTo: inEqualEmail2, protocol: InequalityProtocol.Uprove }
          ],
          SSN: [{ inEqualTo: inEqualSsn, protocol: InequalityProtocol.Uprove }]
        }
      }
    });

    checkResult(req.verify([]));

    checkReqJson(req, []);

    checkBlindedAttributes(req, blindedSubject);

    const blindedCredBuilder = req.generateBlindedCredentialBuilder();
    blindedCredBuilder.subject = {
      fname: 'John',
      lname: 'Smith',
      education: {
        university: {
          name: 'Example University'
        },
        transcript: {
          rank: 100,
          CGPA: 2.57,
          scores: {
            english: 60,
            mathematics: 70,
            science: 50,
            history: 45,
            geography: 40
          }
        }
      }
    };
    blindedCredBuilder.setCredentialStatus('dock:accumulator:accumId124', MEM_CHECK_STR, 'tran:2022-YZ4-250');
    const blindedCred = blindedCredBuilder.sign(sk1);
    accumulator1Witness = await accumulator1.membershipWitness(
      accumulator1Members[249],
      accumulator1Sk,
      accumulator1State
    );

    credential1 = isBBS()
      ? blindedCred.toCredential(blindedSubject)
      : blindedCred.toCredential(blindedSubject, blinding);
    verifyCred(credential1, pk1, sk1);
    const verifAccumulator = PositiveAccumulator.fromAccumulated(accumulator1.accumulated);
    expect(
      verifAccumulator.verifyMembershipWitness(
        accumulator1Members[249],
        accumulator1Witness,
        accumulator1Pk,
        dockAccumulatorParams()
      )
    ).toEqual(true);

    checkBlindedCredJson(blindedCred, sk1, pk1, blindedSubject, blinding);
  });

  it('should be able to request a blinded-credential with the same revocation id and accumulator as in another credential', async () => {
    // The goal here is that the blinded credential will be considered revoked when the presented credential is revoked. eg, user has a credential `C1` and
    // he wants to get another credential `C2` in such a way that when `C1` is  revoked, `C2` will be considered revoked as well but the issuer
    // of `C2` will not learn the revocation id of `C1`. Thus `C2` is chained to `C1`
    const blindedSubject = {
      sensitive: {
        email: 'alice@example.com',
        SSN: '456-789012-1'
      },
      education: {
        studentId: 's-23-456789',
        university: {
          registrationNumber: 'XYZ-456-123'
        }
      }
    };
    const revId = 'tran:2022-YZ4-250';
    const reqBuilder = newReqBuilder(schema1, blindedSubject);
    reqBuilder.statusToBlind('dock:accumulator:accumId124', MEM_CHECK_STR, revId);

    expect(reqBuilder.addCredentialToPresentation(credential1, isPS() ? pk1 : undefined)).toEqual(0);

    // Prove that revocation id in the requested blinded credential is same as in the presented credential. This is
    // needed to convince that the blinded credential's revocation status will stay the same as the presented credential's.
    reqBuilder.enforceEqualityOnBlindedAttribute([`${STATUS_STR}.${REV_ID_STR}`, [[0, `${STATUS_STR}.${REV_ID_STR}`]]]);

    reqBuilder.addAccumInfoForCredStatus(0, accumulator1Witness, accumulator1.accumulated, accumulator1Pk, {
      blockNo: 2010334
    });
    const [req, blinding] = finalize(reqBuilder);

    const acc = new Map();
    acc.set(0, accumulator1Pk);
    checkResult(req.verify([pk1], acc));

    checkReqJson(req, [pk1], acc);

    checkBlindedAttributes(req, blindedSubject, true);

    const blindedCredBuilder = req.generateBlindedCredentialBuilder();
    blindedCredBuilder.subject = {
      fname: 'John',
      lname: 'Smith',
      education: {
        university: {
          name: 'Example University'
        },
        transcript: {
          rank: 100,
          CGPA: 2.57,
          scores: {
            english: 60,
            mathematics: 70,
            science: 50,
            history: 45,
            geography: 40
          }
        }
      }
    };

    const blindedCred = blindedCredBuilder.sign(sk1);
    const credential = isBBS()
      ? blindedCred.toCredential(blindedSubject, {[REV_ID_STR]: revId})
      : blindedCred.toCredential(blindedSubject, blinding, {[REV_ID_STR]: revId});
    verifyCred(credential, pk1, sk1);
    expect(credential.credentialStatus).toEqual(credential1.credentialStatus);

    checkBlindedCredJson(blindedCred, sk1, pk1, blindedSubject, blinding, {[REV_ID_STR]: revId});

    // Using a different rev id fails
    const wrongRevId = 'tran:2022-YZ4-150';
    expect(revId).not.toEqual(wrongRevId);
    const credentialInvalid = isBBS()
      ? blindedCred.toCredential(blindedSubject, {[REV_ID_STR]: wrongRevId})
      : blindedCred.toCredential(blindedSubject, blinding, {[REV_ID_STR]: wrongRevId});
    if (isKvac()) {
      expect(credentialInvalid.verifyUsingSecretKey(sk1).verified).toEqual(false);
    } else {
      expect(credentialInvalid.verify(pk1).verified).toEqual(false);
    }
  });

  it('should be able to request a blinded-credential with the same top level attributes as in another credential', async () => {
    // The goal here is that the blinded credential should have the same top level attributes as the credential presented during its issuance.
    // In this test, the blinded credential's attributes "validFrom" and "validUntil" are the same as in the credential being presented during issuance
    let schema;
    if (withSchemaRef) {
      schema = new CredentialSchema(
        nonEmbeddedSchema,
        DefaultSchemaParsingOpts,
        true,
        undefined,
        getExampleSchema(13)
      );
    } else {
      schema = new CredentialSchema(getExampleSchema(13));
    }

    const revId = 'tran:2022-YZ4-250';

    let credBuilder = new CredentialBuilder();
    credBuilder.schema = schema;
    credBuilder.subject = {
      fname: 'John',
      lname: 'Smith',
      timeOfBirth: 1662010849619,
      sensitive: {
        email: 'john.smith@example.com',
        userId: 'user:123-xyz-#',
      },
    };
    credBuilder.setTopLevelField('validFrom', 1662010840000);
    credBuilder.setTopLevelField('validUntil', 1662010849999);
    credBuilder.setCredentialStatus('dock:accumulator:accumId124', MEM_CHECK_STR, revId);
    const credential4 = credBuilder.sign(sk1);
    verifyCred(credential4, pk1, sk1);

    const blindedSubject = {
      sensitive: {
        email: 'alice@example.com',
        userId: '456-789012-1'
      },
    };
    const reqBuilder = newReqBuilder(schema, blindedSubject);
    reqBuilder.statusToBlind('dock:accumulator:accumId124', MEM_CHECK_STR, revId);
    reqBuilder.topLevelAttributesToBlind('validFrom', 1662010840000);
    reqBuilder.topLevelAttributesToBlind('validUntil', 1662010849999);

    expect(reqBuilder.addCredentialToPresentation(credential4, isPS() ? pk1 : undefined)).toEqual(0);
    // Prove that revocation id in the requested blinded credential is same as in the presented credential
    reqBuilder.enforceEqualityOnBlindedAttribute([`${STATUS_STR}.${REV_ID_STR}`, [[0, `${STATUS_STR}.${REV_ID_STR}`]]]);

    // Prove that attributes "validFrom" and "validUntil" in the requested blinded credential are the same as in the presented credential
    reqBuilder.enforceEqualityOnBlindedAttribute(['validFrom', [[0, 'validFrom']]]);
    reqBuilder.enforceEqualityOnBlindedAttribute(['validUntil', [[0, 'validUntil']]]);

    reqBuilder.addAccumInfoForCredStatus(0, accumulator1Witness, accumulator1.accumulated, accumulator1Pk, {
      blockNo: 2010334
    });
    const [req, blinding] = finalize(reqBuilder);

    const acc = new Map();
    acc.set(0, accumulator1Pk);
    checkResult(req.verify([pk1], acc));

    checkReqJson(req, [pk1], acc);

    const blindedCredBuilder = req.generateBlindedCredentialBuilder();
    blindedCredBuilder.subject = {
      fname: 'Alice',
      lname: 'Smith',
      timeOfBirth: 1662010849619,
    };

    const blindedCred = blindedCredBuilder.sign(sk1);
    const blindedTopLevelFields = new Map<string, unknown>();
    blindedTopLevelFields.set('validFrom', 1662010840000);
    blindedTopLevelFields.set('validUntil', 1662010849999);
    const credential5 = isBBS()
      ? blindedCred.toCredential(blindedSubject, {[REV_ID_STR]: revId}, blindedTopLevelFields)
      : blindedCred.toCredential(blindedSubject, blinding, {[REV_ID_STR]: revId}, blindedTopLevelFields);
    verifyCred(credential5, pk1, sk1);

    checkBlindedCredJson(blindedCred, sk1, pk1, blindedSubject, blinding, {[REV_ID_STR]: revId}, blindedTopLevelFields);

    // Using a different top level fields fails
    const wrongTopLevelFields = new Map<string, unknown>();
    wrongTopLevelFields.set('validFrom', 1662010840001);
    wrongTopLevelFields.set('validUntil', 1662010849990);
    const credentialInvalid = isBBS()
      ? blindedCred.toCredential(blindedSubject, {[REV_ID_STR]: revId}, wrongTopLevelFields)
      : blindedCred.toCredential(blindedSubject, blinding, {[REV_ID_STR]: revId}, wrongTopLevelFields);
    if (isKvac()) {
      expect(credentialInvalid.verifyUsingSecretKey(sk1).verified).toEqual(false);
    } else {
      expect(credentialInvalid.verify(pk1).verified).toEqual(false);
    }
  })

  it('should be able to request a blinded-credential while presenting another credential and proving some attributes equal', () => {
    const blindedSubject = {
      email: 'john.smith@example.com',
      SSN: '123-456789-0',
      userId: 'user:123-xyz-#',
      secret: 'my-secret-that-wont-tell-anyone'
    };
    const reqBuilder = newReqBuilder(schema2, blindedSubject);
    expect(reqBuilder.addCredentialToPresentation(credential1, isPS() ? pk1 : undefined)).toEqual(0);
    reqBuilder.markCredentialAttributesRevealed(
      0,
      new Set<string>([
        'credentialSubject.education.university.name',
        'credentialSubject.education.university.registrationNumber'
      ])
    );
    reqBuilder.enforceEqualityOnBlindedAttribute(['credentialSubject.SSN', [[0, 'credentialSubject.sensitive.SSN']]]);
    reqBuilder.enforceEqualityOnBlindedAttribute(['credentialSubject.email', [[0, 'credentialSubject.sensitive.email']]]);
    reqBuilder.addAccumInfoForCredStatus(0, accumulator1Witness, accumulator1.accumulated, accumulator1Pk, {
      blockNo: 2010334
    });

    const [req, blinding] = finalize(reqBuilder);
    expect(req.presentation.spec.credentials[0].revealedAttributes).toEqual({
      credentialSubject: {
        education: { university: { name: 'Example University', registrationNumber: 'XYZ-123-789' } }
      }
    });
    expect(req.presentation.spec.getStatus(0)).toEqual({
      id: 'dock:accumulator:accumId124',
      [TYPE_STR]: VB_ACCUMULATOR_22,
      revocationCheck: 'membership',
      accumulated: accumulator1.accumulated,
      extra: { blockNo: 2010334 }
    });

    const acc = new Map();
    acc.set(0, accumulator1Pk);
    checkResult(req.verify([pk1], acc));

    checkReqJson(req, [pk1], acc);

    checkBlindedAttributes(req, blindedSubject);

    const blindedCredBuilder = req.generateBlindedCredentialBuilder();
    blindedCredBuilder.subject = {
      fname: 'John',
      lname: 'Smith',
      country: 'USA',
      city: 'New York',
      timeOfBirth: 1662010849619,
      height: 181.5,
      weight: 210.4,
      BMI: 23.25,
      score: -13.5
    };
    const blindedCred = blindedCredBuilder.sign(sk2);

    credential2 = isBBS()
      ? blindedCred.toCredential(blindedSubject)
      : blindedCred.toCredential(blindedSubject, blinding);
    verifyCred(credential2, pk2, sk2);

    checkBlindedCredJson(blindedCred, sk2, pk2, blindedSubject, blinding);
  });

  it('should be able to request a blinded-credential while presenting 2 credentials and proving some attributes equal and predicates on some credential attributes', () => {
    setupBoundCheck();
    setupBoundCheckBpp();
    setupBoundCheckSmc();
    setupBoundCheckSmcWithKV();
    setupSaver();

    const boundCheckSnarkId = 'random';
    const commKeyId1 = 'random-1';
    const commKeyId2 = 'random-10';
    const ekId1 = 'random-2';
    const ekId2 = 'random-20';
    const snarkPkId1 = 'random-3';
    const snarkPkId2 = 'random-30';
    const boundCheckBppId = 'random-4';
    const boundCheckSmcId = 'random-5';
    const boundCheckSmcKVId = 'random-6';

    const ck1 = SaverChunkedCommitmentKey.generate(stringToBytes('a new nonce'));
    const commKey1 = ck1.decompress();
    const ck2 = SaverChunkedCommitmentKey.generate(stringToBytes('a new nonce - 1'));
    const commKey2 = ck2.decompress();

    const blindedSubject = [
      {
        name: 'John',
        location: {
          geo: {
            lat: -23.658,
            long: 2.556
          }
        }
      },
      {
        name: 'Smith',
        location: {
          geo: {
            lat: 35.01,
            long: -40.987
          }
        }
      },
      {
        name: 'Random-2',
        location: {
          geo: {
            lat: -67.0,
            long: -10.12
          }
        }
      }
    ];

    const reqBuilder = newReqBuilder(schema3, blindedSubject);
    expect(reqBuilder.addCredentialToPresentation(credential1, isPS() ? pk1 : undefined)).toEqual(0);
    expect(reqBuilder.addCredentialToPresentation(credential2, isPS() ? pk2 : undefined)).toEqual(1);

    reqBuilder.markCredentialAttributesRevealed(
      0,
      new Set<string>([
        'credentialSubject.education.university.name',
        'credentialSubject.education.university.registrationNumber'
      ])
    );
    reqBuilder.markCredentialAttributesRevealed(1, new Set<string>(['credentialSubject.country']));

    reqBuilder.enforceCredentialAttributesEqual([0, 'credentialSubject.fname'], [1, 'credentialSubject.fname']);
    reqBuilder.enforceCredentialAttributesEqual([0, 'credentialSubject.lname'], [1, 'credentialSubject.lname']);

    reqBuilder.enforceEqualityOnBlindedAttribute(['credentialSubject.0.name', [[0, 'credentialSubject.fname']]]);
    reqBuilder.enforceEqualityOnBlindedAttribute(['credentialSubject.1.name', [[1, 'credentialSubject.lname']]]);

    reqBuilder.addAccumInfoForCredStatus(0, accumulator1Witness, accumulator1.accumulated, accumulator1Pk, {
      blockNo: 2010334
    });

    const [minCGPA, maxCGPA] = [2.5, 3.5];
    // @ts-ignore
    expect(minCGPA).toBeLessThan(credential1.subject.education.transcript.CGPA);
    // @ts-ignore
    expect(maxCGPA).toBeGreaterThan(credential1.subject.education.transcript.CGPA);
    reqBuilder.enforceBoundsOnCredentialAttribute(
      0,
      'credentialSubject.education.transcript.CGPA',
      minCGPA,
      maxCGPA,
      boundCheckSnarkId,
      boundCheckProvingKey
    );

    const [minRank, maxRank] = [50, 200];
    // @ts-ignore
    expect(minRank).toBeLessThan(credential1.subject.education.transcript.rank);
    // @ts-ignore
    expect(maxRank).toBeGreaterThan(credential1.subject.education.transcript.rank);
    reqBuilder.enforceBoundsOnCredentialAttribute(
      0,
      'credentialSubject.education.transcript.rank',
      minRank,
      maxRank,
      boundCheckBppId,
      boundCheckBppParams
    );

    const [minHist, maxHist] = [20, 60];
    // @ts-ignore
    expect(minHist).toBeLessThan(credential1.subject.education.transcript.scores.history);
    // @ts-ignore
    expect(maxHist).toBeGreaterThan(credential1.subject.education.transcript.scores.history);
    reqBuilder.enforceBoundsOnCredentialAttribute(
      0,
      'credentialSubject.education.transcript.scores.history',
      minHist,
      maxHist
    );

    const [minEng, maxEng] = [20, 100];
    // @ts-ignore
    expect(minEng).toBeLessThan(credential1.subject.education.transcript.scores.english);
    // @ts-ignore
    expect(maxEng).toBeGreaterThan(credential1.subject.education.transcript.scores.english);
    reqBuilder.enforceBoundsOnCredentialAttribute(
      0,
      'credentialSubject.education.transcript.scores.english',
      minEng,
      maxEng,
      boundCheckSmcId,
      boundCheckSmcParams
    );

    const [minSc, maxSc] = [30, 100];
    // @ts-ignore
    expect(minSc).toBeLessThan(credential1.subject.education.transcript.scores.science);
    // @ts-ignore
    expect(maxSc).toBeGreaterThan(credential1.subject.education.transcript.scores.science);
    reqBuilder.enforceBoundsOnCredentialAttribute(
      0,
      'credentialSubject.education.transcript.scores.science',
      minSc,
      maxSc,
      boundCheckSmcKVId,
      boundCheckSmcKVProverParams
    );

    reqBuilder.verifiablyEncryptCredentialAttribute(
      0,
      'credentialSubject.sensitive.SSN',
      chunkBitSize,
      commKeyId1,
      ekId1,
      snarkPkId1,
      commKey1,
      saverEk,
      saverProvingKey
    );
    reqBuilder.verifiablyEncryptCredentialAttribute(
      1,
      'credentialSubject.SSN',
      chunkBitSize,
      commKeyId1,
      ekId1,
      snarkPkId1
    );
    // The same snark setup is repeated here but this is only for testing. In practice, different snark setup will be used
    // as the encryption if being done for different parties.
    reqBuilder.verifiablyEncryptCredentialAttribute(
      1,
      'credentialSubject.SSN',
      chunkBitSize,
      commKeyId2,
      ekId2,
      snarkPkId2,
      commKey2,
      saverEk,
      saverProvingKey
    );

    const [req, blinding] = finalize(reqBuilder);

    expect(req.presentation.spec.credentials[0].bounds).toEqual({
      credentialSubject: {
        education: {
          transcript: {
            CGPA: [{ min: 2.5, max: 3.5, paramId: boundCheckSnarkId, protocol: BoundCheckProtocol.Legogroth16 }],
            rank: [{ min: 50, max: 200, paramId: boundCheckBppId, protocol: BoundCheckProtocol.Bpp }],
            scores: {
              english: [{ min: 20, max: 100, paramId: boundCheckSmcId, protocol: BoundCheckProtocol.Smc }],
              science: [{ min: 30, max: 100, paramId: boundCheckSmcKVId, protocol: BoundCheckProtocol.SmcKV }],
              history: [{ min: 20, max: 60, paramId: undefined, protocol: BoundCheckProtocol.Bpp }]
            }
          }
        }
      }
    });
    expect(req.presentation.spec.credentials[0].verifiableEncryptions).toEqual({
      credentialSubject: {
        sensitive: {
          SSN: [
            {
              chunkBitSize,
              commitmentGensId: commKeyId1,
              encryptionKeyId: ekId1,
              snarkKeyId: snarkPkId1,
              protocol: VerifiableEncryptionProtocol.Saver
            }
          ]
        }
      }
    });
    expect(req.presentation.spec.credentials[1].verifiableEncryptions).toEqual({
      credentialSubject: {
        SSN: [
          {
            chunkBitSize,
            commitmentGensId: commKeyId1,
            encryptionKeyId: ekId1,
            snarkKeyId: snarkPkId1,
            protocol: VerifiableEncryptionProtocol.Saver
          },
          {
            chunkBitSize,
            commitmentGensId: commKeyId2,
            encryptionKeyId: ekId2,
            snarkKeyId: snarkPkId2,
            protocol: VerifiableEncryptionProtocol.Saver
          }
        ]
      }
    });
    expect(req.presentation.attributeCiphertexts.size).toEqual(2);
    expect(req.presentation.attributeCiphertexts.get(0)).toBeDefined();
    expect(req.presentation.attributeCiphertexts.get(1)).toBeDefined();

    const acc = new Map();
    acc.set(0, accumulator1Pk);
    const pp = new Map();
    pp.set(boundCheckSnarkId, boundCheckVerifyingKey);
    pp.set(commKeyId1, commKey1);
    pp.set(commKeyId2, commKey2);
    pp.set(ekId1, saverEk);
    pp.set(ekId2, saverEk);
    pp.set(snarkPkId1, saverVerifyingKey);
    pp.set(snarkPkId2, saverVerifyingKey);
    pp.set(boundCheckBppId, boundCheckBppParams);
    pp.set(boundCheckSmcId, boundCheckSmcParams);
    pp.set(boundCheckSmcKVId, boundCheckSmcKVVerifierParams);
    checkResult(req.verify([pk1, pk2], acc, pp));

    checkReqJson(req, [pk1, pk2], acc, pp);

    expect(
      checkCiphertext(
        credential1,
        req.presentation.attributeCiphertexts?.get(0),
        'sensitive.SSN',
        saverSk,
        saverDk,
        saverVerifyingKey,
        chunkBitSize
      )
    ).toEqual(1);

    expect(
      checkCiphertext(
        credential2,
        req.presentation.attributeCiphertexts?.get(1),
        'SSN',
        saverSk,
        saverDk,
        saverVerifyingKey,
        chunkBitSize
      )
    ).toEqual(2);

    checkBlindedAttributes(req, blindedSubject);

    const blindedCredBuilder = req.generateBlindedCredentialBuilder();
    blindedCredBuilder.subject = [
      {
        location: {
          name: 'Somewhere'
        }
      },
      {
        location: {
          name: 'Somewhere-1'
        }
      },
      {
        location: {
          name: 'Somewhere-2'
        }
      }
    ];
    blindedCredBuilder.setTopLevelField('issuer', {
      name: 'An issuer',
      desc: 'Just an issuer',
      logo: 'https://images.example-issuer.com/logo.png'
    });
    blindedCredBuilder.setTopLevelField('issuanceDate', 1662010849700);
    blindedCredBuilder.setTopLevelField('expirationDate', 1662011950934);
    const blindedCred = blindedCredBuilder.sign(sk3);

    credential3 = isBBS()
      ? blindedCred.toCredential(blindedSubject)
      : blindedCred.toCredential(blindedSubject, blinding);
    verifyCred(credential3, pk3, sk3);

    checkBlindedCredJson(blindedCred, sk3, pk3, blindedSubject, blinding);
  });

  it('should be able to request a blinded-credential and prove bounds on and verifiably encrypt some of the blinded attributes', () => {
    setupBoundCheck();
    setupSaver();

    const boundCheckSnarkId = 'random';
    const commKeyId = 'random-1';
    const ekId = 'random-2';
    const snarkPkId = 'random-3';

    const ck = SaverChunkedCommitmentKey.generate(stringToBytes('a new nonce'));
    const commKey = ck.decompress();

    let schema;
    if (withSchemaRef) {
      schema = new CredentialSchema(nonEmbeddedSchema, DefaultSchemaParsingOpts, true, undefined, getExampleSchema(8));
    } else {
      schema = new CredentialSchema(getExampleSchema(8));
    }
    const blindedSubject = {
      sensitive: {
        phone: '810-1234567',
        email: 'john.smith@example.com',
        SSN: '123-456789-0'
      },
      timeOfBirth: 1662010849619
    };

    const reqBuilder = newReqBuilder(schema, blindedSubject);
    expect(reqBuilder.addCredentialToPresentation(credential1, pk1)).toEqual(0);
    reqBuilder.markCredentialAttributesRevealed(0, new Set<string>(['credentialSubject.education.university.name']));

    reqBuilder.enforceEqualityOnBlindedAttribute([
      'credentialSubject.sensitive.email',
      [[0, 'credentialSubject.sensitive.email']]
    ]);

    reqBuilder.addAccumInfoForCredStatus(0, accumulator1Witness, accumulator1.accumulated, accumulator1Pk, {
      blockNo: 2010334
    });

    reqBuilder.verifiablyEncryptCredentialAttribute(
      0,
      'credentialSubject.sensitive.SSN',
      chunkBitSize,
      commKeyId,
      ekId,
      snarkPkId,
      commKey,
      saverEk,
      saverProvingKey
    );

    reqBuilder.enforceBoundsOnBlindedAttribute(
      'credentialSubject.timeOfBirth',
      1662010849610,
      1662010849620,
      boundCheckSnarkId,
      boundCheckProvingKey
    );
    reqBuilder.verifiablyEncryptBlindedAttribute(
      'credentialSubject.sensitive.SSN',
      chunkBitSize,
      commKeyId,
      ekId,
      snarkPkId
    );

    const [req, blinding] = finalize(reqBuilder);

    expect(req.presentation.spec.blindCredentialRequest.bounds).toEqual({
      credentialSubject: {
        timeOfBirth: [
          {
            min: 1662010849610,
            max: 1662010849620,
            paramId: boundCheckSnarkId,
            protocol: BoundCheckProtocol.Legogroth16
          }
        ]
      }
    });
    expect(req.presentation.spec.credentials[0].verifiableEncryptions).toEqual({
      credentialSubject: {
        sensitive: {
          SSN: [
            {
              chunkBitSize,
              commitmentGensId: commKeyId,
              encryptionKeyId: ekId,
              snarkKeyId: snarkPkId,
              protocol: VerifiableEncryptionProtocol.Saver
            }
          ]
        }
      }
    });
    expect(req.presentation.attributeCiphertexts).toBeDefined();
    expect(req.presentation.spec.blindCredentialRequest.verifiableEncryptions).toEqual({
      credentialSubject: {
        sensitive: {
          SSN: [
            {
              chunkBitSize,
              commitmentGensId: commKeyId,
              encryptionKeyId: ekId,
              snarkKeyId: snarkPkId,
              protocol: VerifiableEncryptionProtocol.Saver
            }
          ]
        }
      }
    });
    expect(req.presentation.blindedAttributeCiphertexts).toBeDefined();

    const acc = new Map();
    acc.set(0, accumulator1Pk);
    const pp = new Map();
    pp.set(boundCheckSnarkId, boundCheckVerifyingKey);
    pp.set(commKeyId, commKey);
    pp.set(ekId, saverEk);
    pp.set(snarkPkId, saverVerifyingKey);
    checkResult(req.verify([pk1], acc, pp));

    checkReqJson(req, [pk1], acc, pp);

    expect(
      checkCiphertext(
        credential1,
        req.presentation.attributeCiphertexts?.get(0),
        'sensitive.SSN',
        saverSk,
        saverDk,
        saverVerifyingKey,
        chunkBitSize
      )
    ).toEqual(1);

    expect(
      checkCiphertext(
        { schema, subject: blindedSubject },
        req.presentation.blindedAttributeCiphertexts,
        'sensitive.SSN',
        saverSk,
        saverDk,
        saverVerifyingKey,
        chunkBitSize
      )
    ).toEqual(1);

    checkBlindedAttributes(req, blindedSubject);

    const blindedCredBuilder = req.generateBlindedCredentialBuilder();
    blindedCredBuilder.subject = {
      fname: 'John',
      lname: 'Smith',
      physical: {
        height: 181.5,
        weight: 210,
        BMI: 23.25
      }
    };
    const blindedCred = blindedCredBuilder.sign(sk3);

    const credential = isBBS()
      ? blindedCred.toCredential(blindedSubject)
      : blindedCred.toCredential(blindedSubject, blinding);
    verifyCred(credential, pk3, sk3);

    checkBlindedCredJson(blindedCred, sk3, pk3, blindedSubject, blinding);
  });

  it('should be able to request a blinded-credential and prove Circom predicates on some of the blinded attributes', async () => {
    const pkIdGrade = 'random1';
    const circuitIdGrade = 'random2';
    const pkIdLtPub = 'random3';
    const circuitIdLtPub = 'random4';

    const r1csGrade = await parseR1CSFile('set_membership_5_public.r1cs');
    const wasmGrade = getWasmBytes('set_membership_5_public.wasm');
    let prk = R1CSSnarkSetup.fromParsedR1CSFile(r1csGrade, 1);
    const provingKeyGrade = prk.decompress();
    const verifyingKeyGrade = prk.getVerifyingKeyUncompressed();

    const r1csLtPub = await parseR1CSFile('less_than_public_64.r1cs');
    const wasmLtPub = getWasmBytes('less_than_public_64.wasm');
    prk = R1CSSnarkSetup.fromParsedR1CSFile(r1csLtPub, 1);
    const provingKeyLtPub = prk.decompress();
    const verifyingKeyLtPub = prk.getVerifyingKeyUncompressed();

    let schema;
    if (withSchemaRef) {
      schema = new CredentialSchema(nonEmbeddedSchema, DefaultSchemaParsingOpts, true, undefined, getExampleSchema(12));
    } else {
      schema = new CredentialSchema(getExampleSchema(12));
    }

    const blindedSubject = {
      education: {
        score1: 55,
        score2: 60,
        grade: 'B+'
      }
    };
    const reqBuilder = newReqBuilder(schema, blindedSubject);

    // Test that the `grade` attribute in credential belongs to the set `requiredGrades` and both `score1` and `score2` are >= 50
    const requiredGrades = ['A+', 'A', 'B+', 'B', 'C'];
    const score = 50;
    const encodedScore = generateFieldElementFromNumber(score);
    const encodedGrades = requiredGrades.map((g: string) =>
      schema.encoder.encodeMessage('credentialSubject.education.grade', g)
    );

    reqBuilder.enforceCircomPredicateOnBlindedAttribute(
      [['x', 'credentialSubject.education.grade']],
      [['set', encodedGrades]],
      circuitIdGrade,
      pkIdGrade,
      r1csGrade,
      wasmGrade,
      provingKeyGrade
    );
    reqBuilder.enforceCircomPredicateOnBlindedAttribute(
      [['a', 'credentialSubject.education.score1']],
      [['b', encodedScore]],
      circuitIdLtPub,
      pkIdLtPub,
      r1csLtPub,
      wasmLtPub,
      provingKeyLtPub
    );
    reqBuilder.enforceCircomPredicateOnBlindedAttribute(
      [['a', 'credentialSubject.education.score2']],
      [['b', encodedScore]],
      circuitIdLtPub,
      pkIdLtPub
    );

    const [req, blinding] = finalize(reqBuilder);

    const pp = new Map();
    pp.set(pkIdGrade, verifyingKeyGrade);
    pp.set(PresentationBuilder.r1csParamId(circuitIdGrade), getR1CS(r1csGrade));
    pp.set(PresentationBuilder.wasmParamId(circuitIdGrade), wasmGrade);
    pp.set(pkIdLtPub, verifyingKeyLtPub);
    pp.set(PresentationBuilder.r1csParamId(circuitIdLtPub), getR1CS(r1csLtPub));
    pp.set(PresentationBuilder.wasmParamId(circuitIdLtPub), wasmLtPub);

    // Setting last 2 outputs to 0 as the circuit will output 1 when the private input (`score` attribute) is less than the public input (50 here) else 0.
    // Here the prover is proving that the private input is greater than or equal to 50
    const circomOutputs = [
      [generateFieldElementFromNumber(1)],
      [generateFieldElementFromNumber(0)],
      [generateFieldElementFromNumber(0)]
    ];

    expect(requiredGrades.indexOf(blindedSubject.education.grade)).toBeGreaterThan(-1);
    expect(blindedSubject.education.score1).toBeGreaterThan(score);
    expect(blindedSubject.education.score2).toBeGreaterThan(score);

    checkResult(req.verify([], undefined, pp, undefined, circomOutputs));

    checkReqJson(req, [], undefined, pp, undefined, circomOutputs);

    expect(req.presentation.spec.blindCredentialRequest.circomPredicates?.length).toEqual(3);
    expect(req.presentation.spec.blindCredentialRequest.circomPredicates[0].privateVars.length).toEqual(1);
    expect(req.presentation.spec.blindCredentialRequest.circomPredicates[0].privateVars[0]).toEqual({
      varName: 'x',
      attributeName: { credentialSubject: { education: { grade: null } } }
    });
    expect(req.presentation.spec.blindCredentialRequest.circomPredicates[0].publicVars.length).toEqual(1);
    expect(req.presentation.spec.blindCredentialRequest.circomPredicates[0].publicVars[0].varName).toEqual('set');
    expect(req.presentation.spec.blindCredentialRequest.circomPredicates[0].publicVars[0].value).toEqual(encodedGrades);

    expect(req.presentation.spec.blindCredentialRequest.circomPredicates[1].privateVars.length).toEqual(1);
    expect(req.presentation.spec.blindCredentialRequest.circomPredicates[1].privateVars[0]).toEqual({
      varName: 'a',
      attributeName: { credentialSubject: { education: { score1: null } } }
    });
    expect(req.presentation.spec.blindCredentialRequest.circomPredicates[1].publicVars.length).toEqual(1);
    expect(req.presentation.spec.blindCredentialRequest.circomPredicates[1].publicVars[0].varName).toEqual('b');
    expect(req.presentation.spec.blindCredentialRequest.circomPredicates[1].publicVars[0].value).toEqual(encodedScore);

    expect(req.presentation.spec.blindCredentialRequest.circomPredicates[2].privateVars.length).toEqual(1);
    expect(req.presentation.spec.blindCredentialRequest.circomPredicates[2].privateVars[0]).toEqual({
      varName: 'a',
      attributeName: { credentialSubject: { education: { score2: null } } }
    });
    expect(req.presentation.spec.blindCredentialRequest.circomPredicates[2].publicVars.length).toEqual(1);
    expect(req.presentation.spec.blindCredentialRequest.circomPredicates[2].publicVars[0].varName).toEqual('b');
    expect(req.presentation.spec.blindCredentialRequest.circomPredicates[2].publicVars[0].value).toEqual(encodedScore);

    const blindedCredBuilder = req.generateBlindedCredentialBuilder();
    blindedCredBuilder.subject = {
      fname: 'John',
      lname: 'Smith',
      education: {
        score3: 30
      }
    };
    const blindedCred = blindedCredBuilder.sign(sk3);

    const credential = isBBS()
      ? blindedCred.toCredential(blindedSubject)
      : blindedCred.toCredential(blindedSubject, blinding);
    verifyCred(credential, pk3, sk3);
  });

  it('should be able to present pseudonyms bounded to credential and blinded attributes', () => {
    const scope1 = stringToBytes('test scope 1');
    const scope2 = stringToBytes('test scope 2');
    const scope3 = stringToBytes('test scope 3');
    const scope4 = stringToBytes('test scope 4');

    // Pseudonym 1 used is bound to 1 credential attribute
    const basesForPs1 = PseudonymBases.generateBasesForAttributes(1, scope1);
    const attributeNames1 = new Map();
    attributeNames1.set(0, ['credentialSubject.sensitive.SSN']);

    // Pseudonym 2 used is bound to 2 credential attributes
    const basesForPs2 = PseudonymBases.generateBasesForAttributes(2, scope2);
    const attributeNames2 = new Map();
    attributeNames2.set(0, ['credentialSubject.sensitive.email']);
    attributeNames2.set(1, ['credentialSubject.userId']);

    // Pseudonym 3 used is bound to 2 credential attributes and 2 blinded attributes
    const basesForPs3 = PseudonymBases.generateBasesForAttributes(4, scope3);
    const attributeNames3 = new Map();
    attributeNames3.set(0, ['credentialSubject.sensitive.email']);
    attributeNames3.set(1, ['credentialSubject.userId']);
    const blindedAttributeNames1 = ['credentialSubject.0.name', 'credentialSubject.1.name'];

    // Pseudonym 4 used is bound to 1 blinded attribute
    const basesForPs4 = PseudonymBases.generateBasesForAttributes(1, scope4);
    const attributeNames4 = new Map();
    const blindedAttributeNames2 = ['credentialSubject.2.name'];

    const blindedSubject = [
      {
        name: 'John',
        location: {
          geo: {
            lat: -23.658,
            long: 2.556
          }
        }
      },
      {
        name: 'Smith',
        location: {
          geo: {
            lat: 35.01,
            long: -40.987
          }
        }
      },
      {
        name: 'Random-2',
        location: {
          geo: {
            lat: -67.0,
            long: -10.12
          }
        }
      }
    ];
    const reqBuilder = newReqBuilder(schema3, blindedSubject);

    expect(reqBuilder.addCredentialToPresentation(credential1, pk1)).toEqual(0);
    expect(reqBuilder.addCredentialToPresentation(credential2, pk2)).toEqual(1);
    reqBuilder.addAccumInfoForCredStatus(0, accumulator1Witness, accumulator1.accumulated, accumulator1Pk, {
      blockNo: 2010334
    });

    reqBuilder.addPseudonymToCredentialAttributes(basesForPs1, attributeNames1);
    reqBuilder.addPseudonymToCredentialAttributes(basesForPs2, attributeNames2);
    reqBuilder.addPseudonymToCredentialAndBlindedAttributes(basesForPs3, attributeNames3, blindedAttributeNames1);
    reqBuilder.addPseudonymToCredentialAndBlindedAttributes(basesForPs4, attributeNames4, blindedAttributeNames2);

    const [req, blinding] = finalize(reqBuilder);

    const acc = new Map();
    acc.set(0, accumulator1Pk);
    checkResult(req.verify([pk1, pk2], acc));

    checkReqJson(req, [pk1, pk2], acc);

    const [decodedBoundedPseudonym1, decodedBasesForPs1] = getDecodedBoundedPseudonym(
      [credential1],
      ['sensitive.SSN'],
      basesForPs1
    );
    const [decodedBoundedPseudonym2, decodedBasesForPs2] = getDecodedBoundedPseudonym(
      [credential1, credential2],
      ['sensitive.email', 'userId'],
      basesForPs2
    );
    const [decodedBoundedPseudonym3, decodedBasesForPs3] = getDecodedBoundedPseudonym(
      [
        credential1,
        credential2,
        { schema: schema3, subject: blindedSubject },
        { schema: schema3, subject: blindedSubject }
      ],
      ['sensitive.email', 'userId', '0.name', '1.name'],
      basesForPs3
    );
    const [decodedBoundedPseudonym4, decodedBasesForPs4] = getDecodedBoundedPseudonym(
      [{ schema: schema3, subject: blindedSubject }],
      ['2.name'],
      basesForPs4
    );

    expect(Object.keys(req.presentation.spec.boundedPseudonyms).length).toEqual(2);
    expect(req.presentation.spec.boundedPseudonyms[decodedBoundedPseudonym1]).toEqual({
      commitKey: {
        basesForAttributes: decodedBasesForPs1,
        baseForSecretKey: undefined
      },
      attributes: Object.fromEntries(attributeNames1)
    });
    expect(req.presentation.spec.boundedPseudonyms[decodedBoundedPseudonym2]).toEqual({
      commitKey: {
        basesForAttributes: decodedBasesForPs2,
        baseForSecretKey: undefined
      },
      attributes: Object.fromEntries(attributeNames2)
    });
    expect(req.presentation.spec.blindCredentialRequest.pseudonyms[decodedBoundedPseudonym3]).toEqual({
      commitKey: {
        basesForAttributes: decodedBasesForPs3,
        baseForSecretKey: undefined
      },
      credentialAttributes: Object.fromEntries(attributeNames3),
      blindedAttributes: blindedAttributeNames1
    });
    expect(req.presentation.spec.blindCredentialRequest.pseudonyms[decodedBoundedPseudonym4]).toEqual({
      commitKey: {
        basesForAttributes: decodedBasesForPs4,
        baseForSecretKey: undefined
      },
      credentialAttributes: Object.fromEntries(attributeNames4),
      blindedAttributes: blindedAttributeNames2
    });

    checkBlindedAttributes(req, blindedSubject);

    const blindedCredBuilder = req.generateBlindedCredentialBuilder();
    blindedCredBuilder.subject = [
      {
        location: {
          name: 'Somewhere'
        }
      },
      {
        location: {
          name: 'Somewhere-1'
        }
      },
      {
        location: {
          name: 'Somewhere-2'
        }
      }
    ];
    blindedCredBuilder.setTopLevelField('issuer', {
      name: 'An issuer',
      desc: 'Just an issuer',
      logo: 'https://images.example-issuer.com/logo.png'
    });
    blindedCredBuilder.setTopLevelField('issuanceDate', 1662010849700);
    blindedCredBuilder.setTopLevelField('expirationDate', 1662011950934);
    const blindedCred = blindedCredBuilder.sign(sk3);

    credential3 = isBBS()
      ? blindedCred.toCredential(blindedSubject)
      : blindedCred.toCredential(blindedSubject, blinding);
    verifyCred(credential3, pk3, sk3);

    checkBlindedCredJson(blindedCred, sk3, pk3, blindedSubject, blinding);
  });
});
