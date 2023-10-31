import {
  Credential,
  CredentialBuilder,
  KeyPair,
  PresentationBuilder,
  PublicKey,
  Scheme,
  SecretKey,
  SignatureLabelBytes,
  SignatureParams
} from '../scheme';
import {
  BoundCheckProtocol,
  CredentialSchema,
  dockSaverEncryptionGens,
  LegoProvingKeyUncompressed,
  LegoVerifyingKeyUncompressed,
  SaverChunkedCommitmentKey,
  SaverDecryptionKeyUncompressed,
  SaverDecryptor,
  SaverEncryptionKeyUncompressed,
  SaverProvingKeyUncompressed,
  SaverSecretKey,
  SaverVerifyingKeyUncompressed,
  SUBJECT_STR,
  VerifiableEncryptionProtocol
} from '../../src';
import { checkResult, getBoundCheckSnarkKeys, readByteArrayFromFile, stringToBytes } from '../utils';
import { initializeWasm } from '@docknetwork/crypto-wasm';
import { checkCiphertext, checkPresentationJson } from './utils';

// Setting it to false will make the test run the SNARK setups making tests quite slow
const loadSnarkSetupFromFiles = true;

describe(`${Scheme} Presentation creation and verification`, () => {
  let sk: SecretKey, pk: PublicKey;

  let credential: Credential;

  let boundCheckProvingKey: LegoProvingKeyUncompressed;
  let boundCheckVerifyingKey: LegoVerifyingKeyUncompressed;

  const chunkBitSize = 16;
  let saverSk: SaverProvingKeyUncompressed;
  let saverProvingKey: SaverProvingKeyUncompressed;
  let saverVerifyingKey: SaverVerifyingKeyUncompressed;
  let saverEk: SaverEncryptionKeyUncompressed;
  let saverDk: SaverDecryptionKeyUncompressed;

  function setupBoundCheckLego() {
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

  beforeAll(async () => {
    await initializeWasm();
    const params = SignatureParams.generate(100, SignatureLabelBytes);
    const keypair = KeyPair.generate(params, stringToBytes('seed1'));
    sk = keypair.sk;
    pk = keypair.pk;

    const schema = CredentialSchema.essential();
    const subjectItem = {
      type: 'object',
      properties: {
        name: { $ref: '#/definitions/encryptableString' },
        location: {
          type: 'object',
          properties: {
            name: { $ref: '#/definitions/encryptableString' },
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
      items: [subjectItem, subjectItem, subjectItem]
    };
    const builder = new CredentialBuilder();
    builder.schema = new CredentialSchema(schema);
    builder.subject = [
      {
        name: 'Random',
        location: {
          name: 'Somewhere',
          geo: {
            lat: -23.658,
            long: 2.556
          }
        }
      },
      {
        name: 'Random-1',
        location: {
          name: 'Somewhere-1',
          geo: {
            lat: 35.01,
            long: -40.987
          }
        }
      },
      {
        name: 'Random-2',
        location: {
          name: 'Somewhere-2',
          geo: {
            lat: -67.0,
            long: -10.12
          }
        }
      }
    ];
    credential = builder.sign(sk);
    checkResult(credential.verify(pk));
  });

  it('with proving multiple bounds on a single attribute', () => {
    setupBoundCheckLego();

    const boundCheckSnarkId1 = 'random';
    const boundCheckSnarkId2 = 'random-2';

    const builder = new PresentationBuilder();
    expect(builder.addCredential(credential, pk)).toEqual(0);

    const [minLat0, maxLat0] = [-30, 50];
    const [minLat1, maxLat1] = [-40, 38];
    // @ts-ignore
    expect(minLat0).toBeLessThan(credential.subject[1].location.geo.lat);
    // @ts-ignore
    expect(maxLat0).toBeGreaterThan(credential.subject[1].location.geo.lat);
    // @ts-ignore
    expect(minLat1).toBeLessThan(credential.subject[1].location.geo.lat);
    // @ts-ignore
    expect(maxLat1).toBeGreaterThan(credential.subject[1].location.geo.lat);
    builder.enforceBounds(
      0,
      'credentialSubject.1.location.geo.lat',
      minLat0,
      maxLat0
    );
    builder.enforceBounds(
      0,
      'credentialSubject.1.location.geo.lat',
      minLat1,
      maxLat1
    );

    const [minLong0, maxLong0] = [-50, 10];
    const [minLong1, maxLong1] = [-55, -10];
    const [minLong2, maxLong2] = [-60, -15];
    // @ts-ignore
    expect(minLong0).toBeLessThan(credential.subject[1].location.geo.long);
    // @ts-ignore
    expect(maxLong0).toBeGreaterThan(credential.subject[1].location.geo.long);
    // @ts-ignore
    expect(minLong1).toBeLessThan(credential.subject[1].location.geo.long);
    // @ts-ignore
    expect(maxLong1).toBeGreaterThan(credential.subject[1].location.geo.long);
    // @ts-ignore
    expect(minLong2).toBeLessThan(credential.subject[1].location.geo.long);
    // @ts-ignore
    expect(maxLong2).toBeGreaterThan(credential.subject[1].location.geo.long);
    builder.enforceBounds(
      0,
      'credentialSubject.1.location.geo.long',
      minLong0,
      maxLong0,
      boundCheckSnarkId1,
      boundCheckProvingKey
    );
    // The same proving key is repeated here but this is only for testing. In practice, different proving key can be used.
    builder.enforceBounds(
      0,
      'credentialSubject.1.location.geo.long',
      minLong1,
      maxLong1,
      boundCheckSnarkId2,
      boundCheckProvingKey
    );
    builder.enforceBounds(
      0,
      'credentialSubject.1.location.geo.long',
      minLong2,
      maxLong2
    );

    const pres = builder.finalize();

    expect(pres.spec.credentials[0].bounds).toEqual({
      credentialSubject: [
        // Since there is no bound check predicate for the first item of this array attribute
        undefined,
        {
          location: {
            geo: {
              lat: [
                {
                  min: minLat0,
                  max: maxLat0,
                  protocol: BoundCheckProtocol.Bpp
                },
                {
                  min: minLat1,
                  max: maxLat1,
                  protocol: BoundCheckProtocol.Bpp
                }
              ],
              long: [
                {
                  min: minLong0,
                  max: maxLong0,
                  paramId: boundCheckSnarkId1,
                  protocol: BoundCheckProtocol.Legogroth16
                },
                {
                  min: minLong1,
                  max: maxLong1,
                  paramId: boundCheckSnarkId2,
                  protocol: BoundCheckProtocol.Legogroth16
                },
                {
                  min: minLong2,
                  max: maxLong2,
                  protocol: BoundCheckProtocol.Bpp
                }
              ]
            }
          }
        }
      ]
    });

    const pp = new Map();
    pp.set(boundCheckSnarkId1, boundCheckVerifyingKey);
    pp.set(boundCheckSnarkId2, boundCheckVerifyingKey);
    checkResult(pres.verify([pk], undefined, pp));

    checkPresentationJson(pres, [pk], undefined, pp);
  });

  it('with proving multiple encryptions on a single attribute', () => {
    setupSaver();

    const ck1 = SaverChunkedCommitmentKey.generate(stringToBytes('nonce 1'));
    const ck2 = SaverChunkedCommitmentKey.generate(stringToBytes('nonce 2'));
    const commKey1 = ck1.decompress();
    const commKey2 = ck2.decompress();

    const commKeyId1 = 'random-1';
    const ekId1 = 'random-2';
    const snarkPkId1 = 'random-3';

    const commKeyId2 = 'random-4';
    const ekId2 = 'random-5';
    const snarkPkId2 = 'random-6';

    const builder = new PresentationBuilder();
    expect(builder.addCredential(credential, pk)).toEqual(0);

    builder.verifiablyEncrypt(
      0,
      'credentialSubject.1.name',
      chunkBitSize,
      commKeyId1,
      ekId1,
      snarkPkId1,
      commKey1,
      saverEk,
      saverProvingKey
    );

    // The same snark setup is repeated here but this is only for testing. In practice, different snark setup will be used
    // as the encryption if being done for different parties.
    builder.verifiablyEncrypt(
      0,
      'credentialSubject.1.name',
      chunkBitSize,
      commKeyId2,
      ekId2,
      snarkPkId2,
      commKey2,
      saverEk,
      saverProvingKey
    );

    const pres = builder.finalize();

    // Verifier checks that the correct encryption key and other parameters were used by the prover
    expect(pres.spec.credentials[0].verifiableEncryptions).toEqual({
      credentialSubject: [
        // Since there is no verifiable encryption predicate for the first item of this array attribute
        undefined,
        {
          name: [
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
      ]
    });

    const pp = new Map();
    pp.set(commKeyId1, commKey1);
    pp.set(ekId1, saverEk);
    pp.set(snarkPkId1, saverVerifyingKey);
    pp.set(commKeyId2, commKey2);
    pp.set(ekId2, saverEk);
    pp.set(snarkPkId2, saverVerifyingKey);
    checkResult(pres.verify([pk], undefined, pp));

    checkPresentationJson(pres, [pk], undefined, pp);
    expect(checkCiphertext(
      credential,
      // @ts-ignore
      pres.attributeCiphertexts?.get(0),
      '1.name',
      saverSk,
      saverDk,
      saverVerifyingKey,
      chunkBitSize
    )).toEqual(2);
  });
});
