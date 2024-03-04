import { VerifyResult } from 'crypto-wasm-new';
import {
  AccumulatorPublicKey,
  AccumulatorSecretKey, BDDT16Credential, BDDT16CredentialBuilder, CredentialSchema, ID_STR,
  initializeWasm, MEM_CHECK_KV_STR, MEM_CHECK_STR,
  PositiveAccumulator, PresentationBuilder, REV_CHECK_STR, RevocationStatusProtocol, SignatureType, TYPE_STR,
  VBMembershipWitness
} from '../../src';
import { BDDT16MacSecretKey } from '../../src/bddt16-mac';
import { Credential, CredentialBuilder, isKvac, PublicKey, Scheme, SecretKey } from '../scheme';
import { checkResult } from '../utils';
import { getExampleSchema, getKeys, setupPrefilledAccum, verifyCred } from './utils';

describe(`Delegated proof verification with BDDT16 MAC and ${Scheme} signatures`, () => {
  let sk: SecretKey, pk: PublicKey;
  let skKvac: BDDT16MacSecretKey;

  let credential1: Credential;
  let credential2: Credential;
  let credential3: Credential;
  let credential4: BDDT16Credential;
  let credential5: BDDT16Credential;

  let accumulator1: PositiveAccumulator;
  let accumulator1Pk: AccumulatorPublicKey;
  let accumulator1Witness: VBMembershipWitness;

  let accumulator2: PositiveAccumulator;
  let accumulator2Sk: AccumulatorSecretKey;
  let accumulator2Witness: VBMembershipWitness;

  beforeAll(async () => {
    await initializeWasm();

    [sk, pk] = getKeys('seed1');
    skKvac = BDDT16MacSecretKey.generate();

    const schema = new CredentialSchema(getExampleSchema(5));
    const subject = {
      fname: 'John',
      lname: 'Smith',
      sensitive: {
        very: {
          secret: 'my-secret-that-wont-tell-anyone'
        },
        email: 'john.smith@acme.com',
        phone: '801009801',
        SSN: '123-456789-0'
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

    const builder1 = new CredentialBuilder();
    builder1.schema = schema;
    builder1.subject = subject;
    builder1.setCredentialStatus('dock:accumulator:accumId123', MEM_CHECK_STR, 'user:A-123');
    credential1 = builder1.sign(sk);
    verifyCred(credential1, pk, sk);

    const builder2 = new CredentialBuilder();
    builder2.schema = schema;
    builder2.subject = subject;
    builder2.setCredentialStatus('dock:accumulator:accumId124', MEM_CHECK_KV_STR, 'user:A-124');
    credential2 = builder2.sign(sk);
    verifyCred(credential2, pk, sk);

    const builder3 = new CredentialBuilder();
    builder3.schema = new CredentialSchema(getExampleSchema(9));
    builder3.subject = {
      fname: 'John',
      lname: 'Smith',
      email: 'john.smith@example.com',
      SSN: '123-456789-0',
      userId: 'user:123-xyz-#',
      country: 'USA',
      city: 'New York',
      timeOfBirth: 1662010849619,
      height: 181.5,
      weight: 210.4,
      BMI: 23.25,
      score: -13.5,
      secret: 'my-secret-that-wont-tell-anyone'
    };
    credential3 = builder3.sign(sk);
    verifyCred(credential3, pk, sk);

    const builder4 = new BDDT16CredentialBuilder();
    builder4.schema = schema;
    builder4.subject = subject;
    builder4.setCredentialStatus('dock:accumulator:accumId123', MEM_CHECK_STR, 'user:A-123');
    // @ts-ignore
    credential4 = builder4.sign(skKvac);
    verifyCred(credential4, undefined, skKvac);

    const builder5 = new BDDT16CredentialBuilder();
    builder5.schema = schema;
    builder5.subject = subject;
    builder5.setCredentialStatus('dock:accumulator:accumId124', MEM_CHECK_KV_STR, 'user:A-124');
    // @ts-ignore
    credential5 = builder5.sign(skKvac);
    verifyCred(credential5, undefined, skKvac);

    // @ts-ignore
    [, accumulator1Pk, accumulator1, accumulator1Witness] = await setupPrefilledAccum(200, 122, 'user:A-', schema);

    // @ts-ignore
    [accumulator2Sk, , accumulator2, accumulator2Witness] = await setupPrefilledAccum(200, 123, 'user:A-', schema);
  });

  it('works', () => {
    const builder = new PresentationBuilder();

    expect(builder.addCredential(credential1, pk)).toEqual(0);
    expect(builder.addCredential(credential2, pk)).toEqual(1);
    expect(builder.addCredential(credential3, pk)).toEqual(2);
    expect(builder.addCredential(credential4)).toEqual(3);
    expect(builder.addCredential(credential5)).toEqual(4);
    builder.addAccumInfoForCredStatus(0, accumulator1Witness, accumulator1.accumulated, accumulator1Pk, {
      blockNo: 2010334
    });
    builder.addAccumInfoForCredStatus(1, accumulator2Witness, accumulator2.accumulated, undefined, {
      blockNo: 2010335
    });
    builder.addAccumInfoForCredStatus(3, accumulator1Witness, accumulator1.accumulated, accumulator1Pk, {
      blockNo: 2010336
    });
    builder.addAccumInfoForCredStatus(4, accumulator2Witness, accumulator2.accumulated, undefined, {
      blockNo: 2010337
    });

    const pres = builder.finalize();

    const pks = new Map();
    pks.set(0, pk);
    pks.set(1, pk);
    pks.set(2, pk);
    const accumPks = new Map();
    accumPks.set(0, accumulator1Pk);
    accumPks.set(3, accumulator1Pk);

    checkResult(pres.verify(pks, accumPks));

    pks.set(3, skKvac);
    pks.set(4, skKvac);
    accumPks.set(1, accumulator2Sk);
    accumPks.set(4, accumulator2Sk);
    checkResult(pres.verify(pks, accumPks));

    const delegatedProofs = pres.getDelegatedProofs();

    expect(delegatedProofs.size).toEqual(isKvac() ? 5 : 3);
    if (isKvac()) {
      for (let j = 0; j < 3; j++) {
        const delgCredProof = delegatedProofs.get(j);
        expect(delgCredProof?.credential).toMatchObject({
          sigType: SignatureType.Bddt16
        });
        checkResult(delgCredProof?.credential?.proof.verify(sk) as VerifyResult);
      }
    }

    const delgCredProof2 = delegatedProofs.get(1);
    if (!isKvac()) {
      expect(delgCredProof2?.credential).not.toBeDefined();
    }
    expect(delgCredProof2?.status).toMatchObject({
      [ID_STR]: 'dock:accumulator:accumId124',
      [TYPE_STR]: RevocationStatusProtocol.Vb22,
      [REV_CHECK_STR]: MEM_CHECK_KV_STR
    });
    checkResult(delgCredProof2?.status?.proof.verify(accumulator2Sk) as VerifyResult);

    const delgCredProof4 = delegatedProofs.get(3);
    expect(delgCredProof4?.credential).toMatchObject({
      sigType: SignatureType.Bddt16
    });
    checkResult(delgCredProof4?.credential?.proof.verify(skKvac) as VerifyResult);
    expect(delgCredProof4?.status).not.toBeDefined();

    const delgCredProof5 = delegatedProofs.get(4);
    expect(delgCredProof5?.credential).toMatchObject({
      sigType: SignatureType.Bddt16
    });
    checkResult(delgCredProof5?.credential?.proof.verify(skKvac) as VerifyResult);
    expect(delgCredProof5?.status).toMatchObject({
      [ID_STR]: 'dock:accumulator:accumId124',
      [TYPE_STR]: RevocationStatusProtocol.Vb22,
      [REV_CHECK_STR]: MEM_CHECK_KV_STR
    });
    checkResult(delgCredProof5?.status?.proof.verify(accumulator2Sk) as VerifyResult);
  })
})