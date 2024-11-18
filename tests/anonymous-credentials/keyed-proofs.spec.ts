import { VerifyResult } from 'crypto-wasm-new';
import {
  AccumulatorPublicKey,
  AccumulatorSecretKey,
  BBDT16Credential,
  BBDT16CredentialBuilder,
  BBDT16MacSecretKey,
  CredentialSchema,
  KeyedProof,
  ID_STR,
  initializeWasm,
  MEM_CHECK_KV_STR,
  MEM_CHECK_STR,
  NON_MEM_CHECK_KV_STR,
  PositiveAccumulator,
  Presentation,
  PresentationBuilder,
  REV_CHECK_STR,
  RevocationStatusProtocol,
  SignatureType,
  TYPE_STR,
  VBMembershipWitness,
  BBDT16MacPublicKeyG1,
  BBDT16MacParams,
  BBDT16_MAC_PARAMS_LABEL_BYTES,
  BBDT16KeyedProof,
  VBAccumMembershipKeyedProof,
  AccumulatorPublicKeyForKeyedVerification,
  KBUniAccumMembershipKeyedProof,
  KBUniAccumNonMembershipKeyedProof, dockAccumulatorParams
} from '../../src';
import {
  KBUniversalMembershipWitness,
  KBUniversalNonMembershipWitness
} from '../../src';
import { KBUniversalAccumulator } from '../../src';
import { Credential, CredentialBuilder, isKvac, isPS, PublicKey, Scheme, SecretKey } from '../scheme';
import { checkResult } from '../utils';
import {
  checkPresentationJson,
  getExampleSchema,
  getKeys,
  setupKBUniAccumulator,
  setupPrefilledAccum,
  verifyCred
} from './utils';

describe(`Keyed proof verification with BBDT16 MAC and ${Scheme} signatures`, () => {
  let sk: SecretKey, pk: PublicKey;
  let skKvac: BBDT16MacSecretKey;
  let pkKvac: BBDT16MacPublicKeyG1;
  let paramsKvac: BBDT16MacParams;

  let credential1: Credential;
  let credential2: Credential;
  let credential3: Credential;
  let credential4: BBDT16Credential;
  let credential5: BBDT16Credential;
  let credential6: Credential;
  let credential7: Credential;

  // Accumulator where membership is publicly verifiable
  let accumulator1: PositiveAccumulator;
  let accumulator1Pk: AccumulatorPublicKey;
  let accumulator1Witness: VBMembershipWitness;

  // Accumulator where membership verification needs secret key
  let accumulator2: PositiveAccumulator;
  let accumulator2Sk: AccumulatorSecretKey;
  let accumulator2Pk: AccumulatorPublicKeyForKeyedVerification;
  let accumulator2Witness: VBMembershipWitness;

  // Accumulator where membership and non-membership verification needs secret key
  let accumulator3: KBUniversalAccumulator;
  let accumulator3Sk: AccumulatorSecretKey;
  let accumulator3Pk: AccumulatorPublicKeyForKeyedVerification;
  let accumulator3MemWitness: KBUniversalMembershipWitness;
  let accumulator3NonMemWitness: KBUniversalNonMembershipWitness;

  beforeAll(async () => {
    await initializeWasm();

    [sk, pk] = getKeys('seed1');
    paramsKvac = BBDT16MacParams.generate(1, BBDT16_MAC_PARAMS_LABEL_BYTES);
    skKvac = BBDT16MacSecretKey.generate();
    pkKvac = skKvac.generatePublicKeyG1(paramsKvac);

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

    const builder4 = new BBDT16CredentialBuilder();
    builder4.schema = schema;
    builder4.subject = subject;
    builder4.setCredentialStatus('dock:accumulator:accumId123', MEM_CHECK_STR, 'user:A-123');
    // @ts-ignore
    credential4 = builder4.sign(skKvac);
    // This is just for testing as only signer has secret key
    verifyCred(credential4, undefined, skKvac);

    // Signer creates validity proof
    const proof = credential4.proofOfValidity(skKvac, pkKvac);
    // Holder checks using validity proof
    checkResult(credential4.verifyUsingValidityProof(proof, pkKvac));

    const builder5 = new BBDT16CredentialBuilder();
    builder5.schema = schema;
    builder5.subject = subject;
    builder5.setCredentialStatus('dock:accumulator:accumId124', MEM_CHECK_KV_STR, 'user:A-124');
    // @ts-ignore
    credential5 = builder5.sign(skKvac);
    // This is just for testing as only signer has secret key
    verifyCred(credential5, undefined, skKvac);

    // Signer creates validity proof
    const proof1 = credential5.proofOfValidity(skKvac, pkKvac);
    // Holder checks using validity proof
    checkResult(credential5.verifyUsingValidityProof(proof1, pkKvac));

    // @ts-ignore
    [, accumulator1Pk, accumulator1, accumulator1Witness] = await setupPrefilledAccum(200, 122, 'user:A-', schema);

    // @ts-ignore
    [accumulator2Sk, , accumulator2, accumulator2Witness] = await setupPrefilledAccum(200, 123, 'user:A-', schema);
    accumulator2Pk = AccumulatorPublicKeyForKeyedVerification.generate(accumulator2Sk, dockAccumulatorParams());

    let others;
    // @ts-ignore
    [accumulator3Sk, , accumulator3, ...others] = await setupKBUniAccumulator(100, 'user:A-', schema);
    accumulator3Pk = AccumulatorPublicKeyForKeyedVerification.generate(accumulator3Sk, dockAccumulatorParams());
    const [domain, state] = others;

    const builder6 = new CredentialBuilder();
    builder6.schema = schema;
    builder6.subject = subject;
    builder6.setCredentialStatus('dock:accumulator:accumId125', MEM_CHECK_KV_STR, 'user:A-25', RevocationStatusProtocol.KbUni24);
    credential6 = builder6.sign(sk);
    await accumulator3.add(domain[24], accumulator3Sk, state);
    accumulator3MemWitness = await accumulator3.membershipWitness(domain[24], accumulator3Sk, state);
    verifyCred(credential6, pk, sk);

    const builder7 = new CredentialBuilder();
    builder7.schema = schema;
    builder7.subject = subject;
    builder7.setCredentialStatus('dock:accumulator:accumId125', NON_MEM_CHECK_KV_STR, 'user:A-26', RevocationStatusProtocol.KbUni24);
    credential7 = builder7.sign(sk);
    accumulator3NonMemWitness = await accumulator3.nonMembershipWitness(domain[25], accumulator3Sk, state);
    verifyCred(credential6, pk, sk);
  });

  it('works', () => {
    // Describes a test with 7 credentials. Credentials 1, 2, 3, 6, 7 are non-KVAC and 4 and 5 is KVAC.
    // Status verification of credential 1 and credential 4 requires public key but for credential 2, 5, 6, 7 requires secret key

    const builder = new PresentationBuilder();

    expect(builder.addCredential(credential1, isPS() ? pk : undefined)).toEqual(0);
    expect(builder.addCredential(credential2, isPS() ? pk : undefined)).toEqual(1);
    expect(builder.addCredential(credential3, isPS() ? pk : undefined)).toEqual(2);
    expect(builder.addCredential(credential4)).toEqual(3);
    expect(builder.addCredential(credential5)).toEqual(4);
    expect(builder.addCredential(credential6, isPS() ? pk : undefined)).toEqual(5);
    expect(builder.addCredential(credential7, isPS() ? pk : undefined)).toEqual(6);

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
    builder.addAccumInfoForCredStatus(5, accumulator3MemWitness, accumulator3.accumulated, undefined, {
      blockNo: 2010338
    });
    builder.addAccumInfoForCredStatus(6, accumulator3NonMemWitness, accumulator3.accumulated, undefined, {
      blockNo: 2010339
    });

    const pres = builder.finalize();

    const pks = new Map();
    pks.set(0, pk);
    pks.set(1, pk);
    pks.set(2, pk);
    pks.set(5, pk);
    pks.set(6, pk);
    const accumPks = new Map();
    accumPks.set(0, accumulator1Pk);
    accumPks.set(3, accumulator1Pk);

    checkResult(pres.verify(pks, accumPks));
    checkPresentationJson(pres, pks, accumPks);

    // Check full verification using secret key. This will be done by a verifier who has the secret key and is useful in
    // situations when issuer and verifier are the same entity (or share the secret key)
    pks.set(3, skKvac);
    pks.set(4, skKvac);
    accumPks.set(1, accumulator2Sk);
    accumPks.set(4, accumulator2Sk);
    accumPks.set(5, accumulator3Sk);
    accumPks.set(6, accumulator3Sk);
    checkResult(pres.verify(pks, accumPks));
    let recreatedPres = checkPresentationJson(pres, pks, accumPks);

    checkKeyedProofs(pres);
    checkKeyedProofs(recreatedPres);

    function checkKeyedProofs(presentation: Presentation) {

      /**
       * Check if the serialized versions of keyed proofs can be verified
       * @param verifyFunc - the function that verifier
       * @param keyedCredProof
       */
      function checkSerialized(verifyFunc, keyedCredProof?: KeyedProof) {
        let j = keyedCredProof?.toJSON();
        let recreated = KeyedProof.fromJSON(j as object);
        verifyFunc(recreated);
      }

      function credProofAvailable(keyedCredProof?: KeyedProof) {
        expect(keyedCredProof?.credential).toMatchObject({
          sigType: SignatureType.Bbdt16
        });

        checkResult(keyedCredProof?.credential?.proof.verify(sk) as VerifyResult);
      }

      function check2(keyedCredProof?: KeyedProof) {
        if (!isKvac()) {
          expect(keyedCredProof?.credential).not.toBeDefined();
        }
        expect(keyedCredProof?.status).toMatchObject({
          [ID_STR]: 'dock:accumulator:accumId124',
          [TYPE_STR]: RevocationStatusProtocol.Vb22,
          [REV_CHECK_STR]: MEM_CHECK_KV_STR
        });
        checkResult(keyedCredProof?.status?.proof.verify(accumulator2Sk) as VerifyResult);

        if (!isKvac()) {
          checkResult(keyedCredProof?.verify(undefined, accumulator2Sk) as VerifyResult);
        }
      }

      function check3(keyedCredProof?: KeyedProof) {
        expect(keyedCredProof?.credential).toMatchObject({
          sigType: SignatureType.Bbdt16
        });

        checkResult(keyedCredProof?.verify(skKvac) as VerifyResult);

        const proof = keyedCredProof?.credential?.proof as BBDT16KeyedProof;
        checkResult(proof.verify(skKvac) as VerifyResult);
        const pv = proof.proofOfValidity(skKvac, pkKvac, paramsKvac);
        checkResult(pv.verify(proof, pkKvac, paramsKvac));
        expect(keyedCredProof?.status).not.toBeDefined();
      }

      function check4(keyedCredProof?: KeyedProof) {
        expect(keyedCredProof?.credential).toMatchObject({
          sigType: SignatureType.Bbdt16
        });
        checkResult(keyedCredProof?.verify(skKvac, accumulator2Sk) as VerifyResult);

        checkResult(keyedCredProof?.credential?.proof.verify(skKvac) as VerifyResult);
        expect(keyedCredProof?.status).toMatchObject({
          [ID_STR]: 'dock:accumulator:accumId124',
          [TYPE_STR]: RevocationStatusProtocol.Vb22,
          [REV_CHECK_STR]: MEM_CHECK_KV_STR
        });
        const proof = keyedCredProof?.status?.proof as VBAccumMembershipKeyedProof;
        checkResult(proof.verify(accumulator2Sk) as VerifyResult);
        const pv = proof.proofOfValidity(accumulator2Sk, accumulator2Pk, dockAccumulatorParams());
        checkResult(pv.verify(proof, accumulator2Pk, dockAccumulatorParams()));
      }

      function check5(keyedCredProof?: KeyedProof) {
        if (!isKvac()) {
          expect(keyedCredProof?.credential).not.toBeDefined();
        }
        expect(keyedCredProof?.status).toMatchObject({
          [ID_STR]: 'dock:accumulator:accumId125',
          [TYPE_STR]: RevocationStatusProtocol.KbUni24,
          [REV_CHECK_STR]: MEM_CHECK_KV_STR
        });
        const proof = keyedCredProof?.status?.proof as KBUniAccumMembershipKeyedProof;
        checkResult(proof.verify(accumulator3Sk) as VerifyResult);
        const pv = proof.proofOfValidity(accumulator3Sk, accumulator3Pk, dockAccumulatorParams());
        checkResult(pv.verify(proof, accumulator3Pk, dockAccumulatorParams()));

        if (!isKvac()) {
          checkResult(keyedCredProof?.verify(undefined, accumulator3Sk) as VerifyResult);
        }
      }

      function check6(keyedCredProof?: KeyedProof) {
        if (!isKvac()) {
          expect(keyedCredProof?.credential).not.toBeDefined();
        }
        expect(keyedCredProof?.status).toMatchObject({
          [ID_STR]: 'dock:accumulator:accumId125',
          [TYPE_STR]: RevocationStatusProtocol.KbUni24,
          [REV_CHECK_STR]: NON_MEM_CHECK_KV_STR
        });
        const proof = keyedCredProof?.status?.proof as KBUniAccumNonMembershipKeyedProof;
        checkResult(proof.verify(accumulator3Sk) as VerifyResult);
        const pv = proof.proofOfValidity(accumulator3Sk, accumulator3Pk, dockAccumulatorParams());
        checkResult(pv.verify(proof, accumulator3Pk, dockAccumulatorParams()));

        if (!isKvac()) {
          checkResult(keyedCredProof?.verify(undefined, accumulator3Sk) as VerifyResult);
        }
      }

      const keyedProofs = presentation.getKeyedProofs();
      expect(keyedProofs.size).toEqual(isKvac() ? 7 : 5);

      if (isKvac()) {
        for (let i = 0; i < 3; i++) {
          const keyedCredProof = keyedProofs.get(i);
          credProofAvailable(keyedCredProof);
          checkSerialized(credProofAvailable, keyedCredProof);
        }
      }

      const keyedCredProof2 = keyedProofs.get(1);
      check2(keyedCredProof2);
      checkSerialized(check2, keyedCredProof2);

      const keyedCredProof4 = keyedProofs.get(3);
      check3(keyedCredProof4);
      checkSerialized(check3, keyedCredProof4);

      const keyedCredProof5 = keyedProofs.get(4);
      check4(keyedCredProof5);
      checkSerialized(check4, keyedCredProof5);

      const keyedCredProof6 = keyedProofs.get(5);
      check5(keyedCredProof6);
      checkSerialized(check5, keyedCredProof6);

      const keyedCredProof7 = keyedProofs.get(6);
      check6(keyedCredProof7);
      checkSerialized(check6, keyedCredProof7);
    }
  })
})