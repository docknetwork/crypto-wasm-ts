import {
  AccumulatorPublicKey,
  AccumulatorSecretKey,
  CredentialSchema, dockAccumulatorParams,
  initializeWasm,
  MEM_CHECK_STR, NON_MEM_CHECK_STR,
  PresentationBuilder,
  RevocationStatusProtocol, TYPE_STR
} from '../../src';
import {
  KBUniversalMembershipWitness,
  KBUniversalNonMembershipWitness
} from '../../src/accumulator/kb-acccumulator-witness';
import { KBUniversalAccumulator } from '../../src/accumulator/kb-universal-accumulator';
import { Credential, CredentialBuilder, isPS, PublicKey, Scheme, SecretKey } from '../scheme';
import { checkResult } from '../utils';
import {
  checkPresentationJson,
  checkSchemaFromJson,
  getExampleSchema,
  getKeys,
  setupKBUniAccumulator,
  verifyCred
} from './utils';

describe(`Presentation of ${Scheme} credential with KB universal accumulator`, () => {
  let sk1: SecretKey, pk1: PublicKey;
  let credential1: Credential;
  let credential2: Credential;
  let accumulator: KBUniversalAccumulator;
  let accumulatorSk: AccumulatorSecretKey;
  let accumulatorPk: AccumulatorPublicKey;
  let memWitness: KBUniversalMembershipWitness;
  let nonMemWitness: KBUniversalNonMembershipWitness;

  beforeAll(async () => {
    await initializeWasm();

    [sk1, pk1] = getKeys('seed1');
    const schema1 = new CredentialSchema(getExampleSchema(5));

    let others;
    // @ts-ignore
    [accumulatorSk, accumulatorPk, accumulator, ...others] = await setupKBUniAccumulator(100, 'user:A-', schema1);
    const [domain, state] = others;

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
    builder1.schema = schema1;
    builder1.subject = subject;
    builder1.setCredentialStatus('dock:accumulator:accumId123', MEM_CHECK_STR, 'user:A-23', RevocationStatusProtocol.KbUni24);
    credential1 = builder1.sign(sk1);
    await accumulator.add(domain[22], accumulatorSk, state);
    memWitness = await accumulator.membershipWitness(domain[22], accumulatorSk, state);
    verifyCred(credential1, pk1, sk1);
    expect(
      accumulator.verifyMembershipWitness(
        domain[22],
        memWitness,
        accumulatorPk,
        dockAccumulatorParams()
      )
    ).toEqual(true);

    const builder2 = new CredentialBuilder();
    builder2.schema = schema1;
    builder2.subject = subject;
    builder2.setCredentialStatus('dock:accumulator:accumId123', NON_MEM_CHECK_STR, 'user:A-30', RevocationStatusProtocol.KbUni24);
    credential2 = builder2.sign(sk1);

    nonMemWitness = await accumulator.nonMembershipWitness(domain[29], accumulatorSk, state);
    verifyCred(credential2, pk1, sk1);
    expect(
      accumulator.verifyNonMembershipWitness(
        domain[29],
        nonMemWitness,
        accumulatorPk,
        dockAccumulatorParams()
      )
    ).toEqual(true);
  })

  it('from 1 credential having credential status with a membership proof', () => {
    const builder = new PresentationBuilder();
    builder.addCredential(credential1, isPS() ? pk1 : undefined);
    builder.addAccumInfoForCredStatus(0, memWitness, accumulator.accumulated, accumulatorPk, {
      blockNo: 100
    });
    const pres = builder.finalize();
    // This check is made by the verifier, i.e. verifier checks that the accumulator id, type, value and timestamp (`blockNo`)
    // are as expected
    expect(pres.spec.getStatus(0)).toEqual({
      id: 'dock:accumulator:accumId123',
      [TYPE_STR]: RevocationStatusProtocol.KbUni24,
      revocationCheck: MEM_CHECK_STR,
      accumulated: accumulator.accumulated,
      extra: { blockNo: 100 }
    });

    // Verifier passes the accumulator public key for verification
    const acc = new Map();
    acc.set(0, accumulatorPk);
    checkResult(pres.verify([pk1], acc));

    const presJson = pres.toJSON();

    // The schema of the credential in the presentation matches the JSON-schema
    // @ts-ignore
    checkSchemaFromJson(presJson.spec.credentials[0].schema, credential1.schema);

    checkPresentationJson(pres, [pk1], acc);
  })

  it('from 1 credential having credential status with a non-membership proof', () => {
    const builder = new PresentationBuilder();
    builder.addCredential(credential2, isPS() ? pk1 : undefined);
    builder.addAccumInfoForCredStatus(0, nonMemWitness, accumulator.accumulated, accumulatorPk, {
      blockNo: 100
    });
    const pres = builder.finalize();
    // This check is made by the verifier, i.e. verifier checks that the accumulator id, type, value and timestamp (`blockNo`)
    // are as expected
    expect(pres.spec.getStatus(0)).toEqual({
      id: 'dock:accumulator:accumId123',
      [TYPE_STR]: RevocationStatusProtocol.KbUni24,
      revocationCheck: NON_MEM_CHECK_STR,
      accumulated: accumulator.accumulated,
      extra: { blockNo: 100 }
    });

    // Verifier passes the accumulator public key for verification
    const acc = new Map();
    acc.set(0, accumulatorPk);
    checkResult(pres.verify([pk1], acc));

    checkPresentationJson(pres, [pk1], acc);
  })

  it('from 2 credentials, one with status with a membership proof and another status with a non-membership proof', () => {
    const builder = new PresentationBuilder();
    builder.addCredential(credential1, isPS() ? pk1 : undefined);
    builder.addAccumInfoForCredStatus(0, memWitness, accumulator.accumulated, accumulatorPk, {
      blockNo: 100
    });
    builder.addCredential(credential2, isPS() ? pk1 : undefined);
    builder.addAccumInfoForCredStatus(1, nonMemWitness, accumulator.accumulated, accumulatorPk, {
      blockNo: 200
    });
    const pres = builder.finalize();

    // This check is made by the verifier, i.e. verifier checks that the accumulator id, type, value and timestamp (`blockNo`)
    // are as expected
    expect(pres.spec.getStatus(0)).toEqual({
      id: 'dock:accumulator:accumId123',
      [TYPE_STR]: RevocationStatusProtocol.KbUni24,
      revocationCheck: MEM_CHECK_STR,
      accumulated: accumulator.accumulated,
      extra: { blockNo: 100 }
    });
    expect(pres.spec.getStatus(1)).toEqual({
      id: 'dock:accumulator:accumId123',
      [TYPE_STR]: RevocationStatusProtocol.KbUni24,
      revocationCheck: NON_MEM_CHECK_STR,
      accumulated: accumulator.accumulated,
      extra: { blockNo: 200 }
    });

    // Verifier passes the accumulator public key for verification
    const acc = new Map();
    acc.set(0, accumulatorPk);
    acc.set(1, accumulatorPk);

    checkResult(pres.verify([pk1, pk1], acc));

    checkPresentationJson(pres, [pk1, pk1], acc);
  })
})