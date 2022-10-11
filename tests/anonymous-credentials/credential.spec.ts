import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  CRED_VERSION_STR,
  Credential,
  CredentialSchema,
  SCHEMA_STR,
  SUBJECT_STR
} from '../../src/anonymous-credentials';
import { BBSPlusPublicKeyG2, BBSPlusSecretKey, KeypairG2, SignatureParamsG1 } from '../../src';
import { checkResult } from '../utils';

describe('Credential signing and verification', () => {
  let sk: BBSPlusSecretKey, pk: BBSPlusPublicKeyG2;

  beforeAll(async () => {
    await initializeWasm();
    const params = SignatureParamsG1.generate(1, Credential.getLabelBytes());
    const keypair = KeypairG2.generate(params);
    sk = keypair.sk;
    pk = keypair.pk;
  });

  it('simple credential signing and verification', () => {
    const schema = {};
    schema[CRED_VERSION_STR] = {type: "string"};
    schema[SCHEMA_STR] = {type: "string"};
    schema[SUBJECT_STR] = {
      fname: {type: "string"},
      lname: {type: "string"}
    };
    const credSchema = new CredentialSchema(schema);

    const cred = new Credential();
    cred.schema = credSchema;
    cred.subject = {fname: 'John', lname: 'Smith'};
    cred.sign(sk);

    checkResult(cred.verify(pk));
    console.log(cred.toJSON());
  });
});
