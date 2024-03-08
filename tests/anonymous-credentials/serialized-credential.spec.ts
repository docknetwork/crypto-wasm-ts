import * as fs from 'fs';

import { Credential, isKvac, isPS, PublicKey, Scheme, SecretKey } from '../scheme';
import { checkResult } from '../utils';
import {initializeWasm} from '../../src';

describe(`${Scheme} Credential creation and verification from JSON`, () => {
  const fileNamePrefix = Scheme.toLowerCase();

  beforeAll(async () => {
    await initializeWasm();
  });

  function check(credVersion: string, schemaVersion: string) {
    for (let i = 1; i <= 3; i++) {
      const pkBin = isKvac() ? undefined : fs.readFileSync(`${__dirname}/serialized-objects/${fileNamePrefix}_pk${i}.bin`);
      const skBin = !isKvac() ? undefined : fs.readFileSync(`${__dirname}/serialized-objects/${fileNamePrefix}_sk${i}.bin`);
      let credentialJson = fs.readFileSync(`${__dirname}/serialized-objects/${fileNamePrefix}_credential${i}-${credVersion}.json`, 'utf8');
      credentialJson = JSON.parse(credentialJson);
      // @ts-ignore
      const pk = isKvac() ? undefined : PublicKey.fromBytes(pkBin);
      const sk = !isKvac() ? undefined : SecretKey.fromBytes(skBin);
      const cred = Credential.fromJSON(credentialJson);
      checkResult(isKvac() ? cred.verifyUsingSecretKey(sk) : cred.verify(pk));
      expect(credentialJson).toEqual(cred.toJSON());
      expect(cred.schema.version).toEqual(schemaVersion);
    }
  }

  const skipIfKvac = isKvac() ? it.skip : it;

  skipIfKvac('check version 0.0.2', () => {
    check('0.0.2', '0.0.1');
  })

  it('check version 0.4.0', () => {
    check('0.4.0', '0.2.0');
  })
})