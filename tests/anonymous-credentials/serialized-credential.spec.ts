import * as fs from 'fs';

import { initializeWasm } from '@docknetwork/crypto-wasm';
import { Credential, PublicKey, Scheme } from '../scheme';
import { checkResult } from '../utils';

describe(`${Scheme} Credential creation and verification from JSON`, () => {
  const fileNamePrefix = Scheme.toLowerCase();

  beforeAll(async () => {
    await initializeWasm();
  });

  function check(credVersion: string, schemaVersion: string) {
    for (let i = 1; i <= 3; i++) {
      const pkBin = fs.readFileSync(`${__dirname}/serialized-objects/${fileNamePrefix}_pk${i}.bin`);
      let credentialJson = fs.readFileSync(`${__dirname}/serialized-objects/${fileNamePrefix}_credential${i}-${credVersion}.json`, 'utf8');
      credentialJson = JSON.parse(credentialJson);
      // @ts-ignore
      const pk = PublicKey.fromBytes(pkBin);
      const cred = Credential.fromJSON(credentialJson);
      checkResult(cred.verify(pk));
      expect(credentialJson).toEqual(cred.toJSON());
      expect(cred.schema.version).toEqual(schemaVersion);
    }
  }

  it('check version 0.0.2', () => {
    check('0.0.2', '0.0.1');
  })

  it('check version 0.4.0', () => {
    check('0.4.0', '0.2.0');
  })
})