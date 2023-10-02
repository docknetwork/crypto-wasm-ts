import * as fs from 'fs';

import { initializeWasm } from '@docknetwork/crypto-wasm';
import { CredentialSchema } from '../../src';

describe('Credential Schema creation from JSON', () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  function check(version: string) {
    const schemasJson = fs.readFileSync(`${__dirname}/serialized-objects/schema-${version}.json`, 'utf8');
    const schemas = JSON.parse(schemasJson);
    for (let i = 0; i < schemas.length; i++) {
      const recreated = CredentialSchema.fromJSON(schemas[i]);
      expect(recreated.version).toEqual(version);
      expect(schemas[i]).toEqual(recreated.toJSON());
    }
  }

  it('check version 0.0.1', () => {
    check('0.0.1')
  })

  it('check version 0.0.2', () => {
    check('0.0.2')
  })

  it('check version 0.0.3', () => {
    check('0.0.3')
  })
})