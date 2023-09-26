import * as fs from 'fs';

import { initializeWasm } from '@docknetwork/crypto-wasm';
import { CredentialSchema } from '../../src';

describe('Credential Schema creation from JSON', () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it('check version 0.0.1', () => {
    const schemasJson = fs.readFileSync(`${__dirname}/serialized-objects/schema-0.0.1.json`, 'utf8');
    const schemas = JSON.parse(schemasJson);
    for (let i = 0; i < schemas.length; i++) {
      const recreated = CredentialSchema.fromJSON(schemas[i]);
      expect(recreated.version).toEqual('0.0.1');
      expect(schemas[i]).toEqual(recreated.toJSON());
    }
  })
})