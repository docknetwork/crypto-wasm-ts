import {
  LegoProvingKey,
  LegoProvingKeyUncompressed,
  LegoVerifyingKey,
  LegoVerifyingKeyUncompressed,
  BoundCheckSnarkSetup
} from '../src';
import { initializeWasm } from '@docknetwork/crypto-wasm';
import { checkLegoProvingKey } from './utils';

describe('Bound check snark setup', () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it('setup legosnark', () => {
    const pk = BoundCheckSnarkSetup();
    checkLegoProvingKey(pk);
  }, 90000);
});
