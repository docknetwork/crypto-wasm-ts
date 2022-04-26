import {
  LegoProvingKey,
  LegoProvingKeyUncompressed,
  LegoVerifyingKey,
  LegoVerifyingKeyUncompressed,
  BoundCheckSnarkSetup
} from '../src';
import { initializeWasm } from '@docknetwork/crypto-wasm';

describe('Bound check snark setup', () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it('setup legosnark', () => {
    const pk = BoundCheckSnarkSetup();
    expect(pk instanceof LegoProvingKey).toBe(true);

    const pkUncompressed = pk.decompress();
    expect(pkUncompressed instanceof LegoProvingKeyUncompressed).toBe(true);

    const vk = pk.getVerifyingKey();
    const vkUncompressed = pk.getVerifyingKeyUncompressed();

    expect(vk instanceof LegoVerifyingKey).toBe(true);
    expect(vkUncompressed instanceof LegoVerifyingKeyUncompressed).toBe(true);

    const vkUncompressed1 = vk.decompress();
    expect(vkUncompressed1 instanceof LegoVerifyingKeyUncompressed).toBe(true);

    expect(vkUncompressed1.value).toEqual(vkUncompressed.value);
  }, 90000);
});
