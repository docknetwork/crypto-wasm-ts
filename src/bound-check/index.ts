import { boundCheckSnarkSetup } from '@docknetwork/crypto-wasm';
import { LegoProvingKey } from '../legosnark';

export function BoundCheckSnarkSetup(): LegoProvingKey {
  const pk = boundCheckSnarkSetup(false);
  return new LegoProvingKey(pk);
}
