import { boundCheckSnarkSetup } from '@docknetwork/crypto-wasm';
import { LegoProvingKey } from '../legosnark';

/**
 * Create SNARK proving key for verifying bounds of a message, i.e. range proof
 * @constructor
 */
export function BoundCheckSnarkSetup(): LegoProvingKey {
  const pk = boundCheckSnarkSetup(false);
  return new LegoProvingKey(pk);
}
