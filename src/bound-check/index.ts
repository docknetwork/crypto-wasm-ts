import { boundCheckSnarkSetup } from '@docknetwork/crypto-wasm';
import { LegoProvingKey } from '../legosnark';

/**
 * Create SNARK proving key for verifying bounds of a message, i.e. range proof.
 * This protocol only works with positive integers so any negative integers or decimal numbers
 * must be converted to positive integers
 * @constructor
 */
export function BoundCheckSnarkSetup(): LegoProvingKey {
  const pk = boundCheckSnarkSetup(false);
  return new LegoProvingKey(pk);
}
