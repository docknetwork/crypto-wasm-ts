import { BytearrayWrapper } from '../bytearray-wrapper';
import { saverVerifyDecryptionUsingSnarkVk, VerifyResult } from '@docknetwork/crypto-wasm';
import {
  Decrypted,
  SaverDecryptionKey,
  SaverDecryptionKeyUncompressed,
  SaverEncryptionGens,
  SaverEncryptionGensUncompressed,
  SaverVerifyingKey,
  SaverVerifyingKeyUncompressed
} from './decryptor';

/**
 * The ciphertext that is sent along the proof
 */
export class SaverCiphertext extends BytearrayWrapper {
  /**
   * Verify that the ciphertext does encrypt the message in `decrypted` using uncompressed public params
   * @param decrypted
   * @param decryptionKey
   * @param snarkVk
   * @param encGens
   * @param chunkButSize - Must be same as the one used by the decryptor to create the parameters.
   */
  verifyDecryption(
    decrypted: Decrypted,
    decryptionKey: SaverDecryptionKeyUncompressed,
    snarkVk: SaverVerifyingKeyUncompressed,
    encGens: SaverEncryptionGensUncompressed,
    chunkButSize: number
  ): VerifyResult {
    return saverVerifyDecryptionUsingSnarkVk(
      this.value,
      decrypted.message,
      decrypted.nu,
      decryptionKey.value,
      snarkVk.value,
      encGens.value,
      chunkButSize,
      true
    );
  }

  /**
   * Same as `this.verifyDecryption` except that is takes compressed parameters
   * @param decrypted
   * @param decryptionKey
   * @param snarkVk
   * @param encGens
   * @param chunkButSize - Must be same as the one used by the decryptor to create the parameters.
   */
  verifyDecryptionUsingCompressedParams(
    decrypted: Decrypted,
    decryptionKey: SaverDecryptionKey,
    snarkVk: SaverVerifyingKey,
    encGens: SaverEncryptionGens,
    chunkButSize: number
  ): VerifyResult {
    return saverVerifyDecryptionUsingSnarkVk(
      this.value,
      decrypted.message,
      decrypted.nu,
      decryptionKey.value,
      snarkVk.value,
      encGens.value,
      chunkButSize,
      false
    );
  }
}
