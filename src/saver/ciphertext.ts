import { BytearrayWrapper } from '../bytearray-wrapper';
import { saverVerifyDecryptionUsingSnarkVk, VerifyResult } from 'crypto-wasm-new';
import {
  Decrypted,
  SaverDecryptionKey,
  SaverDecryptionKeyUncompressed,
  SaverEncryptionGens,
  SaverEncryptionGensUncompressed,
  SaverVerifyingKey,
  SaverVerifyingKeyUncompressed
} from './decryptor';
import { getChunkBitSize } from './util';

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
   * @param chunkBitSize - Must be same as the one used by the decryptor to create the parameters.
   */
  verifyDecryption(
    decrypted: Decrypted,
    decryptionKey: SaverDecryptionKeyUncompressed,
    snarkVk: SaverVerifyingKeyUncompressed,
    encGens: SaverEncryptionGensUncompressed,
    chunkBitSize: number
  ): VerifyResult {
    return saverVerifyDecryptionUsingSnarkVk(
      this.value,
      decrypted.message,
      decrypted.nu,
      decryptionKey.value,
      snarkVk.value,
      encGens.value,
      getChunkBitSize(chunkBitSize),
      true
    );
  }

  /**
   * Same as `this.verifyDecryption` except that is takes compressed parameters
   * @param decrypted
   * @param decryptionKey
   * @param snarkVk
   * @param encGens
   * @param chunkBitSize - Must be same as the one used by the decryptor to create the parameters.
   */
  verifyDecryptionUsingCompressedParams(
    decrypted: Decrypted,
    decryptionKey: SaverDecryptionKey,
    snarkVk: SaverVerifyingKey,
    encGens: SaverEncryptionGens,
    chunkBitSize: number
  ): VerifyResult {
    return saverVerifyDecryptionUsingSnarkVk(
      this.value,
      decrypted.message,
      decrypted.nu,
      decryptionKey.value,
      snarkVk.value,
      encGens.value,
      getChunkBitSize(chunkBitSize),
      false
    );
  }
}
