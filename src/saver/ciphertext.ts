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

export class SaverCiphertext extends BytearrayWrapper {
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
