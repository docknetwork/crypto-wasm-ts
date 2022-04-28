import {
  saverDecompressEncryptionGenerators,
  saverDecompressEncryptionKey,
  saverDecompressDecryptionKey,
  saverDecompressSnarkPk,
  saverDecompressSnarkVk,
  saverDecryptorSetup,
  saverGenerateEncryptionGenerators,
  saverGetSnarkVkFromPk,
  saverDecryptCiphertextUsingSnarkVk
} from '@docknetwork/crypto-wasm';

import { getChunkBitSize } from './util';
import { ICompressed, IUncompressed } from '../ICompressed';
import { BytearrayWrapper } from '../bytearray-wrapper';
import { SaverCiphertext } from './ciphertext';

export class SaverSecretKey extends BytearrayWrapper {}

export class SaverEncryptionGensUncompressed extends BytearrayWrapper implements IUncompressed {}

export class SaverEncryptionGens extends BytearrayWrapper implements ICompressed<SaverEncryptionGensUncompressed> {
  static generate(label?: Uint8Array): SaverEncryptionGens {
    const gens = saverGenerateEncryptionGenerators(label);
    return new SaverEncryptionGens(gens);
  }

  decompress(): SaverEncryptionGensUncompressed {
    return new SaverEncryptionGensUncompressed(saverDecompressEncryptionGenerators(this.value));
  }
}

export class SaverEncryptionKeyUncompressed extends BytearrayWrapper implements IUncompressed {}

export class SaverEncryptionKey extends BytearrayWrapper implements ICompressed<SaverEncryptionKeyUncompressed> {
  decompress(): SaverEncryptionKeyUncompressed {
    return new SaverEncryptionKeyUncompressed(saverDecompressEncryptionKey(this.value));
  }
}

export class SaverDecryptionKeyUncompressed extends BytearrayWrapper implements IUncompressed {}

export class SaverDecryptionKey extends BytearrayWrapper implements ICompressed<SaverDecryptionKeyUncompressed> {
  decompress(): SaverDecryptionKeyUncompressed {
    return new SaverDecryptionKeyUncompressed(saverDecompressDecryptionKey(this.value));
  }
}

export class SaverProvingKeyUncompressed extends BytearrayWrapper implements IUncompressed {}

export class SaverProvingKey extends BytearrayWrapper implements ICompressed<SaverProvingKeyUncompressed> {
  decompress(): SaverProvingKeyUncompressed {
    return new SaverProvingKeyUncompressed(saverDecompressSnarkPk(this.value));
  }

  getVerifyingKey(): SaverVerifyingKey {
    return new SaverVerifyingKey(saverGetSnarkVkFromPk(this.value, false));
  }

  getVerifyingKeyUncompressed(): SaverVerifyingKeyUncompressed {
    return new SaverVerifyingKeyUncompressed(saverGetSnarkVkFromPk(this.value, true));
  }
}

export class SaverVerifyingKeyUncompressed extends BytearrayWrapper implements IUncompressed {}

export class SaverVerifyingKey extends BytearrayWrapper implements ICompressed<SaverVerifyingKeyUncompressed> {
  decompress(): SaverVerifyingKeyUncompressed {
    return new SaverVerifyingKeyUncompressed(saverDecompressSnarkVk(this.value));
  }
}

export class Decrypted {
  message: Uint8Array;
  nu: Uint8Array;

  constructor(message: Uint8Array, nu: Uint8Array) {
    this.message = message;
    this.nu = nu;
  }
}

export class SaverDecryptor {
  static setup(
    encGens: SaverEncryptionGens,
    chunkBitSize?: number
  ): [SaverProvingKey, SaverSecretKey, SaverEncryptionKey, SaverDecryptionKey] {
    const c = getChunkBitSize(chunkBitSize);
    const [snarkPk, sk, ek, dk] = saverDecryptorSetup(c, encGens.value, false);
    return [
      new SaverProvingKey(snarkPk),
      new SaverSecretKey(sk),
      new SaverEncryptionKey(ek),
      new SaverDecryptionKey(dk)
    ];
  }

  static decryptCiphertext(
    ciphertext: SaverCiphertext,
    secretKey: SaverSecretKey,
    decryptionKey: SaverDecryptionKeyUncompressed,
    snarkVk: SaverVerifyingKeyUncompressed,
    chunkBitSize: number
  ): Decrypted {
    return new Decrypted(
      ...saverDecryptCiphertextUsingSnarkVk(
        ciphertext.value,
        secretKey.value,
        decryptionKey.value,
        snarkVk.value,
        chunkBitSize,
        true
      )
    );
  }

  static decryptCiphertextUsingCompressedParams(
    ciphertext: SaverCiphertext,
    secretKey: Uint8Array,
    decryptionKey: SaverDecryptionKey,
    snarkVk: SaverVerifyingKey,
    chunkBitSize: number
  ): Decrypted {
    return new Decrypted(
      ...saverDecryptCiphertextUsingSnarkVk(
        ciphertext.value,
        secretKey,
        decryptionKey.value,
        snarkVk.value,
        chunkBitSize,
        false
      )
    );
  }
}
