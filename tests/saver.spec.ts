import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  getChunkBitSize,
  SaverChunkedCommitmentGens,
  SaverChunkedCommitmentGensUncompressed,
  SaverDecryptionKey,
  SaverDecryptionKeyUncompressed,
  SaverDecryptor,
  SaverEncryptionGens,
  SaverEncryptionGensUncompressed,
  SaverEncryptionKey,
  SaverEncryptionKeyUncompressed,
  SaverProvingKey,
  SaverProvingKeyUncompressed,
  SaverSecretKey,
  SaverVerifyingKey,
  SaverVerifyingKeyUncompressed
} from '../src';
import { stringToBytes } from './utils';

describe('SAVER setup', () => {
  let encGens: SaverEncryptionGens;
  let snarkProvingKey: SaverProvingKey;
  let snarkProvingKeyUncompressed: SaverProvingKeyUncompressed;

  beforeAll(async () => {
    await initializeWasm();
  });

  it('create encryption generators', () => {
    const gens1 = SaverEncryptionGens.generate();
    const gens1Uncompressed = gens1.decompress();
    expect(gens1Uncompressed instanceof SaverEncryptionGensUncompressed).toBe(true);

    const label = stringToBytes('Some string to deterministically generate EncryptionGens');
    const gens2 = SaverEncryptionGens.generate(label);
    const gens3 = SaverEncryptionGens.generate(label);
    const gens2Uncompressed = gens2.decompress();
    const gens3Uncompressed = gens3.decompress();

    expect(gens2.value).toEqual(gens3.value);
    expect(gens2Uncompressed.value).toEqual(gens3Uncompressed.value);

    encGens = gens2;
  });

  it('create commitment generators', () => {
    const gens1 = SaverChunkedCommitmentGens.generate();
    const gens1Uncompressed = gens1.decompress();
    expect(gens1Uncompressed instanceof SaverChunkedCommitmentGensUncompressed).toBe(true);

    const label = stringToBytes('Some string to deterministically generate ChunkedCommitmentGens');
    const gens2 = SaverChunkedCommitmentGens.generate(label);
    const gens3 = SaverChunkedCommitmentGens.generate(label);
    const gens2Uncompressed = gens2.decompress();
    const gens3Uncompressed = gens3.decompress();

    expect(gens2.value).toEqual(gens3.value);
    expect(gens2Uncompressed.value).toEqual(gens3Uncompressed.value);
  });

  it('do setup for decryptor', () => {
    expect(getChunkBitSize()).toEqual(16);
    expect(getChunkBitSize(4)).toEqual(4);
    expect(getChunkBitSize(8)).toEqual(8);
    expect(getChunkBitSize(16)).toEqual(16);
    expect(() => getChunkBitSize(2)).toThrow();
    expect(() => getChunkBitSize(3)).toThrow();
    expect(() => getChunkBitSize(10)).toThrow();
    expect(() => getChunkBitSize(17)).toThrow();

    expect(() => SaverDecryptor.setup(encGens, 2)).toThrow();
    expect(() => SaverDecryptor.setup(encGens, 3)).toThrow();
    expect(() => SaverDecryptor.setup(encGens, 10)).toThrow();
    expect(() => SaverDecryptor.setup(encGens, 17)).toThrow();

    const [snarkPk, sk, ek, dk] = SaverDecryptor.setup(encGens, 16);
    expect(snarkPk instanceof SaverProvingKey).toBe(true);
    expect(sk instanceof SaverSecretKey).toBe(true);
    expect(ek instanceof SaverEncryptionKey).toBe(true);
    expect(dk instanceof SaverDecryptionKey).toBe(true);

    snarkProvingKeyUncompressed = snarkPk.decompress();
    const ekUncompressed = ek.decompress();
    const dkUncompressed = dk.decompress();

    expect(snarkProvingKeyUncompressed instanceof SaverProvingKeyUncompressed).toBe(true);
    expect(ekUncompressed instanceof SaverEncryptionKeyUncompressed).toBe(true);
    expect(dkUncompressed instanceof SaverDecryptionKeyUncompressed).toBe(true);

    snarkProvingKey = snarkPk;
  }, 150000);

  it('extract verifying key', () => {
    const snarkVk = snarkProvingKey.getVerifyingKey();
    const snarkVkUncompressed = snarkProvingKey.getVerifyingKeyUncompressed();

    expect(snarkVk instanceof SaverVerifyingKey).toBe(true);
    expect(snarkVkUncompressed instanceof SaverVerifyingKeyUncompressed).toBe(true);

    const snarkVkUncompressed1 = snarkVk.decompress();

    expect(snarkVkUncompressed1 instanceof SaverVerifyingKeyUncompressed).toBe(true);

    expect(snarkVkUncompressed1.value).toEqual(snarkVkUncompressed.value);
  }, 250000);
});
