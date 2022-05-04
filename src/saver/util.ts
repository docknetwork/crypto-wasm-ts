export const DEFAULT_CHUNK_BIT_SIZE = 16;

/**
 * Validate the given chunk size and throw error if its invalid. If not provided then return the default value.
 * @param chunkBitSize
 */
export function getChunkBitSize(chunkBitSize?: number): number {
  if (chunkBitSize === undefined) {
    return DEFAULT_CHUNK_BIT_SIZE;
  }
  if (chunkBitSize !== 4 && chunkBitSize !== 8 && chunkBitSize !== 16) {
    throw new Error(`Chunk bit size of ${chunkBitSize} is not acceptable. Only 4, 8 and 16 allowed`);
  }
  return chunkBitSize;
}
