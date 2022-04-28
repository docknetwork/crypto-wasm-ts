export function getChunkBitSize(chunkBitSize?: number): number {
  if (chunkBitSize === undefined) {
    return 16;
  }
  if (chunkBitSize !== 4 && chunkBitSize !== 8 && chunkBitSize !== 16) {
    throw new Error(`Chunk bit size of ${chunkBitSize} is not acceptable. Only 4, 8 and 16 allowed`);
  }
  return chunkBitSize;
}
