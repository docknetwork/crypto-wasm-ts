export function getChunkBitSize(chunkBitSize?: number): number {
  if (chunkBitSize === undefined) {
    return 8;
  }
  if (chunkBitSize !== 4 && chunkBitSize !== 8) {
    throw new Error(`Chunk bit size of ${chunkBitSize} is not acceptable. Only 4 and 8 allowed`);
  }
  return chunkBitSize;
}
