export interface ICompressed<UncompressedType> {
  readonly value: Uint8Array;

  decompress(): UncompressedType;
}

export interface IUncompressed {
  readonly value: Uint8Array;
}
