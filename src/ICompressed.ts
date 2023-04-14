/**
 * Interface for parameters with elliptic curve points in uncompressed form.
 */
export interface IUncompressed {
  readonly value: Uint8Array;
}

/**
 * Interface for parameters with elliptic curve points in compressed form.
 * They can be converted into uncompressed form. Uncompressed data is larger in byte-size but
 * more CPU efficient to work with (in this lib's context) as the cost to decompress is avoided.
 */
export interface ICompressed<UncompressedType> {
  readonly value: Uint8Array;

  /**
   * Convert to uncompressed form
   */
  decompress(): UncompressedType;
}
