import { Versioned } from './versioned';

export class Presentation extends Versioned {
  // NOTE: Follows semver and must be updated accordingly when the logic of this class changes or the
  // underlying crypto changes.
  static VERSION = '0.0.1';

  _context?: Uint8Array;
  _nonce?: Uint8Array;

  constructor() {
    super(Presentation.VERSION);
  }

  get context(): Uint8Array | undefined {
    return this._context;
  }

  set context(context: Uint8Array | undefined) {
    this._context = context;
  }

  get nonce(): Uint8Array | undefined {
    return this._nonce;
  }

  set nonce(nonce: Uint8Array | undefined) {
    this._nonce = nonce;
  }

  toJSON(): string {
    return JSON.stringify({
      $version: this.version
    });
  }
}
