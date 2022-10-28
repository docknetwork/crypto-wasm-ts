/**
 * Inherited by classes that want to support versioning. This will help in debugging as well.
 */
export class Versioned {
  _version: string;

  constructor(version?: string) {
    this._version = version !== undefined ? version : '0.0.1';
  }

  get version() {
    return this._version;
  }

  set version(version: string) {
    this._version = version;
  }
}
