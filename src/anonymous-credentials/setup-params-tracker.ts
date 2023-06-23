import { SetupParam } from '../composite-proof';
import {
  dockAccumulatorMemProvingKey,
  dockAccumulatorNonMemProvingKey, dockAccumulatorParams,
  dockSaverEncryptionGens,
  dockSaverEncryptionGensUncompressed
} from './types-and-consts';

/**
 * Track `SetupParam` create during proving and verification. This class is meant for internal use only.
 */
export class SetupParamsTracker {
  setupParams: SetupParam[];

  // Param id to setupParams index map as `SetupParam` is created only once for a param
  paramIdToSetupParamIdx: Map<string, number>;

  // Index in `setupParams` array for various static parameters
  _accumParamsIdx?: number;
  _memPrkIdx?: number;
  _nonMemPrkIdx?: number;
  _encGensIdx?: number;
  _encGensCompIdx?: number;

  constructor() {
    this.setupParams = [];
    this.paramIdToSetupParamIdx = new Map();
  }

  add(sp: SetupParam): number {
    this.setupParams.push(sp);
    return this.setupParams.length - 1;
  }

  addForParamId(paramId: string, sp: SetupParam): number {
    if (this.isTrackingParam(paramId)) {
      throw new Error(`Already tracking param id ${paramId}`);
    }
    this.setupParams.push(sp);
    const i = this.lastIndex();
    this.paramIdToSetupParamIdx.set(paramId, i);
    return i;
  }

  lastIndex(): number {
    return this.nthLastIndex(1);
  }

  indexForParam(paramId: string): number {
    if (!this.isTrackingParam(paramId)) {
      throw new Error(`Not tracking param id ${paramId}`);
    }
    return this.paramIdToSetupParamIdx.get(paramId) as number;
  }

  nthLastIndex(n: number): number {
    if (this.setupParams.length < n) {
      throw new Error(`Invalid index ${n} for setup params array of size ${this.setupParams.length}`);
    }
    return this.setupParams.length - n;
  }

  hasAccumulatorParams(): boolean {
    return this._accumParamsIdx !== undefined;
  }

  hasAccumulatorMemProvingKey(): boolean {
    return this._memPrkIdx !== undefined;
  }

  hasAccumulatorNonMemProvingKey(): boolean {
    return this._nonMemPrkIdx !== undefined;
  }

  hasEncryptionGensCompressed(): boolean {
    return this._encGensCompIdx !== undefined;
  }

  hasEncryptionGensUncompressed(): boolean {
    return this._encGensIdx !== undefined;
  }

  isTrackingParam(paramId: string): boolean {
    return this.paramIdToSetupParamIdx.get(paramId) !== undefined;
  }

  addAccumulatorParams(): number {
    if (this.hasAccumulatorParams()) {
      throw new Error('Already present');
    }
    this.setupParams.push(SetupParam.vbAccumulatorParams(dockAccumulatorParams()));
    this._accumParamsIdx = this.lastIndex();
    return this._accumParamsIdx;
  }

  addAccumulatorMemProvingKey(): number {
    if (this.hasAccumulatorMemProvingKey()) {
      throw new Error('Already present');
    }
    this.setupParams.push(SetupParam.vbAccumulatorMemProvingKey(dockAccumulatorMemProvingKey()));
    this._memPrkIdx = this.lastIndex();
    return this._memPrkIdx;
  }

  addAccumulatorNonMemProvingKey(): number {
    if (this.hasAccumulatorNonMemProvingKey()) {
      throw new Error('Already present');
    }
    this.setupParams.push(SetupParam.vbAccumulatorNonMemProvingKey(dockAccumulatorNonMemProvingKey()));
    this._nonMemPrkIdx = this.lastIndex();
    return this._nonMemPrkIdx;
  }

  addEncryptionGensCompressed(): number {
    if (this.hasEncryptionGensCompressed()) {
      throw new Error('Already present');
    }
    this.setupParams.push(SetupParam.saverEncryptionGens(dockSaverEncryptionGens()));
    this._encGensCompIdx = this.lastIndex();
    return this._encGensCompIdx;
  }

  addEncryptionGensUncompressed(): number {
    if (this.hasEncryptionGensUncompressed()) {
      throw new Error('Already present');
    }
    this.setupParams.push(SetupParam.saverEncryptionGensUncompressed(dockSaverEncryptionGensUncompressed()));
    this._encGensIdx = this.lastIndex();
    return this._encGensIdx;
  }

  get accumParamsIdx(): number {
    if (this._accumParamsIdx === undefined) {
      throw new Error('Not set yet');
    }
    return this._accumParamsIdx;
  }

  get memPrkIdx(): number {
    if (this._memPrkIdx === undefined) {
      throw new Error('Not set yet');
    }
    return this._memPrkIdx;
  }

  get nonMemPrkIdx(): number {
    if (this._nonMemPrkIdx === undefined) {
      throw new Error('Not set yet');
    }
    return this._nonMemPrkIdx;
  }

  get encGensIdx(): number {
    if (this._encGensIdx === undefined) {
      throw new Error('Not set yet');
    }
    return this._encGensIdx;
  }

  get encGensCompIdx(): number {
    if (this._encGensCompIdx === undefined) {
      throw new Error('Not set yet');
    }
    return this._encGensCompIdx;
  }
}
