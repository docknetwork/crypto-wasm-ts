import {
  initializeWasm,
  BoundCheckSnarkSetup,
  BoundCheckBppParams,
  BoundCheckBppParamsUncompressed,
  BoundCheckSmcParams,
  BoundCheckSmcParamsUncompressed,
  BoundCheckSmcWithKVSetup,
  BoundCheckSmcWithKVProverParams,
  BoundCheckSmcWithKVProverParamsUncompressed,
  BoundCheckSmcWithKVVerifierParamsUncompressed,
  BoundCheckSmcWithKVVerifierParams
} from '../src';
import { areUint8ArraysEqual, checkLegoProvingKey, stringToBytes } from './utils';

describe('Bound check snark setup', () => {
  beforeAll(async () => {
    await initializeWasm();
  });

  it('setup for legosnark', () => {
    const pk = BoundCheckSnarkSetup();
    checkLegoProvingKey(pk);
  }, 90000);

  it('setup for Bulletproofs++', () => {
    const params = new BoundCheckBppParams(stringToBytes('test'));
    expect(params instanceof BoundCheckBppParams).toEqual(true);
    expect(params.decompress() instanceof BoundCheckBppParamsUncompressed).toEqual(true);

    // Using the same label to create params
    const params1 = new BoundCheckBppParams(stringToBytes('test'));
    expect(areUint8ArraysEqual(params.bytes, params1.bytes)).toEqual(true);

    // Using different label to create params
    const params2 = new BoundCheckBppParams(stringToBytes('test1'));
    expect(areUint8ArraysEqual(params.bytes, params2.bytes)).toEqual(false);
  }, 10000);

  it('setup for set-membership check based', () => {
    const params = new BoundCheckSmcParams(stringToBytes('test'));
    expect(params instanceof BoundCheckSmcParams).toEqual(true);
    expect(params.decompress() instanceof BoundCheckSmcParamsUncompressed).toEqual(true);
  }, 10000);

  it('setup for set-membership check with keyed-verification based', () => {
    const p = BoundCheckSmcWithKVSetup(stringToBytes('test'));
    expect(p[0] instanceof BoundCheckSmcWithKVProverParams).toEqual(true);
    expect(p[0].decompress() instanceof BoundCheckSmcWithKVProverParamsUncompressed).toEqual(true);
    expect(p[1] instanceof BoundCheckSmcWithKVVerifierParams).toEqual(true);
    expect(p[1].decompress() instanceof BoundCheckSmcWithKVVerifierParamsUncompressed).toEqual(true);
  }, 10000);
});
