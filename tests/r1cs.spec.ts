import { generateFieldElementFromNumber, initializeWasm } from '@docknetwork/crypto-wasm';
import { checkLegoProvingKey, fromLeToBigInt, getWasmBytes, parseR1CSFile } from './utils';
import { CircomCircuit, CircomInputs, processParsedR1CSFile, R1CSSnarkSetup } from '../src';

describe('For R1CS from Circom', () => {
  beforeAll(async () => {
    // Load the WASM module
    await initializeWasm();
  });

  it('check less_than circuit', async () => {
    const ltR1cs = await parseR1CSFile('less_than_32.r1cs');
    const ltWasm = getWasmBytes('less_than_32.wasm');

    const ltInputs = new CircomInputs();
    ltInputs.setPrivateInput('a', generateFieldElementFromNumber(100));
    ltInputs.setPrivateInput('b', generateFieldElementFromNumber(200));

    expect(CircomCircuit.isSatisfied(ltR1cs, ltWasm, ltInputs));

    const wires = CircomCircuit.generateWires(ltWasm, ltInputs);
    expect(fromLeToBigInt(wires[0])).toEqual(BigInt("1"));
    expect(fromLeToBigInt(wires[1])).toEqual(BigInt("1"));
    expect(fromLeToBigInt(wires[2])).toEqual(BigInt("100"));
    expect(fromLeToBigInt(wires[3])).toEqual(BigInt("200"));

    const ltInputs1 = new CircomInputs();
    ltInputs1.setPrivateInput('a', generateFieldElementFromNumber(200));
    ltInputs1.setPrivateInput('b', generateFieldElementFromNumber(100));

    expect(CircomCircuit.isSatisfied(ltR1cs, ltWasm, ltInputs1));

    const wires1 = CircomCircuit.generateWires(ltWasm, ltInputs1);
    expect(fromLeToBigInt(wires1[0])).toEqual(BigInt("1"));
    expect(fromLeToBigInt(wires1[1])).toEqual(BigInt("0"));
    expect(fromLeToBigInt(wires1[2])).toEqual(BigInt("200"));
    expect(fromLeToBigInt(wires1[3])).toEqual(BigInt("100"));
  });

  it('check less_than_public circuit', async () => {
    const ltPubR1cs = await parseR1CSFile('less_than_public_64.r1cs');
    const ltPubWasm = getWasmBytes('less_than_public_64.wasm');

    const ltPubInputs = new CircomInputs();
    ltPubInputs.setPrivateInput('a', generateFieldElementFromNumber(100));
    ltPubInputs.setPublicInput('b', generateFieldElementFromNumber(200));

    expect(CircomCircuit.isSatisfied(ltPubR1cs, ltPubWasm, ltPubInputs));

    const wires = CircomCircuit.generateWires(ltPubWasm, ltPubInputs);
    expect(fromLeToBigInt(wires[0])).toEqual(BigInt("1"));
    expect(fromLeToBigInt(wires[1])).toEqual(BigInt("1"));
    expect(fromLeToBigInt(wires[2])).toEqual(BigInt("200"));
    expect(fromLeToBigInt(wires[3])).toEqual(BigInt("100"));

    const ltPubInputs1 = new CircomInputs();
    ltPubInputs1.setPrivateInput('a', generateFieldElementFromNumber(200));
    ltPubInputs1.setPublicInput('b', generateFieldElementFromNumber(100));

    expect(CircomCircuit.isSatisfied(ltPubR1cs, ltPubWasm, ltPubInputs1));

    const wires1 = CircomCircuit.generateWires(ltPubWasm, ltPubInputs1);
    expect(fromLeToBigInt(wires1[0])).toEqual(BigInt("1"));
    expect(fromLeToBigInt(wires1[1])).toEqual(BigInt("0"));
    expect(fromLeToBigInt(wires1[2])).toEqual(BigInt("100"));
    expect(fromLeToBigInt(wires1[3])).toEqual(BigInt("200"));
  });

  it('generate proving key for less_than circuit', async () => {
    const ltR1cs = await parseR1CSFile('less_than_32.r1cs');
    const pk = R1CSSnarkSetup.fromParsedR1CSFile(ltR1cs);
    checkLegoProvingKey(pk);

    const processedR1cs = processParsedR1CSFile(ltR1cs);
    const pk1 = R1CSSnarkSetup.fromR1CS(processedR1cs, 2);
    checkLegoProvingKey(pk1);
  });

  it('generate proving key for less_than_public circuit', async () => {
    const ltPubR1cs = await parseR1CSFile('less_than_public_64.r1cs');
    const pk = R1CSSnarkSetup.fromParsedR1CSFile(ltPubR1cs);
    checkLegoProvingKey(pk);

    const processedR1cs = processParsedR1CSFile(ltPubR1cs);
    const pk1 = R1CSSnarkSetup.fromR1CS(processedR1cs, 1);
    checkLegoProvingKey(pk1);
  });
});