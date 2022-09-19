import { CircomInputs } from './circom-inputs';
import { R1CS, r1csCircuitSatisfied, r1csGenerateWires } from '@docknetwork/crypto-wasm';
import { getR1CS, ParsedR1CSFile } from './index';

export class CircomCircuit {
  static generateWires(wasmBytes: Uint8Array, inputs: CircomInputs): Uint8Array[] {
    return r1csGenerateWires(wasmBytes, inputs.wires);
  }

  static isSatisfied(r1cs: R1CS | ParsedR1CSFile, wasmBytes: Uint8Array, inputs: CircomInputs): boolean {
    let processedR1cs = getR1CS(r1cs);
    return r1csCircuitSatisfied(
      processedR1cs.curveName,
      processedR1cs.numPublic,
      processedR1cs.numPrivate,
      processedR1cs.constraints,
      wasmBytes,
      inputs.wires
    );
  }
}