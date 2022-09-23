import { CircomInputs } from './circom-inputs';
import { R1CS, r1csCircuitSatisfied, r1csGenerateWires } from '@docknetwork/crypto-wasm';
import { getR1CS, ParsedR1CSFile } from './index';

export class CircomCircuit {
  /**
   * Generate all the wires of the circuit, including the explicit input "1", public and private
   * @param wasmBytes
   * @param inputs
   */
  static generateWires(wasmBytes: Uint8Array, inputs: CircomInputs): Uint8Array[] {
    return r1csGenerateWires(wasmBytes, inputs.wires);
  }

  /**
   * For the circuit given by the R1CS and WASM files, check if its constraints are satisfied with the given (public and private)
   * inputs.
   * @param r1cs
   * @param wasmBytes
   * @param inputs
   */
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
