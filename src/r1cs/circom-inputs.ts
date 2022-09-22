/**
 * Prepare inputs given to the Circom program for feeding into composite proof system.
 */
export class CircomInputs {
  // Mapping of input (signal) name to value(s)
  wires: Map<string, Uint8Array[]>;
  // Names of private inputs. Must be in the order that they are defined in the program
  privates: string[];
  // Names of public inputs.
  publics: string[];

  constructor() {
    this.wires = new Map<string, Uint8Array[]>();
    this.privates = [];
    this.publics = [];
  }

  /**
   * Set a private input with a non-array value
   * @param name
   * @param value
   */
  setPrivateInput(name: string, value: Uint8Array) {
    this.setWire(name, [value]);
    this.privates.push(name);
  }

  /**
   * Set a private input with am array value
   * @param name
   * @param values
   */
  setPrivateArrayInput(name: string, values: Uint8Array[]) {
    this.setWire(name, values);
    this.privates.push(name);
  }

  /**
   * Set a public input with a non-array value
   * @param name
   * @param value
   */
  setPublicInput(name: string, value: Uint8Array) {
    this.setWire(name, [value]);
    this.publics.push(name);
  }

  /**
   * Set a public input with am array value
   * @param name
   * @param values
   */
  setPublicArrayInput(name: string, values: Uint8Array[]) {
    this.setWire(name, values);
    this.publics.push(name);
  }

  ensureInputUnset(name: string) {
    if (this.wires.has(name)) {
      throw new Error(`Input ${name} already set`);
    }
  }

  private setWire(name: string, values: Uint8Array[]) {
    this.ensureInputUnset(name);
    this.wires.set(name, values);
  }
}