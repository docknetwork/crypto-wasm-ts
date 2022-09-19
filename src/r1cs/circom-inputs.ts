export class CircomInputs {
  wires: Map<string, Uint8Array[]>;

  constructor() {
    this.wires = new Map<string, Uint8Array[]>();
  }

  setInput(name: string, value: Uint8Array) {
    this.ensureInputUnset(name);
    this.wires.set(name, [value]);
  }

  setArrayInput(name: string, values: Uint8Array[]) {
    this.ensureInputUnset(name);
    this.wires.set(name, values);
  }

  ensureInputUnset(name: string) {
    if (this.wires.has(name)) {
      throw new Error(`Input ${name} already set`);
    }
  }
}