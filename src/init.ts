import {
  initializeWasm as newInit,
  isWasmInitialized as newCheck,
  requireWasmInitialized as newRequire
} from 'crypto-wasm-new';
import {
  initializeWasm as oldInit,
  isWasmInitialized as oldCheck,
  requireWasmInitialized as oldRequire
} from 'crypto-wasm-old';

export async function initializeWasm() {
  await oldInit();
  await newInit();
}

export function isWasmInitialized(): boolean {
  return oldCheck() && newCheck();
}

export function requireWasmInitialized() {
  oldRequire();
  newRequire();
}
