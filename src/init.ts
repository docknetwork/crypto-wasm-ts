import {
  initializeWasm as newInit,
  isWasmInitialized as newCheck,
  requireWasmInitialized as newRequire
} from 'crypto-wasm-new';

export async function initializeWasm() {
  await newInit();
}

export function isWasmInitialized(): boolean {
  return newCheck();
}

export function requireWasmInitialized() {
  newRequire();
}
