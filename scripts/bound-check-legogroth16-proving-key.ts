#!/usr/bin/env ts-node

import { Command } from 'commander';
import { BoundCheckSnarkSetup, initializeWasm } from '../src';
import { addCommonOptions, writeLegosnarkKeysToFiles } from './helpers';

async function main() {
  const program = new Command();

  addCommonOptions(program, 'bound-check')

  program.parse();
  const opts = program.opts();

  await initializeWasm();
  const pk = BoundCheckSnarkSetup();
  writeLegosnarkKeysToFiles(pk, opts);
  process.exit(0);
}

main()
