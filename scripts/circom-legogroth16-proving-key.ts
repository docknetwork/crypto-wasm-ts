#!/usr/bin/env ts-node

import * as path from 'path';
import * as r1csf from 'r1csfile';
import { Command } from 'commander';
import { initializeWasm, R1CSSnarkSetup } from '../src';
import { addCommonOptions, writeLegosnarkKeysToFiles } from './helpers';

async function main() {
  const program = new Command();
  program
    .argument('<r1csFile>', 'Absolute path of the R1CS file of the circuit');

  addCommonOptions(program, 'circom')

  program.parse();

  const fileName = program.args[0];
  if (path.extname(fileName) !== '.r1cs') {
    throw new Error('The file must be an R1CS file and its extension should be .r1cs');
  }
  if (!path.isAbsolute(fileName)) {
    throw new Error('Provide an absolute path for the file');
  }
  const opts = program.opts();

  await initializeWasm();
  const parsed = await r1csf.readR1cs(fileName);
  const pk = R1CSSnarkSetup.fromParsedR1CSFile(parsed);
  writeLegosnarkKeysToFiles(pk, opts);
  process.exit(0);
}


main()
