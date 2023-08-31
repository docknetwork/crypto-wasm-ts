#!/usr/bin/env ts-node

import * as fs from 'fs';
import * as path from 'path';

import { Command, Option } from 'commander';
import {
  dockSaverEncryptionGens,
  getChunkBitSize,
  initializeWasm, SaverDecryptor,
} from '../src';
import { addCommonOptions } from './helpers';

async function main() {
  const program = new Command();
  program
    .addOption(new Option('--chunkBitSize [size]', 'chunk bit size').default(16).argParser((c) => {
      return getChunkBitSize(parseInt(c))
    }));

  addCommonOptions(program, 'saver')

  program.parse();
  const opts = program.opts();

  await initializeWasm();
  const encGens = dockSaverEncryptionGens();
  const suffix = opts.uncompressed ? '-uncompressed' : '';
  const pkFileName = `${opts.prefix}-proving-key-16${suffix}.bin`;
  const vkFileName = `${opts.prefix}-verifying-key-16${suffix}.bin`;
  const ekFileName = `${opts.prefix}-encryption-key-16${suffix}.bin`;
  const dkFileName = `${opts.prefix}-decryption-key-16${suffix}.bin`;
  const skFileName = `${opts.prefix}-secret-key-16.bin`;
  let comp: string;
  if (opts.uncompressed) {
    comp = 'uncompressed';
  } else {
    comp = 'compressed';
  }
  console.info(`Generating ${comp} proving, verification, encryption, decryption and secret key files as ${pkFileName}, ${vkFileName}, ${ekFileName}, ${dkFileName}, ${skFileName}`);
  const [snarkPk, sk, ek, dk] = SaverDecryptor.setup(encGens, opts.chunkBitSize);

  let pkBytes, vkBytes, ekBytes, dkBytes;
  const skBytes = sk.bytes;
  if (opts.uncompressed) {
    pkBytes = snarkPk.decompress().bytes;
    vkBytes = snarkPk.getVerifyingKeyUncompressed().bytes;
    ekBytes = ek.decompress().bytes;
    dkBytes = dk.decompress().bytes;
  } else {
    pkBytes = snarkPk.bytes;
    vkBytes = snarkPk.getVerifyingKey().bytes;
    ekBytes = ek.bytes;
    dkBytes = dk.bytes;
  }

  fs.writeFileSync(`${path.resolve('./')}/${pkFileName}`, pkBytes);
  fs.writeFileSync(`${path.resolve('./')}/${vkFileName}`, vkBytes);
  fs.writeFileSync(`${path.resolve('./')}/${ekFileName}`, ekBytes);
  fs.writeFileSync(`${path.resolve('./')}/${dkFileName}`, dkBytes);
  fs.writeFileSync(`${path.resolve('./')}/${skFileName}`, skBytes);
}

main()