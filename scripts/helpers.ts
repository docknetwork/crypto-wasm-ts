import fs from 'fs';
import path from 'path';
import { Command, Option } from 'commander';
import { getProvingAndVerifiyingKeyBytes, LegoProvingKey } from '../src';

export function addCommonOptions(cmd: Command, defaultPrefix: string) {
  // TODO: Following commented format does not work. Find out why?
  // .option('--prefix <file name prefix>', 'Prefix of the names of proving and verifying key files', defaultPrefix)
  cmd
    .addOption(new Option('--prefix <file name prefix>', 'Prefix of the names of proving and verifying key files').default(defaultPrefix))
    .option('--uncompressed <true or false>', 'Whether to return the keys in uncompressed form or not', false);
}

export function writeLegosnarkKeysToFiles(pk: LegoProvingKey, options: Record<string, any>) {
  const pkFileName = `${options.prefix}-proving-key.bin`;
  const vkFileName = `${options.prefix}-verifying-key.bin`;
  if (options.uncompressed) {
    console.info(`Generating uncompressed proving and verification files as ${pkFileName} and ${vkFileName}`);
  } else {
    console.info(`Generating compressed proving and verification files as ${pkFileName} and ${vkFileName}`);
  }
  const [pkBytes, vkBytes] = getProvingAndVerifiyingKeyBytes(pk, options.uncompressed);
  fs.writeFileSync(`${path.resolve('./')}/${pkFileName}`, pkBytes);
  fs.writeFileSync(`${path.resolve('./')}/${vkFileName}`, vkBytes);
}