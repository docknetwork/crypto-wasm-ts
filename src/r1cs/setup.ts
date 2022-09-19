import { LegoProvingKey } from '../legosnark';
import { R1CS, r1csSnarkSetup } from '@docknetwork/crypto-wasm';
import { ParsedR1CSFile, processParsedR1CSFile } from './index';

export class R1CSSnarkSetup {
  static fromParsedR1CSFile(parsedR1cs: ParsedR1CSFile, commitWitnessCount?: number): LegoProvingKey {
    if (commitWitnessCount === undefined) {
      commitWitnessCount = parsedR1cs.nPrvInputs;
    }
    const processedR1cs = processParsedR1CSFile(parsedR1cs);
    return R1CSSnarkSetup.fromR1CS(processedR1cs, commitWitnessCount);
  }

  static fromR1CS(processedR1cs: R1CS, commitWitnessCount: number): LegoProvingKey {
    const pk = r1csSnarkSetup(processedR1cs.curveName, processedR1cs.numPublic, processedR1cs.numPrivate, processedR1cs.constraints as [], commitWitnessCount, false);
    return new LegoProvingKey(pk);
  }
}