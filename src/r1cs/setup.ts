import { LegoProvingKey } from '../legosnark';
import { R1CS, r1csSnarkSetup } from 'crypto-wasm-new';
import { ParsedR1CSFile, processParsedR1CSFile } from './file';

/**
 * Create SNARK proving and verifying key from the parsed R1CS file.
 */
export class R1CSSnarkSetup {
  /**
   * Create proving key from a parsed R1CS file. Returns the compressed proving key.
   * @param parsedR1cs
   * @param commitWitnessCount - If not provided, uses the number of private inputs (only explicitly defined, not intermediate)
   * to the circuit
   */
  static fromParsedR1CSFile(parsedR1cs: ParsedR1CSFile, commitWitnessCount?: number): LegoProvingKey {
    if (commitWitnessCount === undefined) {
      commitWitnessCount = parsedR1cs.nPrvInputs;
    }
    const processedR1cs = processParsedR1CSFile(parsedR1cs);
    return R1CSSnarkSetup.fromR1CS(processedR1cs, commitWitnessCount);
  }

  static fromR1CS(processedR1cs: R1CS, commitWitnessCount: number): LegoProvingKey {
    const pk = r1csSnarkSetup(
      processedR1cs.curveName,
      processedR1cs.numPublic,
      processedR1cs.numPrivate,
      processedR1cs.constraints as [],
      commitWitnessCount,
      false // return compressed key
    );
    return new LegoProvingKey(pk);
  }
}
