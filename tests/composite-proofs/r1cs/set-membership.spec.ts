import {
  initializeWasm,
  CircomInputs,
  CompositeProof,
  LegoProvingKeyUncompressed,
  LegoVerifyingKeyUncompressed,
  MetaStatement,
  MetaStatements,
  ParsedR1CSFile,
  ProofSpec,
  R1CSSnarkSetup,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../../src';
import { generateFieldElementFromNumber, generateRandomFieldElement } from 'crypto-wasm-new';
import {
  checkResult,
  getParamsAndKeys,
  getRevealedUnrevealed,
  getWasmBytes,
  parseR1CSFile, proverStmt,
  signAndVerify, verifierStmt
} from '../../utils';
import {
  PublicKey,
  SecretKey,
  KeyPair,
  Signature,
  SignatureParams,
  buildWitness,
  buildVerifierStatement,
  Scheme
} from '../../scheme';

describe(`${Scheme} Proof with R1CS and Circom circuits: set membership check`, () => {
  let r1cs: ParsedR1CSFile;
  let wasm: Uint8Array;

  let provingKey: LegoProvingKeyUncompressed, verifyingKey: LegoVerifyingKeyUncompressed;

  let sigParams: SignatureParams, sigSk: SecretKey, sigPk: PublicKey;
  let messages: Uint8Array[], sig: Signature;

  const messageCount = 5;

  beforeAll(async () => {
    // Load the WASM module
    await initializeWasm();

    r1cs = await parseR1CSFile('set_membership_5_public.r1cs');
    wasm = getWasmBytes('set_membership_5_public.wasm');
  });

  it('do verifier setup', () => {
    const pk = R1CSSnarkSetup.fromParsedR1CSFile(r1cs);
    provingKey = pk.decompress();
    verifyingKey = pk.getVerifyingKeyUncompressed();
  });

  it('do signers setup', () => {
    [sigParams, sigSk, sigPk] = getParamsAndKeys(messageCount);

    messages = [];
    for (let i = 0; i < messageCount; i++) {
      messages.push(generateFieldElementFromNumber(1000 + i));
    }

    let result;
    [sig, result] = signAndVerify(messages, sigParams, sigSk, sigPk);
    checkResult(result);
  });

  it('check for message present in the set', () => {
    const publicSet = [
      generateRandomFieldElement(),
      generateRandomFieldElement(),
      generateRandomFieldElement(),
      generateRandomFieldElement(),
      messages[2]
    ];
    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(messages, new Set<number>());

    const statement1 = proverStmt(sigParams, revealedMsgs, sigPk);
    const statement2 = Statement.r1csCircomProver(r1cs, wasm, provingKey);

    const proverStatements = new Statements();
    proverStatements.add(statement1);
    proverStatements.add(statement2);

    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(0, 2);
    witnessEq1.addWitnessRef(1, 0);

    const metaStatements = new MetaStatements();
    metaStatements.add(MetaStatement.witnessEquality(witnessEq1));

    const proofSpecProver = new ProofSpec(proverStatements, metaStatements);
    expect(proofSpecProver.isValid()).toEqual(true);

    const witness1 = buildWitness(sig, unrevealedMsgs, false);

    const inputs = new CircomInputs();
    inputs.setPrivateInput('x', messages[2]);
    inputs.setPublicArrayInput('set', publicSet);
    const witness2 = Witness.r1csCircomWitness(inputs);

    const witnesses = new Witnesses(witness1);
    witnesses.add(witness2);

    const proof = CompositeProof.generate(proofSpecProver, witnesses);

    const statement3 = Statement.r1csCircomVerifier([generateFieldElementFromNumber(1), ...publicSet], verifyingKey);
    const statement4 = verifierStmt(sigParams, revealedMsgs, sigPk);

    const verifierStatements = new Statements();
    verifierStatements.add(statement4);
    verifierStatements.add(statement3);

    const proofSpecVerifier = new ProofSpec(verifierStatements, metaStatements);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    checkResult(proof.verify(proofSpecVerifier));
  });
});
