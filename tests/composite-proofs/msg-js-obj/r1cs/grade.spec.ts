import { generateFieldElementFromNumber } from 'crypto-wasm-new';
import {
  areUint8ArraysEqual,
  checkResult,
  getParamsAndKeys,
  getWasmBytes,
  parseR1CSFile,
  stringToBytes
} from '../../../utils';
import {
  initializeWasm,
  CircomInputs,
  CompositeProof,
  Encoder,
  encodeRevealedMsgs,
  getIndicesForMsgNames,
  getRevealedAndUnrevealed,
  LegoProvingKeyUncompressed,
  LegoVerifyingKeyUncompressed,
  MetaStatements,
  ParsedR1CSFile,
  ProofSpec,
  R1CSSnarkSetup,
  SignedMessages,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../../../src';
import { checkMapsEqual } from '../index';
import { defaultEncoder } from '../data-and-encoder';
import {
  SignatureParams,
  KeyPair,
  PublicKey,
  Signature,
  buildVerifierStatement,
  buildWitness,
  Scheme,
  adaptKeyForParams
} from '../../../scheme';
import { adaptedSigParams, proverStmt, signAndVerify, verifierStmt } from '../util';

// Test for scenario where the user wants to prove that his grade belongs/does not belong to the given set.
// Similar test can be written for other "set-membership" relations like user is not resident of certain cities
describe(`${Scheme} Proving that grade is either A+, A, B+, B or C`, () => {
  let encoder: Encoder;

  const label = stringToBytes('Sig params label');
  let sigPk: PublicKey, sk, params;

  let signed1: SignedMessages<Signature>;
  let signed2: SignedMessages<Signature>;

  const allowedGrades = ['A+', 'A', 'B+', 'B', 'C'];
  let encodedGrades: Uint8Array[];
  let r1cs: ParsedR1CSFile;
  let wasm: Uint8Array;

  let provingKey: LegoProvingKeyUncompressed, verifyingKey: LegoVerifyingKeyUncompressed;

  const attributesStruct = {
    fname: null,
    lname: null,
    email: null,
    SSN: null,
    'user-id': null,
    grade: null
  };

  // 1st attribute where grade is B+ and a satisfactory proof can be created
  const attributes1 = {
    fname: 'John',
    lname: 'Smith',
    email: 'john.smith@example.com',
    SSN: '123-456789-0',
    'user-id': 'user:123-xyz-#',
    grade: 'B+'
  };

  // 2nd attribute where grade is E and its not an acceptable grade so proof will fail
  const attributes2 = {
    fname: 'Carol',
    lname: 'Smith',
    email: 'carol.smith@example.com',
    SSN: '233-456788-1',
    'user-id': 'user:764-xyz-#',
    grade: 'E'
  };

  beforeAll(async () => {
    await initializeWasm();

    // Setup encoder
    encoder = new Encoder(undefined, defaultEncoder);
    encodedGrades = allowedGrades.map((g: string) => encoder.encodeDefault(g));

    // This can be done by the verifier or the verifier can publish only the Circom program and
    // prover can check that the same R1CS and WASM are generated.
    r1cs = await parseR1CSFile('set_membership_5_public.r1cs');
    wasm = getWasmBytes('set_membership_5_public.wasm');
  });

  it('verifier generates SNARk proving and verifying key', async () => {
    const pk = R1CSSnarkSetup.fromParsedR1CSFile(r1cs, 1);
    provingKey = pk.decompress();
    verifyingKey = pk.getVerifyingKeyUncompressed();
  });

  it('signers signs attributes', () => {
    // Message count shouldn't matter as `label` is known
    [params, sk, sigPk] = getParamsAndKeys(20, label);

    signed1 = signAndVerify(attributes1, encoder, label, sk, sigPk);
    signed2 = signAndVerify(attributes2, encoder, label, sk, sigPk);
  });

  it('proof verifies when grade is either A+, A, B+, B or C', () => {
    expect(encodedGrades.some((g) => areUint8ArraysEqual(g, signed1.encodedMessages['grade']))).toEqual(true);

    const revealedNames = new Set<string>();
    revealedNames.add('fname');

    const sigParams = adaptedSigParams(attributesStruct, label);
    const [revealedMsgs, unrevealedMsgs, revealedMsgsRaw] = getRevealedAndUnrevealed(
      attributes1,
      revealedNames,
      encoder
    );
    expect(revealedMsgsRaw).toEqual({ fname: 'John' });

    const statement1 = proverStmt(sigParams, revealedMsgs, sigPk);
    const statement2 = Statement.r1csCircomProver(r1cs, wasm, provingKey);

    const statementsProver = new Statements(statement1);
    const sIdx2 = statementsProver.add(statement2);

    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(0, getIndicesForMsgNames(['grade'], attributesStruct)[0]);
    witnessEq1.addWitnessRef(sIdx2, 0);

    const metaStmtsProver = new MetaStatements();
    metaStmtsProver.addWitnessEquality(witnessEq1);

    // The prover should independently construct this `ProofSpec`
    const proofSpecProver = new ProofSpec(statementsProver, metaStmtsProver);
    expect(proofSpecProver.isValid()).toEqual(true);

    const witness1 = buildWitness(signed1.signature, unrevealedMsgs, false);

    const inputs = new CircomInputs();
    inputs.setPrivateInput('x', signed1.encodedMessages['grade']);
    inputs.setPublicArrayInput('set', encodedGrades);
    const witness2 = Witness.r1csCircomWitness(inputs);

    const witnesses = new Witnesses(witness1);
    witnesses.add(witness2);

    const proof = CompositeProof.generate(proofSpecProver, witnesses);

    // Verifier independently encodes revealed messages
    const revealedMsgsFromVerifier = encodeRevealedMsgs(revealedMsgsRaw, attributesStruct, encoder);
    checkMapsEqual(revealedMsgs, revealedMsgsFromVerifier);

    const statement3 = verifierStmt(sigParams, revealedMsgs, sigPk);
    // generateFieldElementFromNumber(1) because membership is being check, use generateFieldElementFromNumber(0) for checking non-membership
    const pub = [generateFieldElementFromNumber(1), ...encodedGrades];
    const statement4 = Statement.r1csCircomVerifier(pub, verifyingKey);

    const verifierStatements = new Statements();
    verifierStatements.add(statement3);
    verifierStatements.add(statement4);

    const statementsVerifier = new Statements();
    const sIdx3 = statementsVerifier.add(statement3);
    const sIdx4 = statementsVerifier.add(statement4);

    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(sIdx3, getIndicesForMsgNames(['grade'], attributesStruct)[0]);
    witnessEq2.addWitnessRef(sIdx4, 0);

    const metaStmtsVerifier = new MetaStatements();
    metaStmtsVerifier.addWitnessEquality(witnessEq2);

    const proofSpecVerifier = new ProofSpec(verifierStatements, metaStmtsVerifier);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    checkResult(proof.verify(proofSpecVerifier));
  });

  it('proof does not verify when grade is none of A+, A, B+, B or C but E', () => {
    expect(encodedGrades.some((g) => areUint8ArraysEqual(g, signed2.encodedMessages['grade']))).toEqual(false);

    const revealedNames = new Set<string>();
    revealedNames.add('fname');

    const sigParams = adaptedSigParams(attributesStruct, label);
    const [revealedMsgs, unrevealedMsgs, revealedMsgsRaw] = getRevealedAndUnrevealed(
      attributes2,
      revealedNames,
      encoder
    );
    expect(revealedMsgsRaw).toEqual({ fname: 'Carol' });

    const statement1 = proverStmt(sigParams, revealedMsgs, sigPk);
    const statement2 = Statement.r1csCircomProver(r1cs, wasm, provingKey);

    const statementsProver = new Statements();
    const sIdx1 = statementsProver.add(statement1);
    const sIdx2 = statementsProver.add(statement2);

    const metaStmtsProver = new MetaStatements();
    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(sIdx1, getIndicesForMsgNames(['grade'], attributesStruct)[0]);
    witnessEq1.addWitnessRef(sIdx2, 0);

    metaStmtsProver.addWitnessEquality(witnessEq1);

    // The prover should independently construct this `ProofSpec`
    const proofSpecProver = new ProofSpec(statementsProver, metaStmtsProver);
    expect(proofSpecProver.isValid()).toEqual(true);

    const witness1 = buildWitness(signed2.signature, unrevealedMsgs, false);

    const inputs = new CircomInputs();
    inputs.setPrivateInput('x', signed2.encodedMessages['grade']);
    inputs.setPublicArrayInput('set', encodedGrades);
    const witness2 = Witness.r1csCircomWitness(inputs);

    const witnesses = new Witnesses(witness1);
    witnesses.add(witness2);

    const proof = CompositeProof.generate(proofSpecProver, witnesses);

    // Verifier independently encodes revealed messages
    const revealedMsgsFromVerifier = encodeRevealedMsgs(revealedMsgsRaw, attributesStruct, encoder);
    checkMapsEqual(revealedMsgs, revealedMsgsFromVerifier);

    const statement3 = verifierStmt(sigParams, revealedMsgs, sigPk);
    const pub = [generateFieldElementFromNumber(0), ...encodedGrades];
    const statement4 = Statement.r1csCircomVerifier(pub, verifyingKey);

    const verifierStatements = new Statements(statement3);
    verifierStatements.add(statement4);

    const statementsVerifier = new Statements();
    const sIdx3 = statementsVerifier.add(statement3);
    const sIdx4 = statementsVerifier.add(statement4);

    const metaStmtsVerifier = new MetaStatements();
    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(sIdx3, getIndicesForMsgNames(['grade'], attributesStruct)[0]);
    witnessEq2.addWitnessRef(sIdx4, 0);

    metaStmtsVerifier.addWitnessEquality(witnessEq2);

    const proofSpecVerifier = new ProofSpec(verifierStatements, metaStmtsVerifier);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    checkResult(proof.verify(proofSpecVerifier));
  });
});
