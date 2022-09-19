import { generateFieldElementFromNumber, initializeWasm } from '@docknetwork/crypto-wasm';
import { areUint8ArraysEqual, checkResult, getWasmBytes, parseR1CSFile, stringToBytes } from '../../../utils';
import {
  BBSPlusPublicKeyG2,
  CircomInputs, CompositeProofG1,
  Encoder, encodeRevealedMsgs,
  getIndicesForMsgNames,
  getRevealedAndUnrevealed,
  getSigParamsForMsgStructure,
  KeypairG2,
  LegoProvingKeyUncompressed,
  LegoVerifyingKeyUncompressed, MetaStatements,
  ParsedR1CSFile, ProofSpecG1,
  R1CSSnarkSetup,
  SignatureParamsG1,
  SignedMessages,
  signMessageObject, Statement, Statements,
  verifyMessageObject, Witness, WitnessEqualityMetaStatement, Witnesses
} from '../../../../src';
import { checkMapsEqual, defaultEncoder } from '../index';


describe('Proving that blood group is not AB-', () => {
  let encoder: Encoder;
  let encodedABNeg: Uint8Array;

  const label = stringToBytes('Sig params label');
  let sigPk: BBSPlusPublicKeyG2;

  let signed1: SignedMessages;
  let signed2: SignedMessages;

  let r1cs: ParsedR1CSFile;
  let wasm: Uint8Array;

  let provingKey: LegoProvingKeyUncompressed, verifyingKey: LegoVerifyingKeyUncompressed;

  const attributesStruct = {
    fname: undefined,
    lname: undefined,
    verySensitive: {
      email: undefined,
      SSN: undefined,
    },
    physical: {
      gender: undefined,
      bloodGroup: undefined
    },
    'user-id': undefined,
  };

  // 1st attribute where blood group is AB+ and a satisfactory proof can be created
  const attributes1 = {
    fname: 'John',
    lname: 'Smith',
    verySensitive: {
      email: 'john.smith@example.com',
      SSN: '123-456789-0',
    },
    physical: {
      gender: 'male',
      bloodGroup: 'AB+'
    },
    'user-id': 'user:123-xyz-#'
  };

  // 2nd attribute where blood group is AB- and its not acceptable so proof will fail
  const attributes2 = {
    fname: 'Carol',
    lname: 'Smith',
    verySensitive: {
      email: 'carol.smith@example.com',
      SSN: '233-456788-1',
    },
    physical: {
      gender: 'female',
      bloodGroup: 'AB-'
    },
    'user-id': 'user:764-xyz-#',
  };

  beforeAll(async () => {
    await initializeWasm();

    // Setup encoder
    encoder = new Encoder(undefined, defaultEncoder);

    encodedABNeg = encoder.encodeDefault('AB-');

    // This should ideally be done by the verifier but the verifier can publish only the Circom program and
    // prover can check that the same R1CS and WASM are generated.
    r1cs = await parseR1CSFile('not_equal_public.r1cs');
    wasm = getWasmBytes('not_equal_public.wasm');
  });

  it('verifier generates SNARk proving and verifying key', async () => {
    const pk = R1CSSnarkSetup.fromParsedR1CSFile(r1cs, 1);
    provingKey = pk.decompress();
    verifyingKey = pk.getVerifyingKeyUncompressed();
  });

  it('signers signs attributes', () => {
    // Message count shouldn't matter as `label` is known
    let params = SignatureParamsG1.generate(1, label);
    const keypair = KeypairG2.generate(params);
    const sk = keypair.secretKey;
    sigPk = keypair.publicKey;

    signed1 = signMessageObject(attributes1, sk, label, encoder);
    expect(verifyMessageObject(attributes1, signed1.signature, sigPk, label, encoder)).toBe(true);

    signed2 = signMessageObject(attributes2, sk, label, encoder);
    expect(verifyMessageObject(attributes2, signed2.signature, sigPk, label, encoder)).toBe(true);
  });

  it('proof verifies when blood groups is not AB-', () => {
    expect(areUint8ArraysEqual(encodedABNeg, signed1.encodedMessages['physical.bloodGroup'])).toEqual(false);

    const revealedNames = new Set<string>();
    revealedNames.add('fname');

    const sigParams = getSigParamsForMsgStructure(attributesStruct, label);
    const [revealedMsgs, unrevealedMsgs, revealedMsgsRaw] = getRevealedAndUnrevealed(
      attributes1,
      revealedNames,
      encoder
    );
    expect(revealedMsgsRaw).toEqual({ fname: 'John' });

    const statement1 = Statement.bbsSignature(sigParams, sigPk, revealedMsgs, false);
    const statement2 = Statement.r1csCircomProver(r1cs, wasm, provingKey);

    const statementsProver = new Statements();
    const sIdx1 = statementsProver.add(statement1);
    const sIdx2 = statementsProver.add(statement2);

    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(sIdx1, getIndicesForMsgNames(['physical.bloodGroup'], attributesStruct)[0]);
    witnessEq1.addWitnessRef(sIdx2, 0);

    const metaStmtsProver = new MetaStatements();
    metaStmtsProver.addWitnessEquality(witnessEq1);

    // The prover should independently construct this `ProofSpec`
    const proofSpecProver = new ProofSpecG1(statementsProver, metaStmtsProver);
    expect(proofSpecProver.isValid()).toEqual(true);

    const witness1 = Witness.bbsSignature(signed1.signature, unrevealedMsgs, false);

    const inputs = new CircomInputs();
    inputs.setInput('in', signed1.encodedMessages['physical.bloodGroup']);
    inputs.setInput('pub', encodedABNeg);
    const witness2 = Witness.r1csCircomWitness(inputs);

    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);

    const proof = CompositeProofG1.generate(proofSpecProver, witnesses);

    // Verifier independently encodes revealed messages
    const revealedMsgsFromVerifier = encodeRevealedMsgs(revealedMsgsRaw, attributesStruct, encoder);
    checkMapsEqual(revealedMsgs, revealedMsgsFromVerifier);

    const statement3 = Statement.bbsSignature(sigParams, sigPk, revealedMsgsFromVerifier, false);
    const pub = [generateFieldElementFromNumber(1), encodedABNeg];
    const statement4 = Statement.r1csCircomVerifier(pub, verifyingKey);

    const statementsVerifier = new Statements();
    const sIdx3 = statementsVerifier.add(statement3);
    const sIdx4 = statementsVerifier.add(statement4);

    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(sIdx3, getIndicesForMsgNames(['physical.bloodGroup'], attributesStruct)[0]);
    witnessEq2.addWitnessRef(sIdx4, 0);

    const metaStmtsVerifier = new MetaStatements();
    metaStmtsVerifier.addWitnessEquality(witnessEq2);

    const proofSpecVerifier = new ProofSpecG1(statementsVerifier, metaStmtsVerifier);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    checkResult(proof.verify(proofSpecVerifier));
  });

  it('proof does not verify when blood groups is AB-', () => {
    expect(areUint8ArraysEqual(encodedABNeg, signed2.encodedMessages['physical.bloodGroup'])).toEqual(true);

    const revealedNames = new Set<string>();
    revealedNames.add('fname');

    const sigParams = getSigParamsForMsgStructure(attributesStruct, label);
    const [revealedMsgs, unrevealedMsgs, revealedMsgsRaw] = getRevealedAndUnrevealed(
      attributes2,
      revealedNames,
      encoder
    );
    expect(revealedMsgsRaw).toEqual({ fname: 'Carol' });

    const statement1 = Statement.bbsSignature(sigParams, sigPk, revealedMsgs, false);
    const statement2 = Statement.r1csCircomProver(r1cs, wasm, provingKey);

    const statementsProver = new Statements();
    const sIdx1 = statementsProver.add(statement1);
    const sIdx2 = statementsProver.add(statement2);

    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(sIdx1, getIndicesForMsgNames(['physical.bloodGroup'], attributesStruct)[0]);
    witnessEq1.addWitnessRef(sIdx2, 0);

    const metaStmtsProver = new MetaStatements();
    metaStmtsProver.addWitnessEquality(witnessEq1);

    // The prover should independently construct this `ProofSpec`
    const proofSpecProver = new ProofSpecG1(statementsProver, metaStmtsProver);
    expect(proofSpecProver.isValid()).toEqual(true);

    const witness1 = Witness.bbsSignature(signed2.signature, unrevealedMsgs, false);

    const inputs = new CircomInputs();
    inputs.setInput('in', signed2.encodedMessages['physical.bloodGroup']);
    inputs.setInput('pub', encodedABNeg);
    const witness2 = Witness.r1csCircomWitness(inputs);

    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);

    const proof = CompositeProofG1.generate(proofSpecProver, witnesses);

    // Verifier independently encodes revealed messages
    const revealedMsgsFromVerifier = encodeRevealedMsgs(revealedMsgsRaw, attributesStruct, encoder);
    checkMapsEqual(revealedMsgs, revealedMsgsFromVerifier);

    const statement3 = Statement.bbsSignature(sigParams, sigPk, revealedMsgsFromVerifier, false);
    const pub = [generateFieldElementFromNumber(1), encodedABNeg];
    const statement4 = Statement.r1csCircomVerifier(pub, verifyingKey);

    const statementsVerifier = new Statements();
    const sIdx3 = statementsVerifier.add(statement3);
    const sIdx4 = statementsVerifier.add(statement4);

    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(sIdx3, getIndicesForMsgNames(['physical.bloodGroup'], attributesStruct)[0]);
    witnessEq2.addWitnessRef(sIdx4, 0);

    const metaStmtsVerifier = new MetaStatements();
    metaStmtsVerifier.addWitnessEquality(witnessEq2);

    const proofSpecVerifier = new ProofSpecG1(statementsVerifier, metaStmtsVerifier);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    expect(proof.verify(proofSpecVerifier).verified).toEqual(false);
  });
})