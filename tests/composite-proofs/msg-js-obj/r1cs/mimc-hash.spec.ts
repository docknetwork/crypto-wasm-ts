import { generateFieldElementFromNumber, initializeWasm } from '@docknetwork/crypto-wasm';
import { checkResult, getWasmBytes, parseR1CSFile, stringToBytes } from '../../../utils';
import {
  BBSPlusPublicKeyG2,
  CircomInputs,
  CompositeProofG1,
  EncodeFunc,
  Encoder,
  encodeRevealedMsgs,
  getIndicesForMsgNames,
  getRevealedAndUnrevealed,
  getSigParamsForMsgStructure,
  KeypairG2,
  LegoProvingKeyUncompressed,
  LegoVerifyingKeyUncompressed,
  MetaStatements,
  ParsedR1CSFile,
  ProofSpecG1,
  R1CSSnarkSetup,
  SignatureParamsG1,
  SignedMessages,
  signMessageObject,
  Statement,
  Statements,
  verifyMessageObject,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../../../src';
import { checkMapsEqual } from '../index';
import { defaultEncoder } from '../data-and-encoder';

// Test for a scenario where user wants to prove that certain attribute of his credential is the preimage of a public MiMC hash.
describe('Proving that blood group is not AB-', () => {
  let encoder: Encoder;
  let encodedPubKeyHash: Uint8Array;

  const pubKeyHash = '30898ada1347d8fc53ffe37656edd4f8c42d4b791730ce05a1f41b72bc30f039'; // This is a big-endian hex string

  const label = stringToBytes('Sig params label');
  let sigPk: BBSPlusPublicKeyG2;

  let signed1: SignedMessages;
  let signed2: SignedMessages;

  let r1cs: ParsedR1CSFile;
  let wasm: Uint8Array;

  let provingKey: LegoProvingKeyUncompressed, verifyingKey: LegoVerifyingKeyUncompressed;

  const attributesStruct = {
    fname: null,
    lname: null,
    sensitive: {
      email: null,
      SSN: null
    },
    verySensitive: {
      publicKey: null // public key will be a big-endian hex string
    }
  };

  // 2 credentials, wherein the 1st credential's attribute hash matching the expected value whereas 2nd credential's does not.
  const attributes1 = {
    fname: 'John',
    lname: 'Smith',
    sensitive: {
      email: 'john.smith@example.com',
      SSN: '123-456789-0'
    },
    verySensitive: {
      publicKey: '4aad01ece9c61230791a0251b1bcb17e06614ed3a27f0e55c060cff7072afd70'
    }
  };
  const attributes2 = {
    fname: 'Carol',
    lname: 'Smith',
    sensitive: {
      email: 'carol.smith@example.com',
      SSN: '233-456788-1'
    },
    verySensitive: {
      publicKey: '699201275c7b728a133a3cd9135f218aa951a2274432c9381fedd8a6ed7e497a'
    }
  };

  beforeAll(async () => {
    await initializeWasm();

    // Setup encoder

    // Convert big-endian hex to little-endian bytearray
    function beHexToLeByteArray(h: unknown): Uint8Array {
      // This should do additional input validation in practice
      const b = Uint8Array.from(Buffer.from(h as string, 'hex'));
      b.reverse();
      return b;
    }

    const encoders = new Map<string, EncodeFunc>();
    // As the public key is specified as an hex, it needs to be converted to bytes first.
    encoders.set('verySensitive.publicKey', beHexToLeByteArray);
    encoder = new Encoder(encoders, defaultEncoder);
    encodedPubKeyHash = beHexToLeByteArray(pubKeyHash);

    // This should ideally be done by the verifier but the verifier can publish only the Circom program and
    // prover can check that the same R1CS and WASM are generated.
    r1cs = await parseR1CSFile('mimc_hash_bls12_381.r1cs');
    wasm = getWasmBytes('mimc_hash_bls12_381.wasm');
  });

  it('verifier generates SNARk proving and verifying key', async () => {
    console.time('Snark setup');
    const pk = R1CSSnarkSetup.fromParsedR1CSFile(r1cs, 1);
    console.timeEnd('Snark setup');
    console.time('Decompress keys');
    provingKey = pk.decompress();
    verifyingKey = pk.getVerifyingKeyUncompressed();
    console.timeEnd('Decompress keys');
  });

  it('signers signs attributes', () => {
    // Message count shouldn't matter as `label` is known
    let params = SignatureParamsG1.generate(1, label);
    const keypair = KeypairG2.generate(params);
    const sk = keypair.secretKey;
    sigPk = keypair.publicKey;

    signed1 = signMessageObject(attributes1, sk, label, encoder);
    checkResult(verifyMessageObject(attributes1, signed1.signature, sigPk, label, encoder));

    signed2 = signMessageObject(attributes2, sk, label, encoder);
    checkResult(verifyMessageObject(attributes2, signed2.signature, sigPk, label, encoder));
  });

  it('proof verifies when public key hash matches the expected hash', () => {
    check(signed1, true);
  });

  it('proof fails to verify when public key hash does not match the expected hash', () => {
    check(signed2, false);
  });

  function check(signed: SignedMessages, doesCheckPass) {
    const revealedNames = new Set<string>();
    revealedNames.add('fname');

    const sigParams = getSigParamsForMsgStructure(attributesStruct, label);
    const [revealedMsgs, unrevealedMsgs, revealedMsgsRaw] = getRevealedAndUnrevealed(
      attributes1,
      revealedNames,
      encoder
    );
    expect(revealedMsgsRaw).toEqual({ fname: 'John' });

    console.time('Proof generate');
    const statement1 = Statement.bbsSignature(sigParams, sigPk, revealedMsgs, false);
    const statement2 = Statement.r1csCircomProver(r1cs, wasm, provingKey);

    const statementsProver = new Statements();
    const sIdx1 = statementsProver.add(statement1);
    const sIdx2 = statementsProver.add(statement2);

    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(sIdx1, getIndicesForMsgNames(['verySensitive.publicKey'], attributesStruct)[0]);
    witnessEq1.addWitnessRef(sIdx2, 0);

    const metaStmtsProver = new MetaStatements();
    metaStmtsProver.addWitnessEquality(witnessEq1);

    // The prover should independently construct this `ProofSpec`
    const proofSpecProver = new ProofSpecG1(statementsProver, metaStmtsProver);
    expect(proofSpecProver.isValid()).toEqual(true);

    const witness1 = Witness.bbsSignature(signed.signature, unrevealedMsgs, false);

    const inputs = new CircomInputs();
    inputs.setPrivateInput('in', signed.encodedMessages['verySensitive.publicKey']);
    inputs.setPublicInput('k', generateFieldElementFromNumber(0));
    const witness2 = Witness.r1csCircomWitness(inputs);

    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);

    const proof = CompositeProofG1.generate(proofSpecProver, witnesses);
    console.timeEnd('Proof generate');

    console.time('Proof verify');
    // Verifier independently encodes revealed messages
    const revealedMsgsFromVerifier = encodeRevealedMsgs(revealedMsgsRaw, attributesStruct, encoder);
    checkMapsEqual(revealedMsgs, revealedMsgsFromVerifier);

    const statement3 = Statement.bbsSignature(sigParams, sigPk, revealedMsgsFromVerifier, false);
    const pub = [encodedPubKeyHash];
    const statement4 = Statement.r1csCircomVerifier(pub, verifyingKey);

    const statementsVerifier = new Statements();
    const sIdx3 = statementsVerifier.add(statement3);
    const sIdx4 = statementsVerifier.add(statement4);

    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(sIdx3, getIndicesForMsgNames(['verySensitive.publicKey'], attributesStruct)[0]);
    witnessEq2.addWitnessRef(sIdx4, 0);

    const metaStmtsVerifier = new MetaStatements();
    metaStmtsVerifier.addWitnessEquality(witnessEq2);

    const proofSpecVerifier = new ProofSpecG1(statementsVerifier, metaStmtsVerifier);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    expect(proof.verify(proofSpecVerifier).verified).toEqual(doesCheckPass);
    console.timeEnd('Proof verify');
  }
});
