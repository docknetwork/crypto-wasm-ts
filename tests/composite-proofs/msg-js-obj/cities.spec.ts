import { generateFieldElementFromNumber, initializeWasm } from '@docknetwork/crypto-wasm';
import { areUint8ArraysEqual, checkResult, stringToBytes } from '../../utils';
import {
  CircomInputs,
  CompositeProofG1,
  Encoder,
  encodeRevealedMsgs,
  getIndicesForMsgNames,
  getRevealedAndUnrevealed,
  MetaStatements,
  ProofSpecG1,
  SetupParam,
  SignedMessages,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../../src';
import { checkMapsEqual } from './index';
import { defaultEncoder } from './data-and-encoder';
import { SignatureParams, KeyPair, PublicKey, Signature, buildStatement, buildWitness, Scheme } from '../../scheme';
import { PederCommKey } from '../../../src/ped-com';

// Test for scenario where the user wants to prove that he is not resident of certain cities.
// Similar test can be written for other "set-membership" relations
describe(`${Scheme} Proving that not resident of certain cities`, () => {
  let encoder: Encoder;

  const label = stringToBytes('Sig params label');
  let sigPk: PublicKey;
  let commKey: PederCommKey;

  let signed: SignedMessages<Signature>;

  const cities = ['NYC', 'SF', 'LA', 'Chicago', 'Seattle'];
  let encodedCities: Uint8Array[];

  const attributesStruct = {
    fname: null,
    lname: null,
    email: null,
    SSN: null,
    city: null
  };

  // City is Boston and a satisfactory proof can be created
  const attributes = {
    fname: 'John',
    lname: 'Smith',
    email: 'john.smith@example.com',
    SSN: '123-456789-0',
    city: 'Boston'
  };

  beforeAll(async () => {
    await initializeWasm();

    // Setup encoder
    encoder = new Encoder(undefined, defaultEncoder);
    encodedCities = cities.map((g: string) => encoder.encodeDefault(g));

    commKey = new PederCommKey(stringToBytes('test'));
  });

  it('signers signs attributes', () => {
    // Message count shouldn't matter as `label` is known
    let params = SignatureParams.generate(1, label);
    const keypair = KeyPair.generate(params);
    const sk = keypair.secretKey;
    sigPk = keypair.publicKey;

    signed = Signature.signMessageObject(attributes, sk, label, encoder);
    checkResult(signed.signature.verifyMessageObject(attributes, sigPk, label, encoder));
  });

  it('proof verifies when city is neither NYC, SF, LA, Chicago, Seattle', () => {
    expect(encodedCities.some((g) => areUint8ArraysEqual(g, signed.encodedMessages['city']))).toEqual(false);

    const revealedNames = new Set<string>();
    revealedNames.add('fname');

    const sigParams = SignatureParams.getSigParamsForMsgStructure(attributesStruct, label);
    const [revealedMsgs, unrevealedMsgs, revealedMsgsRaw] = getRevealedAndUnrevealed(
      attributes,
      revealedNames,
      encoder
    );
    expect(revealedMsgsRaw).toEqual({ fname: 'John' });

    const setupParams = [SetupParam.pedCommKeyG1(commKey)];

    const statementsProver = new Statements();
    const metaStmtsProver = new MetaStatements();
    const witnesses = new Witnesses();

    const sIdx1 = statementsProver.add(buildStatement(sigParams, sigPk, revealedMsgs, false));
    witnesses.add(buildWitness(signed.signature, unrevealedMsgs, false));

    for (const c of encodedCities) {
      const sIdx = statementsProver.add(Statement.publicInequalityG1FromSetupParamRefs(c, 0));
      witnesses.add(Witness.publicInequality(signed.encodedMessages['city']));
      const witnessEq = new WitnessEqualityMetaStatement();
      witnessEq.addWitnessRef(sIdx1, getIndicesForMsgNames(['city'], attributesStruct)[0]);
      witnessEq.addWitnessRef(sIdx, 0);
      metaStmtsProver.addWitnessEquality(witnessEq);
    }

    // The prover should independently construct this `ProofSpec`
    const proofSpecProver = new ProofSpecG1(statementsProver, metaStmtsProver, setupParams);
    expect(proofSpecProver.isValid()).toEqual(true);

    const proof = CompositeProofG1.generate(proofSpecProver, witnesses);

    // Verifier independently encodes revealed messages
    const revealedMsgsFromVerifier = encodeRevealedMsgs(revealedMsgsRaw, attributesStruct, encoder);
    checkMapsEqual(revealedMsgs, revealedMsgsFromVerifier);

    const statementsVerifier = new Statements();
    const metaStmtsVerifier = new MetaStatements();

    const sIdx2 = statementsVerifier.add(buildStatement(sigParams, sigPk, revealedMsgs, false));

    for (const c of encodedCities) {
      const sIdx = statementsVerifier.add(Statement.publicInequalityG1FromSetupParamRefs(c, 0));
      const witnessEq = new WitnessEqualityMetaStatement();
      witnessEq.addWitnessRef(sIdx2, getIndicesForMsgNames(['city'], attributesStruct)[0]);
      witnessEq.addWitnessRef(sIdx, 0);
      metaStmtsVerifier.addWitnessEquality(witnessEq);
    }

    const proofSpecVerifier = new ProofSpecG1(statementsVerifier, metaStmtsVerifier, setupParams);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    checkResult(proof.verify(proofSpecVerifier));
  });
});
