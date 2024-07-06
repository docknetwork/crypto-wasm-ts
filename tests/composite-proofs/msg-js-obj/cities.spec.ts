import {
  areUint8ArraysEqual,
  CompositeProof,
  Encoder,
  encodeRevealedMsgs,
  getIndicesForMsgNames,
  getRevealedAndUnrevealed,
  initializeWasm,
  MetaStatements,
  ProofSpec,
  SetupParam,
  SignedMessages,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../../src';
import { PederCommKey } from '../../../src/ped-com';
import { buildWitness, PublicKey, Scheme, SecretKey, Signature, SignatureParams } from '../../scheme';
import { checkResult, getParamsAndKeys, stringToBytes } from '../../utils';
import { defaultEncoder } from './data-and-encoder';
import { checkMapsEqual } from './index';
import { adaptedSigParams, proverStmt, signAndVerify, verifierStmt } from './util';

// Test for scenario where the user wants to prove that he is not resident of certain cities.
// Similar test can be written for other "set-membership" relations
describe(`${Scheme} Proving that not resident of certain cities`, () => {
  let encoder: Encoder;

  const label = stringToBytes('Sig params label');
  let params: SignatureParams;
  let sk: SecretKey;
  let pk: PublicKey;
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
    [params, sk, pk] = getParamsAndKeys(100, label);

    signed = signAndVerify(attributes, encoder, label, sk, pk);
  });

  it('proof verifies when city is neither NYC, SF, LA, Chicago, Seattle', () => {
    expect(encodedCities.some((g) => areUint8ArraysEqual(g, signed.encodedMessages['city']))).toEqual(false);

    const revealedNames = new Set<string>();
    revealedNames.add('fname');

    const sigParams = adaptedSigParams(attributesStruct, label);
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

    const sIdx1 = statementsProver.add(proverStmt(
      sigParams,
      revealedMsgs,
      pk
    ));
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
    const proofSpecProver = new ProofSpec(statementsProver, metaStmtsProver, setupParams);
    expect(proofSpecProver.isValid()).toEqual(true);

    const proof = CompositeProof.generate(proofSpecProver, witnesses);

    // Verifier independently encodes revealed messages
    const revealedMsgsFromVerifier = encodeRevealedMsgs(revealedMsgsRaw, attributesStruct, encoder);
    checkMapsEqual(revealedMsgs, revealedMsgsFromVerifier);

    const statementsVerifier = new Statements();
    const metaStmtsVerifier = new MetaStatements();

    const sIdx2 = statementsVerifier.add(verifierStmt(
      sigParams,
      revealedMsgsFromVerifier,
      pk
    ));

    for (const c of encodedCities) {
      const sIdx = statementsVerifier.add(Statement.publicInequalityG1FromSetupParamRefs(c, 0));
      const witnessEq = new WitnessEqualityMetaStatement();
      witnessEq.addWitnessRef(sIdx2, getIndicesForMsgNames(['city'], attributesStruct)[0]);
      witnessEq.addWitnessRef(sIdx, 0);
      metaStmtsVerifier.addWitnessEquality(witnessEq);
    }

    const proofSpecVerifier = new ProofSpec(statementsVerifier, metaStmtsVerifier, setupParams);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    checkResult(proof.verify(proofSpecVerifier));
  });
});
