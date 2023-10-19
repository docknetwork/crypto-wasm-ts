import { initializeWasm } from '@docknetwork/crypto-wasm';
import { areUint8ArraysEqual, checkResult, stringToBytes } from '../../utils';
import {
  CompositeProofG1,
  Encoder,
  encodeRevealedMsgs,
  getIndicesForMsgNames,
  getRevealedAndUnrevealed,
  MetaStatements,
  ProofSpecG1,
  SignedMessages,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../../src';
import { checkMapsEqual } from './index';
import { defaultEncoder } from './data-and-encoder';
import {
  PublicKey,
  KeyPair,
  SignatureParams,
  Signature,
  buildStatement,
  buildWitness,
  isPS,
  Scheme,
  adaptKeyForParams
} from '../../scheme';
import { PederCommKey } from '../../../src/ped-com';

// Test for a scenario where a user wants to prove that his blood group is AB- without revealing the blood group.
// Similar test can be written for other "not-equals" relations like user is not resident of certain city
describe(`${Scheme} Proving that blood group is not AB-`, () => {
  let encoder: Encoder;
  let encodedABNeg: Uint8Array;

  const label = stringToBytes('Sig params label');
  let pk: PublicKey;
  let commKey: PederCommKey;

  // CredentialBuilder for the user with blood group AB+
  let signed1: SignedMessages<Signature>;
  // CredentialBuilder for the user with blood group AB-
  let signed2: SignedMessages<Signature>;

  // Structure of credential that has the blood group attribute
  const attributesStruct = {
    fname: null,
    lname: null,
    verySensitive: {
      email: null,
      SSN: null
    },
    physical: {
      gender: null,
      bloodGroup: null
    },
    'user-id': null
  };

  // 1st credential where blood group is AB+ and a satisfactory proof can be created
  const attributes1 = {
    fname: 'John',
    lname: 'Smith',
    verySensitive: {
      email: 'john.smith@example.com',
      SSN: '123-456789-0'
    },
    physical: {
      gender: 'male',
      bloodGroup: 'AB+'
    },
    'user-id': 'user:123-xyz-#'
  };

  // 2nd credential where blood group is AB- and its not acceptable so proof will fail
  const attributes2 = {
    fname: 'Carol',
    lname: 'Smith',
    verySensitive: {
      email: 'carol.smith@example.com',
      SSN: '233-456788-1'
    },
    physical: {
      gender: 'female',
      bloodGroup: 'AB-'
    },
    'user-id': 'user:764-xyz-#'
  };

  beforeAll(async () => {
    await initializeWasm();

    // Setup encoder
    encoder = new Encoder(undefined, defaultEncoder);

    encodedABNeg = encoder.encodeDefault('AB-');

    commKey = new PederCommKey(stringToBytes('test'));
  });

  it('signers signs attributes', () => {
    // Message count shouldn't matter as `label` is known
    const params = SignatureParams.generate(100, label);
    const keypair = KeyPair.generate(params);
    const sk = keypair.secretKey;
    pk = keypair.publicKey;

    signed1 = Signature.signMessageObject(attributes1, sk, label, encoder);
    checkResult(signed1.signature.verifyMessageObject(attributes1, pk, label, encoder));

    signed2 = Signature.signMessageObject(attributes2, sk, label, encoder);
    checkResult(signed2.signature.verifyMessageObject(attributes2, pk, label, encoder));
  });

  it('proof verifies when blood groups is not AB-', () => {
    expect(areUint8ArraysEqual(encodedABNeg, signed1.encodedMessages['physical.bloodGroup'])).toEqual(false);

    const revealedNames = new Set<string>();
    revealedNames.add('fname');

    const sigParams = SignatureParams.getSigParamsForMsgStructure(attributesStruct, label);
    const sigPK = adaptKeyForParams(pk, sigParams);
    const [revealedMsgs, unrevealedMsgs, revealedMsgsRaw] = getRevealedAndUnrevealed(
      attributes1,
      revealedNames,
      encoder
    );
    expect(revealedMsgsRaw).toEqual({ fname: 'John' });

    const statement1 = buildStatement(sigParams, sigPK, revealedMsgs, false);
    const statement2 = Statement.publicInequalityG1FromCompressedParams(encodedABNeg, commKey);

    const statementsProver = new Statements();
    const sIdx1 = statementsProver.add(statement1);
    const sIdx2 = statementsProver.add(statement2);

    const metaStmtsProver = new MetaStatements();
    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(sIdx1, getIndicesForMsgNames(['physical.bloodGroup'], attributesStruct)[0]);
    witnessEq1.addWitnessRef(sIdx2, 0);

    metaStmtsProver.addWitnessEquality(witnessEq1);

    // The prover should independently construct this `ProofSpec`
    const proofSpecProver = new ProofSpecG1(statementsProver, metaStmtsProver);
    expect(proofSpecProver.isValid()).toEqual(true);

    const witness1 = buildWitness(signed1.signature, unrevealedMsgs, false);

    const witness2 = Witness.publicInequality(signed1.encodedMessages['physical.bloodGroup']);

    const witnesses = new Witnesses([witness1, witness2]);

    const proof = CompositeProofG1.generate(proofSpecProver, witnesses);

    // Verifier independently encodes revealed messages
    const revealedMsgsFromVerifier = encodeRevealedMsgs(revealedMsgsRaw, attributesStruct, encoder);
    checkMapsEqual(revealedMsgs, revealedMsgsFromVerifier);

    const statement3 = buildStatement(sigParams, sigPK, revealedMsgsFromVerifier, false);
    const statement4 = Statement.publicInequalityG1FromCompressedParams(encodedABNeg, commKey);

    const statementsVerifier = new Statements();
    const sIdx3 = statementsVerifier.add(statement3);
    const sIdx4 = statementsVerifier.add(statement4);

    const metaStmtsVerifier = new MetaStatements();
    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(sIdx3, getIndicesForMsgNames(['physical.bloodGroup'], attributesStruct)[0]);
    witnessEq2.addWitnessRef(sIdx4, 0);

    metaStmtsVerifier.addWitnessEquality(witnessEq2);

    const proofSpecVerifier = new ProofSpecG1(statementsVerifier, metaStmtsVerifier);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    checkResult(proof.verify(proofSpecVerifier));
  });
});
