import { generateRandomG1Element, initializeWasm } from '@docknetwork/crypto-wasm';
import { checkResult, stringToBytes } from '../../utils';
import {
  AttributeBoundPseudonym,
  CompositeProofG1,
  getAdaptedSignatureParamsForMessages, getIndicesForMsgNames, getRevealedAndUnrevealed, MetaStatement,
  MetaStatements,
  ProofSpecG1,
  PseudonymBases,
  Statement,
  Statements,
  Witness, WitnessEqualityMetaStatement,
  Witnesses
} from '../../../src';
import {
  attributes1,
  attributes1Struct,
  attributes4,
  attributes4Struct,
  GlobalEncoder
} from './data-and-encoder';
import {
  KeyPair,
  BlindSignature,
  SignatureParams,
  isPS,
  isBBSPlus,
  getWitnessForBlindSigRequest,
  getStatementForBlindSigRequest,
  Scheme, buildStatement, buildWitness, isBBS
} from '../../scheme';

const skipIfPS = isPS() ? describe.skip : describe;

skipIfPS(`With ${Scheme}, requesting blind signatures after providing a valid proof and pseudonym`, () => {
  // A user requests a signature, called `signature1` with a `user-id` attributes from `signer1`.
  // User then uses `signature1` to request a blind signature called `signature2` while proving that one of the blinded
  // attributes is `user-id` from signature1 and submits a pseudonym for `user-id` so that a single user cannot request
  // multiple signatures
  // Created for this PR https://github.com/docknetwork/crypto-wasm-ts/pull/19

  const label = stringToBytes('Sig params label - this is public');
  // For pseudonym of attribute `user-id`. This can be made poll specific as well.
  const scope1 = stringToBytes('Unique string');
  // For pseudonym of attributes `user-id` and `secret`
  const scope2 = stringToBytes('For voting in poll id test-poll');

  let params, h, pk1, sk1, pk2, sk2, signed1, signed2, basesForPseudonym1, basesForPseudonym2;

  beforeAll(async () => {
    // Load the WASM module
    await initializeWasm();
    params = SignatureParams.generate(100, label);
    h = generateRandomG1Element();
    const keypair1 = KeyPair.generate(params);
    sk1 = keypair1.secretKey;
    pk1 = keypair1.publicKey;
    const keypair2 = KeyPair.generate(params);
    sk2 = keypair2.secretKey;
    pk2 = keypair2.publicKey;

    // User requests `signature1` and verifies it
    signed1 = SignatureParams.signMessageObject(attributes1, sk1, label, GlobalEncoder);
    checkResult(SignatureParams.verifyMessageObject(attributes1, signed1.signature, pk1, label, GlobalEncoder));

    // pseudonym1 is for attribute `user-id` only
    basesForPseudonym1 = PseudonymBases.generateBasesForAttributes(1, scope1);
    // pseudonym2 is for attributes `user-id` and `secret`
    basesForPseudonym2 = PseudonymBases.generateBasesForAttributes(2, scope2);
  });

  it('shares a proof and request a blind signature', () => {
    // Share a pseudonym to `user-id` and prove that the same `user-id` is blinded in the request for the blind signature

    // The signer can check if he has seen this pseudonym before and according approve/reject the blind signature request
    const pseudonymId = AttributeBoundPseudonym.new(basesForPseudonym1, [signed1.encodedMessages['user-id']]);

    // The user will hide the "user-id" and "secret" attributes from the signer for the 2nd signature
    const hiddenAttrNames = new Set<string>();
    hiddenAttrNames.add('sensitive.user-id');
    hiddenAttrNames.add('sensitive.secret');

    // The attributes known to signer for the 2nd signature
    const knownAttributes = {
      fname: 'John',
      lname: 'Smith',
      sensitive: {
        email: 'john.smith@example.com',
      },
      'poll-id': 'test-poll',
      'registration-id': '12345671209'
    };

    const sigParams1 = getAdaptedSignatureParamsForMessages(params, attributes1Struct);
    const sigPk1 = isPS() ? pk1.adaptForLess(sigParams1.supportedMessageCount()) : pk1;

    const sigParams2 = getAdaptedSignatureParamsForMessages(params, attributes4Struct);
    const sigPk2 = isPS() ? pk2.adaptForLess(sigParams2.supportedMessageCount()) : pk2;
    const sigSk2 = isPS() ? sk2.adaptForLess(sigParams2.supportedMessageCount()) : sk2;

    const [names, encodedValues] = GlobalEncoder.encodeMessageObject(attributes4);
    const hiddenMsgs = new Map<number, Uint8Array>();
    let found = 0;
    hiddenAttrNames.forEach((n) => {
      const i = names.indexOf(n);
      if (i !== -1) {
        hiddenMsgs.set(i, encodedValues[i]);
        found++;
      }
    });
    if (hiddenAttrNames.size !== found) {
      throw new Error(
        `Some of the hidden message names were not found in the given messages object, ${
          hiddenAttrNames.size - found
        } missing names`
      );
    }

    const proverStatements = new Statements();
    const witnesses = new Witnesses();
    const proverMetaStatements = new MetaStatements();

    const [revealed, unrevealed] = getRevealedAndUnrevealed(attributes1, new Set(), GlobalEncoder);

    const stId1 = proverStatements.add(buildStatement(sigParams1, sigPk1, revealed, false));
    const stId2 = proverStatements.add(Statement.attributeBoundPseudonym(pseudonymId, basesForPseudonym1));
    witnesses.add(buildWitness(signed1.signature, unrevealed, false));
    witnesses.add(Witness.attributeBoundPseudonym([signed1.encodedMessages['user-id']]));

    const blindings = new Map();
    let blinding, request;
    if (isPS()) {
      // @ts-ignore
      [blinding, request] = BlindSignature.generateRequest(hiddenMsgs, sigParams2, h, blindings);
    } else if (isBBSPlus()) {
      // @ts-ignore
      [blinding, request] = BlindSignature.generateRequest(hiddenMsgs, sigParams2, false);
    } else {
      // @ts-ignore
      request = BlindSignature.generateRequest(hiddenMsgs, sigParams2, false);
    }

    const stId3 = proverStatements.add(getStatementForBlindSigRequest(request, sigParams2, h));
    witnesses.add(getWitnessForBlindSigRequest(hiddenMsgs, blinding, blindings));

    // To prove that `user-id` is same in `signature1`, `pseudonym1` and blind signature request
    const witnessEq = new WitnessEqualityMetaStatement();
    witnessEq.addWitnessRef(stId1, getIndicesForMsgNames(['user-id'], attributes1Struct)[0]);
    witnessEq.addWitnessRef(stId2, 0);
    if (isBBSPlus()) {
      witnessEq.addWitnessRef(stId3, 1);
    } else if (isBBS()) {
      witnessEq.addWitnessRef(stId3, 0);
    }

    proverMetaStatements.addWitnessEquality(witnessEq);

    const proofSpecProver = new ProofSpecG1(proverStatements, proverMetaStatements);
    expect(proofSpecProver.isValid()).toEqual(true);

    const proof = CompositeProofG1.generate(proofSpecProver, witnesses);

    // The signer is the verifier of the user's proof here. Uses the blind signature request to create the statement
    // and proof spec independently.
    const verifierStatements = new Statements();
    const verifierMetaStatements = new MetaStatements();

    const stId4 = verifierStatements.add(buildStatement(sigParams1, sigPk1, revealed, false));
    const stId5 = verifierStatements.add(Statement.attributeBoundPseudonym(pseudonymId, basesForPseudonym1));

    const stId6 = verifierStatements.add(getStatementForBlindSigRequest(request, sigParams2, h));

    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(stId4, getIndicesForMsgNames(['user-id'], attributes1Struct)[0]);
    witnessEq1.addWitnessRef(stId5, 0);

    if (isBBSPlus()) {
      witnessEq.addWitnessRef(stId6, 1);
    } else if (isBBS()) {
      witnessEq.addWitnessRef(stId6, 0);
    }

    verifierMetaStatements.addWitnessEquality(witnessEq1)

    const proofSpecVerifier = new ProofSpecG1(verifierStatements, verifierMetaStatements);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    // Signer/verifier verifies the proof
    checkResult(proof.verify(proofSpecVerifier));

    // Signer generates the blind signature using the signature request and attributes known to him. It sends the blind
    // signature to the user
    const blingSignature = BlindSignature.blindSignMessageObject(
      request,
      knownAttributes,
      sigSk2,
      attributes4Struct,
      isPS() ? h : sigParams2,
      GlobalEncoder
    );

    // User unblinds the blind signature
    const unblindedSig = isPS()
      // @ts-ignore
      ? blingSignature.signature.unblind(blindings, sigPk2)
      : isBBSPlus()
        // @ts-ignore
        ? blingSignature.signature.unblind(blinding)
        : blingSignature.signature;

    checkResult(SignatureParams.verifyMessageObject(attributes4, unblindedSig, sigPk2, sigParams2, GlobalEncoder));

    signed2 = {
      encodedMessages: GlobalEncoder.encodeMessageObjectAsObject(attributes4),
      signature: unblindedSig
    };
  });

  it('creates a proof for 2nd signature and shares pseudonym from 2 attributes', () => {
    // Prove knowledge of both signatures and share a pseudonym from 2 attributes of 2nd signature

    const sigParams1 = getAdaptedSignatureParamsForMessages(params, attributes1Struct);
    const sigPk1 = isPS() ? pk1.adaptForLess(sigParams1.supportedMessageCount()) : pk1;

    const sigParams2 = getAdaptedSignatureParamsForMessages(params, attributes4Struct);
    const sigPk2 = isPS() ? pk2.adaptForLess(sigParams2.supportedMessageCount()) : pk2;

    const revealedNames = new Set<string>();
    revealedNames.add('poll-id');

    // The verifier can check if he has seen this pseudonym before and according approve/reject the proof
    const pseudonymIdSk = AttributeBoundPseudonym.new(basesForPseudonym2, [signed2.encodedMessages['sensitive.user-id'], signed2.encodedMessages['sensitive.secret']]);

    const proverStatements = new Statements();
    const witnesses = new Witnesses();
    const proverMetaStatements = new MetaStatements();

    const [revealed1, unrevealed1] = getRevealedAndUnrevealed(attributes1, new Set(), GlobalEncoder);
    const [revealed2, unrevealed2] = getRevealedAndUnrevealed(attributes4, revealedNames, GlobalEncoder);

    const stId1 = proverStatements.add(buildStatement(sigParams1, sigPk1, revealed1, false));
    const stId2 = proverStatements.add(buildStatement(sigParams2, sigPk2, revealed2, false));
    const stId3 = proverStatements.add(Statement.attributeBoundPseudonym(pseudonymIdSk, basesForPseudonym2));
    witnesses.add(buildWitness(signed1.signature, unrevealed1, false));
    witnesses.add(buildWitness(signed2.signature, unrevealed2, false));
    witnesses.add(Witness.attributeBoundPseudonym([signed2.encodedMessages['sensitive.user-id'], signed2.encodedMessages['sensitive.secret']]));

    // Additional `Statement`s can be added for checking revocation status here

    // To prove attribute `user-id` is same in both signatures
    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(stId1, getIndicesForMsgNames(['user-id'], attributes1Struct)[0]);
    witnessEq1.addWitnessRef(stId2, getIndicesForMsgNames(['sensitive.user-id'], attributes4Struct)[0]);
    proverMetaStatements.addWitnessEquality(witnessEq1);

    // To prove attribute `user-id` is same in `signature2` and `pseudonym2`
    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(stId2, getIndicesForMsgNames(['sensitive.user-id'], attributes4Struct)[0]);
    if (isBBSPlus()) {
      witnessEq2.addWitnessRef(stId3, 1);
    } else if (isBBS()) {
      witnessEq2.addWitnessRef(stId3, 0);
    }
    proverMetaStatements.addWitnessEquality(witnessEq2);

    // To prove attribute `secret` is same in `signature2` and `pseudonym2`
    const witnessEq3 = new WitnessEqualityMetaStatement();
    witnessEq3.addWitnessRef(stId2, getIndicesForMsgNames(['sensitive.secret'], attributes4Struct)[0]);
    if (isBBSPlus()) {
      witnessEq3.addWitnessRef(stId3, 2);
    } else if (isBBS()) {
      witnessEq3.addWitnessRef(stId3, 1);
    }
    proverMetaStatements.addWitnessEquality(witnessEq3);

    const proofSpecProver = new ProofSpecG1(proverStatements, proverMetaStatements);
    expect(proofSpecProver.isValid()).toEqual(true);

    const proof = CompositeProofG1.generate(proofSpecProver, witnesses);

    const verifierStatements = new Statements();
    const verifierMetaStatements = new MetaStatements();

    const stId4 = verifierStatements.add(buildStatement(sigParams1, sigPk1, revealed1, false));
    const stId5 = verifierStatements.add(buildStatement(sigParams2, sigPk2, revealed2, false));
    const stId6 = verifierStatements.add(Statement.attributeBoundPseudonym(pseudonymIdSk, basesForPseudonym2));

    const witnessEq4 = new WitnessEqualityMetaStatement();
    witnessEq4.addWitnessRef(stId4, getIndicesForMsgNames(['user-id'], attributes1Struct)[0]);
    witnessEq4.addWitnessRef(stId5, getIndicesForMsgNames(['sensitive.user-id'], attributes4Struct)[0]);
    verifierMetaStatements.addWitnessEquality(witnessEq4);

    const witnessEq5 = new WitnessEqualityMetaStatement();
    witnessEq5.addWitnessRef(stId5, getIndicesForMsgNames(['sensitive.user-id'], attributes4Struct)[0]);
    if (isBBSPlus()) {
      witnessEq5.addWitnessRef(stId6, 1);
    } else if (isBBS()) {
      witnessEq5.addWitnessRef(stId6, 0);
    }
    verifierMetaStatements.addWitnessEquality(witnessEq5);

    const witnessEq6 = new WitnessEqualityMetaStatement();
    witnessEq6.addWitnessRef(stId5, getIndicesForMsgNames(['sensitive.secret'], attributes4Struct)[0]);
    if (isBBSPlus()) {
      witnessEq6.addWitnessRef(stId6, 2);
    } else if (isBBS()) {
      witnessEq6.addWitnessRef(stId6, 1);
    }
    verifierMetaStatements.addWitnessEquality(witnessEq6);

    const proofSpecVerifier = new ProofSpecG1(verifierStatements, verifierMetaStatements);
    expect(proofSpecVerifier.isValid()).toEqual(true);

    checkResult(proof.verify(proofSpecVerifier));
  })
});
