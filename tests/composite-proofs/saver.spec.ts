import { generateRandomFieldElement, initializeWasm } from '@docknetwork/crypto-wasm';
import {
  CompositeProofG1,
  KeypairG2,
  MetaStatement,
  MetaStatements,
  SaverChunkedCommitmentGens,
  SaverDecryptionKeyUncompressed,
  SaverDecryptor,
  SaverEncryptionGens,
  SaverEncryptionGensUncompressed,
  SaverEncryptionKeyUncompressed,
  SaverProvingKeyUncompressed, SaverSecretKey,
  SaverVerifyingKeyUncompressed,
  SetupParam,
  SignatureG1,
  SignatureParamsG1,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../src';
import { getRevealedUnrevealed, stringToBytes } from '../utils';

describe('Verifiable encryption of signed messages', () => {
  const messageCount = 5;
  const chunkBitSize = 8;
  const encMsgIdx = 1;

  let snarkProvingKey: SaverProvingKeyUncompressed,
    snarkVerifyingKey: SaverVerifyingKeyUncompressed,
    saverSk: SaverSecretKey,
    saverEk: SaverEncryptionKeyUncompressed,
    saverDk: SaverDecryptionKeyUncompressed,
    saverEncGens: SaverEncryptionGensUncompressed;
  // There are 2 signers
  let sigParams1: SignatureParamsG1,
    sigSk1: Uint8Array,
    sigPk1: Uint8Array,
    sigParams2: SignatureParamsG1,
    sigSk2: Uint8Array,
    sigPk2: Uint8Array;
  let messages1: Uint8Array[], messages2: Uint8Array[], sig1: SignatureG1, sig2: SignatureG1;

  beforeAll(async () => {
    await initializeWasm();
  });

  it('do decryptor setup', () => {
    const gens = SaverEncryptionGens.generate();
    const [snarkPk, sk, ek, dk] = SaverDecryptor.setup(gens, chunkBitSize);
    saverEncGens = gens.decompress();
    snarkProvingKey = snarkPk.decompress();
    snarkVerifyingKey = snarkPk.getVerifyingKeyUncompressed();
    saverSk = sk;
    saverEk = ek.decompress();
    saverDk = dk.decompress();
  }, 300000);

  it('do signers setup', () => {
    sigParams1 = SignatureParamsG1.generate(messageCount);
    const sigKeypair1 = KeypairG2.generate(sigParams1);
    sigSk1 = sigKeypair1.secretKey;
    sigPk1 = sigKeypair1.publicKey;

    sigParams2 = SignatureParamsG1.generate(messageCount);
    const sigKeypair2 = KeypairG2.generate(sigParams2);
    sigSk2 = sigKeypair2.secretKey;
    sigPk2 = sigKeypair2.publicKey;

    messages1 = [];
    messages2 = [];
    for (let i = 0; i < messageCount; i++) {
      messages1.push(generateRandomFieldElement());
      messages2.push(generateRandomFieldElement());
    }

    sig1 = SignatureG1.generate(messages1, sigSk1, sigParams1, false);
    sig2 = SignatureG1.generate(messages2, sigSk2, sigParams2, false);
    expect(sig1.verify(messages1, sigPk1, sigParams1, false).verified).toEqual(true);
    expect(sig2.verify(messages2, sigPk2, sigParams2, false).verified).toEqual(true);
  });

  function decryptAndVerify(proof: CompositeProofG1, statementIndex: number, message: Uint8Array) {
    const ciphertext = proof.getSaverCiphertext(statementIndex);
    const decrypted = SaverDecryptor.decryptCiphertext(ciphertext, saverSk, saverDk, snarkVerifyingKey, chunkBitSize);
    expect(decrypted.message).toEqual(message);
    expect(
      ciphertext.verifyDecryption(decrypted, saverDk, snarkVerifyingKey, saverEncGens, chunkBitSize).verified
    ).toEqual(true);
  }

  function proveAndVerifySingle(
    sigParams: SignatureParamsG1,
    sigPk: Uint8Array,
    messages: Uint8Array[],
    sig: SignatureG1,
    label: string
  ) {
    const gens = SaverChunkedCommitmentGens.generate(stringToBytes(label));
    const commGens = gens.decompress();

    const revealedIndices = new Set<number>();
    revealedIndices.add(0);
    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(messages, revealedIndices);
    const statement1 = Statement.bbsSignature(sigParams, sigPk, revealedMsgs, false);
    const statement2 = Statement.saverProver(chunkBitSize, saverEncGens, commGens, saverEk, snarkProvingKey);

    const proverStatements = new Statements();
    proverStatements.add(statement1);
    proverStatements.add(statement2);

    const witnessEq = new WitnessEqualityMetaStatement();
    witnessEq.addWitnessRef(0, encMsgIdx);
    witnessEq.addWitnessRef(1, 0);
    const metaStatements = new MetaStatements();
    metaStatements.add(MetaStatement.witnessEquality(witnessEq));

    const witness1 = Witness.bbsSignature(sig, unrevealedMsgs, false);
    const witness2 = Witness.saver(messages[encMsgIdx]);
    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);

    const proof = CompositeProofG1.generateWithDeconstructedProofSpec(proverStatements, metaStatements, witnesses);

    const statement3 = Statement.saverVerifier(chunkBitSize, saverEncGens, commGens, saverEk, snarkVerifyingKey);
    const verifierStatements = new Statements();
    verifierStatements.add(statement1);
    verifierStatements.add(statement3);

    expect(proof.verifyWithDeconstructedProofSpec(verifierStatements, metaStatements).verified).toEqual(true);

    decryptAndVerify(proof, 1, messages[encMsgIdx]);
  }

  it('prove knowledge of verifiable encryption of 1 message from 1st signature', () => {
    proveAndVerifySingle(sigParams1, sigPk1, messages1, sig1, 'public test label 1');
  }, 20000);

  it('prove knowledge of verifiable encryption of 1 message from 2nd signature', () => {
    proveAndVerifySingle(sigParams2, sigPk2, messages2, sig2, 'public test label 2');
  }, 20000);

  it('prove knowledge of verifiable encryption of 1 message from both signatures', () => {
    const commGens = SaverChunkedCommitmentGens.generate(stringToBytes('public test label 3')).decompress();
    const [revealedMsgs1, unrevealedMsgs1] = getRevealedUnrevealed(messages1, new Set<number>());
    const [revealedMsgs2, unrevealedMsgs2] = getRevealedUnrevealed(messages2, new Set<number>());

    const proverSetupParams = [];
    proverSetupParams.push(SetupParam.saverEncryptionGensUncompressed(saverEncGens));
    proverSetupParams.push(SetupParam.saverCommitmentGensUncompressed(commGens));
    proverSetupParams.push(SetupParam.saverEncryptionKeyUncompressed(saverEk));
    proverSetupParams.push(SetupParam.saverProvingKeyUncompressed(snarkProvingKey));

    const statement1 = Statement.bbsSignature(sigParams1, sigPk1, revealedMsgs1, false);
    const statement2 = Statement.bbsSignature(sigParams2, sigPk2, revealedMsgs2, false);
    const statement3 = Statement.saverProverFromSetupParamRefs(chunkBitSize, 0, 1, 2, 3);
    const statement4 = Statement.saverProverFromSetupParamRefs(chunkBitSize, 0, 1, 2, 3);

    const proverStatements = new Statements();
    proverStatements.add(statement1);
    proverStatements.add(statement2);
    proverStatements.add(statement3);
    proverStatements.add(statement4);

    const witnessEq1 = new WitnessEqualityMetaStatement();
    witnessEq1.addWitnessRef(0, encMsgIdx);
    witnessEq1.addWitnessRef(2, 0);

    const witnessEq2 = new WitnessEqualityMetaStatement();
    witnessEq2.addWitnessRef(1, encMsgIdx);
    witnessEq2.addWitnessRef(3, 0);

    const metaStatements = new MetaStatements();
    metaStatements.add(MetaStatement.witnessEquality(witnessEq1));
    metaStatements.add(MetaStatement.witnessEquality(witnessEq2));

    const witnesses = new Witnesses();
    witnesses.add(Witness.bbsSignature(sig1, unrevealedMsgs1, false));
    witnesses.add(Witness.bbsSignature(sig2, unrevealedMsgs2, false));
    witnesses.add(Witness.saver(messages1[encMsgIdx]));
    witnesses.add(Witness.saver(messages2[encMsgIdx]));

    const proof = CompositeProofG1.generateWithDeconstructedProofSpec(
      proverStatements,
      metaStatements,
      witnesses,
      proverSetupParams
    );

    const verifierSetupParams = [];
    verifierSetupParams.push(SetupParam.saverEncryptionGensUncompressed(saverEncGens));
    verifierSetupParams.push(SetupParam.saverCommitmentGensUncompressed(commGens));
    verifierSetupParams.push(SetupParam.saverEncryptionKeyUncompressed(saverEk));
    verifierSetupParams.push(SetupParam.saverVerifyingKeyUncompressed(snarkVerifyingKey));

    const statement5 = Statement.saverVerifierFromSetupParamRefs(chunkBitSize, 0, 1, 2, 3);
    const statement6 = Statement.saverVerifierFromSetupParamRefs(chunkBitSize, 0, 1, 2, 3);
    const verifierStatements = new Statements();
    verifierStatements.add(statement1);
    verifierStatements.add(statement2);
    verifierStatements.add(statement5);
    verifierStatements.add(statement6);

    expect(
      proof.verifyWithDeconstructedProofSpec(verifierStatements, metaStatements, verifierSetupParams).verified
    ).toEqual(true);

    decryptAndVerify(proof, 2, messages1[encMsgIdx]);
    decryptAndVerify(proof, 3, messages2[encMsgIdx]);
  }, 40000);
});
