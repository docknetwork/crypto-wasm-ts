import { generateRandomFieldElement, initializeWasm } from '@docknetwork/crypto-wasm';
import {
  BBSPlusPublicKeyG2,
  BBSPlusSecretKey,
  CompositeProofG1,
  KeypairG2,
  MetaStatement,
  MetaStatements,
  QuasiProofSpecG1,
  SaverChunkedCommitmentGens,
  SaverDecryptionKeyUncompressed,
  SaverDecryptor,
  SaverEncryptionGens,
  SaverEncryptionGensUncompressed,
  SaverEncryptionKeyUncompressed,
  SaverProvingKeyUncompressed,
  SaverSecretKey,
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
  const chunkBitSize = 16;
  const encMsgIdx = 4;
  let messageCount;

  let snarkProvingKey: SaverProvingKeyUncompressed,
    snarkVerifyingKey: SaverVerifyingKeyUncompressed,
    saverSk: SaverSecretKey,
    saverEk: SaverEncryptionKeyUncompressed,
    saverDk: SaverDecryptionKeyUncompressed,
    saverEncGens: SaverEncryptionGensUncompressed;
  // There are 2 signers
  let sigParams1: SignatureParamsG1,
    sigSk1: BBSPlusSecretKey,
    sigPk1: BBSPlusPublicKeyG2,
    sigParams2: SignatureParamsG1,
    sigSk2: BBSPlusSecretKey,
    sigPk2: BBSPlusPublicKeyG2;
  let messages1AsStrings: string[], messages2AsStrings: string[];
  let messages1: Uint8Array[], messages2: Uint8Array[], sig1: SignatureG1, sig2: SignatureG1;

  beforeAll(async () => {
    await initializeWasm();
  });

  it('do decryptor setup', () => {
    const gens = SaverEncryptionGens.generate();
    // `chunkBitSize` is optional, it will default to reasonable good value.
    const [snarkPk, secretKey, encryptionKey, decryptionKey] = SaverDecryptor.setup(gens, chunkBitSize);
    console.log(snarkPk.value.length, encryptionKey.value.length, decryptionKey.value.length, gens.value.length);
    saverSk = secretKey;

    // The following decompressions can be done by anyone. Ideally the decryptor will publish `gens`, `snarkPk`, `encryptionKey`
    // and `decryptionKey` and respective parties will create/keep the information necessary for them.
    saverEncGens = gens.decompress();
    snarkProvingKey = snarkPk.decompress();
    snarkVerifyingKey = snarkPk.getVerifyingKeyUncompressed();
    saverEk = encryptionKey.decompress();
    saverDk = decryptionKey.decompress();
    console.log(
      snarkProvingKey.value.length,
      snarkVerifyingKey.value.length,
      saverEk.value.length,
      saverDk.value.length,
      saverEncGens.value.length
    );
  }, 300000);

  it('do signers setup', () => {
    // Setup the messages, its important to use a reversible encoding for the messages used in verifiable encryption as
    // the decryptor should be able to decrypt the message without the holder's help.

    // Following are encoded assuming messages are utf-8 and each character is 8 bits (1 byte) and
    // thus the maximum length of string can be 32. If these are known to ascii, then can be encoded using a more
    // efficient encoding as each character will be 7 bits and thus strings of length 36 (256 / 7) can be used.
    messages1AsStrings = [
      'John Jacob Smith Sr.',
      'San Francisco, California',
      'john.jacob.smith.1971@gmail.com',
      '+1 123-4567890009',
      'user-id:1234567890012134'
    ];

    messages2AsStrings = [
      'Alice Jr. from Wonderland',
      'Wonderland',
      'alice.wonderland.1980@gmail.com',
      '+1 456-7891230991',
      'user-id:9876543210987654'
    ];

    messageCount = messages1AsStrings.length;

    messages1 = [];
    messages2 = [];
    for (let i = 0; i < messageCount; i++) {
      messages1.push(SignatureG1.reversibleEncodeStringMessageForSigning(messages1AsStrings[i]));
      messages2.push(SignatureG1.reversibleEncodeStringMessageForSigning(messages2AsStrings[i]));
    }

    sigParams1 = SignatureParamsG1.generate(messageCount);
    const sigKeypair1 = KeypairG2.generate(sigParams1);
    sigSk1 = sigKeypair1.secretKey;
    sigPk1 = sigKeypair1.publicKey;

    sigParams2 = SignatureParamsG1.generate(messageCount);
    const sigKeypair2 = KeypairG2.generate(sigParams2);
    sigSk2 = sigKeypair2.secretKey;
    sigPk2 = sigKeypair2.publicKey;

    sig1 = SignatureG1.generate(messages1, sigSk1, sigParams1, false);
    sig2 = SignatureG1.generate(messages2, sigSk2, sigParams2, false);
    expect(sig1.verify(messages1, sigPk1, sigParams1, false).verified).toEqual(true);
    expect(sig2.verify(messages2, sigPk2, sigParams2, false).verified).toEqual(true);
  });

  function decryptAndVerify(proof: CompositeProofG1, statementIndex: number, message: Uint8Array) {
    // Verifier extracts the ciphertext
    const ciphertext = proof.getSaverCiphertext(statementIndex);

    // Decryptor gets the ciphertext from the verifier and decrypts it
    const decrypted = SaverDecryptor.decryptCiphertext(ciphertext, saverSk, saverDk, snarkVerifyingKey, chunkBitSize);
    expect(decrypted.message).toEqual(message);

    // Decryptor shares the decryption result with verifier which the verifier can check for correctness.
    expect(
      ciphertext.verifyDecryption(decrypted, saverDk, snarkVerifyingKey, saverEncGens, chunkBitSize).verified
    ).toEqual(true);
  }

  function proveAndVerifySingle(
    sigParams: SignatureParamsG1,
    sigPk: BBSPlusPublicKeyG2,
    messages: Uint8Array[],
    messagesAsStrings: string[],
    sig: SignatureG1,
    label: string
  ) {
    const gens = SaverChunkedCommitmentGens.generate(stringToBytes(label));
    const commGens = gens.decompress();

    const revealedIndices = new Set<number>();
    revealedIndices.add(0);
    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(messages, revealedIndices);
    const statement1 = Statement.bbsSignature(sigParams, sigPk, revealedMsgs, false);
    const statement2 = Statement.saverProver(saverEncGens, commGens, saverEk, snarkProvingKey, chunkBitSize);

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

    const proverProofSpec = new QuasiProofSpecG1(proverStatements, metaStatements);
    const proof = CompositeProofG1.generateUsingQuasiProofSpec(proverProofSpec, witnesses);

    const statement3 = Statement.saverVerifier(saverEncGens, commGens, saverEk, snarkVerifyingKey, chunkBitSize);
    const verifierStatements = new Statements();
    verifierStatements.add(statement1);
    verifierStatements.add(statement3);

    const verifierProofSpec = new QuasiProofSpecG1(verifierStatements, metaStatements);
    expect(proof.verifyUsingQuasiProofSpec(verifierProofSpec).verified).toEqual(true);

    // The ciphertext present in the proof is decrypted and checked to match the original message
    decryptAndVerify(proof, 1, messages[encMsgIdx]);

    // Message can be successfully decoded to the original string
    const decoded = SignatureG1.reversibleDecodeStringMessageForSigning(messages[encMsgIdx]);
    expect(decoded).toEqual(messagesAsStrings[encMsgIdx]);
  }

  it('prove knowledge of verifiable encryption of 1 message from 1st signature', () => {
    proveAndVerifySingle(sigParams1, sigPk1, messages1, messages1AsStrings, sig1, 'public test label 1');
  }, 20000);

  it('prove knowledge of verifiable encryption of 1 message from 2nd signature', () => {
    proveAndVerifySingle(sigParams2, sigPk2, messages2, messages2AsStrings, sig2, 'public test label 2');
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
    const statement3 = Statement.saverProverFromSetupParamRefs(0, 1, 2, 3, chunkBitSize);
    const statement4 = Statement.saverProverFromSetupParamRefs(0, 1, 2, 3, chunkBitSize);

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

    const proverProofSpec = new QuasiProofSpecG1(proverStatements, metaStatements, proverSetupParams);
    const proof = CompositeProofG1.generateUsingQuasiProofSpec(proverProofSpec, witnesses);

    const verifierSetupParams = [];
    verifierSetupParams.push(SetupParam.saverEncryptionGensUncompressed(saverEncGens));
    verifierSetupParams.push(SetupParam.saverCommitmentGensUncompressed(commGens));
    verifierSetupParams.push(SetupParam.saverEncryptionKeyUncompressed(saverEk));
    verifierSetupParams.push(SetupParam.saverVerifyingKeyUncompressed(snarkVerifyingKey));

    const statement5 = Statement.saverVerifierFromSetupParamRefs(0, 1, 2, 3, chunkBitSize);
    const statement6 = Statement.saverVerifierFromSetupParamRefs(0, 1, 2, 3, chunkBitSize);
    const verifierStatements = new Statements();
    verifierStatements.add(statement1);
    verifierStatements.add(statement2);
    verifierStatements.add(statement5);
    verifierStatements.add(statement6);

    const verifierProofSpec = new QuasiProofSpecG1(verifierStatements, metaStatements, verifierSetupParams);
    expect(proof.verifyUsingQuasiProofSpec(verifierProofSpec).verified).toEqual(true);

    decryptAndVerify(proof, 2, messages1[encMsgIdx]);
    decryptAndVerify(proof, 3, messages2[encMsgIdx]);
  }, 40000);
});
