import {
  areUint8ArraysEqual,
  CompositeProof,
  dockSaverEncryptionGensUncompressed,
  initializeWasm,
  MetaStatement,
  MetaStatements,
  QuasiProofSpec,
  SaverChunkedCommitmentKey,
  SaverDecryptionKeyUncompressed,
  SaverDecryptor,
  SaverEncryptionGens,
  SaverEncryptionGensUncompressed,
  SaverEncryptionKeyUncompressed,
  SaverProvingKeyUncompressed,
  SaverSecretKey,
  SaverVerifyingKeyUncompressed,
  SetupParam,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../src';
import { buildWitness, PublicKey, Scheme, SecretKey, Signature, SignatureParams } from '../scheme';
import {
  checkResult,
  getParamsAndKeys,
  getRevealedUnrevealed,
  proverStmt,
  readByteArrayFromFile,
  signAndVerify,
  stringToBytes,
  verifierStmt
} from '../utils';

describe(`${Scheme} Verifiable encryption of signed messages`, () => {
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
  let sigParams1: SignatureParams,
    sigSk1: SecretKey,
    sigPk1: PublicKey,
    sigParams2: SignatureParams,
    sigSk2: SecretKey,
    sigPk2: PublicKey;
  let messages1AsStrings: string[], messages2AsStrings: string[];
  let messages1: Uint8Array[], messages2: Uint8Array[], sig1: Signature, sig2: Signature;

  beforeAll(async () => {
    await initializeWasm();
  });

  // Setting it to false will make the test run the SNARK setups making tests quite slow
  const loadSnarkSetupFromFiles = true;

  it('do decryptor setup', () => {
    if (loadSnarkSetupFromFiles && chunkBitSize === 16) {
      saverSk = new SaverSecretKey(readByteArrayFromFile('snark-setups/saver-secret-key-16.bin'));
      saverEncGens = dockSaverEncryptionGensUncompressed();
      snarkProvingKey = new SaverProvingKeyUncompressed(
        readByteArrayFromFile('snark-setups/saver-proving-key-16-uncompressed.bin')
      );
      snarkVerifyingKey = new SaverVerifyingKeyUncompressed(
        readByteArrayFromFile('snark-setups/saver-verifying-key-16-uncompressed.bin')
      );
      saverEk = new SaverEncryptionKeyUncompressed(
        readByteArrayFromFile('snark-setups/saver-encryption-key-16-uncompressed.bin')
      );
      saverDk = new SaverDecryptionKeyUncompressed(
        readByteArrayFromFile('snark-setups/saver-decryption-key-16-uncompressed.bin')
      );
    } else {
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
    }
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
      messages1.push(Signature.reversibleEncodeStringForSigning(messages1AsStrings[i]));
      messages2.push(Signature.reversibleEncodeStringForSigning(messages2AsStrings[i]));
    }

    [sigParams1, sigSk1, sigPk1] = getParamsAndKeys(messageCount);
    [sigParams2, sigSk2, sigPk2] = getParamsAndKeys(messageCount);

    let result1, result2;
    [sig1, result1] = signAndVerify(messages1, sigParams1, sigSk1, sigPk1);
    checkResult(result1);
    [sig2, result2] = signAndVerify(messages2, sigParams2, sigSk2, sigPk2);
    checkResult(result2);
  });

  function decryptAndVerify(proof: CompositeProof, statementIndex: number, message: Uint8Array) {
    // Verifier extracts the ciphertext
    const ciphertext = proof.getSaverCiphertext(statementIndex);
    const ciphertext1 = proof.getSaverCiphertexts([statementIndex]);
    expect(areUint8ArraysEqual(ciphertext.bytes, ciphertext1[0].bytes)).toEqual(true);

    // Decryptor gets the ciphertext from the verifier and decrypts it
    const decrypted = SaverDecryptor.decryptCiphertext(ciphertext, saverSk, saverDk, snarkVerifyingKey, chunkBitSize);
    expect(decrypted.message).toEqual(message);

    // Decryptor shares the decryption result with verifier which the verifier can check for correctness.
    expect(
      ciphertext.verifyDecryption(decrypted, saverDk, snarkVerifyingKey, saverEncGens, chunkBitSize).verified
    ).toEqual(true);
  }

  function proveAndVerifySingle(
    sigParams: SignatureParams,
    sigPk: PublicKey,
    messages: Uint8Array[],
    messagesAsStrings: string[],
    sig: Signature,
    label: string
  ) {
    const ck = SaverChunkedCommitmentKey.generate(stringToBytes(label));
    const commKey = ck.decompress();

    const revealedIndices = new Set<number>();
    revealedIndices.add(0);
    const [revealedMsgs, unrevealedMsgs] = getRevealedUnrevealed(messages, revealedIndices);
    const statement1 = proverStmt(sigParams, revealedMsgs, sigPk);
    const statement2 = Statement.saverProver(saverEncGens, commKey, saverEk, snarkProvingKey, chunkBitSize);

    const proverStatements = new Statements(statement1);
    proverStatements.add(statement2);

    const witnessEq = new WitnessEqualityMetaStatement();
    witnessEq.addWitnessRef(0, encMsgIdx);
    witnessEq.addWitnessRef(1, 0);
    const metaStatements = new MetaStatements();
    metaStatements.add(MetaStatement.witnessEquality(witnessEq));

    const witness1 = buildWitness(sig, unrevealedMsgs, false);
    const witness2 = Witness.saver(messages[encMsgIdx]);
    const witnesses = new Witnesses(witness1);
    witnesses.add(witness2);

    const proverProofSpec = new QuasiProofSpec(proverStatements, metaStatements);
    const proof = CompositeProof.generateUsingQuasiProofSpec(proverProofSpec, witnesses);

    const statement3 = Statement.saverVerifier(saverEncGens, commKey, saverEk, snarkVerifyingKey, chunkBitSize);
    const statement4 = verifierStmt(sigParams, revealedMsgs, sigPk);
    const verifierStatements = new Statements(statement4);
    verifierStatements.add(statement3);

    const verifierProofSpec = new QuasiProofSpec(verifierStatements, metaStatements);
    expect(proof.verifyUsingQuasiProofSpec(verifierProofSpec).verified).toEqual(true);

    // The ciphertext present in the proof is decrypted and checked to match the original message
    decryptAndVerify(proof, 1, messages[encMsgIdx]);

    // Message can be successfully decoded to the original string
    const decoded = Signature.reversibleDecodeStringForSigning(messages[encMsgIdx]);
    expect(decoded).toEqual(messagesAsStrings[encMsgIdx]);
  }

  it('prove knowledge of verifiable encryption of 1 message from 1st signature', () => {
    proveAndVerifySingle(sigParams1, sigPk1, messages1, messages1AsStrings, sig1, 'public test label 1');
  }, 20000);

  it('prove knowledge of verifiable encryption of 1 message from 2nd signature', () => {
    proveAndVerifySingle(sigParams2, sigPk2, messages2, messages2AsStrings, sig2, 'public test label 2');
  }, 20000);

  it('prove knowledge of verifiable encryption of 1 message from both signatures', () => {
    const commKey = SaverChunkedCommitmentKey.generate(stringToBytes('public test label 3')).decompress();
    const [revealedMsgs1, unrevealedMsgs1] = getRevealedUnrevealed(messages1, new Set<number>());
    const [revealedMsgs2, unrevealedMsgs2] = getRevealedUnrevealed(messages2, new Set<number>());

    const proverSetupParams: SetupParam[] = [];
    proverSetupParams.push(SetupParam.saverEncryptionGensUncompressed(saverEncGens));
    proverSetupParams.push(SetupParam.saverCommitmentKeyUncompressed(commKey));
    proverSetupParams.push(SetupParam.saverEncryptionKeyUncompressed(saverEk));
    proverSetupParams.push(SetupParam.saverProvingKeyUncompressed(snarkProvingKey));

    const statement1 = proverStmt(sigParams1, revealedMsgs1, sigPk1);
    const statement2 = proverStmt(sigParams2, revealedMsgs2, sigPk2);
    const statement3 = Statement.saverProverFromSetupParamRefs(0, 1, 2, 3, chunkBitSize);
    const statement4 = Statement.saverProverFromSetupParamRefs(0, 1, 2, 3, chunkBitSize);

    const proverStatements = new Statements([].concat(statement1, statement2));
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
    witnesses.add(buildWitness(sig1, unrevealedMsgs1, false));
    witnesses.add(buildWitness(sig2, unrevealedMsgs2, false));
    witnesses.add(Witness.saver(messages1[encMsgIdx]));
    witnesses.add(Witness.saver(messages2[encMsgIdx]));

    const proverProofSpec = new QuasiProofSpec(proverStatements, metaStatements, proverSetupParams);
    const proof = CompositeProof.generateUsingQuasiProofSpec(proverProofSpec, witnesses);

    const verifierSetupParams: SetupParam[] = [];
    verifierSetupParams.push(SetupParam.saverEncryptionGensUncompressed(saverEncGens));
    verifierSetupParams.push(SetupParam.saverCommitmentKeyUncompressed(commKey));
    verifierSetupParams.push(SetupParam.saverEncryptionKeyUncompressed(saverEk));
    verifierSetupParams.push(SetupParam.saverVerifyingKeyUncompressed(snarkVerifyingKey));

    const statement5 = Statement.saverVerifierFromSetupParamRefs(0, 1, 2, 3, chunkBitSize);
    const statement6 = Statement.saverVerifierFromSetupParamRefs(0, 1, 2, 3, chunkBitSize);
    const statement7 = verifierStmt(sigParams1, revealedMsgs1, sigPk1);
    const statement8 = verifierStmt(sigParams2, revealedMsgs2, sigPk2);
    const verifierStatements = new Statements();
    verifierStatements.add(statement7);
    verifierStatements.add(statement8);
    verifierStatements.add(statement5);
    verifierStatements.add(statement6);

    const verifierProofSpec = new QuasiProofSpec(verifierStatements, metaStatements, verifierSetupParams);
    expect(proof.verifyUsingQuasiProofSpec(verifierProofSpec).verified).toEqual(true);

    decryptAndVerify(proof, 2, messages1[encMsgIdx]);
    decryptAndVerify(proof, 3, messages2[encMsgIdx]);
  }, 40000);
});
