import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  Accumulator,
  AccumulatorParams,
  AccumulatorPublicKey,
  AccumulatorSecretKey,
  BBSPlusPublicKeyG2,
  BBSPlusSecretKey,
  BBSPlusBlindSignature,
  BBSPlusBlindSignatureG1,
  CompositeProofG1,
  BBSPlusKeypairG2,
  MembershipProvingKey,
  MembershipWitness,
  MetaStatement,
  MetaStatements,
  NonMembershipProvingKey,
  NonMembershipWitness,
  PositiveAccumulator,
  ProofSpecG1,
  BBSPlusSignatureG1,
  BBSPlusSignatureParamsG1,
  Statement,
  Statements,
  UniversalAccumulator,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses,
  randomFieldElement
} from '../src';
import { areUint8ArraysEqual, stringToBytes } from './utils';

// Test demonstrating the flow where holder (user) gets credentials (message lists and signatures) from multiple issuers (signers)
// one by one and it proves the knowledge of previously received credentials before getting the next credential (message list and signature).
// The issuer also adds one of their credential attribute (message) in the accumulator and while proving knowledge of credentials,
// it also proves accumulator memberships. Also, in each credential, there is a secret message at index 0, which the holder does not
// reveal to anyone, not even the issuer and in the proof, it proves that the secret message is same in all credentials.

// Credential 1 and 2 have 6 attributes (including secret and user id for accumulator)
const credential12AttrCount = 6;
// Credential 3 has 10 attributes (including secret and user id for accumulator)
const credential3AttrCount = 10;

// Credential 1's attributes excluding secret and user id
const credential1Attributes: any[] = [];
// Credential 2's attributes excluding secret and user id
const credential2Attributes: any[] = [];
// Credential 3's attributes excluding secret and user id
const credential3Attributes: any[] = [];

// Credential 1's attributes including secret and user id
let credential1AttributesFinal: Uint8Array[];
// Credential 2's attributes including secret and user id
let credential2AttributesFinal: Uint8Array[];
// Credential 3's attributes including secret and user id
let credential3AttributesFinal: Uint8Array[];

let Credential1: BBSPlusSignatureG1;
let Credential2: BBSPlusSignatureG1;
let Credential3: BBSPlusSignatureG1;

// Issuer 1 and 2 use same params
let Issuer12SigParams: BBSPlusSignatureParamsG1;
let Issuer3SigParams: BBSPlusSignatureParamsG1;
// Secret key and public key for issuers
let Issuer1Sk: BBSPlusSecretKey;
let Issuer1Pk: BBSPlusPublicKeyG2;
let Issuer2Sk: BBSPlusSecretKey;
let Issuer2Pk: BBSPlusPublicKeyG2;
let Issuer3Sk: BBSPlusSecretKey;
let Issuer3Pk: BBSPlusPublicKeyG2;

// Accumulator params
let Accum1Params: AccumulatorParams;
let Accum2Params: AccumulatorParams;
let Accum3Params: AccumulatorParams;

// Secret key and public key for accumulator managers
let Accum1Sk: AccumulatorSecretKey;
let Accum1Pk: AccumulatorPublicKey;
let Accum2Sk: AccumulatorSecretKey;
let Accum2Pk: AccumulatorPublicKey;
let Accum3Sk: AccumulatorSecretKey;
let Accum3Pk: AccumulatorPublicKey;
let Accum1Prk: MembershipProvingKey;
let Accum2Prk: MembershipProvingKey;

// Proving key for non-membership
let Accum3NonMemPrk: NonMembershipProvingKey;
// Proving key for membership
let Accum3MemPrk: MembershipProvingKey;
// Positive accumulator that stores the secret key as well
let Accum1: PositiveAccumulator;
// Positive accumulator that needs the secret key to passed when needed. This is to avoid having secret key in memory all the time.
let Accum2: PositiveAccumulator;
let Accum3: UniversalAccumulator;

export interface BlindSigRequest {
  proof: CompositeProofG1;
  commitment: Uint8Array;
}

const DEBUG = false;

function log(msg: any) {
  if (DEBUG) {
    console.log(msg);
  }
}

describe('A demo showing combined use of BBS+ signatures and accumulators using the composite proof system', () => {
  it('runs', async () => {
    function setupAttributes() {
      // 2 of the messages are reserved for a secret (eg. link secret known only to holder) and a user-id that is added to accumulator.
      for (let i = 2; i < credential12AttrCount; i++) {
        credential1Attributes.push(`credential1's Message${i + 1}`);
      }
      for (let i = 2; i < credential12AttrCount; i++) {
        credential2Attributes.push(`credential2's Message${i + 1}`);
      }
      for (let i = 2; i < credential3AttrCount; i++) {
        credential3Attributes.push(`credential3's Message${i + 1}`);
      }
    }

    function checkPublicKey(sk: BBSPlusSecretKey, pk: BBSPlusPublicKeyG2, params: any) {
      if (!pk.isValid()) {
        throw new Error('Public key is invalid');
      }
      const gpk = sk.generatePublicKeyG2(params);
      if (!areUint8ArraysEqual(gpk.value, pk.value)) {
        throw new Error(`Generated public key ${gpk.value} different from expected public key ${pk.value}`);
      }
      if (!gpk.isValid()) {
        throw new Error('Generated public key is invalid');
      }
    }

    function setupIssuer1Keys() {
      const kp = BBSPlusKeypairG2.generate(Issuer12SigParams);
      Issuer1Sk = kp.secretKey;
      Issuer1Pk = kp.publicKey;
      checkPublicKey(Issuer1Sk, Issuer1Pk, Issuer12SigParams);
      log("Issuer 1's secret and public keys are:");
      log(Issuer1Sk);
      log(Issuer1Pk);
    }

    function setupIssuer2Keys() {
      const kp = BBSPlusKeypairG2.generate(Issuer12SigParams, stringToBytes('my secret passphrase'));
      Issuer2Sk = kp.secretKey;
      Issuer2Pk = kp.publicKey;
      checkPublicKey(Issuer2Sk, Issuer2Pk, Issuer12SigParams);
      log("Issuer 2's secret and public keys are:");
      log(Issuer2Sk);
      log(Issuer2Pk);
    }

    function setupIssuer3Keys() {
      const seed = stringToBytes('my-secret-seed');
      const kp = BBSPlusKeypairG2.generate(Issuer3SigParams, seed);
      Issuer3Sk = kp.secretKey;
      Issuer3Pk = kp.publicKey;
      checkPublicKey(Issuer3Sk, Issuer3Pk, Issuer3SigParams);
      log("Issuer 3's secret and public keys are:");
      log(Issuer3Sk);
      log(Issuer3Pk);
    }

    function setupIssuer12SigParams() {
      const label = stringToBytes('Params for Issuer 1 and 2');
      Issuer12SigParams = BBSPlusSignatureParamsG1.generate(credential12AttrCount, label);
      if (!Issuer12SigParams.isValid()) {
        throw new Error('Params is invalid');
      }
      if (Issuer12SigParams.supportedMessageCount() !== credential12AttrCount) {
        throw new Error(
          `supportedMessageCount returns ${Issuer12SigParams.supportedMessageCount()} but should be ${credential12AttrCount}`
        );
      }
      log("Issuer 1 and 2's signature params are:");
      log(Issuer12SigParams);
    }

    function setupIssuer3SigParams() {
      const label = stringToBytes('Params for Issuer 3');
      Issuer3SigParams = BBSPlusSignatureParamsG1.generate(credential3AttrCount, label);
      if (!Issuer3SigParams.isValid()) {
        throw new Error('Params is invalid');
      }
      if (Issuer3SigParams.supportedMessageCount() !== credential3AttrCount) {
        throw new Error(
          `supportedMessageCount returns ${Issuer3SigParams.supportedMessageCount()} but should be ${credential3AttrCount}`
        );
      }
      log("Issuer 3's signature params are:");
      log(Issuer3SigParams);
    }

    function setupAccumulator1() {
      const label = stringToBytes('Params for Accumulator 1');
      Accum1Params = Accumulator.generateParams(label);
      Accum1Sk = Accumulator.generateSecretKey();
      Accum1Pk = Accumulator.generatePublicKeyFromSecretKey(Accum1Sk, Accum1Params);
      Accum1 = PositiveAccumulator.initialize(Accum1Params, Accum1Sk);
      Accum1Prk = Accumulator.generateMembershipProvingKey(stringToBytes('Some public label'));
    }

    function setupAccumulator2() {
      Accum2Params = Accumulator.generateParams();
      const seed = stringToBytes('some-secret-seed');
      Accum2Sk = Accumulator.generateSecretKey(seed);
      Accum2Pk = Accumulator.generatePublicKeyFromSecretKey(Accum2Sk, Accum2Params);
      Accum2 = PositiveAccumulator.initialize(Accum2Params);
      Accum2Prk = Accumulator.generateMembershipProvingKey();
    }

    async function setupAccumulator3() {
      Accum3Params = Accumulator.generateParams();
      const seed = stringToBytes('secret-seed-for-non-universal-accum');
      const keypair = Accumulator.generateKeypair(Accum3Params, seed);
      Accum3Sk = keypair.secretKey;
      Accum3Pk = keypair.publicKey;
      const maxSize = 100;

      Accum3 = await UniversalAccumulator.initialize(maxSize, Accum3Params, Accum3Sk);
      Accum3NonMemPrk = Accumulator.generateNonMembershipProvingKey(stringToBytes('Another public label'));
      Accum3MemPrk = Accum3NonMemPrk.deriveMembershipProvingKey();
    }

    function prepareMessagesForBlindSigning(messages: Uint8Array[]) {
      const encodedMessages: Uint8Array[] = [];
      for (const msg of messages) {
        encodedMessages.push(BBSPlusSignatureG1.encodeMessageForSigning(msg));
      }
      return encodedMessages;
    }

    function addRevocationIdToAttributes(attributes: Uint8Array[], id: Uint8Array) {
      // Assuming add at 0 index
      attributes.splice(0, 0, id);
    }

    function msgArrayToMapForBlindSign(messages: Uint8Array[]): Map<number, Uint8Array> {
      const map = new Map();
      for (let i = 0; i < messages.length; i++) {
        // Leaving index 0 for link secret
        map.set(i + 1, messages[i]);
      }
      return map;
    }

    function blindSigRequestWithSecretStatementAndWitness(
      secret: Uint8Array,
      sigParams: BBSPlusSignatureParamsG1
    ): [Uint8Array, Uint8Array, Uint8Array, Uint8Array] {
      const encodedSecret = BBSPlusSignatureG1.encodeMessageForSigning(secret);
      const blinding = BBSPlusBlindSignature.generateBlinding();
      const indicesToCommit = new Set<number>();
      // Holder secret is at index 0
      indicesToCommit.add(0);
      const msgsToCommit = new Map();
      msgsToCommit.set(0, encodedSecret);

      // Commit to the secret using params
      const [commitment] = sigParams.commitToMessages(msgsToCommit, false, blinding);

      // Create a statement and witness for proving knowledge opening of the Pedersen commitment
      const bases = sigParams.getParamsForIndices([...indicesToCommit]);
      const statement = Statement.pedersenCommitmentG1(bases, commitment);
      const witness = Witness.pedersenCommitment([blinding, encodedSecret]);
      return [statement, witness, commitment, blinding];
    }

    function blindSigRequestWithSecret(
      secret: Uint8Array,
      sigParams: BBSPlusSignatureParamsG1,
      nonce?: Uint8Array
    ): [BlindSigRequest, Uint8Array] {
      const [statement, witness, commitment, blinding] = blindSigRequestWithSecretStatementAndWitness(
        secret,
        sigParams
      );

      const statements = new Statements();
      statements.add(statement);

      // Proof spec with statement and meta-statement
      const proofSpec = new ProofSpecG1(statements, new MetaStatements());
      expect(proofSpec.isValid()).toEqual(true);

      const witnesses = new Witnesses();
      witnesses.add(witness);
      // Composite proof for proving knowledge of opening of Pedersen commitment
      const proof = CompositeProofG1.generate(proofSpec, witnesses, nonce);
      return [{ proof, commitment }, blinding];
    }

    function blindSigRequestWithSecretAndCredential(
      secret: Uint8Array,
      sigParamsForRequestedCredential: BBSPlusSignatureParamsG1,
      credential: BBSPlusSignatureG1,
      sigParams: BBSPlusSignatureParamsG1,
      pk: BBSPlusPublicKeyG2,
      revealedMsgs: Map<number, Uint8Array>,
      unrevealedMsgs: Map<number, Uint8Array>,
      accumParams: AccumulatorParams,
      accumPk: AccumulatorPublicKey,
      prk: MembershipProvingKey,
      accumulated: Uint8Array,
      membershipWitness: MembershipWitness,
      nonce?: Uint8Array
    ): [BlindSigRequest, Uint8Array] {
      // Create composite proof of 3 statements,
      // 1) knowledge of a signature,
      // 2) accumulator membership and
      // 3) opening of commitment in the blind signature request.

      const statement1 = Statement.bbsPlusSignature(sigParams, pk, revealedMsgs, false);
      const witness1 = Witness.bbsPlusSignature(credential, unrevealedMsgs, false);

      const statement2 = Statement.accumulatorMembership(accumParams, accumPk, prk, accumulated);
      const witness2 = Witness.accumulatorMembership(unrevealedMsgs.get(1) as Uint8Array, membershipWitness);

      const [statement3, witness3, commitment, blinding] = blindSigRequestWithSecretStatementAndWitness(
        secret,
        sigParamsForRequestedCredential
      );

      const statements = new Statements();
      statements.add(statement1);
      statements.add(statement2);
      statements.add(statement3);

      // Prove equality of holder's secret in `credential` and blind signature request.
      const witnessEq1 = new WitnessEqualityMetaStatement();
      // Holder secret is at index 0 in statement 0
      witnessEq1.addWitnessRef(0, 0);
      // Holder secret is at index 1 in statement 1, the opening of commitment of the blind signature respect
      witnessEq1.addWitnessRef(2, 1);

      // Prove equality of holder's user id in `credential` and accumulator membership.
      const witnessEq2 = new WitnessEqualityMetaStatement();
      witnessEq2.addWitnessRef(0, 1);
      witnessEq2.addWitnessRef(1, 0);

      const ms1 = MetaStatement.witnessEquality(witnessEq1);
      const ms2 = MetaStatement.witnessEquality(witnessEq2);
      const metaStatements = new MetaStatements();
      metaStatements.add(ms1);
      metaStatements.add(ms2);

      // Create proof spec with statements and meta statements
      const proofSpec = new ProofSpecG1(statements, metaStatements);
      expect(proofSpec.isValid()).toEqual(true);

      const witnesses = new Witnesses();
      witnesses.add(witness1);
      witnesses.add(witness2);
      witnesses.add(witness3);
      const proof = CompositeProofG1.generate(proofSpec, witnesses, nonce);
      return [{ proof, commitment }, blinding];
    }

    function blindSigRequestWithSecretAnd2Credentials(
      secret: Uint8Array,
      sigParamsForRequestedCredential: BBSPlusSignatureParamsG1,
      credential: BBSPlusSignatureG1,
      sigParams: BBSPlusSignatureParamsG1,
      pk: BBSPlusPublicKeyG2,
      revealedMsgs: Map<number, Uint8Array>,
      unrevealedMsgs: Map<number, Uint8Array>,
      accumParams: AccumulatorParams,
      accumPk: AccumulatorPublicKey,
      prk: MembershipProvingKey,
      accumulated: Uint8Array,
      membershipWitness: MembershipWitness,
      credential2: BBSPlusSignatureG1,
      sigParams2: BBSPlusSignatureParamsG1,
      pk2: BBSPlusPublicKeyG2,
      revealedMsgs2: Map<number, Uint8Array>,
      unrevealedMsgs2: Map<number, Uint8Array>,
      accumParams2: AccumulatorParams,
      accumPk2: AccumulatorPublicKey,
      prk2: MembershipProvingKey,
      accumulated2: Uint8Array,
      membershipWitness2: MembershipWitness,
      nonce?: Uint8Array
    ): [BlindSigRequest, Uint8Array] {
      // Create composite proof of 5 statements,
      // 1) knowledge of a signature in credential,
      // 2) accumulator membership for credential,
      // 3) knowledge of a signature in credential1,
      // 4) accumulator membership for credential1,
      // 5) opening of commitment in the blind signature request.

      const statement1 = Statement.bbsPlusSignature(sigParams, pk, revealedMsgs, false);
      const witness1 = Witness.bbsPlusSignature(credential, unrevealedMsgs, false);

      const statement2 = Statement.accumulatorMembership(accumParams, accumPk, prk, accumulated);
      const witness2 = Witness.accumulatorMembership(unrevealedMsgs.get(1) as Uint8Array, membershipWitness);

      const statement3 = Statement.bbsPlusSignature(sigParams2, pk2, revealedMsgs2, false);
      const witness3 = Witness.bbsPlusSignature(credential2, unrevealedMsgs2, false);

      const statement4 = Statement.accumulatorMembership(accumParams2, accumPk2, prk2, accumulated2);
      const witness4 = Witness.accumulatorMembership(unrevealedMsgs2.get(1) as Uint8Array, membershipWitness2);

      const [statement5, witness5, commitment, blinding] = blindSigRequestWithSecretStatementAndWitness(
        secret,
        sigParamsForRequestedCredential
      );

      const statements = new Statements();
      statements.add(statement1);
      statements.add(statement2);
      statements.add(statement3);
      statements.add(statement4);
      statements.add(statement5);

      // Prove equality of holder's secret in `credential`, `credential1` and blind signature request.
      const witnessEq1 = new WitnessEqualityMetaStatement();
      witnessEq1.addWitnessRef(0, 0);
      witnessEq1.addWitnessRef(2, 0);
      witnessEq1.addWitnessRef(4, 1);

      // Prove equality of holder's user id in `credential` and accumulator membership.
      const witnessEq2 = new WitnessEqualityMetaStatement();
      witnessEq2.addWitnessRef(0, 1);
      witnessEq2.addWitnessRef(1, 0);

      // Prove equality of holder's user id in `credential1` and accumulator membership.
      const witnessEq3 = new WitnessEqualityMetaStatement();
      witnessEq3.addWitnessRef(2, 1);
      witnessEq3.addWitnessRef(3, 0);

      const metaStatements = new MetaStatements();
      metaStatements.add(MetaStatement.witnessEquality(witnessEq1));
      metaStatements.add(MetaStatement.witnessEquality(witnessEq2));
      metaStatements.add(MetaStatement.witnessEquality(witnessEq3));

      const proofSpec = new ProofSpecG1(statements, metaStatements);
      expect(proofSpec.isValid()).toEqual(true);

      const witnesses = new Witnesses();
      witnesses.add(witness1);
      witnesses.add(witness2);
      witnesses.add(witness3);
      witnesses.add(witness4);
      witnesses.add(witness5);
      const proof = CompositeProofG1.generate(proofSpec, witnesses, nonce);
      return [{ proof, commitment }, blinding];
    }

    function issueBlindSig(
      blindSigReq: BlindSigRequest,
      sigParams: BBSPlusSignatureParamsG1,
      sk: BBSPlusSecretKey,
      otherMsgs: Map<number, Uint8Array>,
      nonce?: Uint8Array
    ) {
      const indicesToCommit = new Set<number>();
      indicesToCommit.add(0);
      // Verify knowledge of opening of commitment and issue blind signature with that commitment
      const bases = sigParams.getParamsForIndices([...indicesToCommit]);
      const statement = Statement.pedersenCommitmentG1(bases, blindSigReq.commitment);
      const statements = new Statements();
      statements.add(statement);

      const proofSpec = new ProofSpecG1(statements, new MetaStatements());
      expect(proofSpec.isValid()).toEqual(true);

      const res = blindSigReq.proof.verify(proofSpec, nonce);
      if (!res.verified) {
        throw new Error(`Failed to verify blind sig request due to ${res.error}`);
      }
      return BBSPlusBlindSignatureG1.generate(blindSigReq.commitment, otherMsgs, sk, sigParams, false);
    }

    function issueBlindSigWithCredVerif(
      blindSigReq: BlindSigRequest,
      sigParamsForRequestedCredential: BBSPlusSignatureParamsG1,
      sk: BBSPlusSecretKey,
      otherMsgs: Map<number, Uint8Array>,
      sigParams: BBSPlusSignatureParamsG1,
      pk: BBSPlusPublicKeyG2,
      revealedMsgs: Map<number, Uint8Array>,
      accumParams: AccumulatorParams,
      accumPk: AccumulatorPublicKey,
      prk: MembershipProvingKey,
      accumulated: Uint8Array,
      nonce?: Uint8Array
    ) {
      // Verify composite proof of 3 statements,
      // 1) knowledge of a signature,
      // 2) accumulator membership and
      // 3) opening of commitment in the blind signature request.

      const indicesToCommit: number[] = [];
      indicesToCommit.push(0);
      const bases = sigParamsForRequestedCredential.getParamsForIndices(indicesToCommit);
      const statement1 = Statement.bbsPlusSignature(sigParams, pk, revealedMsgs, false);
      const statement2 = Statement.accumulatorMembership(accumParams, accumPk, prk, accumulated);
      const statement3 = Statement.pedersenCommitmentG1(bases, blindSigReq.commitment);

      const statements = new Statements();
      statements.add(statement1);
      statements.add(statement2);
      statements.add(statement3);

      const witnessEq1 = new WitnessEqualityMetaStatement();
      witnessEq1.addWitnessRef(0, 0);
      witnessEq1.addWitnessRef(2, 1);

      const witnessEq2 = new WitnessEqualityMetaStatement();
      witnessEq2.addWitnessRef(0, 1);
      witnessEq2.addWitnessRef(1, 0);

      const ms1 = MetaStatement.witnessEquality(witnessEq1);
      const ms2 = MetaStatement.witnessEquality(witnessEq2);
      const metaStatements = new MetaStatements();
      metaStatements.add(ms1);
      metaStatements.add(ms2);

      const proofSpec = new ProofSpecG1(statements, metaStatements);
      expect(proofSpec.isValid()).toEqual(true);

      const res = blindSigReq.proof.verify(proofSpec, nonce);
      if (!res.verified) {
        throw new Error(`Failed to verify blind sig request due to ${res.error}`);
      }
      return BBSPlusBlindSignatureG1.generate(blindSigReq.commitment, otherMsgs, sk, sigParamsForRequestedCredential, false);
    }

    function issueBlindSigWith2CredVerifs(
      blindSigReq: BlindSigRequest,
      sigParamsForRequestedCredential: BBSPlusSignatureParamsG1,
      sk: BBSPlusSecretKey,
      otherMsgs: Map<number, Uint8Array>,
      sigParams: BBSPlusSignatureParamsG1,
      pk: BBSPlusPublicKeyG2,
      revealedMsgs: Map<number, Uint8Array>,
      accumParams: AccumulatorParams,
      accumPk: AccumulatorPublicKey,
      prk: MembershipProvingKey,
      accumulated: Uint8Array,
      sigParams2: BBSPlusSignatureParamsG1,
      pk2: BBSPlusPublicKeyG2,
      revealedMsgs2: Map<number, Uint8Array>,
      accumParams2: AccumulatorParams,
      accumPk2: AccumulatorPublicKey,
      prk2: MembershipProvingKey,
      accumulated2: Uint8Array,
      nonce?: Uint8Array
    ) {
      // Verify composite proof of 5 statements,
      // 1) knowledge of a signature in credential,
      // 2) accumulator membership for credential,
      // 3) knowledge of a signature in credential1,
      // 4) accumulator membership for credential1,
      // 5) opening of commitment in the blind signature request.

      const indicesToCommit: number[] = [];
      indicesToCommit.push(0);
      const bases = sigParamsForRequestedCredential.getParamsForIndices(indicesToCommit);
      const statement1 = Statement.bbsPlusSignature(sigParams, pk, revealedMsgs, false);
      const statement2 = Statement.accumulatorMembership(accumParams, accumPk, prk, accumulated);
      const statement3 = Statement.bbsPlusSignature(sigParams2, pk2, revealedMsgs2, false);
      const statement4 = Statement.accumulatorMembership(accumParams2, accumPk2, prk2, accumulated2);
      const statement5 = Statement.pedersenCommitmentG1(bases, blindSigReq.commitment);

      const statements = new Statements();
      statements.add(statement1);
      statements.add(statement2);
      statements.add(statement3);
      statements.add(statement4);
      statements.add(statement5);

      const witnessEq1 = new WitnessEqualityMetaStatement();
      witnessEq1.addWitnessRef(0, 0);
      witnessEq1.addWitnessRef(2, 0);
      witnessEq1.addWitnessRef(4, 1);

      const witnessEq2 = new WitnessEqualityMetaStatement();
      witnessEq2.addWitnessRef(0, 1);
      witnessEq2.addWitnessRef(1, 0);

      const witnessEq3 = new WitnessEqualityMetaStatement();
      witnessEq3.addWitnessRef(2, 1);
      witnessEq3.addWitnessRef(3, 0);

      const metaStatements = new MetaStatements();
      metaStatements.add(MetaStatement.witnessEquality(witnessEq1));
      metaStatements.add(MetaStatement.witnessEquality(witnessEq2));
      metaStatements.add(MetaStatement.witnessEquality(witnessEq3));

      const proofSpec = new ProofSpecG1(statements, metaStatements);
      expect(proofSpec.isValid()).toEqual(true);

      const res = blindSigReq.proof.verify(proofSpec, nonce);
      if (!res.verified) {
        throw new Error(`Failed to verify blind sig request due to ${res.error}`);
      }
      return BBSPlusBlindSignatureG1.generate(blindSigReq.commitment, otherMsgs, sk, sigParamsForRequestedCredential, false);
    }

    function proofOf3Creds(
      credential: BBSPlusSignatureG1,
      sigParams: BBSPlusSignatureParamsG1,
      pk: BBSPlusPublicKeyG2,
      revealedMsgs: Map<number, Uint8Array>,
      unrevealedMsgs: Map<number, Uint8Array>,
      accumParams: AccumulatorParams,
      accumPk: AccumulatorPublicKey,
      prk: MembershipProvingKey,
      accumulated: Uint8Array,
      membershipWitness: MembershipWitness,
      credential2: BBSPlusSignatureG1,
      sigParams2: BBSPlusSignatureParamsG1,
      pk2: BBSPlusPublicKeyG2,
      revealedMsgs2: Map<number, Uint8Array>,
      unrevealedMsgs2: Map<number, Uint8Array>,
      accumParams2: AccumulatorParams,
      accumPk2: AccumulatorPublicKey,
      prk2: MembershipProvingKey,
      accumulated2: Uint8Array,
      membershipWitness2: MembershipWitness,
      credential3: BBSPlusSignatureG1,
      sigParams3: BBSPlusSignatureParamsG1,
      pk3: BBSPlusPublicKeyG2,
      revealedMsgs3: Map<number, Uint8Array>,
      unrevealedMsgs3: Map<number, Uint8Array>,
      accumParams3: AccumulatorParams,
      accumPk3: AccumulatorPublicKey,
      prk3: MembershipProvingKey,
      accumulated3: Uint8Array,
      membershipWitness3: MembershipWitness,
      nonce?: Uint8Array
    ) {
      // Create composite proof of 6 statements,
      // 1) knowledge of a signature in credential,
      // 2) accumulator membership for credential,
      // 3) knowledge of a signature in credential1,
      // 4) accumulator membership for credential1,
      // 5) knowledge of a signature in credential2,
      // 6) accumulator membership for credential2,

      const statement1 = Statement.bbsPlusSignature(sigParams, pk, revealedMsgs, false);
      const witness1 = Witness.bbsPlusSignature(credential, unrevealedMsgs, false);

      const statement2 = Statement.accumulatorMembership(accumParams, accumPk, prk, accumulated);
      const witness2 = Witness.accumulatorMembership(unrevealedMsgs.get(1) as Uint8Array, membershipWitness);

      const statement3 = Statement.bbsPlusSignature(sigParams2, pk2, revealedMsgs2, false);
      const witness3 = Witness.bbsPlusSignature(credential2, unrevealedMsgs2, false);

      const statement4 = Statement.accumulatorMembership(accumParams2, accumPk2, prk2, accumulated2);
      const witness4 = Witness.accumulatorMembership(unrevealedMsgs2.get(1) as Uint8Array, membershipWitness2);

      const statement5 = Statement.bbsPlusSignature(sigParams3, pk3, revealedMsgs3, false);
      const witness5 = Witness.bbsPlusSignature(credential3, unrevealedMsgs3, false);

      const statement6 = Statement.accumulatorMembership(accumParams3, accumPk3, prk3, accumulated3);
      const witness6 = Witness.accumulatorMembership(unrevealedMsgs3.get(1) as Uint8Array, membershipWitness3);

      const statements = new Statements();
      statements.add(statement1);
      statements.add(statement2);
      statements.add(statement3);
      statements.add(statement4);
      statements.add(statement5);
      statements.add(statement6);

      const witnessEq1 = new WitnessEqualityMetaStatement();
      witnessEq1.addWitnessRef(0, 0);
      witnessEq1.addWitnessRef(2, 0);
      witnessEq1.addWitnessRef(4, 0);

      const witnessEq2 = new WitnessEqualityMetaStatement();
      witnessEq2.addWitnessRef(0, 1);
      witnessEq2.addWitnessRef(1, 0);

      const witnessEq3 = new WitnessEqualityMetaStatement();
      witnessEq3.addWitnessRef(2, 1);
      witnessEq3.addWitnessRef(3, 0);

      const witnessEq4 = new WitnessEqualityMetaStatement();
      witnessEq4.addWitnessRef(4, 1);
      witnessEq4.addWitnessRef(5, 0);

      const metaStatements = new MetaStatements();
      metaStatements.add(MetaStatement.witnessEquality(witnessEq1));
      metaStatements.add(MetaStatement.witnessEquality(witnessEq2));
      metaStatements.add(MetaStatement.witnessEquality(witnessEq3));
      metaStatements.add(MetaStatement.witnessEquality(witnessEq4));

      const proofSpec = new ProofSpecG1(statements, metaStatements);
      expect(proofSpec.isValid()).toEqual(true);

      const witnesses = new Witnesses();
      witnesses.add(witness1);
      witnesses.add(witness2);
      witnesses.add(witness3);
      witnesses.add(witness4);
      witnesses.add(witness5);
      witnesses.add(witness6);

      return CompositeProofG1.generate(proofSpec, witnesses, nonce);
    }

    function verifyProofOf3Creds(
      proof: CompositeProofG1,
      sigParams: BBSPlusSignatureParamsG1,
      pk: BBSPlusPublicKeyG2,
      revealedMsgs: Map<number, Uint8Array>,
      accumParams: AccumulatorParams,
      accumPk: AccumulatorPublicKey,
      prk: MembershipProvingKey,
      accumulated: Uint8Array,
      sigParams2: BBSPlusSignatureParamsG1,
      pk2: BBSPlusPublicKeyG2,
      revealedMsgs2: Map<number, Uint8Array>,
      accumParams2: AccumulatorParams,
      accumPk2: AccumulatorPublicKey,
      prk2: MembershipProvingKey,
      accumulated2: Uint8Array,
      sigParams3: BBSPlusSignatureParamsG1,
      pk3: BBSPlusPublicKeyG2,
      revealedMsgs3: Map<number, Uint8Array>,
      accumParams3: AccumulatorParams,
      accumPk3: AccumulatorPublicKey,
      prk3: MembershipProvingKey,
      accumulated3: Uint8Array,
      nonce?: Uint8Array
    ) {
      // Verify composite proof of 6 statements,
      // 1) knowledge of a signature in credential,
      // 2) accumulator membership for credential,
      // 3) knowledge of a signature in credential1,
      // 4) accumulator membership for credential1,
      // 5) knowledge of a signature in credential2,
      // 6) accumulator membership for credential2,

      const statement1 = Statement.bbsPlusSignature(sigParams, pk, revealedMsgs, false);
      const statement2 = Statement.accumulatorMembership(accumParams, accumPk, prk, accumulated);
      const statement3 = Statement.bbsPlusSignature(sigParams2, pk2, revealedMsgs2, false);
      const statement4 = Statement.accumulatorMembership(accumParams2, accumPk2, prk2, accumulated2);
      const statement5 = Statement.bbsPlusSignature(sigParams3, pk3, revealedMsgs3, false);
      const statement6 = Statement.accumulatorMembership(accumParams3, accumPk3, prk3, accumulated3);

      const statements = new Statements();
      statements.add(statement1);
      statements.add(statement2);
      statements.add(statement3);
      statements.add(statement4);
      statements.add(statement5);
      statements.add(statement6);

      const witnessEq1 = new WitnessEqualityMetaStatement();
      witnessEq1.addWitnessRef(0, 0);
      witnessEq1.addWitnessRef(2, 0);
      witnessEq1.addWitnessRef(4, 0);

      const witnessEq2 = new WitnessEqualityMetaStatement();
      witnessEq2.addWitnessRef(0, 1);
      witnessEq2.addWitnessRef(1, 0);

      const witnessEq3 = new WitnessEqualityMetaStatement();
      witnessEq3.addWitnessRef(2, 1);
      witnessEq3.addWitnessRef(3, 0);

      const witnessEq4 = new WitnessEqualityMetaStatement();
      witnessEq4.addWitnessRef(4, 1);
      witnessEq4.addWitnessRef(5, 0);

      const metaStatements = new MetaStatements();
      metaStatements.add(MetaStatement.witnessEquality(witnessEq1));
      metaStatements.add(MetaStatement.witnessEquality(witnessEq2));
      metaStatements.add(MetaStatement.witnessEquality(witnessEq3));
      metaStatements.add(MetaStatement.witnessEquality(witnessEq4));

      const proofSpec = new ProofSpecG1(statements, metaStatements);
      expect(proofSpec.isValid()).toEqual(true);

      const res = proof.verify(proofSpec, nonce);
      if (!res.verified) {
        throw new Error(`Failed to verify proof of 3 creds due to ${res.error}`);
      }
    }

    /**
     * Unblind the given blind signature, verify it and add the holder's secret to the messages
     * @param blindedSig
     * @param blinding
     * @param holderSecret
     * @param msgs
     * @param pk
     * @param sigParams
     */
    function unBlindAndVerify(
      blindedSig: BBSPlusBlindSignatureG1,
      blinding: Uint8Array,
      holderSecret: Uint8Array,
      msgs: Uint8Array[],
      pk: BBSPlusPublicKeyG2,
      sigParams: BBSPlusSignatureParamsG1
    ): [BBSPlusSignatureG1, Uint8Array[]] {
      const unblinded = blindedSig.unblind(blinding);
      let final: Uint8Array[] = [];
      final.push(BBSPlusSignatureG1.encodeMessageForSigning(holderSecret));
      final = final.concat(msgs);
      const res1 = unblinded.verify(final, pk, sigParams, false);
      if (!res1.verified) {
        throw new Error(`Failed to verify unblinded sig1 due to ${res1.error}`);
      }
      return [unblinded, final];
    }

    await initializeWasm();

    // Initialize attributes which will be signed
    setupAttributes();

    // Setup Issuers
    setupIssuer12SigParams();
    setupIssuer3SigParams();
    setupIssuer1Keys();
    setupIssuer2Keys();
    setupIssuer3Keys();

    // Setup Accumulators
    setupAccumulator1();
    setupAccumulator2();
    await setupAccumulator3();

    const holderSecret = stringToBytes('MySecret123');

    // Get Credential 1
    // Holder prepares request for blind signature hiding `holderSecret` from the Issuer
    const [blindSigReq1, blinding1] = blindSigRequestWithSecret(holderSecret, Issuer12SigParams);

    // Issuer prepares messages for signing including user id
    const holderAttrs1 = prepareMessagesForBlindSigning(credential1Attributes);
    // Add user id in messages which will be added to the accumulator
    const revocationId1 = Accumulator.encodeBytesAsAccumulatorMember(stringToBytes('user-id: xyz123'));
    addRevocationIdToAttributes(holderAttrs1, revocationId1);

    // Issuer issues a blind signature after verifying the knowledge of committed values
    const blindedCred1 = issueBlindSig(
      blindSigReq1,
      Issuer12SigParams,
      Issuer1Sk,
      msgArrayToMapForBlindSign(holderAttrs1)
    );
    // Accumulator managers adds rev id to the accumulator
    await Accum1.add(revocationId1);
    const membershipWitness1 = await Accum1.membershipWitness(revocationId1);

    // Holder unblinds and verifies signature
    [Credential1, credential1AttributesFinal] = unBlindAndVerify(
      blindedCred1,
      blinding1,
      holderSecret,
      holderAttrs1,
      Issuer1Pk,
      Issuer12SigParams
    );
    // Holder checks that attribute at index 1 is in the accumulator
    const memCheck1 = Accum1.verifyMembershipWitness(
      credential1AttributesFinal[1],
      membershipWitness1,
      Accum1Pk,
      Accum1Params
    );
    if (!memCheck1) {
      throw new Error('Membership check failed in accumulator 1');
    }

    // Get Credential 2. For this holder has to prove possession of credential 1, reveal the last attribute and prove
    // the user-id attribute is in the accumulator `Accum1`

    // Holder reveals 1 attribute at index `credential12AttrCount - 1`
    const revealed1 = new Set<number>();
    revealed1.add(credential12AttrCount - 1);
    const revealedMsgs1 = new Map();
    const unrevealedMsgs1 = new Map();
    for (let i = 0; i < credential12AttrCount; i++) {
      if (revealed1.has(i)) {
        revealedMsgs1.set(i, credential1AttributesFinal[i]);
      } else {
        unrevealedMsgs1.set(i, credential1AttributesFinal[i]);
      }
    }

    // Create request to verify blind signature along with proof of one credential
    const [blindSigReq2, blinding2] = blindSigRequestWithSecretAndCredential(
      holderSecret,
      Issuer12SigParams,
      Credential1,
      Issuer12SigParams,
      Issuer1Pk,
      revealedMsgs1,
      unrevealedMsgs1,
      Accum1Params,
      Accum1Pk,
      Accum1Prk,
      Accum1.accumulated,
      membershipWitness1
    );

    // Issuer prepares messages for signing including rev id
    const holderMessages2 = prepareMessagesForBlindSigning(credential2Attributes);
    const revocationId2 = Accumulator.encodeBytesAsAccumulatorMember(stringToBytes('user-id: abc9090'));
    addRevocationIdToAttributes(holderMessages2, revocationId2);

    // Issuer gives blind signature after verifying credential and revocation check
    const blindedCred2 = issueBlindSigWithCredVerif(
      blindSigReq2,
      Issuer12SigParams,
      Issuer2Sk,
      msgArrayToMapForBlindSign(holderMessages2),
      Issuer12SigParams,
      Issuer1Pk,
      revealedMsgs1,
      Accum1Params,
      Accum1Pk,
      Accum1Prk,
      Accum1.accumulated
    );

    await Accum2.add(revocationId2, Accum2Sk);
    const membershipWitness2 = await Accum2.membershipWitness(revocationId2, Accum2Sk);

    [Credential2, credential2AttributesFinal] = unBlindAndVerify(
      blindedCred2,
      blinding2,
      holderSecret,
      holderMessages2,
      Issuer2Pk,
      Issuer12SigParams
    );
    const memCheck2 = Accum2.verifyMembershipWitness(revocationId2, membershipWitness2, Accum2Pk, Accum2Params);
    if (!memCheck2) {
      throw new Error('Membership check failed in accumulator 2');
    }

    // Get Credential 3. For this holder has to prove possession of credential 1 and 2, reveal the last attribute of both, and prove
    // the user-id attribute from both is in the accumulators `Accum1` and `Accum2`
    // Holder reveals 1 attribute at index `credential12AttrCount - 1`
    const revealed2 = new Set<number>();
    revealed2.add(credential12AttrCount - 1);
    const revealedMsgs2 = new Map();
    const unrevealedMsgs2 = new Map();
    for (let i = 0; i < credential12AttrCount; i++) {
      if (revealed2.has(i)) {
        revealedMsgs2.set(i, credential2AttributesFinal[i]);
      } else {
        unrevealedMsgs2.set(i, credential2AttributesFinal[i]);
      }
    }

    // Create request to verify blind signature along with proof of one credential
    const [blindSigReq3, blinding3] = blindSigRequestWithSecretAnd2Credentials(
      holderSecret,
      Issuer3SigParams,
      Credential1,
      Issuer12SigParams,
      Issuer1Pk,
      revealedMsgs1,
      unrevealedMsgs1,
      Accum1Params,
      Accum1Pk,
      Accum1Prk,
      Accum1.accumulated,
      membershipWitness1,
      Credential2,
      Issuer12SigParams,
      Issuer2Pk,
      revealedMsgs2,
      unrevealedMsgs2,
      Accum2Params,
      Accum2Pk,
      Accum2Prk,
      Accum2.accumulated,
      membershipWitness2
    );

    // Issuer prepares messages for signing including rev id
    const holderMessages3 = prepareMessagesForBlindSigning(credential3Attributes);
    const revocationId3 = Accumulator.encodeBytesAsAccumulatorMember(stringToBytes('user-id: pqr2029'));
    addRevocationIdToAttributes(holderMessages3, revocationId3);

    // Issuer gives blind signature after verifying credential and revocation check
    const blindedCred3 = issueBlindSigWith2CredVerifs(
      blindSigReq3,
      Issuer3SigParams,
      Issuer3Sk,
      msgArrayToMapForBlindSign(holderMessages3),
      Issuer12SigParams,
      Issuer1Pk,
      revealedMsgs1,
      Accum1Params,
      Accum1Pk,
      Accum1Prk,
      Accum1.accumulated,
      Issuer12SigParams,
      Issuer2Pk,
      revealedMsgs2,
      Accum2Params,
      Accum2Pk,
      Accum2Prk,
      Accum2.accumulated
    );

    await Accum3.add(revocationId3, Accum3Sk);
    const membershipWitness3 = await Accum3.membershipWitness(revocationId3, Accum3Sk);

    [Credential3, credential3AttributesFinal] = unBlindAndVerify(
      blindedCred3,
      blinding3,
      holderSecret,
      holderMessages3,
      Issuer3Pk,
      Issuer3SigParams
    );
    const memCheck3 = Accum3.verifyMembershipWitness(revocationId3, membershipWitness3, Accum3Pk);
    if (!memCheck3) {
      throw new Error('Membership check failed in accumulator 3');
    }

    const revealed3 = new Set<number>();
    revealed3.add(credential3AttrCount - 1);
    const revealedMsgs3 = new Map();
    const unrevealedMsgs3 = new Map();
    for (let i = 0; i < credential3AttrCount; i++) {
      if (revealed3.has(i)) {
        revealedMsgs3.set(i, credential3AttributesFinal[i]);
      } else {
        unrevealedMsgs3.set(i, credential3AttributesFinal[i]);
      }
    }

    const proof = proofOf3Creds(
      Credential1,
      Issuer12SigParams,
      Issuer1Pk,
      revealedMsgs1,
      unrevealedMsgs1,
      Accum1Params,
      Accum1Pk,
      Accum1Prk,
      Accum1.accumulated,
      membershipWitness1,
      Credential2,
      Issuer12SigParams,
      Issuer2Pk,
      revealedMsgs2,
      unrevealedMsgs2,
      Accum2Params,
      Accum2Pk,
      Accum2Prk,
      Accum2.accumulated,
      membershipWitness2,
      Credential3,
      Issuer3SigParams,
      Issuer3Pk,
      revealedMsgs3,
      unrevealedMsgs3,
      Accum3Params,
      Accum3Pk,
      Accum3MemPrk,
      Accum3.accumulated,
      membershipWitness3
    );

    verifyProofOf3Creds(
      proof,
      Issuer12SigParams,
      Issuer1Pk,
      revealedMsgs1,
      Accum1Params,
      Accum1Pk,
      Accum1Prk,
      Accum1.accumulated,
      Issuer12SigParams,
      Issuer2Pk,
      revealedMsgs2,
      Accum2Params,
      Accum2Pk,
      Accum2Prk,
      Accum2.accumulated,
      Issuer3SigParams,
      Issuer3Pk,
      revealedMsgs3,
      Accum3Params,
      Accum3Pk,
      Accum3MemPrk,
      Accum3.accumulated
    );

    const nonMember = randomFieldElement();
    const d = UniversalAccumulator.dForNonMembershipWitness(nonMember, [
      Accumulator.encodeBytesAsAccumulatorMember(revocationId3)
    ]);
    const nonMemWitness = await Accum3.nonMembershipWitnessGivenD(nonMember, d, Accum3Sk);
    const nonMemCheck = Accum3.verifyNonMembershipWitness(nonMember, nonMemWitness, Accum3Pk);
    if (!nonMemCheck) {
      throw new Error('Membership check failed in accumulator 3');
    }

    const j1 = Accum1.toJSON();
    if (!areUint8ArraysEqual(Accum1.value, PositiveAccumulator.fromJSON(j1).value)) {
      throw new Error('From JSON failed for Accum1');
    }

    const j2 = Accum2.toJSON();
    if (!areUint8ArraysEqual(Accum2.value, PositiveAccumulator.fromJSON(j2).value)) {
      throw new Error('From JSON failed for Accum2');
    }

    const j3 = Accum3.toJSON();
    const k = UniversalAccumulator.fromJSON(j3).value;
    if (!areUint8ArraysEqual(Accum3.value.f_V, k.f_V)) {
      throw new Error('From JSON failed for Accum3');
    }
    if (!areUint8ArraysEqual(Accum3.value.V, k.V)) {
      throw new Error('From JSON failed for Accum3');
    }

    const j4 = membershipWitness1.toJSON();
    if (!areUint8ArraysEqual(membershipWitness1.value, MembershipWitness.fromJSON(j4).value)) {
      throw new Error('From JSON failed for witness 1');
    }

    const j5 = membershipWitness2.toJSON();
    if (!areUint8ArraysEqual(membershipWitness2.value, MembershipWitness.fromJSON(j5).value)) {
      throw new Error('From JSON failed for witness 2');
    }

    const j6 = membershipWitness3.toJSON();
    if (!areUint8ArraysEqual(membershipWitness3.value, MembershipWitness.fromJSON(j6).value)) {
      throw new Error('From JSON failed for witness 1');
    }

    const j7 = nonMemWitness.toJSON();
    const l = NonMembershipWitness.fromJSON(j7).value;
    if (!areUint8ArraysEqual(nonMemWitness.value.d, l.d)) {
      throw new Error('From JSON failed for non-member witness');
    }
    if (!areUint8ArraysEqual(nonMemWitness.value.C, l.C)) {
      throw new Error('From JSON failed for non-member witness');
    }
  });
});
