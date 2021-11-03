import {AccumulatorParams, generateRandomFieldElement, initializeWasm, universalAccumulatorComputeD} from "../../lib";
import { Accumulator, BlindSignature, BlindSignatureG1, CompositeProof,
    KeypairG2, MembershipWitness, MetaStatement, MetaStatements, NonMembershipWitness, PositiveAccumulator, ProofSpec, Signature,
    SignatureG1, SignatureParamsG1, Statement, Statements, UniversalAccumulator, Witness, WitnessEqualityMetaStatement,
    Witnesses } from "../../lib/ts";
import { areUint8ArraysEqual, stringToBytes } from "../utilities";

const credential12MsgCount = 6;
const credential3MsgCount = 10;

const credential1Messages: any[] = [];
const credential2Messages: any[] = [];
const credential3Messages: any[] = [];

let credential1MessagesFinal: Uint8Array[];
let credential2MessagesFinal: Uint8Array[];
let credential3MessagesFinal: Uint8Array[];

let Credential1: SignatureG1;
let Credential2: SignatureG1;
let Credential3: SignatureG1;

// Issuer 1 and 2 use same params
let Issuer12SigParams: SignatureParamsG1;
let Issuer3SigParams: SignatureParamsG1;
let Issuer1Sk: Uint8Array;
let Issuer1Pk: Uint8Array;
let Issuer2Sk: Uint8Array;
let Issuer2Pk: Uint8Array;
let Issuer3Sk: Uint8Array;
let Issuer3Pk: Uint8Array;

let Accum1Params: AccumulatorParams;
let Accum2Params: AccumulatorParams;
let Accum3Params: AccumulatorParams;
let Accum1Sk: Uint8Array;
let Accum1Pk: Uint8Array;
let Accum2Sk: Uint8Array;
let Accum2Pk: Uint8Array;
let Accum3Sk: Uint8Array;
let Accum3Pk: Uint8Array;
let Accum1Prk: Uint8Array;
let Accum2Prk: Uint8Array;
let Accum3NonMemPrk: Uint8Array;
let Accum3MemPrk: Uint8Array;
// Positive accumulator that stores the secret key as well
let Accum1: PositiveAccumulator;
// Positive accumulator that needs the secret key to passed when needed. This is to avoid having secret key in memory all the time.
let Accum2: PositiveAccumulator;
let Accum3: UniversalAccumulator;

export interface BlindSigRequest {
    proof: CompositeProof;
    commitment: Uint8Array;
}

const DEBUG = false;

function log(msg: any) {
    if (DEBUG) {
        console.log(msg)
    }
}

describe("Full demo", () => {
   it("runs", async () => {
       function setupMessages() {
           // 2 of the messages are reserved for a secret (eg. link secret) and accumulator index
           for (let i = 2; i < credential12MsgCount; i++) {
               credential1Messages.push(`credential1's Message${i + 1}`);
           }
           for (let i = 2; i < credential12MsgCount; i++) {
               credential2Messages.push(`credential2's Message${i + 1}`);
           }
           for (let i = 2; i < credential3MsgCount; i++) {
               credential3Messages.push(`credential3's Message${i + 1}`);
           }
       }

       function checkPublicKey(sk: Uint8Array, pk: Uint8Array, params: any) {
           if (!KeypairG2.isPublicKeyValid(pk)) {
               throw new Error('Public key is invalid');
           }
           const gpk = KeypairG2.generatePublicKeyFromSecretKey(sk, params);
           if (!areUint8ArraysEqual(gpk, pk)) {
               throw new Error(`Generated public key ${gpk} different from expected public key ${pk}`);
           }
           if (!KeypairG2.isPublicKeyValid(gpk)) {
               throw new Error('Generated public key is invalid');
           }
       }

       function setupIssuer1Keys() {
           const kp = KeypairG2.generate(Issuer12SigParams);
           Issuer1Sk = kp.secretKey;
           Issuer1Pk = kp.publicKey;
           checkPublicKey(Issuer1Sk, Issuer1Pk, Issuer12SigParams);
           log("Issuer 1's secret and public keys are:");
           log(Issuer1Sk);
           log(Issuer1Pk);
       }

       function setupIssuer2Keys() {
           const kp = KeypairG2.generate(Issuer12SigParams, stringToBytes("my secret passphrase"));
           Issuer2Sk = kp.secretKey;
           Issuer2Pk = kp.publicKey;
           checkPublicKey(Issuer2Sk, Issuer2Pk, Issuer12SigParams);
           log("Issuer 2's secret and public keys are:");
           log(Issuer2Sk);
           log(Issuer2Pk);
       }

       function setupIssuer3Keys() {
           const seed = stringToBytes("my-secret-seed");
           const kp = KeypairG2.generate(Issuer3SigParams, seed)
           Issuer3Sk = kp.secretKey;
           Issuer3Pk = kp.publicKey;
           checkPublicKey(Issuer3Sk, Issuer3Pk, Issuer3SigParams);
           log("Issuer 3's secret and public keys are:");
           log(Issuer3Sk);
           log(Issuer3Pk);
       }

       function setupIssuer12SigParams() {
           const label = stringToBytes("Params for Issuer 1 and 2");
           Issuer12SigParams = SignatureParamsG1.generate(credential12MsgCount, label);
           if (!Issuer12SigParams.isValid()) {
               throw new Error('Params is invalid');
           }
           if (Issuer12SigParams.supportedMessageCount() !== credential12MsgCount) {
               throw new Error(`supportedMessageCount returns ${Issuer12SigParams.supportedMessageCount()} but should be ${credential12MsgCount}`);
           }
           log("Issuer 1 and 2's signature params are:");
           log(Issuer12SigParams);
       }

       function setupIssuer3SigParams() {
           const label = stringToBytes("Params for Issuer 3");
           Issuer3SigParams = SignatureParamsG1.generate(credential3MsgCount, label);
           if (!Issuer3SigParams.isValid()) {
               throw new Error('Params is invalid');
           }
           if (Issuer3SigParams.supportedMessageCount() !== credential3MsgCount) {
               throw new Error(`supportedMessageCount returns ${Issuer3SigParams.supportedMessageCount()} but should be ${credential3MsgCount}`);
           }
           log("Issuer 3's signature params are:");
           log(Issuer3SigParams);
       }

       function setupAccumulator1() {
           const label = stringToBytes("Params for Accumulator 1");
           Accum1Params = Accumulator.generateParams(label);
           Accum1Sk = Accumulator.generateSecretKey();
           Accum1Pk = Accumulator.generatePublicKeyFromSecretKey(Accum1Sk, Accum1Params);
           Accum1 = PositiveAccumulator.initialize(Accum1Params, Accum1Sk);
           Accum1Prk = Accumulator.generateMembershipProvingKey(stringToBytes("Some public label"));
       }

       function setupAccumulator2() {
           Accum2Params = Accumulator.generateParams();
           const seed = stringToBytes("some-secret-seed");
           Accum2Sk = Accumulator.generateSecretKey(seed);
           Accum2Pk = Accumulator.generatePublicKeyFromSecretKey(Accum2Sk, Accum2Params);
           Accum2 = PositiveAccumulator.initialize(Accum2Params);
           Accum2Prk = Accumulator.generateMembershipProvingKey();
       }

       async function setupAccumulator3() {
           Accum3Params = Accumulator.generateParams();
           const seed = stringToBytes("secret-seed-for-non-universal-accum");
           const keypair = Accumulator.generateKeypair(Accum3Params, seed);
           Accum3Sk = keypair.secret_key;
           Accum3Pk = keypair.public_key;
           const maxSize = 100;

           const initialElements = [];
           for (let i = 0; i < maxSize; i++) {
               initialElements.push(generateRandomFieldElement());
           }

           const fV = UniversalAccumulator.initialElementsProduct(initialElements, Accum3Sk);
           Accum3 = UniversalAccumulator.initializeGivenInitialElementsProduct(maxSize, fV, Accum3Params);
           Accum3NonMemPrk = Accumulator.generateNonMembershipProvingKey(stringToBytes("Another public label"));
           Accum3MemPrk = Accumulator.deriveMembershipKeyFromNonMembershipProvingKey(Accum3NonMemPrk);
       }

       function prepareMessagesForBlindSigning(messages: Uint8Array[]) {
           const encodedMessages = [];
           for (const msg of messages) {
               encodedMessages.push(Signature.encodeMessageForSigning(msg));
           }
           return encodedMessages;
       }

       function addRevocationIdToMessages(messages: Uint8Array[], id: Uint8Array) {
           // Assuming add at 0 index
           messages.splice(0, 0, id);
       }

       function msgArrayToMapForBlindSign(messages: Uint8Array[]): Map<number, Uint8Array> {
           const map = new Map();
           for (let i = 0; i < messages.length; i++) {
               // Leaving index 0 for link secret
               map.set(i + 1, messages[i]);
           }
           return map;
       }

       function blindSigRequestWithSecretStatementAndWitness(secret: Uint8Array, sigParams: SignatureParamsG1): [Uint8Array, Uint8Array, Uint8Array, Uint8Array] {
           const encodedSecret = Signature.encodeMessageForSigning(secret);
           const blinding = BlindSignature.generateBlinding();
           const indicesToCommit = new Set<number>();
           indicesToCommit.add(0);
           const msgsToCommit = new Map();
           msgsToCommit.set(0, encodedSecret);

           const [commitment] = sigParams.commitToMessages(msgsToCommit, false, blinding);
           const bases = sigParams.getParamsForIndices([...indicesToCommit]);
           const statement = Statement.pedersenCommitmentG1(bases, commitment);
           const witness = Witness.pedersenCommitment([
               blinding, encodedSecret
           ]);
           return [statement, witness, commitment, blinding]
       }

       function blindSigRequestWithSecret(secret: Uint8Array, sigParams: SignatureParamsG1, nonce?: Uint8Array): [BlindSigRequest, Uint8Array] {
           const [statement, witness, commitment, blinding] = blindSigRequestWithSecretStatementAndWitness(secret, sigParams);
           const statements = new Statements();
           statements.add(statement);
           const proofSpec = new ProofSpec(statements, new MetaStatements());
           const witnesses = new Witnesses();
           witnesses.add(witness);
           const proof = CompositeProof.generate(proofSpec, witnesses, nonce);
           return [{proof, commitment}, blinding]
       }

       function blindSigRequestWithSecretAndCredential(
           secret: Uint8Array, sigParamsForRequestedCredential: SignatureParamsG1,
           credential: SignatureG1, sigParams: SignatureParamsG1, pk: Uint8Array, revealedMsgs: Map<number, Uint8Array>, unrevealedMsgs: Map<number, Uint8Array>,
           accumParams: AccumulatorParams, accumPk: Uint8Array, prk: Uint8Array, accumulated: Uint8Array, membershipWitness: MembershipWitness, nonce?: Uint8Array
       ): [BlindSigRequest, Uint8Array] {
           const statement1 = Statement.poKBBSSignature(sigParams, pk, revealedMsgs, false);
           const witness1 = Witness.poKBBSSignature(credential, unrevealedMsgs, false);

           const statement2 = Statement.accumulatorMembership(accumParams, accumPk, prk, accumulated);
           const witness2 = Witness.accumulatorMembership(unrevealedMsgs.get(1) as Uint8Array, membershipWitness);

           const [statement3, witness3, commitment, blinding] = blindSigRequestWithSecretStatementAndWitness(
               secret, sigParamsForRequestedCredential
           );

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

           const proofSpec = new ProofSpec(statements, metaStatements);
           const witnesses = new Witnesses();
           witnesses.add(witness1);
           witnesses.add(witness2);
           witnesses.add(witness3);
           const proof = CompositeProof.generate(proofSpec, witnesses, nonce);
           return [{proof, commitment}, blinding]
       }

       function blindSigRequestWithSecretAnd2Credentials(
           secret: Uint8Array, sigParamsForRequestedCredential: SignatureParamsG1,
           credential: SignatureG1, sigParams: SignatureParamsG1, pk: Uint8Array, revealedMsgs: Map<number, Uint8Array>, unrevealedMsgs: Map<number, Uint8Array>,
           accumParams: AccumulatorParams, accumPk: Uint8Array, prk: Uint8Array, accumulated: Uint8Array, membershipWitness: MembershipWitness,
           credential2: SignatureG1, sigParams2: SignatureParamsG1, pk2: Uint8Array, revealedMsgs2: Map<number, Uint8Array>, unrevealedMsgs2: Map<number, Uint8Array>,
           accumParams2: AccumulatorParams, accumPk2: Uint8Array, prk2: Uint8Array, accumulated2: Uint8Array, membershipWitness2: MembershipWitness,
           nonce?: Uint8Array,
       ): [BlindSigRequest, Uint8Array] {
           const statement1 = Statement.poKBBSSignature(sigParams, pk, revealedMsgs, false);
           const witness1 = Witness.poKBBSSignature(credential, unrevealedMsgs, false);

           const statement2 = Statement.accumulatorMembership(accumParams, accumPk, prk, accumulated);
           const witness2 = Witness.accumulatorMembership(unrevealedMsgs.get(1) as Uint8Array, membershipWitness);

           const statement3 = Statement.poKBBSSignature(sigParams2, pk2, revealedMsgs2, false);
           const witness3 = Witness.poKBBSSignature(credential2, unrevealedMsgs2, false);

           const statement4 = Statement.accumulatorMembership(accumParams2, accumPk2, prk2, accumulated2);
           const witness4 = Witness.accumulatorMembership(unrevealedMsgs2.get(1) as Uint8Array, membershipWitness2);

           const [statement5, witness5, commitment, blinding] = blindSigRequestWithSecretStatementAndWitness(
               secret, sigParamsForRequestedCredential
           );

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

           const proofSpec = new ProofSpec(statements, metaStatements);

           const witnesses = new Witnesses();
           witnesses.add(witness1);
           witnesses.add(witness2);
           witnesses.add(witness3);
           witnesses.add(witness4);
           witnesses.add(witness5);
           const proof = CompositeProof.generate(proofSpec, witnesses, nonce);
           return [{proof, commitment}, blinding]
       }

       function issueBlindSig(blindSigReq: BlindSigRequest, sigParams: SignatureParamsG1, sk: Uint8Array, otherMsgs: Map<number, Uint8Array>, nonce?: Uint8Array) {
           const indicesToCommit = new Set<number>();
           indicesToCommit.add(0);
           const bases = sigParams.getParamsForIndices([...indicesToCommit]);
           const statement = Statement.pedersenCommitmentG1(bases, blindSigReq.commitment);
           const statements = new Statements();
           statements.add(statement);

           const proofSpec = new ProofSpec(statements, new MetaStatements());
           const res = blindSigReq.proof.verify(proofSpec, nonce);
           if (!res.verified) {
               throw new Error(`Failed to verify blind sig request due to ${res.error}`);
           }
           return BlindSignatureG1.generate(blindSigReq.commitment, otherMsgs, sk, sigParams, false);
       }

       function issueBlindSigWithCredVerif(
           blindSigReq: BlindSigRequest, sigParamsForRequestedCredential: SignatureParamsG1, sk: Uint8Array, otherMsgs: Map<number, Uint8Array>,
           sigParams: SignatureParamsG1, pk: Uint8Array, revealedMsgs: Map<number, Uint8Array>,
           accumParams: AccumulatorParams, accumPk: Uint8Array, prk: Uint8Array, accumulated: Uint8Array,
           nonce?: Uint8Array
       ) {
           const indicesToCommit = [];
           indicesToCommit.push(0);
           const bases = sigParamsForRequestedCredential.getParamsForIndices(indicesToCommit);
           const statement1 = Statement.poKBBSSignature(sigParams, pk, revealedMsgs, false);
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

           const proofSpec = new ProofSpec(statements, metaStatements);

           const res = blindSigReq.proof.verify(proofSpec, nonce);
           if (!res.verified) {
               throw new Error(`Failed to verify blind sig request due to ${res.error}`);
           }
           return BlindSignatureG1.generate(blindSigReq.commitment, otherMsgs, sk, sigParamsForRequestedCredential, false);
       }

       function issueBlindSigWith2CredVerifs(
           blindSigReq: BlindSigRequest, sigParamsForRequestedCredential: SignatureParamsG1, sk: Uint8Array, otherMsgs: Map<number, Uint8Array>,
           sigParams: SignatureParamsG1, pk: Uint8Array, revealedMsgs: Map<number, Uint8Array>,
           accumParams: AccumulatorParams, accumPk: Uint8Array, prk: Uint8Array, accumulated: Uint8Array,
           sigParams2: SignatureParamsG1, pk2: Uint8Array, revealedMsgs2: Map<number, Uint8Array>,
           accumParams2: AccumulatorParams, accumPk2: Uint8Array, prk2: Uint8Array, accumulated2: Uint8Array,
           nonce?: Uint8Array
       ) {
           const indicesToCommit = [];
           indicesToCommit.push(0);
           const bases = sigParamsForRequestedCredential.getParamsForIndices(indicesToCommit);
           const statement1 = Statement.poKBBSSignature(sigParams, pk, revealedMsgs, false);
           const statement2 = Statement.accumulatorMembership(accumParams, accumPk, prk, accumulated);
           const statement3 = Statement.poKBBSSignature(sigParams2, pk2, revealedMsgs2, false);
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

           const proofSpec = new ProofSpec(statements, metaStatements);

           const res = blindSigReq.proof.verify(proofSpec, nonce);
           if (!res.verified) {
               throw new Error(`Failed to verify blind sig request due to ${res.error}`);
           }
           return BlindSignatureG1.generate(blindSigReq.commitment, otherMsgs, sk, sigParamsForRequestedCredential, false);
       }

       function proofOf3Creds(
           credential: SignatureG1, sigParams: SignatureParamsG1, pk: Uint8Array, revealedMsgs: Map<number, Uint8Array>, unrevealedMsgs: Map<number, Uint8Array>,
           accumParams: AccumulatorParams, accumPk: Uint8Array, prk: Uint8Array, accumulated: Uint8Array, membershipWitness: MembershipWitness,
           credential2: SignatureG1, sigParams2: SignatureParamsG1, pk2: Uint8Array, revealedMsgs2: Map<number, Uint8Array>, unrevealedMsgs2: Map<number, Uint8Array>,
           accumParams2: AccumulatorParams, accumPk2: Uint8Array, prk2: Uint8Array, accumulated2: Uint8Array, membershipWitness2: MembershipWitness,
           credential3: SignatureG1, sigParams3: SignatureParamsG1, pk3: Uint8Array, revealedMsgs3: Map<number, Uint8Array>, unrevealedMsgs3: Map<number, Uint8Array>,
           accumParams3: AccumulatorParams, accumPk3: Uint8Array, prk3: Uint8Array, accumulated3: Uint8Array, membershipWitness3: MembershipWitness,
           nonce?: Uint8Array
       ) {
           const statement1 = Statement.poKBBSSignature(sigParams, pk, revealedMsgs, false);
           const witness1 = Witness.poKBBSSignature(credential, unrevealedMsgs, false);

           const statement2 = Statement.accumulatorMembership(accumParams, accumPk, prk, accumulated);
           const witness2 = Witness.accumulatorMembership(unrevealedMsgs.get(1) as Uint8Array, membershipWitness);

           const statement3 = Statement.poKBBSSignature(sigParams2, pk2, revealedMsgs2, false);
           const witness3 = Witness.poKBBSSignature(credential2, unrevealedMsgs2, false);

           const statement4 = Statement.accumulatorMembership(accumParams2, accumPk2, prk2, accumulated2);
           const witness4 = Witness.accumulatorMembership(unrevealedMsgs2.get(1) as Uint8Array, membershipWitness2);

           const statement5 = Statement.poKBBSSignature(sigParams3, pk3, revealedMsgs3, false);
           const witness5 = Witness.poKBBSSignature(credential3, unrevealedMsgs3, false);

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

           const proofSpec = new ProofSpec(statements, metaStatements);

           const witnesses = new Witnesses();
           witnesses.add(witness1);
           witnesses.add(witness2);
           witnesses.add(witness3);
           witnesses.add(witness4);
           witnesses.add(witness5);
           witnesses.add(witness6);

           return CompositeProof.generate(proofSpec, witnesses, nonce);
       }

       function verifyProofOf3Creds(
           proof: CompositeProof,
           sigParams: SignatureParamsG1, pk: Uint8Array, revealedMsgs: Map<number, Uint8Array>,
           accumParams: AccumulatorParams, accumPk: Uint8Array, prk: Uint8Array, accumulated: Uint8Array,
           sigParams2: SignatureParamsG1, pk2: Uint8Array, revealedMsgs2: Map<number, Uint8Array>,
           accumParams2: AccumulatorParams, accumPk2: Uint8Array, prk2: Uint8Array, accumulated2: Uint8Array,
           sigParams3: SignatureParamsG1, pk3: Uint8Array, revealedMsgs3: Map<number, Uint8Array>,
           accumParams3: AccumulatorParams, accumPk3: Uint8Array, prk3: Uint8Array, accumulated3: Uint8Array,
           nonce?: Uint8Array
       ) {
           const statement1 = Statement.poKBBSSignature(sigParams, pk, revealedMsgs, false);
           const statement2 = Statement.accumulatorMembership(accumParams, accumPk, prk, accumulated);
           const statement3 = Statement.poKBBSSignature(sigParams2, pk2, revealedMsgs2, false);
           const statement4 = Statement.accumulatorMembership(accumParams2, accumPk2, prk2, accumulated2);
           const statement5 = Statement.poKBBSSignature(sigParams3, pk3, revealedMsgs3, false);
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

           const proofSpec = new ProofSpec(statements, metaStatements);

           const res = proof.verify(proofSpec, nonce);
           if (!res.verified) {
               throw new Error(`Failed to verify proof of 3 creds due to ${res.error}`);
           }
       }

       function unBlindAndVerify(
           blindedSig: BlindSignatureG1, blinding: Uint8Array, secret: Uint8Array, msgs: Uint8Array[], pk: Uint8Array, sigParams: SignatureParamsG1
       ): [SignatureG1, Uint8Array[]] {
           const unblinded = blindedSig.unblind(blinding);
           let final = [];
           final.push(Signature.encodeMessageForSigning(secret));
           final = final.concat(msgs);
           const res1 = unblinded.verify(final, pk, sigParams, false);
           if (!res1.verified) {
               throw new Error(`Failed to verify unblinded sig1 due to ${res1.error}`);
           }
           return [unblinded, final];
       }

       await initializeWasm();

       // Initialize messages which will be signed
       setupMessages();

       console.log(SignatureParamsG1);
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

       const holderSecret = stringToBytes("MySecret123");

       // Get Credential 1
       // Holder prepares request for blind signature
       const [blindSigReq1, blinding1] = blindSigRequestWithSecret(holderSecret, Issuer12SigParams);

       // Issuer prepares messages for signing including rev id
       const holderMessages1 = prepareMessagesForBlindSigning(credential1Messages);
       const revocationId1 = Accumulator.encodeBytesAsAccumulatorMember(stringToBytes("user-id: xyz123"));
       addRevocationIdToMessages(holderMessages1, revocationId1);

       // Issuer issues a blind signature after verifying the knowledge of committed values
       const blindedCred1 = issueBlindSig(blindSigReq1, Issuer12SigParams, Issuer1Sk, msgArrayToMapForBlindSign(holderMessages1));
       // Accumulator managers adds rev id to the accumulator
       await Accum1.add(revocationId1);
       const membershipWitness1 = await Accum1.membershipWitness(revocationId1);

       // Holder unblinds and verifies signature
       [Credential1, credential1MessagesFinal] = unBlindAndVerify(blindedCred1, blinding1, holderSecret, holderMessages1, Issuer1Pk, Issuer12SigParams);
       const memCheck1 = Accum1.verifyMembershipWitness(revocationId1, membershipWitness1, Accum1Pk, Accum1Params);
       if (!memCheck1) {
           throw new Error("Membership check failed in accumulator 1")
       }

       // Get Credential 2
       // Holder reveals 1 attribute at index `credential12MsgCount - 1`
       const revealed1 = new Set<number>();
       revealed1.add(credential12MsgCount - 1);
       const revealedMsgs1 = new Map();
       const unrevealedMsgs1 = new Map();
       for (let i = 0; i < credential12MsgCount; i++) {
           if (revealed1.has(i)) {
               revealedMsgs1.set(i, credential1MessagesFinal[i]);
           } else {
               unrevealedMsgs1.set(i, credential1MessagesFinal[i]);
           }
       }

       // Create request to verify blind signature along with proof of one credential
       const [blindSigReq2, blinding2] = blindSigRequestWithSecretAndCredential(
           holderSecret, Issuer12SigParams, Credential1, Issuer12SigParams, Issuer1Pk, revealedMsgs1, unrevealedMsgs1,
           Accum1Params, Accum1Pk, Accum1Prk, Accum1.accumulated, membershipWitness1
       );

       // Issuer prepares messages for signing including rev id
       const holderMessages2 = prepareMessagesForBlindSigning(credential2Messages);
       const revocationId2 = Accumulator.encodeBytesAsAccumulatorMember(stringToBytes("user-id: abc9090"));
       addRevocationIdToMessages(holderMessages2, revocationId2);

       // Issuer gives blind signature after verifying credential and revocation check
       const blindedCred2 = issueBlindSigWithCredVerif(
           blindSigReq2, Issuer12SigParams, Issuer2Sk, msgArrayToMapForBlindSign(holderMessages2),
           Issuer12SigParams, Issuer1Pk, revealedMsgs1,
           Accum1Params, Accum1Pk, Accum1Prk, Accum1.accumulated
       );

       await Accum2.add(revocationId2, Accum2Sk);
       const membershipWitness2 = await Accum2.membershipWitness(revocationId2, Accum2Sk);

       [Credential2, credential2MessagesFinal] = unBlindAndVerify(
           blindedCred2, blinding2, holderSecret, holderMessages2, Issuer2Pk, Issuer12SigParams
       );
       const memCheck2 = Accum2.verifyMembershipWitness(revocationId2, membershipWitness2, Accum2Pk, Accum2Params);
       if (!memCheck2) {
           throw new Error("Membership check failed in accumulator 2")
       }

       // Get Credential 3
       // Holder reveals 1 attribute at index `credential12MsgCount - 1`
       const revealed2 = new Set<number>();
       revealed2.add(credential12MsgCount - 1);
       const revealedMsgs2 = new Map();
       const unrevealedMsgs2 = new Map();
       for (let i = 0; i < credential12MsgCount; i++) {
           if (revealed2.has(i)) {
               revealedMsgs2.set(i, credential2MessagesFinal[i]);
           } else {
               unrevealedMsgs2.set(i, credential2MessagesFinal[i]);
           }
       }

       // Create request to verify blind signature along with proof of one credential
       const [blindSigReq3, blinding3] = blindSigRequestWithSecretAnd2Credentials(
           holderSecret, Issuer3SigParams,
           Credential1, Issuer12SigParams, Issuer1Pk, revealedMsgs1, unrevealedMsgs1,
           Accum1Params, Accum1Pk, Accum1Prk, Accum1.accumulated, membershipWitness1,
           Credential2, Issuer12SigParams, Issuer2Pk, revealedMsgs2, unrevealedMsgs2,
           Accum2Params, Accum2Pk, Accum2Prk, Accum2.accumulated, membershipWitness2
       );

       // Issuer prepares messages for signing including rev id
       const holderMessages3 = prepareMessagesForBlindSigning(credential3Messages);
       const revocationId3 = Accumulator.encodeBytesAsAccumulatorMember(stringToBytes("user-id: pqr2029"));
       addRevocationIdToMessages(holderMessages3, revocationId3);

       // Issuer gives blind signature after verifying credential and revocation check
       const blindedCred3 = issueBlindSigWith2CredVerifs(
           blindSigReq3, Issuer3SigParams, Issuer3Sk, msgArrayToMapForBlindSign(holderMessages3),
           Issuer12SigParams, Issuer1Pk, revealedMsgs1,
           Accum1Params, Accum1Pk, Accum1Prk, Accum1.accumulated,
           Issuer12SigParams, Issuer2Pk, revealedMsgs2,
           Accum2Params, Accum2Pk, Accum2Prk, Accum2.accumulated,
       );

       await Accum3.add(revocationId3, Accum3Sk);
       const membershipWitness3 = await Accum3.membershipWitness(revocationId3, Accum3Sk);

       [Credential3, credential3MessagesFinal] = unBlindAndVerify(
           blindedCred3, blinding3, holderSecret, holderMessages3, Issuer3Pk, Issuer3SigParams
       );
       const memCheck3 = Accum3.verifyMembershipWitness(revocationId3, membershipWitness3, Accum3Pk);
       if (!memCheck3) {
           throw new Error("Membership check failed in accumulator 3")
       }

       const revealed3 = new Set<number>();
       revealed3.add(credential3MsgCount - 1);
       const revealedMsgs3 = new Map();
       const unrevealedMsgs3 = new Map();
       for (let i = 0; i < credential3MsgCount; i++) {
           if (revealed3.has(i)) {
               revealedMsgs3.set(i, credential3MessagesFinal[i]);
           } else {
               unrevealedMsgs3.set(i, credential3MessagesFinal[i]);
           }
       }

       const proof = proofOf3Creds(
           Credential1, Issuer12SigParams, Issuer1Pk, revealedMsgs1, unrevealedMsgs1,
           Accum1Params, Accum1Pk, Accum1Prk, Accum1.accumulated, membershipWitness1,
           Credential2, Issuer12SigParams, Issuer2Pk, revealedMsgs2, unrevealedMsgs2,
           Accum2Params, Accum2Pk, Accum2Prk, Accum2.accumulated, membershipWitness2,
           Credential3, Issuer3SigParams, Issuer3Pk, revealedMsgs3, unrevealedMsgs3,
           Accum3Params, Accum3Pk, Accum3MemPrk, Accum3.accumulated, membershipWitness3
       );

       verifyProofOf3Creds(
           proof,
           Issuer12SigParams, Issuer1Pk, revealedMsgs1,
           Accum1Params, Accum1Pk, Accum1Prk, Accum1.accumulated,
           Issuer12SigParams, Issuer2Pk, revealedMsgs2,
           Accum2Params, Accum2Pk, Accum2Prk, Accum2.accumulated,
           Issuer3SigParams, Issuer3Pk, revealedMsgs3,
           Accum3Params, Accum3Pk, Accum3MemPrk, Accum3.accumulated,
       );

       const nonMember = generateRandomFieldElement();
       const d = universalAccumulatorComputeD(nonMember, [Accumulator.encodeBytesAsAccumulatorMember(revocationId3)]);
       const nonMemWitness = await Accum3.nonMembershipWitnessGivenD(nonMember, d, Accum3Sk);
       const nonMemCheck = Accum3.verifyNonMembershipWitness(nonMember, nonMemWitness, Accum3Pk);
       if (!nonMemCheck) {
           throw new Error("Membership check failed in accumulator 3")
       }

       const j1 = Accum1.toJSON();
       if (!areUint8ArraysEqual(Accum1.value, PositiveAccumulator.fromJSON(j1).value)) {
           throw new Error('From JSON failed for Accum1')
       }

       const j2 = Accum2.toJSON();
       if (!areUint8ArraysEqual(Accum2.value, PositiveAccumulator.fromJSON(j2).value)) {
           throw new Error('From JSON failed for Accum2')
       }

       const j3 = Accum3.toJSON();
       const k = UniversalAccumulator.fromJSON(j3).value;
       if (!areUint8ArraysEqual(Accum3.value.f_V, k.f_V)) {
           throw new Error('From JSON failed for Accum3')
       }
       if (!areUint8ArraysEqual(Accum3.value.V, k.V)) {
           throw new Error('From JSON failed for Accum3')
       }

       const j4 = membershipWitness1.toJSON();
       if (!areUint8ArraysEqual(membershipWitness1.value, MembershipWitness.fromJSON(j4).value)) {
           throw new Error('From JSON failed for witness 1')
       }

       const j5 = membershipWitness2.toJSON();
       if (!areUint8ArraysEqual(membershipWitness2.value, MembershipWitness.fromJSON(j5).value)) {
           throw new Error('From JSON failed for witness 2')
       }

       const j6 = membershipWitness3.toJSON();
       if (!areUint8ArraysEqual(membershipWitness3.value, MembershipWitness.fromJSON(j6).value)) {
           throw new Error('From JSON failed for witness 1')
       }

       const j7 = nonMemWitness.toJSON();
       const l = NonMembershipWitness.fromJSON(j7).value;
       if (!areUint8ArraysEqual(nonMemWitness.value.d, l.d)) {
           throw new Error('From JSON failed for non-member witness')
       }
       if (!areUint8ArraysEqual(nonMemWitness.value.C, l.C)) {
           throw new Error('From JSON failed for non-member witness')
       }
   })
});
