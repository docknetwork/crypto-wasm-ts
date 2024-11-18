# crypto-wasm-ts

This repository is a Typescript interface to [Dock's Rust crypto library](https://github.com/docknetwork/crypto). It uses 
the [WASM wrapper](https://github.com/docknetwork/crypto-wasm).

## Contents
- [crypto-wasm-ts](#crypto-wasm-ts)
  - [Contents](#contents)
  - [Getting started](#getting-started)
    - [Build](#build)
    - [Test](#test)
  - [Overview](#overview)
    - [BBS Signature](#bbs-signature)
    - [Accumulator](#accumulator)
    - [Composite proof](#composite-proof)
  - [Usage](#usage)
    - [BBS signatures](#bbs-signatures)
      - [Setup](#setup)
      - [Signing and verification](#signing-and-verification)
      - [Proof of knowledge of signature](#proof-of-knowledge-of-signature)
    - [Accumulators](#accumulators)
      - [Setup](#setup-1)
      - [Updating the accumulator](#updating-the-accumulator)
      - [Generating witnesses](#generating-witnesses)
      - [Updating witnesses](#updating-witnesses)
      - [Prefilled accumulator](#prefilled-accumulator)
    - [Composite proofs](#composite-proofs)
      - [Terminology](#terminology)
      - [Examples](#examples)
        - [Selective disclosure](#selective-disclosure)
        - [BBS signature over varying number of messages](#bbs-signature-over-varying-number-of-messages)
        - [Multiple BBS signatures](#multiple-bbs-signatures)
        - [BBS signature together with accumulator membership](#bbs-signature-together-with-accumulator-membership)
        - [Getting a blind signature](#getting-a-blind-signature)
        - [Pseudonyms](#pseudonyms)
        - [Social KYC](#social-kyc)
    - [Verifiable encryption using SAVER](#verifiable-encryption-using-saver)
      - [Encoding for verifiable encryption](#encoding-for-verifiable-encryption)
    - [Bound check (range proof)](#bound-check-range-proof)
      - [Encoding for negative or decimal numbers](#encoding-for-negative-or-decimal-numbers)
    - [Optimization](#optimization)
    - [Working with messages as JS objects](#working-with-messages-as-js-objects)
    - [Writing predicates in Circom](#writing-predicates-in-circom)
    - [Anonymous credentials](#anonymous-credentials)

## Getting started

To use this package within your project simply run

```
npm install @docknetwork/crypto-wasm-ts
```

Or with [Yarn](https://yarnpkg.com/)

```
yarn add @docknetwork/crypto-wasm-ts
```

### Build

To build the project run:

```
yarn build
```

### Test

To run the all tests in the project run:

```
yarn test
```

## Overview
Following is a conceptual explanation of the primitives.

### BBS Signatures
Disclaimer: There's multiple variations of the BBS scheme available out there, of which BBS+ was thought to be the version that is proven to be secure. However, in a recent [paper](https://eprint.iacr.org/2023/275), it was proven that in the initial BBS design was secure, with even a smaller signature size. This version is also the one used in the [IRTF standardization effort](https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html).

The BBS signature Scheme (henceforth referred to as just BBS) allows for signing an ordered list of messages, producing a signature of constant size independent of the number
of messages. The signer needs to have a public-private keypair and signature parameters which are public values whose size
depends on the number of messages being signed. A verifier who needs to verify the signature needs to know the
signature parameters used to sign the messages and the public key of the signer. In the context of anonymous credentials, 
messages are called attributes.  
BBS also allows a user to request a blind signature from a signer where the signer does not know 1 or more messages
from the list. The user can then unblind the blind signature to get a regular signature which can be verified by a verifier in
the usual way. Such blind signatures can be used to hide a user specific secret like a private key or some unique identifier
as a message in the message list and the signer does not become aware of the hidden message.     
With a BBS signature, a user in possession of the signature and messages and create a [zero-knowledge proof of knowledge](https://en.wikipedia.org/wiki/Proof_of_knowledge)
of the signature and the corresponding signed messages such that he can prove to a verifier that he knows a signature and the
messages and optionally reveal one or more of the messages.  
A typical use of BBS signatures looks like:
- Signature parameters of the required size are assumed to exist and published at a public location. The signer can create
  his own or reuse parameters created by another party.
- Signer creates a public-private keypair and publishes the public key. 
  The keypair can be reused for signing other messages as well.
- User requests a signature from the signer.
- Signer signs the message list using the signature parameters and his private key.
- User verifies the signature on the  message list using the signature parameters and signer's public key
- User creates a proof of knowledge of the signature and message list and optionally reveals 1 or more messages to the verifier.
- The verifier uses the signature parameters and signer's public key to verify this proof.
  If successful, the verifier is convinced that the user does have a signature from the
  signer and any messages revealed were part of the message list signed by the signer.

### Accumulator
An accumulator is a set-like data structure in which elements can be added or removed but the size of the accumulator remains constant.
However, an accumulator cannot be directly checked for presence of an element, an element needs to have accompanying data called
the witness (its the manager's signature on the element), the element and the witness and these together can be used to check the presence or absence of the element.
An accumulator can be considered similar to the root of the merkle tree where the inclusion proof is the witness of the element 
(non-membership proofs aren't possible with simple merkle trees). As with merkle trees, as elements are added or removed from the accumulator,
the witness (inclusion proof) needs to be updated for the current accumulated value (root).

2 kinds of accumulators are provided, **positive** and **universal**. 
Positive support only membership witnesses while universal support both membership and non-membership witnesses. 
Creating non-membership witnesses is expensive however, and the cost depends on the number of members present in the accumulator.
Both accumulators are owned by an accumulator manager who has the private key to the accumulator
and only the owner can add or remove elements or create witnesses using the accumulator.  
Accumulator allows proving membership of the member (or non-member) and the corresponding witness in zero knowledge meaning
a user in possession of an accumulator member (or non-member) and the witness can convince a verifier that he knows of an
element present (or absent) in the accumulator without revealing the element or the witness. Note, the like merkle trees,
witnesses (inclusion proof) are tied to the accumulated value (root) and need to be updated as accumulator changes.  
Witnesses can be updated either by the accumulator manager using his private key or the manager can publish witness update
information and the updates (additions and removals) and users can update their witnesses.
A typical use of accumulator looks like:
- Accumulator parameters are assumed to exist and published at a public location. The manager can create his own params or
  reuse existing ones.
- Accumulator manager creates a keypair and publishes the public key.
- Accumulator manager initializes the accumulator and publishes the accumulator.
- User requests an element to be added to the accumulator and the membership witness from the manager. The user could have
  also requested a non-membership witness for an absent element.
- Signer checks whether requested element is not already present (in his database) and adds the element to the
  accumulator if not already present. He publishes the new accumulator and creates a (non)membership witness and sends to the user.
- User verifies the (non)membership using the element, the witness, the new accumulated value and the accumulator params and signer's public key.
- To prove knowledge of (non)membership in zero knowledge, user and verifier agree on a proving key. Anyone can generate this.
- User can create a proof of knowledge of the element and the witness corresponding to the accumulator.
- Verifier can verify above proof using the current accumulator, the parameters and signer's public key and is convinced
  that the user knows of an element and its witness and the (non)-membership.

### Composite proof
The above primitives can be combined using the composite proof system. An example is (in zero knowledge) proving knowledge of 2
different signatures and the message lists.
Another example is proving knowledge of the signature and messages and certain message's presence (absence) in an accumulator.
Or the knowledge of 5 signatures and proving certain message is the same in the 5 message lists.

## Usage

Before calling any function that calls the underlying WASM, use `initializeWasm` to load the WASM module.
This function returns a promise which is resolved once the WASM module is successfully loaded.  

```ts
import { initializeWasm } from '@docknetwork/crypto-wasm-ts'
// Load the WASM module
await initializeWasm();
```

### Supported Signature Schemes
The library has support for BBS, BBS+, PS, and BBDT16 schemes.  
Although they're similar in many aspects, specially for BBS and BBS, you're advised to consult the tests for changes
between the different schemes. 
However, you can make a good guess just by looking at the schema [here](./tests/scheme.ts#80).

For all the following examples, BBS will be used, but the concepts should be transferable to other schemes.

### BBS signatures

BBS signatures sign an ordered list of messages and thus it is important to serialize your signing payload in this format. 
Eg, in case of a credential with attributes in JSON format where each attribute is a key, convert the JSON to a list of 
attributes and this conversion should be deterministic, meaning attributes should always end up in the same order. Following 
is a conversion of a JSON credential with 4 attributes to a list where the values are placed in the alphabetical order of the keys:

Given JSON
```json
{
  "ssn": "12345678",
  "fname": "John",
  "lname": "Smith",
  "city": "NYC"
}
```

Converted to list
```
["NYC", "John", "Smith", "12345678"]
```

Now each element of the above list must be converted to bytearrays, i.e. `Uint8Array` and the type of above list becomes `Uint8Array[]`.

#### Setup

Before messages can be signed, 2 things are needed:

- **Signature parameters**: Public values, that can be created by anyone but must be known to the signer and verifier to sign and verify respectively. To create them, the number of messages (attributes) being signed must be known and the size of the parameters increases with the number. In the above example, number of attributes is 4. These parameters can be generated randomly or deterministically by using a publicly known label. It is advised to use the latter as it allows for extending/shrinking the same parameters when number of messages change.
- **Keypair**: To create and verify BBS signatures, the signer (issuer in case of a credential) needs to create a secret key to sign, public key to verify. 

  2 ways of generating signature parameters

  ```ts
  import { BBSSignatureParams } from '@docknetwork/crypto-wasm-ts';
  const messageCount = 4;

  // Randomly generated params
  const paramsRandom = BBSSignatureParams.generate(messageCount);

  // the following function will be useful throughout the documentation
  function stringToBytes(message: string): Uint8Array {
    return Uint8Array.from(Buffer.from(message, 'utf-8'));
  }
  const label = stringToBytes("My sig params");
  // Deterministically generated params
  const paramsDeterministc = BBSSignatureParams.generate(messageCount, label);

  // Deterministic params can be extended if messageCount changes, say to 5 or 3
  const paramsDeterministc5 = paramsDeterministc.adapt(5);
  const paramsDeterministc3 = paramsDeterministc.adapt(3);
  ```
  
  Generating a keypair once signature parameters are created.

  ```ts
  import { BBSKeypair } from '@docknetwork/crypto-wasm-ts';
  const keypair = BBSKeypair.generate(paramsDeterministc);
  const sk = keypair.secretKey;
  const pk = keypair.publicKey;
  ```

  #### ByteArray messages
  Each one of the messages should be a Uint8Array 

  ```ts
  const messages: Uint8Array[] = ["NYC", "John", "Smith", "12345678"].map(element => stringToBytes(element));
  ```

#### Signing and verification

When the messages are arbitrary bytes, they need to be encoded to a field element (a number in certain range). You can either let the signing function encode it by passing 
the `encode` argument as true to encode it using your own encoding function.
  
  Letting the signing function encode  
  ```ts
  import { BBSSignature } from '@docknetwork/crypto-wasm-ts';
  
  // The signing function will encode bytes to a field element as true is passed
  const sig = BBSSignature.generate(messages, sk, paramsDeterministc, true);
  
  // As the messages are not encoded, pass true to the verification function to make it encode messages before verifying the signature.
  const result = sig.verify(messages, pk, paramsDeterministc, true);
  
  console.assert(result.verified);
  ```
  
  Passing pre-encoded messages to signing function
  ```ts
  const encodedMessages = [];

  for (let i = 0; i < messages.length; i++) {
    encodedMessages.push(generateFieldElementFromBytes(messages[i]));
  }
  // The signing function will not encode as false is passed
  const sig = BBSSignature.generate(encodedMessages, sk, params, false);

  // As the messages are pre-encoded, pass false to the verification function to avoid encoding messages before verifying the signature.
  const result = sig.verify(encodedMessages, pk, params, false);
  console.assert(result.verified);
  ```

#### Proof of knowledge of signature

Proving and verifying knowledge of signature can be done with or without using the composite proof system but this doc will only describe using the composite proof system. For the other way, see tests [here](./tests/scheme.spec.ts)

The code for BBS lives [here](./src/bbs/). 

### Accumulators

#### Setup

Similar to BBS signatures, accumulators also have a setup phase where public parameters and keys are generated and these 
public values need to be published. The accumulator manager's signing key is needed to update the accumulator or create 
a witness and the public key is needed to verify the (non)membership. This document talks only about Positive accumulator, 
for universal accumulator see the corresponding tests.

  Similar to BBS, parameters can be generated randomly or deterministically.
  ```ts
  // Randomly generated params
  const paramsRandom = PositiveAccumulator.generateParams();
  
  const label = stringToBytes("My sig params");
  // Deterministically generated params
  const params = PositiveAccumulator.generateParams(label);
  ```

  Generating a keypair once parameters are created.
  ```ts
  const keypair = PositiveAccumulator.generateKeypair(params);
  ```

  Initialize the accumulator
  ```ts
  const accumulator = PositiveAccumulator.initialize(params);
  ```

Care must be taken to not add duplicate elements in the accumulator or remove non-existent elements or creating witness of 
non-existing elements. The accumulator itself cannot make such checks and thus this state must be tracked separately. 
The interface for such a state is [IAccumulatorState](src/accumulator/IAccumulatorState.ts). Its strongly recommended that 
this state should be passed as an argument to the add, remove, and other functions that expect it. However, it's not mandatory
as the caller might have its own way of avoiding such issues. The tests below use an in-memory state `InMemoryState` which 
implements `IAccumulatorState` interface.

#### Updating the accumulator

Elements can be added/removed one by one or in a batch. Before adding an element, it must be encoded to a field element. 
Encoding a positive integer can be done using `encodePositiveNumberAsAccumulatorMember`, arbitrary bytes can be encoded as 
`encodeBytesAsAccumulatorMember`.

  Adding 2 elements in the accumulator
  ```ts
  const state = new InMemoryState();
  
  const e1 = Accumulator.encodePositiveNumberAsAccumulatorMember(101);
  const bytes: Uint8Array = [...];
  const e2 = Accumulator.encodeBytesAsAccumulatorMember(bytes);
  
  await accumulator.add(e1, sk, state);
  await accumulator.add(e2, sk, state);
  ```
  
  Removing an existing element
  ```ts
  await accumulator.remove(e2, sk, state);
  ```

  Adding multiple elements in a batch
  ```ts
  const e3 = Accumulator.encodePositiveNumberAsAccumulatorMember(103);
  const e4 = Accumulator.encodePositiveNumberAsAccumulatorMember(104);
  
  await accumulator.addBatch([e3, e4], sk, state);
  ```

  Adding and removing multiple elements in a batch
  ```ts
  // Elements to add
  const additions: Uint8Array[] = [...];
  // Elements to remove
  const removals: Uint8Array[] = [...];
  
  await accumulator.addRemoveBatches(additions, removals, sk, state);
  ```

#### Generating witnesses

Once an element is added to the accumulator by the manager, a witness is required to verify the membership. Also required 
is the accumulator value when the witness was created, this value should be publicly available. 

  Generating a membership witness
  ```ts
  // Note that the secret key is needed to create the witness
  const witness = await accumulator.membershipWitness(e4, sk, state)
  ```

  Verify the membership
  ```ts
  // The accumulated value `accumulator.accumulated` is posted publicly
  const verifAccumulator = PositiveAccumulator.fromAccumulated(accumulator.accumulated);

  // Note that only public values needed to verify the membership
  console.assert(verifAccumulator.verifyMembershipWitness(e4, witness, pk, params));
  ```

#### Updating witnesses

As the accumulator changes, the witness needs to be updated as well. The witness can be updated without the manager's 
help if the updates (additions, removals) are known.

  Update witness after an addition
  ```ts
  // Say element e8 was added after the witness of e4 was created
  witness.updatePostAdd(e8, e4, accumulator.accumulated);
  ```

  Update witness after a removal
    ```ts
    // Say element e1 was removed after the witness of e4 was created
    witness.updatePostRemove(e1, e4, accumulator.accumulated);
    ```

The above method of updating the witness by going over each update is slow. The manager can make this process more efficient 
for all members by publishing a `WitnessUpdatePublicInfo` built using the updates to the older accumulator. All members can then 
use this public information to update their witnesses.

  Manager creates `WitnessUpdatePublicInfo` and then updates the accumulator
  ```ts
  // The current accumulated value is accumulator.accumulated
  
  // Elements to add
  const additions: Uint8Array[] = [...];
  // Elements to remove
  const removals: Uint8Array[] = [...];
  
  // This will be published along with `additions` and `removals`
  const witnessUpdInfo = WitnessUpdatePublicInfo.new(accumulator.accumulated, additions, removals, sk);
  
  // Update the accumulator now
  await accumulator.addRemoveBatches(additions, removals, sk, state);
  ```

  The member can now fetch the update information and update as
  ```ts
  witness.updateUsingPublicInfoPostBatchUpdate(e4, additions, removals, witnessUpdInfo);
  ```

The member can update his witness given multiple such updates using `updateUsingPublicInfoPostMultipleBatchUpdates`. See the [tests](./tests/accumulator.spec.ts) for examples. 

#### Prefilled accumulator

The above workflow requires that after every addition to the accumulator, the new accumulator must be published along with witness 
update info so that other members can update their witnesses. This is however expensive as the accumulator and update info might be posted 
on the blockchain and also every existing member has to update its witness. One way to mitigate that is to create pre-filled 
accumulators meaning that before publishing the accumulator the first time, the manager adds all the member ids in the accumulator.
This strategy assumes that member ids are either predictable like monotonically increasing numbers or the manager can internally keep 
a map of random ids like UUIDs to a number. Now when the manager actually wants to allow a member to prove membership, he can 
create a witness for that member but the accumulator value remains same and thus the witness for existing members also remain same. 
It should be noted though that changing the accumulator value causes change in all existing witnesses and thus its better 
to make a good estimate of the number of members during prefill stage. See [this test](tests/prefilled-positive-accumulator.spec.ts) for 
a complete example using a positive accumulator.


Proof of membership and non-memberships can be done with or without using the composite proof system but this doc will only describe
using the composite proof system.

The code for accumulators lives [here](./src/accumulator).

### Composite proofs

#### Terminology

- **Statement** - The kind of proof that needs to be done and the public parameters needed to verify that proof. Eg. a BBS signature
  statement contains public key of the signer, signature params, any revealed messages, etc. Each statement in a proof has a unique index.
- **Witness** - Private data that needs to be kept hidden from the verifier. This can be the messages/attributes that are not being disclosed, 
  the signature itself, the accumulator member, accumulator witness. Every witness corresponds to some `Statement`.
- **WitnessRef** - A witness might consist of several hidden data points, hidden attributes for example. To refer to each data 
  point uniquely, a pair of indices is used where the 1st item is the `Statement` index and 2nd item is index of that data point in the witness. 
- **MetaStatement** - Describes a condition that must hold between witnesses of several statements or the same statement. Eg. to 
  express equality between attributes of 2 credentials, `MetaStatement` will refer to the `WitnessRef` of each attribute. This is
  public information as well.
- **SetupParam** - Represents (public) setup parameters of different protocols.
This is helpful when the same setup parameter needs to be passed to several `Statement`s
- **ProofSpec** - This is the proof specification and its goal is to unambiguously define **all** what needs to be proven.
This is created from all `Statement`s, `MetaStatement`s and an optional context. Both prover and verifier should independently create this.
The prover uses the `ProofSpec` and all `Witness`es to create the proof and the verifier uses the`ProofSpec` to verify the proof.  

#### Examples

##### Selective disclosure 

A complete example is shown in this [test](tests/composite-proofs/single-signature.spec.ts).  

Proving knowledge of 1 BBS signature over the attributes and only disclosing some attributes. Say there are 5 attributes in the 
credential: SSN, first name, last name, email and city, and they are present in the attribute list in that order. The prover wants 
to reveal his last name and city, but not any other attribute while proving that he possesses such a credential signed by the issuer.

```ts
// The attributes, [SSN, first name, last name, email, city]
const messages: Uint8Array[] = [...];

// Public values
const params: BBSSignatureParams;
const pk: BBSPublicKey;

// The signature
const sig: BBSSignature = ...;

// Prover prepares the attributes he wants to disclose, i.e. attribute index 2 and 4 (indexing is 0-based), and the ones he wants to hide. 
const revealedMsgIndices: Set<number> = new Set();
revealedMsgIndices.add(2);
revealedMsgIndices.add(4);

// revealedMsgs are the attributes disclosed to the verifier
const revealedMsgs: Map<number, Uint8Array> = new Map();
revealedMsgs.set(2, messages[2]);

// unrevealedMsgs are the attributes hidden from the verifier
const unrevealedMsgs: Map<number, Uint8Array> = new Map();
unrevealedMsgs.set(0, messages[0]);
unrevealedMsgs.set(1, messages[1]);
unrevealedMsgs.set(3, messages[3]);
```

Since there is only 1 kind of proof, i.e. the knowledge of a BBS signature and the signed attributes, there would be only 1 `Statement`. 

```ts
import { Statement, Statements } from '@docknetwork/crypto-wasm-ts'

// Create a BBS signature, true indicates that attributes/messages are arbitrary bytes and should be encoded first
const statement1 = Statement.bbsSignatureProverConstantTime(paramsDeterministc, revealedMsgs, true);
const statements = new Statements();
statements.add(statement1);

// Optional context of the proof, this can specify the reason why the proof was created or date of the proof, or self-attested attributes (as JSON string), etc
const context = stringToBytes('some context');
```

Once it has been established what needs to be proven, `ProofSpec` needs to be created which represents all the requirements. 
Both the prover and verifier should independently construct this `ProofSpec`. Note that there are no `MetaStatements` as there are no 
other conditions on the witnesses and thus its empty 

```ts
import { ProofSpec, MetaStatements } from '@docknetwork/crypto-wasm-ts';

const ms = new MetaStatements();
const proofSpec = new ProofSpec(statements, ms, [], context);
```

Prover creates `Witness` using the signature and hidden attributes 

```ts
import { Witness, Witnesses } from '@docknetwork/crypto-wasm-ts';

const witness1 = Witness.bbsSignatureConstantTime(sig, unrevealedMsgs, true);
const witnesses = new Witnesses();
witnesses.add(witness1);
```

Prover now uses the `ProofSpec` to create the proof. To ensure that the prover is not replaying, i.e. reusing a proof created by someone else, the verifier can request the prover to include its provided nonce in the proof.

```ts
import { CompositeProof } from '@docknetwork/crypto-wasm-ts';

const nonce = stringToBytes('a unique nonce given by verifier');
const proof = CompositeProof.generate(proofSpec, witnesses, nonce);
```

Verifier can now verify this proof. Note that the verifier does not and must not receive `ProofSpec` from prover, it 
needs to generate on its own.

```ts
console.assert(proof.verify(proofSpec, nonce).verified);
```

##### BBS signatures over varying number of messages 

The examples shown here have assumed that the number of messages for given signature params is fixed but that might not be always true. 
An example is where some of the messages in the signature are null (like N/A) in certain signatures. Eg, when the messages are attributes
in a credential that specifies the educational qualifications and institutes of a person, someone with a high school level education will 
have N/A for attributes like university name, major, etc. One way to deal with it is to decide some sentinel value like 0 for all the N/A
attributes and disclose those attributes while creating a proof. Other is to have certain attribute in the credential specify which attribute 
indices that are N/A and always reveal this attribute. A complete example of the latter is shown in this [test](tests/composite-proofs/variable-number-of-messages.spec.ts).

##### Multiple BBS signatures

A complete example is shown in this [test](tests/composite-proofs/many-bbs-signatures.spec.ts).

Proving knowledge of 2 BBS signatures over the attributes and only disclosing some attribute and proving equality of 1 attribute 
without disclosing it. Say there are 2 credentials and hence 2 BBS signatures. One credential has 5 attributes: SSN, first name, 
last name, email and city and the other has 6 attributes name, email, city, employer, employee id and SSN and in that order. 
The prover wants to prove that he has those 2 credentials, reveal his employer name and prove that SSN in both credentials is 
the same without revealing the SSN.

```ts
// The attributes from 1st credential, [SSN, first name, last name, email, city]
const messages1: Uint8Array[] = [...];
// The attributes from 2nd credential, [name, email, city, employer, employee id, SSN]
const messages2: Uint8Array[] = [...];

// Public values for 1st issuer
const parasm1: BBSSignatureParams;
const pk1: BBSPublicKey;

// Public values for 2nd issuer
const parasm2: BBSSignatureParams;
const pk2: BBSPublicKey;

// The signature from 1st credential
const sig1: BBSSignature = ...;

// The signature from 2nd credential
const sig2: BBSSignature = ...;
```

Since the prover is proving possession of 2 BBS signatures, there will be 2 `Statement`s. Also, for the 2nd signature prover is 
revealing _employer_ attribute, which is at index 3.

```ts
// Statement for signature of 1st signer, not revealing any messages to the verifier
const statement1 = Statement.bbsSignatureProverConstantTime(params1, new Map(), true);

// Statement for signature of 2nd signer, revealing 1 message to the verifier
const revealedMsgIndices: Set<number> = new Set();
revealedMsgIndices.add(3);
const revealedMsgs: Map<number, Uint8Array> = new Map();
const unrevealedMsgs2: Map<number, Uint8Array> = new Map();
for (let i = 0; i < messageCount2; i++) {
  if (revealedMsgIndices.has(i)) {
    revealedMsgs.set(i, messages2[i]);
  } else {
    unrevealedMsgs2.set(i, messages2[i]);
  }
}
const statement2 = Statement.bbsSignatureProverConstantTime(params2, revealedMsgs, true);

// Collect all the statements
const statements = new Statements();
const sId1 = statements.add(statement1);
const sId2 = statements.add(statement2);
```

The prover has 2 prove that both credentials contain the same SSN which is same as saying for the 1st signature (1st `Statement`), 
attribute at index 0 is equal to 2nd signature's (2nd `Statement`) attribute index 5. This requires the use of a `MetaStatement` to 
express this condition, specifically `MetaStatement.witnessEquality` which takes the `WitnessRef` for each witness that needs to be 
proven equal. `WitnessRef` for SSN in 1st signature is (0, 0) and in 2nd signature is (1, 5). Create a `WitnessEqualityMetaStatement` to express that.

```ts
// For proving equality of SSN, messages1[0] == messages2[5], specify using MetaStatement
const witnessEq = new WitnessEqualityMetaStatement();
witnessEq.addWitnessRef(0, 0);
witnessEq.addWitnessRef(1, 5);
const ms = MetaStatement.witnessEquality(witnessEq);

const metaStatements = new MetaStatements();
metaStatements.add(ms);
```

Incase equality of additional attribute also needs to be proven say email, then `WitnessEqualityMetaStatement` needs to be created 
for the `WitnessRef` of email in both signatures.

```ts
// For proving equality of email, messages1[3] == messages2[1], specify using MetaStatement
const witnessEq2 = new WitnessEqualityMetaStatement();
witnessEq2.addWitnessRef(sId1, 3);
witnessEq2.addWitnessRef(sId2, 1);
const ms2 = MetaStatement.witnessEquality(witnessEq2);

metaStatements.add(ms2);
```

Similar to before, once it has been established what needs to be proven, `ProofSpec` needs to be created with all `Statements`s and `MetaStatement`s.
```ts
const proofSpec = new ProofSpec(statements, metaStatements);
```

The prover creates the witnesses with both signatures and messages that he is hiding from the verifier

```ts
// Using the messages and signature from 1st signer
const unrevealedMsgs1 = new Map(messages1.map((m, i) => [i, m]));
const witness1 = Witness.bbsSignatureConstantTime(sig1, unrevealedMsgs1, true);

// Using the messages and signature from 2nd signer
const witness2 = Witness.bbsSignatureConstantTime(sig2, unrevealedMsgs2, true);

const witnesses = new Witnesses();
witnesses.add(witness1);
witnesses.add(witness2);

const proof = CompositeProof.generate(proofSpec, witnesses);
```

Verifier verifies the proof.

```ts
console.assert(proof.verify(proofSpec).verified);
```

##### BBS signature together with accumulator membership

Say a prover has a credential where one of the attribute is added to an accumulator. The prover wants to prove that his attribute is a 
member of the accumulator without revealing the attribute itself. Say the attributes are SSN, first name, last name, email and 
user-id and the prover wants to prove that the user-id is present in the accumulator without revealing it to the verifier.

```ts
// The attributes, [SSN, first name, last name, email, user-id]
const messages: Uint8Array[] = [...];
```

Because the attributes for accumulator and BBS signatures are encoded differently, attributes are pre-encoded.

```ts
// Encode messages for signing as well as adding to the accumulator
const encodedMessages = [];
for (let i = 0; i < messageCount; i++) {
  if (i === messageCount-1) {
    // Last one, i.e. user id is added to the accumulator so encode accordingly
    encodedMessages.push(Accumulator.encodeBytesAsAccumulatorMember(messages[i]));
  } else {
    encodedMessages.push(Signature.encodeMessageForSigning(messages[i]));
  }
}
```

Both signer and accumulator manager will have public params and their secret keys 

```ts
const sigParams = BBSSignatureParams.generate(5, label);

// Signers keys
const sigSk: BBSPlusSecretKey = ...;
const sigPk: BBSPublicKey = ...;

// Accumulator manager's params, keys and state
const accumParams = PositiveAccumulator.generateParams(stringToBytes('Accumulator params'));
const accumKeypair = PositiveAccumulator.generateKeypair(accumParams);
const accumulator = PositiveAccumulator.initialize(accumParams);
const state = new InMemoryState();
```

Signer signs the credential and accumulator manager adds the attribute to the credential and sends the witness to the prover
```ts
// Signer signs the message
const sig: BBSSignature = ...;

// user-id is at index 4 is the message list
const userIdIdx = 4;
await accumulator.add(encodedMessages[userIdIdx], accumKeypair.secret_key, state);
const accumWitness = await accumulator.membershipWitness(encodedMessages[userIdIdx], accumKeypair.secret_key, state)
```

To prove accumulator membership in zero-knowledge, the prover and verifier agree on set of public parameters called the `ProvingKey`. 
This is not specific to the accumulator and can be reused for any number of accumulators. Also a prover might use different 
proving keys when interacting with different verifiers. Its recommended generating the proving key deterministically by passing a label.

```ts
const provingKey = Accumulator.generateMembershipProvingKey(stringToBytes('Our proving key'));
```

The prover needs to prove 2 `Statement`s, knowledge of BBS signature and knowledge of accumulator member and corresponding witness.

```ts
const statement1 = Statement.bbsSignatureProverConstantTime(sigParams, revealedMsgs, false);
const statement2 = Statement.accumulatorMembership(accumParams, accumKeypair.public_key, provingKey, accumulator.accumulated);
const statements = new Statements();
statements.add(statement1);
statements.add(statement2);
```

The prover also needs to prove that the accumulator member is same as the credential attribute at index 4, the user id. 
The `WitnessRef` of the accumulator member is (1, 0) as index of membership `Statement` is 1 and index of member is always 0.

```ts
// The last message in the signature is same as the accumulator member
const witnessEq = new WitnessEqualityMetaStatement();
// Witness ref for last message in the signature
witnessEq.addWitnessRef(0, userIdIdx);
// Witness ref for accumulator member
witnessEq.addWitnessRef(1, 0);
const ms = MetaStatement.witnessEquality(witnessEq);

const metaStatements = new MetaStatements();
metaStatements.add(ms);

const proofSpec = new ProofSpec(statements, metaStatements);
```

The prover creates `Witness`es for all statements and then creates the proof. The `Witness` for `Statement.accumulatorMembership` contains
the member and the accumulator witness. 

```ts
const witness1 = Witness.bbsSignatureConstantTime(sig, unrevealedMsgs, false);
const witness2 = Witness.accumulatorMembership(encodedMessages[userIdIdx], accumWitness);
const witnesses = new Witnesses();
witnesses.add(witness1);
witnesses.add(witness2);

const proof = CompositeProof.generate(proofSpec, witnesses);
```

##### Getting a blind signature (Example applies to BBS+)
Disclaimer: With BBS, there is no blinding (the commitment is computationally hiding, though it can be made perfectly hiding by adding a dummy attribute). However, it can be easily achieved with BBS+.
A complete example is shown in this [test](tests/composite-proofs/blind-signature.spec.ts).

A signature is blind when the signer is not aware of the message (or a part of the message) that he is signing, thus the signer is blind.
Blind signature in credential is used when the holder does not want the signer to learn some attribute, eg. one of the credential 
attribute is a secret key and the holder does not want the signer to learn the secret key. Here the user creates a commitment to 
the "blinded", i.e. hidden attributes to convince the signer that he is only hiding the certain attribute(s). Eg if a credential has 5 
attributes secret1, name, secret2, email, city and the user wants to hide secret1 and secret2 from the signer, the signer wants to 
be sure that the user is indeed hiding attributes at index 0 and 2, not others. The prover uses the composite proof system to 
prove that he knows that the commitment contains those 2 attributes

```ts
// Messages are secret1, name, secret2, email, city

// Signature params for 5 attributes
const sigParams = BBSPlusSignatureParamsG1.generate(5, label);

// Prepare messages that will be blinded (hidden) and known to signer
const blindedMessages = new Map();

// User wants to hide messages at indices 0 and 2 from signer
const blindedIndices: number[] = [];
blindedIndices.push(0);
blindedMessages.set(0, stringToBytes('my-secret'));
blindedIndices.push(2);
blindedMessages.set(2, stringToBytes('my-another-secret'));
```

The signature requester, prover in this case, creates a blind signature request. In addition to the request, it also returns 
randomness `blinding` that goes into the commitment. This randomness is later used

```ts
import { BBSPlusBlindSignatureG1 } from '@docknetwork/crypto-wasm-ts';

// Blind signature request will contain a commitment, 
const [blinding, request] = BBSPlusBlindSignatureG1.generateRequest(blindedMessages, params, true);
```

The proof needs to be over only 1 `Statement`, the statement proving knowledge of the committed attributes in the commitment. 
To create the commitment, a commitment key (public values) needs to be created from the signature params

```ts
// Take parts of the sig params corresponding to the blinded messages and create the commitment key commKey
const commKey = params.getParamsForIndices(request.blindedIndices);
const statement1 = Statement.pedersenCommitmentG1(bases, request.commitment);

const statements = new Statements();
statements.add(statement1);

const proofSpec = new ProofSpec(statements, new MetaStatements());
```

Now the prover creates witness for the commitment `Statement` using the randomness and the hidden attributes.
```ts
import { getBBSWitnessForBlindSigRequest } from '@docknetwork/crypto-wasm-ts';
const witness1 = getBBSWitnessForBlindSigRequest(blindedMessages)
const witnesses = new Witnesses();
witnesses.add(witness1);

const proof = CompositeProof.generate(proofSpec, witnesses);
```

Signer now verifies the proof. Note that the signer independently creates the `ProofSpec` as he knows which attributes are being 
hidden from him. If the proof is correct, signer creates a blind signature using the known attributes and the commitment 
and sends to the prover.

```ts
console.assert(proof.verify(proofSpec).verified);

// Signer is convinced that user knows the opening to the commitment

// Signer creates a blind signature with these revealed messages and the commitment.
revealedMessages.set(1, stringToBytes('John Smith'));
revealedMessages.set(3, stringToBytes('john.smith@emample.com'));
revealedMessages.set(4, stringToBytes('New York'));
const blindSig = BBSPlusBlindSignatureG1.generate(request.commitment, revealedMessages, sk, params, true);
```

The prover can now "unblind" the signature meaning he can convert a blind signature into a regular BBS signature 
which he can use in proof as shown in examples above

```ts
// Unbling the signature from the randomness of the commitment.
const sig = blindSig.unblind(blinding);

// Combine blinded and revealed messages in an array
const messages = Array(blindedMessages.size + revealedMessages.size);
for (const [i, m] of blindedMessages.entries()) {
  messages[i] = m;
}
for (const [i, m] of revealedMessages.entries()) {
  messages[i] = m;
}

// Signature can be verified
const result = sig.verify(messages, pk, params, true);
console.assert(result.verified);
```

##### Pseudonyms

A pseudonym is meant to be used as a unique identifier. It can be considered as a public key where the creator of the 
pseudonym has the secret key, and it can prove the knowledge of this secret key. A pseudonym can also be bound to multiple 
attributes from multiple credentials. This concept was introduced in [Attribute-based Credentials for Trust](https://link.springer.com/book/10.1007/978-3-319-14439-9). 

**Motivation**: Proving knowledge of BBS signatures is unlinkable meaning the verifier cannot link to 2 proofs presented from the same
credential (signature). But this might not always be desirable for the verifier and the prover might agree to being linked for any 
proofs that he creates for that particular verifier without revealing any attribute of the credential.  
A verifier wants to attach a unique identifier to a prover without either learning anything unintended (by prover)
from the prover's signature nor can that unique identifier be used by other verifiers to identify the prover,
eg. a seller (as a verifier) should be able to identify repeat customers (prover) by using a unique identifier, but
he should not be able to share that unique identifier with other sellers using their own identifier for that prover.


Above is achieved by making the prover go through a one-time registration process with the verifier where the prover creates 
a pseudonym and shares the pseudonym with the verifier. The prover on subsequent interactions share the pseudonym and 
proof of knowledge of the pseudonym's secret key with the verifier. Thus, pseudonyms allow for verifier-local and opt-in linkability.

In the [test](tests/composite-proofs/pseudonyms.spec.ts), the credential has 4 attributes, SSN, first name, 
last name and email and during registration, the prover creates many pseudonyms, for different verifiers, some are bound to attributes 
and some not. See the test for more details.

##### Social KYC
A social KYC (Know Your Customer) credential claims that the subject owns certain social media profile like a twitter profile 
credential claims that a user owns the twitter profile with certain handle. Here the issuer of the credential must verify 
the user's control of the profile. One way to achieve that is for the user to post a unique issuer supplied challenge string 
on his profile, like tweeting it when requesting twitter profile credential. This makes the process 2-step, in step 1 user 
requests the challenge from issuer and which he tweets and in step 2, he asks the issuer to check the tweet and issue him 
a credential. An alternate approach is for the user to post a commitment to some random value on his profile and then request 
a credential from the issuer by supplying a proof of knowledge of the opening (committed random value) of the commitment. 
The issuer is convinced that no one else could know the opening of the commitment which was posted by the user. Note that 
the user is proving knowledge of the committed value and not revealing it to the issuer because revealing the value will 
allow the issuer to request a similar credential from some another issuer of it the revealed value is leaked then someone 
else can impersonate the user.  
The [test](tests/composite-proofs/social-kyc.spec.ts) shows a complete example.

The code for composite proof lives [here](./src/composite-proof). See the tests [here](./tests/composite-proofs) for various scenarios.
For a more involved demo with multiple BBS signatures being used with accumulator and knowledge of signatures being proved 
before requesting blind signatures, see [here](./tests/demo.spec.ts). This test paints a picture where before getting any credential, 
a user has to prove possession of a credential and membership in an accumulator (except the 1st credential).

### Verifiable encryption using SAVER

Note: This section assumes you have read some of the previous examples on composite proof.

A complete example as a test is [here](./tests/composite-proofs/saver.spec.ts) 

Say a verifier wants the prover to encrypt an attribute from his credential for a 3rd party say a regulator. The verifier should be 
able to check that the prover did encrypt a specific attribute from his credential and not some arbitrary value. Also, the verifier
should be able to check that the ciphertext is encrypted for the specific public key. This is achieved through verifiable 
encryption and implemented using a protocol called [SAVER](https://eprint.iacr.org/2019/1270).  
For this, the decryptor needs to do a setup where it creates several parameters including encrytion key, decryption key, 
SNARK proving key and verification key, etc. The decryptor then publishes the public parameters. In the snippet below,
`snarkPk`, `encryptionKey`, `decryptionKey` and `gens` are published.

```ts
import { SaverEncryptionGens } from '@docknetwork/crypto-wasm-ts';

const encGens = SaverEncryptionGens.generate();
const [snarkPk, secretKey, encryptionKey, decryptionKey] = SaverDecryptor.setup(encGens);
```

`SaverDecryptor.setup` above takes an optional parameter `chunkBitSize` which can make the encryption and proving faster (or slower)
while making decryption slower (or faster). Since encryption and proving are done more often, a higher default value of 16 
is chosen for this parameter. Note that once parameters have been created with a certain value of `chunkBitSize`, the same value
should be used while encryption, decryption, proving and verification (as shown below). 

#### Encoding for verifiable encryption

For signers (issuers of credentials), it's important to encode attributes that need to be verifiably encrypted using a reversible 
encoding as the decryption might happen much later than the proof verification and thus the decryptor should be able to independently 
recover the actual attributes. This situation is different from selective disclosure where the actual attributes are given to the 
verifier who can then encode the attributes before verifying the proof. One such pair of functions are `Signature.reversibleEncodeStringForSigning`
and `Signature.reversibleDecodeStringForSigning` and you can see its use in the above-mentioned test. Theese conversions are abstracted in this [Encoders](./src/bbs-plus/encoder.ts) class and you can see the usage 
in [these tests](tests/composite-proofs/msg-js-obj/saver.spec.ts) of the  `Encoder` initialized [here](tests/composite-proofs/msg-js-obj/data-and-encoder.ts). 

For creating the proof of knowledge of the BBS signature and verifiably encrypting an attribute, the prover creates the following 2 statements.

```ts
import { SaverChunkedCommitmentKey } from '@docknetwork/crypto-wasm-ts';

// Signer's parameters
let sigParams: BBSSignatureParams, sigPk: BBSPublicKey, sig: BBSSignature;
// Signed messages
let messages: Uint8Array[];
...
...
// The value used by decryptor during setup
let chunkBitSize = ...;
...
...
// The following is either created by the verifier and is shared with the prover or created by the prover using a public bytes 
// as argument to `SaverChunkedCommitmentKey.generate`  
const gens = SaverChunkedCommitmentKey.generate(<some public bytes>);
...
...
// Uncompressed form of `gens` created above
const commKey = gens.decompress();
// Uncompressed form of other parameters created by decryptor
const saverEncGens = encGens.decompress();
const saverEk = encryptionKey.decompress();
const snarkProvingKey = snarkPk.decompress();
...
...
const statement1 = Statement.bbsSignatureProverConstantTime(sigParams, revealedMsgs, false);
const statement2 = Statement.saverProver(saverEncGens, commKey, saverEk, snarkProvingKey, chunkBitSize);

const proverStatements = new Statements();
proverStatements.add(statement1);
proverStatements.add(statement2);
```

`statement1` is the for proving knowledge of a BBS signature as seen in previous examples. `statement2` is for proving the encryption of message from a 
BBS signature. Some things to note about this statement.

- The statement is created using `Statement.saverProver` because it is being created by a prover. A verifier would have
  used `Statement.saverVerifier` to create it and one of the arguments would be different (shown below).
- The argument `saverEncGens` is the encryption generators created by decryptor. However, before they are passed to `Statement.saverProver`, the are uncompressed (ref. elliptic curve point compression) as shown in the above snippet. Uncompressing them doubles their size but makes them faster to work with. However, if you still want to use the compressed parameters use `Statement.saverProverFromCompressedParams`
- `saverEk` is the encryption key created by the decryptor during `setup` but is uncompressed.
- `snarkProvingKey` is the proving key created by the decryptor during `setup` but is uncompressed.

The prover then establishes the equality between the message in the BBS signature and the message being encrypted by using
`WitnessEqualityMetaStatement` as below. `encMsgIdx` is the index of the message being encrypted in the array of signed 
messages under BBS, `messages`. For the second statement, there is only 1 witness, thus the index 0.

```ts
const witnessEq = new WitnessEqualityMetaStatement();
witnessEq.addWitnessRef(0, encMsgIdx);
witnessEq.addWitnessRef(1, 0);
const metaStatements = new MetaStatements();
metaStatements.add(MetaStatement.witnessEquality(witnessEq));
```

The prover then creates witness for both statements. The message `messages[encMsgIdx]` passed to `Witness.saver` is the
message being encrypted. `unrevealedMsgs` passed to `Witness.bbsSignatureConstantTime` is created from `messages` and consists of
messages not being revealed to the verifier.

```ts
const witness1 = Witness.bbsSignatureConstantTime(sig, unrevealedMsgs, false);
const witness2 = Witness.saver(messages[encMsgIdx]);
const witnesses = new Witnesses();
witnesses.add(witness1);
witnesses.add(witness2);
```

The prover then creates a proof specification using `QuasiProofSpec`. This is different from `ProofSpec` object seen in 
previous examples as it does not call WASM to get a proof specification object and thus is more efficient.  
Now prover creates the proof using `CompositeProof.generateUsingQuasiProofSpec`

```ts
import { QuasiProofSpec } from '@docknetwork/crypto-wasm-ts';

const proverProofSpec = new QuasiProofSpec(proverStatements, metaStatements);
const proof = CompositeProof.generateUsingQuasiProofSpec(proverProofSpec, witnesses);
```

Similarly, the verifier also creates 2 statements and the same meta statement to verify the proof.  

```ts
// Get the uncompressed verifying key from the compressed proving key.
const snarkVerifyingKey = snarkPk.getVerifyingKeyUncompressed();

const statement1 = Statement.bbsSignatureProverConstantTime(sigParams, revealedMsgs, false);
const statement2 = Statement.saverVerifier(saverEncGens, commKey, saverEk, snarkVerifyingKey, chunkBitSize);
const verifierStatements = new Statements();
verifierStatements.add(statement1);
verifierStatements.add(statement2);

const witnessEq = new WitnessEqualityMetaStatement();
witnessEq.addWitnessRef(0, encMsgIdx);
witnessEq.addWitnessRef(1, 0);
const metaStatements = new MetaStatements();
metaStatements.add(MetaStatement.witnessEquality(witnessEq));
```

The above has a few differences from the prover's statements:

- Instead of using `Statement.saverProver`, verifier uses `Statement.saverVerifier`.
- Instead of proving key, verifier uses verifying key for the snark.

The verifier now creates the proof specification and verifies the proof.

```ts
const verifierProofSpec = new QuasiProofSpec(verifierStatements, metaStatements);
// result.verified should be true for the proof to be valid.
const result = proof.verifyUsingQuasiProofSpec(verifierProofSpec);
```

The verifier will now extract the ciphertext from the proof so that it can share that with the decryptor later. Here `1` 
passed to `proof.getSaverCiphertext` is the index (0-based) of the statement in the list of statements being proven and the 
statement from verifiable encryption was the 2nd one.

```ts
const ciphertext = proof.getSaverCiphertext(1);
```

The decryptor can decrypt the ciphertext to get message that was encrypted.

```ts
const saverDk = decryptionKey.decompress();
// decrypted.message is the message
const decrypted = SaverDecryptor.decryptCiphertext(ciphertext, saverSk, saverDk, snarkVerifyingKey, chunkBitSize);
```

Sometimes the verifier might want to know the decrypted message but might not trust that the decryptor to correctly tell 
him the decrypted message. In this it can verify the decryption done by the decryptor as below

```ts
// result.verified should be true
const result = ciphertext.verifyDecryption(decrypted, saverDk, snarkVerifyingKey, saverEncGens, chunkBitSize);
```

### Bound check (range proof)

Note: This section assumes you have read some of the previous examples on composite proof.

A complete example as a test is [here](./tests/composite-proofs/bound-check.spec.ts)

Allows a verifier to check that some attribute of the credential satisfies given bounds `min` and `max`, i.e. `min <= message < max` 
without learning the attribute itself. Both `min` and `max` are positive integers. This can be implemented using different protocols, 
- LegoGroth16, a protocol described in the SNARK framework [Legosnark](https://eprint.iacr.org/2019/142) in appendix H.2. Requires a trusted setup, which in practice is done by the verifier. 
- Bulletproofs++, a transparent (no trusted setup required) range proof protocol.
- Set-membership check based range proof which require a trusted setup but offer 2 variations - one with keyed verification which has the most optimal execution 
  and the other that performs similar to LegoGroth16 for proving but worse in verification.

The above mentioned test uses all these variations. 

#### Encoding for negative or decimal numbers

To work with negative integers or decimal numbers, they must be converted to positive integers first and this conversion must happen before these are signed. 
When working with negative integers, add the absolute value of the smallest (negative) integer to all values including bounds. Eg, if the smallest negative 
number a value can be is -300, the signer should sign `value + 300` to ensure that values are always positive. During the bound check, say the verifier has to 
check if the value is between -200 and 50, the verifier should ask the prover to the bounds as 100 (-200 + 300) and 350 (50 + 300). When working with decimal 
numbers, convert them to integers by multiplying with a number to make it integer, like if a decimal value can have maximum of 3 decimal places, they should be 
multiplied by 1000.  The [test](./tests/composite-proofs/bound-check.spec.ts) mentioned above shows these scenarios.  
The conversions defined in the above tests are abstracted in this [Encoders](./src/bbs-plus/encoder.ts) class and you can see the usage 
in [these tests](tests/composite-proofs/msg-js-obj/bound-check.spec.ts) of the  `Encoder` initialized [here](tests/composite-proofs/msg-js-obj/data-and-encoder.ts).  


For this, the verifier needs to first create the setup parameters which he then shares with the prover. Note that the 
verifier does not have to create them each time a proof needs to be verified, but only once and publish them somewhere 
such that all provers interacting with the proof can use them.  
In the following snippet, the verifier asks to prove that a certain message satisfies the lower and upper bounds `min` and `max`,
i.e. `min <= message < max`. Note than both bounds are positive integers and lower bound is inclusive but upper bound is not.
To change from exclusive to inclusive bounds and vice-versa, add or subtract 1 from bounds. The snippet shows LegoGroth16.

```ts
import { BoundCheckSnarkSetup } from '@docknetwork/crypto-wasm-ts';

const provingKey = BoundCheckSnarkSetup();
```

For creating the proof of knowledge of the BBS signature and one of the signed message being in certain bounds, the prover creates the following 2 statements.

```ts

// Signer's parameters
let sigParams: BBSSignature, pk: BBSPublicKey, sig: BBSSignature;
// Signed messages - already encoded
let messages: Uint8Array[];
...
// define the min and max bounds
let min: number = ...;
let max: number = ...;
...
// Decompress the proving key 
const snarkProvingKey = provingKey.decompress();
const statement1 = Statement.bbsSignatureProverConstantTime(sigParams, revealedMsgs, false);
const statement2 = Statement.boundCheckLegoProver(min, max, snarkProvingKey);
const proverStatements = new Statements();
proverStatements.add(statement1);
proverStatements.add(statement2);
```

`statement1` is the for proving knowledge of a BBS signature as seen in previous examples. `statement2` is for proving the bounds of a message from the BBS signature. 

Some things to note about this statement:

- The statement is created using `Statement.boundCheckLegoProver` because it is being created by a prover. A verifier would have
  used `Statement.boundCheckLegoVerifier` to create it and one of the arguments would be different (shown below).
- The argument `snarkProvingKey` is the public parameter created by the verifier. However, before they are passed to `Statement.boundCheckLegoProver`, they are uncompressed (ref. elliptic curve point compression) as shown in the above snippet. Uncompressing them doubles their size but makes them faster to work with. However, if you still want to use the compressed parameters use `Statement.boundCheckLegoProverFromCompressedParams`

The prover then establishes the equality between the message in the BBS signature and the bounded message by using
`WitnessEqualityMetaStatement` as below. `msgIdx` is the index of the bounded message in the array of signed messages 
under BBS, `messages`. For the second statement, there is only 1 witness, thus the index 0.

```ts
import { WitnessEqualityMetaStatement, MetaStatement, MetaStatements } from '@docknetwork/crypto-wasm-ts';
const witnessEq = new WitnessEqualityMetaStatement();
const msgIdx = 3;  // the index of the SSN number
witnessEq.addWitnessRef(0, msgIdx);
witnessEq.addWitnessRef(1, 0);
const metaStatements = new MetaStatements();
metaStatements.add(MetaStatement.witnessEquality(witnessEq));
```

The prover then creates witness for both statements. The message `messages[msgIdx]` passed to `Witness.boundCheckLegoGroth16` is the
bounded message. `unrevealedMsgs` passed to `Witness.bbsSignatureConstantTime` is created from `messages` and consists of
messages not being revealed to the verifier.

```ts
const witness1 = Witness.bbsSignatureConstantTime(sig, unrevealedMsgs, false);
const witness2 = Witness.boundCheckLegoGroth16(messages[msgIdx]);
const witnesses = new Witnesses();
witnesses.add(witness1);
witnesses.add(witness2);
```

The prover then creates a proof specification using `QuasiProofSpec`. This is different from `ProofSpec` object seen in
previous examples as it does not call WASM to get a proof specification object and thus is more efficient.  
Now prover creates the proof using `CompositeProof.generateUsingQuasiProofSpec`

```ts
import { QuasiProofSpec } from '@docknetwork/crypto-wasm-ts';

const proverProofSpec = new QuasiProofSpec(proverStatements, metaStatements);
const proof = CompositeProof.generateUsingQuasiProofSpec(proverProofSpec, witnesses);
```

Similarly, the verifier also creates 2 statements and the same meta statement to verify the proof.

```ts
// Get the uncompressed verifying key from the compressed proving key.
const snarkVerifyingKey = provingKey.getVerifyingKeyUncompressed();

const statement1 = Statement.bbsSignatureVerifierConstantTime(sigParams, sigPk, revealedMsgs, false);
const statement2 = Statement.boundCheckLegoVerifier(min, max, snarkVerifyingKey);
const verifierStatements = new Statements();
verifierStatements.add(statement1);
verifierStatements.add(statement2);

const witnessEq = new WitnessEqualityMetaStatement();
witnessEq.addWitnessRef(0, msgIdx);
witnessEq.addWitnessRef(1, 0);
const metaStatements = new MetaStatements();
metaStatements.add(MetaStatement.witnessEquality(witnessEq));
```

The above has a few differences from the prover's statements:

- Instead of using `Statement.boundCheckLegoProver`, verifier uses `Statement.boundCheckLegoVerifier`.
- Instead of proving key, verifier uses verifying key for the snark.

The verifier now creates the proof specification and verifies the proof.

```ts
const verifierProofSpec = new QuasiProofSpec(verifierStatements, metaStatements);
// result.verified should be true for the proof to be valid.
const result = proof.verifyUsingQuasiProofSpec(verifierProofSpec);
```

### Optimization

You might notice some public parameters are huge and also the statements involving them take noticeable time to create. Eg,
`snarkProvingKey`, `snarkVerifyingKey`, `saverEk` are huge and thus creating `Statement.saverProver`, `Statement.saverVerifier`, 
`Statement.boundCheckLegoProver` and `Statement.boundCheckLegoVerifier` take some time to create. This becomes a bigger problem 
when several messages need to be encrypted for the same decryptor or bounds over several messages need to be proved.  
To solve this, the public parameters don't need to be passed directly to the `Statement`s. They can be wrapped in a `SetupParam`
and then a reference to them is passed as an argument in place of the parameter itself to the `Statement`. See the snippet 
below for creating 2 statements for verifiable encryption for the same setup parameters:

```ts
import { SetupParam } from '@docknetwork/crypto-wasm-ts';

// Prover creates an array of `SetupParam`s
const proverSetupParams = [];
proverSetupParams.push(SetupParam.saverEncryptionGensUncompressed(saverEncGens));
proverSetupParams.push(SetupParam.saverCommitmentGensUncompressed(commKey));
proverSetupParams.push(SetupParam.saverEncryptionKeyUncompressed(saverEk));
proverSetupParams.push(SetupParam.saverProvingKeyUncompressed(snarkProvingKey));

// Passing reference to parameters as array indices from `proverSetupParams`
const statement3 = Statement.saverProverFromSetupParamRefs(0, 1, 2, 3, chunkBitSize);
const statement4 = Statement.saverProverFromSetupParamRefs(0, 1, 2, 3, chunkBitSize);
```

Note the use of `Statement.saverProverFromSetupParamRefs` rather than `Statement.saverProver`. The arguments:

- 0 for the encryption generators which are at index 0 in `proverSetupParams`
- 1 for the commitment generators which are at index 1 in `proverSetupParams`
- 2 for the encryption key which is at index 2 in `proverSetupParams`
- 3 for the proving key which is at index 3 in `proverSetupParams`

Now the prover creates the proof specification by passing `SetupParam`s array as well.

```ts
const proverStatements = new Statements();
...
proverStatements.add(statement3);
proverStatements.add(statement4);
...
...
...
const proverProofSpec = new QuasiProofSpec(proverStatements, metaStatements, proverSetupParams);
const proof = CompositeProof.generateUsingQuasiProofSpec(proverProofSpec, witnesses);
```

Similarly, the verifier can create his own `SetupParam`s array for his proof specification and then proof

```ts
const verifierSetupParams = [];
verifierSetupParams.push(SetupParam.saverEncryptionGensUncompressed(saverEncGens));
verifierSetupParams.push(SetupParam.saverCommitmentGensUncompressed(commKey));
verifierSetupParams.push(SetupParam.saverEncryptionKeyUncompressed(saverEk));
verifierSetupParams.push(SetupParam.saverVerifyingKeyUncompressed(snarkVerifyingKey));

const statement5 = Statement.saverVerifierFromSetupParamRefs(0, 1, 2, 3, chunkBitSize);
const statement6 = Statement.saverVerifierFromSetupParamRefs(0, 1, 2, 3, chunkBitSize);

const verifierStatements = new Statements();
...
...
verifierStatements.add(statement5);
verifierStatements.add(statement6);

const verifierProofSpec = new QuasiProofSpec(verifierStatements, metaStatements, verifierSetupParams);
const result = proof.verifyUsingQuasiProofSpec(verifierProofSpec);
```

For a complete example, see [these tests](./tests/composite-proofs/saver.spec.ts)

Similarly, for bound checks, use `Statement.boundCheckLegoProverFromSetupParamRefs` and `Statement.boundCheckVerifierFromSetupParamRefs`.  
For complete example, see [these tests](./tests/composite-proofs/bound-check.spec.ts)

### Working with messages as JS objects

The above interfaces have been found to be a bit difficult to work with when signing messages/credentials that are represented as JS objects like

```json
{
  "fname": "John",
  "lname": "Smith",
  "sensitive": {
    "secret": "my-secret-that-wont-tell-anyone",
    "email": "john.smith@example.com",
    "SSN": "123-456789-0",
    "user-id": "user:123-xyz-#"
  },
  "location": {
    "country": "USA",
    "city": "New York"
  },
  "timeOfBirth": 1662010849619,
  "physical": {
    "height": 181.5,
    "weight": 210,
    "BMI": 23.25
  },
  "score": -13.5
}
```

[Here](./src/sign-verify-js-objs.ts) are some utilities to make this task a bit easier. The idea is to flatten the JSON, sort the keys alphabetically 
to have a list with deterministic order and then use the [encoder](./src/encoder.ts) to encode each value as a field element (a number between 0 and another large number).  
The encoder can be configured to use different encoding functions for different keys to convert values from different types 
like string, positive or negative integers or decimal numbers to field elements.  
[The tests here](tests/composite-proofs/msg-js-obj) contain plenty of examples.


### Writing predicates in Circom

Simple predicates like a range proof or equality of messages in zero knowledge are already hardcoded in the library but we 
cannot imagine all the possible predicates different use-cases can require. We expect developers to write these predicates 
in a programming language that we can then use to create zero-knowledge proofs. We currently support [Circom](https://docs.circom.io/), version 2.
The predicates can be written as Circom programs and then compiled for curve BLS12-381. The generated R1CS and WASM can then be feed 
to the composite proof system to generate a zero knowledge proof of the predicate.

The workflow is this:

1. Express the predicates/arbitrary computation as a Circom program.
2. Compile the above program to get the constraints (R1CS file) and witness generator (WASM file, takes input wires and calculates all the intermediate wires).
3. Use the constraints from step 2 to generate SNARK proving and verification key of LegoGroth16.
4. Use the R1CS and WASM files from step 2 and proving key from step 3 to create a LegoGroth16 proof.
5. Use the verification key from step 3 to verify the LegoGroth16 proof.

The steps 1-3 are done by the verifier and the result of these steps, i.e. the program (`.circom` file), R1CS (`.r1cs` file), 
WASM (`.wasm` file), proving and verification key are shared with any potential prover (published or shared P2P). Step 4 is 
done by the prover and step 5 again by the verifier. Since R1CS and WASM files are harder to inspect that Circom programs, 
to guard against a verifier tricking the prover to prove unintended predicates (and thus reveal more information than required), 
a prover can take the Circom program and generate the R1CS and WASM files himself (do step 2 as well).

See some of the following tests for Circom usage:

1. [The yearly income, calculate from monthly payslips is less/greater than certain amount.](./tests/composite-proofs/msg-js-obj/r1cs/yearly-income.spec.ts).
2. [The sum of assets is greater than the sum of liabilities where are assets and liabilities are calculated from several credentials.](./tests/composite-proofs/msg-js-obj/r1cs/assets-liabilities.spec.ts)
3. [The blood group is not AB-](./tests/composite-proofs/msg-js-obj/r1cs/blood-group.spec.ts)
4. [The grade is either A+, A, B+, B or C but nothing else.](./tests/composite-proofs/msg-js-obj/r1cs/grade.spec.ts)
5. [Either vaccinated less than 30 days ago OR last checked negative less than 2 days ago](./tests/composite-proofs/msg-js-obj/r1cs/vaccination.spec.ts)
6. [All receipts (used as credentials) have different receipt (credential) ids](./tests/composite-proofs/msg-js-obj/r1cs/all_receipts_different.spec.ts). This test shows using multiple circuits in a single proof.
7. [Certain attribute is the preimage of an MiMC hash](./tests/composite-proofs/msg-js-obj/r1cs/mimc-hash.spec.ts)

The Circom programs and corresponding R1CS and WASM files for the tests are [here](./tests/circom).

### Anonymous credentials

The composite proof system is used to implement anonymous credentials. See [here](src/anonymous-credentials/) for details.

[Slides](https://www.slideshare.net/SSIMeetup/anonymous-credentials-with-range-proofs-verifiable-encryption-zksnarks-circom-support-and-blinded-issuance-lovesh-harchandani) and [video](https://www.youtube.com/watch?v=e_E_6Fx5dro) for a presentation given at SSI meetup. Mostl of the presentation goes over the code, mostly anonymous credentials from this library.  