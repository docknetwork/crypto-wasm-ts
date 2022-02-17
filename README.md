# crypto-wasm-ts

This repository is a Typescript interface to [Dock's Rust crypto library](https://github.com/docknetwork/crypto). It uses 
the [WASM wrapper](https://github.com/docknetwork/crypto-wasm).

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

### BBS+ Signatures
BBS+ signature allow for signing an ordered list of messages, producing a signature of constant size independent of the number
of messages. The signer needs to have a public-private keypair and signature parameters which are public values whose size
depends on the number of messages being signed. A verifier who needs to verify the signature needs to know the
signature parameters used to sign the messages and the public key of the signer. In the context of anonymous credentials, 
messages are called attributes.  
BBS+ signature also allow a user to request a blind signature from a signer where the signer does not know 1 or more messages
from the list. The user can then unblind the blind signature to get a regular signature which can be verified by a verifier in
the usual way. Such blind signatures can be used to hide a user specific secret like a private key or some unique identifier
as a message in the message list and the signer does not become aware of the hidden message.     
With a BBS signature, a user in possession of the signature and messages and create a [zero-knowledge proof of knowledge](https://en.wikipedia.org/wiki/Proof_of_knowledge)
of the signature and the corresponding signed messages such that he can prove to a verifier that he knows a signature and the
messages and optionally reveal one or more of the messages.  
A typical use of BBS+ signatures looks like:
- Signature parameters of the required size are assumed to exist and published at a public location. The signer can create
  his own or reuse parameters created by another party.
- Signer public-private keypair and publishes the public key. The keypair can be reused for signing other messages as well.
- User requests a signature from the signer.
- Signer signs the message list using the signature parameters and his private key.
- User verifies the signature on the  message list using the signature parameters and signer's public key
- User creates a proof of knowledge of the signature and message list and optionally reveals 1 or more messages to the verifier.
- The verifier uses the signature parameters and signer's public key to verify this proof. If successful, the verifier is
  convinced that the user does have a signature from the signer and any messages revealed were part of the message list
  signed by the signer.

### Accumulator
An accumulator is a "set like" data-structure in which elements can be added or removed but the size of the accumulator remains
constant. But an accumulator cannot be directly checked for presence of an element, an element needs to have accompanying data called
the witness (its the manager's signature on the element), the element and the witness and these together can be used to check the presence
or absence of the element. An accumulator can be considered similar to the root of the merkle tree where the inclusion proof is the witness
of the element (non-membership proofs aren't possible with simple merkle trees). As with merkle trees, as elements are added or
removed from the accumulator, the witness (inclusion proof) needs to be updated for the current accumulated value (root).  
2 kinds of accumulators are provided, **positive** and **universal**. Positive support only membership witnesses while universal support both
membership and non-membership witnesses. Creating non-membership witnesses is expensive however and the cost depends on the
number of members present in the accumulator. Both accumulators are owned by an accumulator manager who has the private key to the accumulator
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

### Composite proofs
The above primitives can be combined using the composite proof system. An example is (in zero knowledge) proving knowledge of 2
different signatures and the message lists. Another example is proving knowledge of the signature and messages and certain message's presence (absence)
in an accumulator. Or the knowledge of 5 signatures and proving certain message is the same in the 5 message lists.

## Usage

Before calling any function that calls the underlying WASM, use `initializeWasm` to load the WASM module. This function returns 
a promise which is resolved once the WASM module is successfully loaded.  

```ts
// Load the WASM module
await initializeWasm();
```

### BBS+ signatures

BBS+ signatures sign an ordered list of messages and thus it is important to serialize your signing payload in this format. 
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

Now each of the above list must be converted to bytearrays, i.e. `Uint8Array` and the type of above list becomes `Uint8Array[]`

#### Setup

Before messages can be signed, 2 things are needed:
- **Signature parameters**: Public values, that can be created by anyone but must be known to the signer and verifier to sign and verify 
  respectively. To create them, the number of messages (attributes) being signed must be known and the size of the parameters increases with 
  the number. In the above example, number of attributes is 4. These parameters can be generated randomly or deterministically by using a 
  publicly known label. It is advised to use the latter as it allows for extending/shrinking the same parameters when number of messages change.     
- **Keypair**: To create and verify BBS+ signature, the signer (issuer in case of a credential) needs to create a secret key to sign, public key to verify. 

  2 ways of generating signature parameters
  ```ts
  const messageCount = 4;
  
  // Randomly generated params
  const paramsRandom = SignatureParamsG1.generate(messageCount);
  
  const label = stringToBytes("My sig params");
  // Deterministically generated params
  const paramsDeterministc = SignatureParamsG1.generate(messageCount, label);
  
  // Deterministic params can be extended if messageCount changes, say to 5 or 3
  const paramsNew = paramsDeterministc.adapt(5);
  const paramsNeww = paramsDeterministc.adapt(3);
  ```
  
  Generating a keypair once signature parameters are created.
  ```ts
  const keypair1 = KeypairG2.generate(paramsDeterministc);
  const sk = keypair.secretKey;
  const pk = keypair.publicKey;
  ```

#### Signing and verification

When the messages are arbitrary bytes, they need to be encoded to a field element (a number in certain range). You can either let the signing function encode it by passing 
the `encode` argument as true to encode it using your own encoding function.
  
  Letting the signing function encode  
  ```ts
  // messages is a list of bytesarrays and converted as mentioned above  
  const messages: Uint8Array[] = [...];
  
  // The signing function will encode bytes to a field element as true is passed
  const sig = SignatureG1.generate(messages, sk, params, true);
  
  // As the messages are not encoded, pass true to the verification function to make it encode messages before verifying the signature.
  const result = sig.verify(messages, pk, params, true);
  expect(result.verified).toEqual(true);
  ```
  
  Passing pre-encoded messages to signing function
  ```ts
  // messages is a list of bytesarrays and converted as mentioned above  
  const messages: Uint8Array[] = [...];
  
  for (let i = 0; i < messages.length; i++) {
    encodedMessages.push(generateFieldElementFromBytes(messages[i]));
  }
  // The signing function will not encode as false is passed
  const sig = SignatureG1.generate(encodedMessages, sk, params, false);

  // As the messages are pre-encoded, pass false to the verification function to avoid encoding messages before verifying the signature.
  const result = sig.verify(encodedMessages, pk, params, false);
  expect(result.verified).toEqual(true);
  ```

Verifying knowledge of signature can be done with or without using the composite proof system but this doc will only describe 
using the composite proof system. For the other way, see tests [here](./tests/bbs-plus.spec.ts)  

The code for BBS+ signature lives [here](./src/bbs-plus). 

### Accumulators

#### Setup

Similar to BBS+ signatures, accumulators also have a setup phase where public parameters and keys are generated and these 
public values need to be published. The accumulator manager's signing key is needed to update the accumulator or create 
a witness and the public key is needed to verify the (non)membership. This document talks only about Positive accumulator, 
for universal accumulator see the corresponding tests.

  Similar to BBS+, parameters can be generated randomly or deterministically.
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
  expect(verifAccumulator.verifyMembershipWitness(e4, witness, pk, params)).toEqual(true);
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

- **Statement** - The kind of proof that needs to be done and the public parameters needed to verify that proof. Eg. a BBS+ signature
  statement contains public key of the signer, signature params, any revealed messages, etc. Each statement in a proof has a unique index.
- **Witness** - Private data that needs to be kept hidden from the verifier. This can be the messages/attributes that are not being disclosed, 
  the signature itself, the accumulator member, accumulator witness. Every witness corresponds to some `Statement`.
- **WitnessRef** - A witness might contain consist of several hidden data points, hidden attributes for example. To refer to each data 
  point uniquely, a pair of indices is used where the 1st item is the `Statement` index and 2nd item is index of that data point in the witness. 
- **MetaStatement** - Describes a condition that must hold between witnesses of several statements or the same statement. Eg. to 
  express equality between attributes of 2 credentials, `MetaStatement` will refer to the `WitnessRef` of each attribute. This is
  public information as well.
- **ProofSpec** - This is the proof specification and its goal is to unambiguously define what **all** needs to be proven. This is created
  from all `Statement`s, `MetaStatement`s and an optional context. Both prover and verifier should independently create this. The prover 
  uses the `ProofSpec` and all `Witness`es to create the proof and the verifier uses the`ProofSpec` to verify the proof.  

#### Examples

##### Selective disclosure 

A complete example is shown in this [test](tests/composite-proofs/single-bbs-signature.spec.ts).  

Proving knowledge of 1 BBS+ signature over the attributes and only disclosing some attributes. Say there are 5 attributes in the 
credential: SSN, first name, last name, email and city, and they are present in the attribute list in that order. The prover wants 
to reveal his last name and city, but not any other attributes while proving that he possesses such a credential signed by the issuer.

```ts
// The attributes, [SSN, first name, last name, email, city]
const messages: Uint8Array[] = [...];

// Public values
const parasm: SignatureParamsG1;
const pk: Uint8Array;

// The signature
const sig: SignatureG1 = ...;

// Prover prepares the attributes he wants to disclose, i.e. attribute index 2 and 4 (indexing is 0-based), and the ones he wants to hide. 
const revealedMsgIndices: Set<number> = new Set();
revealedMsgIndices.add(2);
revealedMsgIndices.add(4);

// revealedMsgs are the attributes disclosed to the verifier
const revealedMsgs: Map<number, Uint8Array> = new Map();
revealedMsgs.set(i, messages[2]);
revealedMsgs.set(i, messages[4]);

// unrevealedMsgs are the attributes hidden from the verifier
const unrevealedMsgs: Map<number, Uint8Array> = new Map();
unrevealedMsgs.set(i, messages[0]);
unrevealedMsgs.set(i, messages[1]);
unrevealedMsgs.set(i, messages[3]);
```

Since there is only 1 kind of proof, i.e. the knowledge of BBS+ signature and the signed attributes, there would be only 1 `Statement`. 

```ts
// Create a BBS+ signature, true indicates that attributes/messages are arbitrary bytes and should be encoded first
const statement1 = Statement.bbsSignature(params, pk, revealedMsgs, true);
const statements = new Statements();
statements.add(statement1);

// Optional context of the proof, this can specify the reason why the proof was created or date of the proof, etc
const context = stringToBytes('some context');
```

Once it has been established what needs to be proven, `ProofSpec` needs to be created which represents all the requirements. 
Both the prover and verifier should independently construct this `ProofSpec`. Note that there are no `MetaStatements` as there are no 
other conditions on the witnesses and thus its empty 

```ts
const ms = new MetaStatements();
const proofSpec = new ProofSpecG1(statements, ms, context);
```

Prover creates `Witness` using the signature and hidden attributes 

```ts
const witness1 = Witness.bbsSignature(sig, unrevealedMsgs, true);
const witnesses = new Witnesses();
witnesses.add(witness1);
```

Prover now uses the `ProofSpec` to create the proof

```ts
const proof = CompositeProofG1.generate(proofSpec, witnesses);
```

Verifier can now verify this proof. Note that the verifier does not and must not receive `ProofSpec` from prover, it 
needs to generate on its own.

```ts
expect(proof.verify(proofSpec).verified).toEqual(true);
```

##### Multiple BBS+ signatures

A complete example is shown in this [test](tests/composite-proofs/many-bbs-signatures.spec.ts).

Proving knowledge of 2 BBS+ signature over the attributes and only disclosing some attribute and proving equality of 1 attribute 
without disclosing it. Say there are 2 credentials and hence 2 BBS+ signatures. One credential has 5 attributes: SSN, first name, 
last name, email and city and the other has 6 attributes name, email, city, employer, employee id and SSN and in that order. 
The prover wants to prove that he has those 2 credentials, reveal his employer name and prove that SSN in both credentials is 
the same without revealing the SSN.

```ts
// The attributes from 1st credential, [SSN, first name, last name, email, city]
const messages1: Uint8Array[] = [...];
// The attributes from 2nd credential, [name, email, city, employer, employee id, SSN]
const messages2: Uint8Array[] = [...];

// Public values for 1st issuer
const parasm1: SignatureParamsG1;
const pk1: Uint8Array;

// Public values for 2nd issuer
const parasm2: SignatureParamsG1;
const pk2: Uint8Array;

// The signature from 1st credential
const sig1: SignatureG1 = ...;

// The signature from 2nd credential
const sig2: SignatureG1 = ...;
```

Since the prover is proving possession of 2 BBS+ signatures, there will be 2 `Statement`s. Also, for the 2nd signature prover is 
revealing _employer_ attribute, which is at index 3.

```ts
// Statement for signature of 1st signer, not revealing any messages to the verifier
const statement1 = Statement.bbsSignature(params1, pk1, new Map(), true);

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
const statement2 = Statement.bbsSignature(params2, pk2, revealedMsgs, true);

// Collect all the statements
const statements = new Statements();
const sId1 = statements.add(statement1);
const sId2 = statements.add(statement2);
```

The prover has 2 prove that both credentials contain the same SSN which is same as saying for the 1st signature (1st `Statement`), 
attribute at index 0 is equal to 2nd signature's (2nd `Statement`) attribute index 5. This requires the use of a `MetaStatement` to 
express this condition, specifically `MetaStatement.witnessEquality` which takes the `WitnessRef` for each witness that needs to be 
proven equal. `WitnessRef` for SSN in 1st signature is (0, 0) and in 2nd signature is (1, 5). Create a `WitnessEqualityMetaStatement` to 
express that.

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
const proofSpec = new ProofSpecG1(statements, metaStatements);
```

The prover creates the witnesses with both signatures and messages that he is hiding from the verifier

```ts
// Using the messages and signature from 1st signer
const unrevealedMsgs1 = new Map(messages1.map((m, i) => [i, m]));
const witness1 = Witness.bbsSignature(sig1, unrevealedMsgs1, true);

// Using the messages and signature from 2nd signer
const witness2 = Witness.bbsSignature(sig2, unrevealedMsgs2, true);

const witnesses = new Witnesses();
witnesses.add(witness1);
witnesses.add(witness2);

const proof = CompositeProofG1.generate(proofSpec, witnesses);
```

Verifier verifies the proof.

```ts
expect(proof.verify(proofSpec).verified).toEqual(true);
```

##### BBS+ signature together with accumulator membership

Say a prover has a credential where one of the attribute is added to an accumulator. The prover wants to prove that his attribute is a 
member of the accumulator without revealing the attribute itself. Say the attributes are SSN, first name, last name, email and 
user-id and the prover wants to prove that the user-id is present in the accumulator without revealing it to the verifier.

```ts
// The attributes, [SSN, first name, last name, email, user-id]
const messages: Uint8Array[] = [...];
```

Because the attributes for accumulator and BBS+ signatures are encoded differently, attributes are pre-encoded.

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
const sigParams = SignatureParamsG1.generate(5, label);

// Signers keys
const sigSk: Uint8Array = ...;
const sigPk: Uint8Array = ...;

// Accumulator manager's params, keys and state
const accumParams = PositiveAccumulator.generateParams(stringToBytes('Accumulator params'));
const accumKeypair = PositiveAccumulator.generateKeypair(accumParams);
const accumulator = PositiveAccumulator.initialize(accumParams);
const state = new InMemoryState();
```

Signer signs the credential and accumulator manager adds the attribute to the credential and sends the witness to the prover
```ts
// Signer signs the message
const sig: SignatureG1 = ...;

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

The prover needs to prove 2 `Statement`s, knowledge of BBS+ signature and knowledge of accumulator member and corresponding witness.

```ts
const statement1 = Statement.bbsSignature(sigParams, sigPk, revealedMsgs, false);
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

const proofSpec = new ProofSpecG1(statements, metaStatements);
```

The prover creates `Witness`es for all statements and then creates the proof. The `Witness` for `Statement.accumulatorMembership` contains
the member and the accumulator witness. 

```ts
const witness1 = Witness.bbsSignature(sig, unrevealedMsgs, false);
const witness2 = Witness.accumulatorMembership(encodedMessages[userIdIdx], accumWitness);
const witnesses = new Witnesses();
witnesses.add(witness1);
witnesses.add(witness2);

const proof = CompositeProofG1.generate(proofSpec, witnesses);
```

##### Getting a blind signature

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
const sigParams = SignatureParamsG1.generate(5, label);

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
// Blind signature request will contain a commitment, 
const [blinding, request] = BlindSignatureG1.generateRequest(blindedMessages, params, true);
```

The proof needs to be over only 1 `Statement`, the statement proving knowledge of the committed attributes in the commitment. 
To create the commitment, a commitment key (public values) needs to be created from the signature params

```ts
// Take parts of the sig params corresponding to the blinded messages and create the commitment key commKey
const commKey = params.getParamsForIndices(request.blindedIndices);
const statement1 = Statement.pedersenCommitmentG1(bases, request.commitment);

const statements = new Statements();
statements.add(statement1);

const proofSpec = new ProofSpecG1(statements, new MetaStatements());
```

Now the prover creates witness for the commitment `Statement` using the randomness and the hidden attributes.
```ts
// The witness to the Pedersen commitment contains the blinding at index 0 by convention and then the hidden messages
const committeds = [blinding];
for (const i of blindedIndices) {
  // The messages are encoded before committing
  committeds.push(Signature.encodeMessageForSigning(blindedMessages.get(i)));
}
const witness1 = Witness.pedersenCommitment(committeds);
const witnesses = new Witnesses();
witnesses.add(witness1);

const proof = CompositeProofG1.generate(proofSpec, witnesses);
```

Signer now verifies the proof. Note that the signer independently creates the `ProofSpec` as he knows which attributes are being 
hidden from him. If the proof is correct, signer creates a blind signature using the known attributes and the commitment 
and sends to the prover.

```ts
expect(proof.verify(proofSpec).verified).toEqual(true);

// Signer is convinced that user knows the opening to the commitment

// Signer creates a blind signature with these known messages and the commitment.
knownMessages.set(1, stringToBytes('John Smith'));
knownMessages.set(3, stringToBytes('john.smith@emample.com'));
knownMessages.set(4, stringToBytes('New York'));
const blindSig = BlindSignatureG1.generate(request.commitment, knownMessages, sk, params, true);
```

The prover can now "unblind" the signature meaning he can convert a blind signature into a regular BBS+ signature 
which he can use in proof as shown in examples above

```ts
// Unbling the signature from the randomness of the commitment.
const sig = blindSig.unblind(blinding);

// Combine blinded and known messages in an array
const messages = Array(blindedMessages.size + knownMessages.size);
for (const [i, m] of blindedMessages.entries()) {
  messages[i] = m;
}
for (const [i, m] of knownMessages.entries()) {
  messages[i] = m;
}

// Signature can be verified
const result = sig.verify(messages, pk, params, true);
expect(result.verified).toEqual(true);
```

##### Verifier-local or opt-in linkability

Proving knowledge of BBS+ signatures is unlinkable meaning the verifier cannot link to 2 proofs presented from the same 
credential. But this might not always be desirable for the verifier and the prover might agree to being linked for any 
proofs that he creates for that particular verifier without revealing any attribute of the credential.  

A verifier wants to attach a unique identifier to a prover without either learning anything unintended (by prover)
from the prover's signature nor can that unique identifier be used by other verifiers to identify the prover,
eg. a seller (as a verifier) should be able to identify repeat customers (prover) by using a unique identifier, but
he should not be able to share that unique identifier with other sellers using their own identifier for that prover.
This is done by making the prover go through a one-time registration process with the verifier by creating a Pedersen
commitment to some value in the signature(s) which the verifier persists, lets call it registration commitment.
At each subsequent proof, the prover resends the commitment with the proof that commitment contains message from the prover's
signature (prover had persisted commitment and randomness) and the verifier checks that the commitment is same as the one during
registration. The registration commitment serves as an identifier.

In the [test](tests/composite-proofs/verifier-local-linkability.spec.ts), the credential has 4 attributes, SSN, first name, 
last name and email and during registration, the prover creates commitment to SSN which serves as the registration 
commitment. See the test for more details.

##### Social KYC
A social KYC (Know Your Customer) credential claims that the subject owns certain social media profile like a twitter profile credential claims that a user owns the twitter profile with certain handle. Here the issuer of the credential must verify the user's control of the profile. One way to achieve that is for the user to post a unique issuer supplied challenge string on his profile, like tweeting it when requesting twitter profile credential. This makes the process 2-step, in step 1 user requests the challenge from issuer and which he tweets and in step 2, he asks the issuer to check the tweet and issue him a credential. An alternate approach is for the user to post a commitment to some random value on his profile and then request a credential from the issuer by supplying a proof of knowledge of the opening (committed random value) of the commitment. The issuer is convinced that no one else could know the opening of the commitment which was posted by the user. Note that the user is proving knowledge of the committed value and not revealing it to the issuer because revealing the value will allow the issuer to request a similar credential from some another issuer of it the revealed value is leaked then someone else can impersonate the user.  
The [test](tests/composite-proofs/social-kyc.spec.ts) shows a complete example.

The code for composite proof lives [here](./src/composite-proof). See the tests [here](./tests/composite-proofs) for various scenarios.
For a more involved demo with multiple BBS+ signatures being used with accumulator and knowledge of signatures being proved 
before requesting blind signatures, see [here](./tests/demo.spec.ts). This test paints a picture where before getting any credential, 
a user has to prove possession of a credential and membership in an accumulator (except the 1st credential).
