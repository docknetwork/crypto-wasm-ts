# crypto-wasm-ts

This repository is a Typescript interface to [Dock's Rust crypto library](https://github.com/docknetwork/crypto). It uses 
the [WASM wrapper](https://github.com/docknetwork/crypto-wasm).

For an overview of the features, [check this](https://github.com/docknetwork/crypto-wasm#overview).

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

## Usage

### BBS+ signatures

The code for BBS+ signature lives [here](./src/bbs-plus). 

Example of using BBS+ signature

```js
import { initializeWasm } from '@docknetwork/crypto-wasm';
import {
  BlindSignatureG1,
  bytesToChallenge,
  KeypairG2,
  PoKSigProtocol,
  Signature,
  SignatureG1,
  SignatureParamsG1
} from '../src';

const stringToBytes = (str: string) => Uint8Array.from(Buffer.from(str, "utf-8"));

const main = async () => {
  // Load the WASM module
  await initializeWasm();

  const messageCount = 10;
  const messages: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    messages.push(stringToBytes(`Message-${i + 1}`));
  }

  const label = stringToBytes("My sig params in g1");
  const params = SignatureParamsG1.generate(messageCount, label);

  const keypair = KeypairG2.generate(params);
  const sk = keypair.secretKey;
  const pk = keypair.publicKey;

  const sig = SignatureG1.generate(messages, sk, params, true);
  const result = sig.verify(messages, pk, params, true);
  console.log(`Signature verified ? ${JSON.stringify(result)}`);

  // 2 revealed messages and 1 user supplied blinding
  const blindings: Map<number, Uint8Array> = new Map();
  blindings.set(1, generateRandomFieldElement());
  const protocol = PoKSigProtocol.initialize(messages, sig, params, true, blindings, revealed);
  const challengeContributionP = protocol.challengeContribution(params, true, revealedMsgs);
  const challengeProver = bytesToChallenge(challengeContributionP);
  const proof = protocol.generateProof(challengeProver);

  let challengeContributionV = proof.challengeContribution(params, true, revealedMsgs);
  let challengeVerifier = bytesToChallenge(challengeContributionV);
  
  const result1 = proof.verify(challengeVerifier, pk, params, true, revealedMsgs);
  console.log(`Proof verified ? ${JSON.stringify(result1)}`);
};

main()
```

See the [test](./tests/bbs-plus.spec.ts) for more.

### Accumulators

The code for accumulators lives [here](./src/accumulator).

Example of using accumulators:

```js
import { initializeWasm } from '@docknetwork/crypto-wasm';

const positiveAccum = async () => {
  // Load the WASM module
  await initializeWasm();

  const label = stringToBytes("Accumulator params");
  const params = PositiveAccumulator.generateParams(label);
  const keypair = PositiveAccumulator.generateKeypair(params);
  const accumulator = PositiveAccumulator.initialize(params);
  const state = new InMemoryState();

  const sk = keypair.secret_key;
  const pk = keypair.public_key;

  const e1 = Accumulator.encodePositiveNumberAsAccumulatorMember(101);
  const e2 = Accumulator.encodePositiveNumberAsAccumulatorMember(102);

  await accumulator.add(e1, sk, state);
  await accumulator.add(e2, sk, state);

  await accumulator.remove(e2, sk, state);

  const e3 = Accumulator.encodePositiveNumberAsAccumulatorMember(103);
  const e4 = Accumulator.encodePositiveNumberAsAccumulatorMember(104);

  await accumulator.addBatch([e3, e4], sk, state);
  
  // Manager creates witness
  const wits = await accumulator.membershipWitnessesForBatch([e3, e4], sk, state);
  
  // Verify the witness
  const tempAccumulator = PositiveAccumulator.fromAccumulated(accumulator.accumulated);

  const result1 = tempAccumulator.verifyMembershipWitness(e3, wits[0], pk, params);
  console.log(result1);
  
  const result2 = tempAccumulator.verifyMembershipWitness(e4, wits[1], pk, params);
  console.log(result2);
};

posttiveAccum()
```

See the [test](./tests/accumulator.spec.ts) for more.

### Composite proofs

The code for composite proof lives [here](./src/composite-proof). See the [test](./tests/demo.spec.ts) for example.

