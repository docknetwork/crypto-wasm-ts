# Threshold BBS+ and BBS

These are bases on this [paper](https://eprint.iacr.org/2023/602.pdf)

There are 3 protocols to be run among signers
1. A DKG (Distributed Key Generation) should be run among signers only once to generate their secret and public keys and the threshold public key. 
   A DKG is mentioned in the FROST paper and implemented [here](../frost-dkg.ts) 
2. A base OT (Oblivious Transfer) implemented [here](./base-ot.ts). This ideally should be run only once and its output should be persisted 
   by the signers but can be run multiple times but each signer should participate and discard their old outputs.
3. The actual signing protocol which is run every time when messages need to be signed. Implemented [here for BBS+](./bbs-plus.ts) and [here for BBS](./bbs.ts). 
   The implementation assumes that a batch of signatures need to be produced because the protocol requires 2 rounds of communication so its better to produce many 
   signatures in just 2 rounds than having 2 round for each signature.

Look at [this test](../../tests/threshold-sigs.spec.ts) for an example.