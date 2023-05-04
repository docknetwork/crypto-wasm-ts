import {
  CompositeProofG1,
  BBSPlusKeypairG2,
  MetaStatements,
  ProofSpecG1,
  BBSPlusSignatureG1,
  BBSPlusBlindSignatureG1,
  BBSPlusSignatureParamsG1,
  Statement,
  Statements,
  Witness,
  Witnesses,
  BBSPlusPublicKeyG2,
  BBSPlusSecretKey
} from '../../src';

import {
  generateRandomFieldElement,
  generateRandomG1Element,
  initializeWasm,
  pedersenCommitmentG1
} from '@docknetwork/crypto-wasm';
import { stringToBytes } from '../utils';
import { Signature } from '../scheme';

describe('Social KYC (Know Your Customer)', () => {
  // A social KYC (Know Your Customer) credential claims that the subject owns certain social media profile like a twitter
  // profile credential claims that a user owns the twitter profile with certain handle. User posts a commitment to some
  // random value on his profile and then requests a credential from the issuer by supplying a proof of knowledge of the
  // opening (committed random value) of the commitment. This test shows an example of user getting a twitter profile
  // credential from an issuer and the credential contains the profile handle, name, description and no. of followers. The
  // credential will contain the user's secret id which he will hide from the issuer, thus gets a blinded credential.

  // Issuer's parameters
  let sigParams: BBSPlusSignatureParamsG1;
  // Issuers secret key and public keys
  let sk: BBSPlusSecretKey, pk: BBSPlusPublicKeyG2;
  // Commitment key for commitment posted on social profile.
  let g: Uint8Array;

  // No of attributes in the KYC credential
  const attributeCount = 5;

  beforeAll(async () => {
    // Load the WASM module
    await initializeWasm();

    sigParams = BBSPlusSignatureParamsG1.generate(attributeCount);

    // Generate keys
    const sigKeypair = BBSPlusKeypairG2.generate(sigParams);
    sk = sigKeypair.secretKey;
    pk = sigKeypair.publicKey;

    g = generateRandomG1Element();
  });

  it('Requesting credential', async () => {
    // Holder creates random value posts a commitment to it on his twitter profile as a tweet.
    const randomValueTweet = generateRandomFieldElement();
    // This commitment will be posted in the tweet
    const commitmentTweet = pedersenCommitmentG1([g], [randomValueTweet]);

    // Prepare messages that will be blinded (hidden) and known to signer
    const blindedAttributes = new Map();

    // User wants to hide his secret id which is the attribute at index 0
    const blindedIndices: number[] = [0];
    blindedAttributes.set(0, stringToBytes('my-secret-id'));

    // Generate a blind signature request
    const req = BBSPlusBlindSignatureG1.generateRequest(blindedAttributes, sigParams, true);
    const [blinding, request] = Array.isArray(req) ? req: [undefined, req];

    // The proof is created for 2 statements.

    // The 1st statement to prove is knowledge of opening of the commitment in the tweet
    const statement1 = Statement.pedersenCommitmentG1([g], commitmentTweet);

    // Take parts of the sig params corresponding to the blinded attribute
    const commKey = sigParams.getParamsForIndices(request.blindedIndices);
    // The 2nd statement is proving knowledge of the blinded attribute, i.e. secret-id in another commitment (not posted in tweet).
    const statement2 = Statement.pedersenCommitmentG1(commKey, request.commitment);

    const statements = new Statements();
    statements.add(statement1);
    statements.add(statement2);

    // Some context to the proof to prevent replayability, for stronger protection this should contain today's date etc as well
    const context = stringToBytes('Verifying twitter profile with issuer 1');

    const proofSpec = new ProofSpecG1(statements, new MetaStatements(), [], context);

    // This is the opening of the commitment posted in tweet
    const witness1 = Witness.pedersenCommitment([randomValueTweet]);

    // The witness to the Pedersen commitment contains the blinding at index 0 by convention and then the hidden attributes
    const committeds = [blinding].filter(Boolean);
    for (const i of blindedIndices) {
      // The attributes are encoded before committing
      committeds.push(BBSPlusSignatureG1.encodeMessageForSigning(blindedAttributes.get(i)));
    }
    const witness2 = Witness.pedersenCommitment(committeds as any);
    const witnesses = new Witnesses();
    witnesses.add(witness1);
    witnesses.add(witness2);

    // User creates this proof and sends to the issuer.
    const proof = CompositeProofG1.generate(proofSpec, witnesses);

    // Issuer checks that the commitment `commitmentTweet` is present in the tweet and then verifies the following
    // proof to check user's knowledge of its opening.
    expect(proof.verify(proofSpec).verified).toEqual(true);

    // Issuer will know these attributes
    const knownAttributes = new Map();
    knownAttributes.set(1, stringToBytes('@johnsmith'));
    knownAttributes.set(2, stringToBytes('John Smith'));
    knownAttributes.set(3, stringToBytes('Some guy on twitter'));
    knownAttributes.set(4, stringToBytes('5000'));

    // Issuer is convinced that user knows the opening to the both commitments
    const blindSig = BBSPlusBlindSignatureG1.generate(request.commitment, knownAttributes, sk, sigParams, true);

    // // User unblinds the signature and now has valid credential
    const sig: Signature = typeof blindSig.unblind === 'function' ? blindSig.unblind(blinding!): blindSig;

    // Combine blinded and known attributes in an array
    const attributes = Array(blindedAttributes.size + knownAttributes.size);
    for (const [i, m] of blindedAttributes.entries()) {
      attributes[i] = m;
    }
    for (const [i, m] of knownAttributes.entries()) {
      attributes[i] = m;
    }

    const result = sig.verify(attributes, pk, sigParams, true);
    expect(result.verified).toEqual(true);
  });
});
