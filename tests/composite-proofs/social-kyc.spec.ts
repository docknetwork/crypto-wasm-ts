import { CompositeProofG1, MetaStatements, ProofSpecG1, Statement, Statements, Witness, Witnesses } from '../../src';

import {
  generateRandomFieldElement,
  generateRandomG1Element,
  initializeWasm,
  pedersenCommitmentG1
} from '@docknetwork/crypto-wasm';
import { checkResult, stringToBytes } from '../utils';
import {
  Signature,
  BlindSignature,
  SignatureParams,
  KeyPair,
  PublicKey,
  SecretKey,
  isPS,
  isBBSPlus,
  getWitnessForBlindSigRequest,
  getStatementForBlindSigRequest
} from '../scheme';
import { encodeMessageForSigning } from '@docknetwork/crypto-wasm';

describe('Social KYC (Know Your Customer)', () => {
  // A social KYC (Know Your Customer) credential claims that the subject owns certain social media profile like a twitter
  // profile credential claims that a user owns the twitter profile with certain handle. User posts a commitment to some
  // random value on his profile and then requests a credential from the issuer by supplying a proof of knowledge of the
  // opening (committed random value) of the commitment. This test shows an example of user getting a twitter profile
  // credential from an issuer and the credential contains the profile handle, name, description and no. of followers. The
  // credential will contain the user's secret id which he will hide from the issuer, thus gets a blinded credential.

  // Issuer's parameters
  let sigParams: SignatureParams;
  // Issuers secret key and public keys
  let sk: SecretKey, pk: PublicKey;
  // Commitment key for commitment posted on social profile.
  let g: Uint8Array;
  let h: Uint8Array;

  // No of attributes in the KYC credential
  const attributeCount = 5;

  beforeAll(async () => {
    // Load the WASM module
    await initializeWasm();

    sigParams = SignatureParams.generate(attributeCount);

    // Generate keys
    const sigKeypair = KeyPair.generate(sigParams);
    sk = sigKeypair.secretKey;
    pk = sigKeypair.publicKey;

    h = generateRandomG1Element();
    g = generateRandomG1Element();
  });

  it('Requesting credential', async () => {
    // Holder creates random value posts a commitment to it on his twitter profile as a tweet.
    const randomValueTweet = generateRandomFieldElement();
    // This commitment will be posted in the tweet
    const commitmentTweet = pedersenCommitmentG1([g], [randomValueTweet]);

    // Prepare messages that will be blinded (hidden) and known to signer
    const blindedAttributes = new Map();

    blindedAttributes.set(0, encodeMessageForSigning(stringToBytes('my-secret-id')));

    // Issuer will know these attributes
    const knownAttributes = new Map();
    knownAttributes.set(1, encodeMessageForSigning(stringToBytes('@johnsmith')));
    knownAttributes.set(2, encodeMessageForSigning(stringToBytes('John Smith')));
    knownAttributes.set(3, encodeMessageForSigning(stringToBytes('Some guy on twitter')));
    knownAttributes.set(4, encodeMessageForSigning(stringToBytes('5000')));

    // Generate a blind signature request
    let blindings, blinding, request;
    if (isPS()) {
      blindings = new Map();
      [blinding, request] = BlindSignature.generateRequest(
        blindedAttributes,
        blindings,
        sigParams,
        h,
        void 0,
        knownAttributes
      );
    } else if (isBBSPlus()) {
      [blinding, request] = BlindSignature.generateRequest(
        blindedAttributes,
        sigParams,
        false,
        void 0,
        knownAttributes
      );
    } else {
      request = BlindSignature.generateRequest(blindedAttributes, sigParams, false, knownAttributes);
    }
    // The proof is created for 2 statements.

    // The 1st statement to prove is knowledge of opening of the commitment in the tweet
    const statement1 = Statement.pedersenCommitmentG1([g], commitmentTweet);

    const statements = new Statements(getStatementForBlindSigRequest(request, sigParams, h));
    statements.prepend(statement1);

    // Some context to the proof to prevent replayability, for stronger protection this should contain today's date etc as well
    const context = stringToBytes('Verifying twitter profile with issuer 1');

    const meta = new MetaStatements();
    const proofSpec = new ProofSpecG1(statements, meta, [], context);

    // This is the opening of the commitment posted in tweet
    const witness1 = Witness.pedersenCommitment([randomValueTweet]);
    // The witness to the Pedersen commitment contains the blinding at index 0 by convention and then the hidden attributes
    const witnesses = new Witnesses(getWitnessForBlindSigRequest(blindedAttributes, blinding, blindings));
    witnesses.prepend(witness1);

    // User creates this proof and sends to the issuer.
    const proof = CompositeProofG1.generate(proofSpec, witnesses);

    // Issuer checks that the commitment `commitmentTweet` is present in the tweet and then verifies the following
    // proof to check user's knowledge of its opening.
    checkResult(proof.verify(proofSpec));

    // Issuer is convinced that user knows the opening to the both commitments
    const blindSig = isPS()
      ? BlindSignature.fromRequest(request, sk, h)
      : BlindSignature.fromRequest(request, sk, sigParams, false);

    // // User unblinds the signature and now has valid credential
    const sig: Signature = isBBSPlus()
      ? blindSig.unblind(blinding!)
      : isPS()
      ? blindSig.unblind(blindings!, pk)
      : blindSig;

    // Combine blinded and known attributes in an array
    const attributes = Array(blindedAttributes.size + knownAttributes.size);
    for (const [i, m] of blindedAttributes.entries()) {
      attributes[i] = m;
    }
    for (const [i, m] of knownAttributes.entries()) {
      attributes[i] = m;
    }

    const result = sig.verify(attributes, pk, sigParams, false);
    expect(result.verified).toEqual(true);
  });
});
