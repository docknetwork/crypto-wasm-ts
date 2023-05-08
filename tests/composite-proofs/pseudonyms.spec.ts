import {
  AttributeBoundPseudonym,
  CompositeProofG1,
  MetaStatement,
  MetaStatements,
  ProofSpecG1,
  Pseudonym,
  PseudonymBases,
  Statement,
  Statements,
  Witness,
  WitnessEqualityMetaStatement,
  Witnesses
} from '../../src';
import { generateRandomFieldElement, initializeWasm } from '@docknetwork/crypto-wasm';
import { getRevealedUnrevealed, stringToBytes } from '../utils';
import {
  KeyPair,
  Signature,
  SignatureParams,
  buildStatement,
  buildWitness,
} from '../scheme'

// Get some attributes for testing
function getAttributes(): Uint8Array[] {
  // Messages to sign
  const attributes: Uint8Array[] = [];
  // SSN
  attributes.push(stringToBytes('123-456789-0'));
  // First name
  attributes.push(stringToBytes('John'));
  // Last name
  attributes.push(stringToBytes('Smith'));
  // Email
  attributes.push(stringToBytes('john.smith@emample.com'));

  // Encode attributes for signing as well as adding to the accumulator
  const encodedAttributes: Uint8Array[] = [];
  for (let i = 0; i < attributes.length; i++) {
    encodedAttributes.push(Signature.encodeMessageForSigning(attributes[i]));
  }

  return encodedAttributes;
}

// User creates a proof that it knows the secret key used in the pseudonym and verifier verifies the proof
function registerUsingPseudonym(pseudonym: Pseudonym, base: Uint8Array, secretKey: Uint8Array) {
  const statement = Statement.pseudonym(pseudonym, base);
  const statements = new Statements();
  statements.add(statement);

  const proofSpec = new ProofSpecG1(statements, new MetaStatements());

  const witness = Witness.pseudonym(secretKey);
  const witnesses = new Witnesses();
  witnesses.add(witness);

  const proof = CompositeProofG1.generate(proofSpec, witnesses);

  expect(proof.verify(proofSpec).verified).toEqual(true);
}

// User creates a proof that it knows the secret key and attributes used in the pseudonym and verifier verifies the proof
function registerUsingAttributeBoundPseudonym(
  pseudonym: AttributeBoundPseudonym,
  basesForAttributes: Uint8Array[],
  attributes: Uint8Array[],
  baseForSecretKey?: Uint8Array,
  secretKey?: Uint8Array
) {
  const statement = Statement.attributeBoundPseudonym(pseudonym, basesForAttributes, baseForSecretKey);
  const statements = new Statements();
  statements.add(statement);

  const proofSpec = new ProofSpecG1(statements, new MetaStatements());

  const witness = Witness.attributeBoundPseudonym(attributes, secretKey);
  const witnesses = new Witnesses();
  witnesses.add(witness);

  const proof = CompositeProofG1.generate(proofSpec, witnesses);

  expect(proof.verify(proofSpec).verified).toEqual(true);
}

describe('Register using pseudonym not bound to any attributes', () => {
  // User creates a secret key and creates 2 pseudonyms from it, one for each service provider.
  let secretKey: Uint8Array;

  const scope1 = stringToBytes('Service provider 1');
  // Base created by service provider 1
  let base1: Uint8Array;
  // Pseudonym used at service provider 1
  let pseudonym1: Pseudonym;

  const scope2 = stringToBytes('Service provider 2');
  // Base created by service provider 2
  let base2: Uint8Array;
  // Pseudonym used at service provider 2
  let pseudonym2: Pseudonym;

  beforeAll(async () => {
    // Load the WASM module
    await initializeWasm();

    // User creates a secret key
    secretKey = generateRandomFieldElement();
  });

  it('At service provider 1', () => {
    // Service provider creates a base
    base1 = PseudonymBases.generateBaseForSecretKey(scope1);

    // User creates a pseudonym from its secret key
    pseudonym1 = Pseudonym.new(base1, secretKey);

    // User registers pseudonym as service provider 1
    registerUsingPseudonym(pseudonym1, base1, secretKey);
  });

  it('At service provider 2', () => {
    // Service provider creates a base
    base2 = PseudonymBases.generateBaseForSecretKey(scope2);

    // User creates a pseudonym from its secret key
    pseudonym2 = Pseudonym.new(base2, secretKey);

    // User registers pseudonym as service provider 2
    registerUsingPseudonym(pseudonym2, base2, secretKey);
  });

  it('Pseudonym different at both service providers', () => {
    expect(base1).not.toEqual(base2);
    expect(pseudonym1.value).not.toEqual(pseudonym2.value);
  });

  it('Usage along with credential', () => {
    // User gets a credential (attributes + signature)
    const encodedAttributes = getAttributes();
    const label = stringToBytes('My sig params in g1');
    const sigParams = SignatureParams.generate(encodedAttributes.length, label);

    // Signers keys
    const sigKeypair = KeyPair.generate(sigParams);
    const sigSk = sigKeypair.secretKey;
    const sigPk = sigKeypair.publicKey;

    const sig = Signature.generate(encodedAttributes, sigSk, sigParams, false);

    // Prover is not revealing any attribute
    const [_, unrevealed] = getRevealedUnrevealed(encodedAttributes, new Set());

    // User using its pseudonym at service provider 1
    {
      const statement1 = buildStatement(sigParams, sigPk, new Map(), false);
      const statement2 = Statement.pseudonym(pseudonym1, base1);
      const statements = new Statements();
      statements.add(statement1);
      statements.add(statement2);

      const proofSpec = new ProofSpecG1(statements, new MetaStatements());

      const witness1 = buildWitness(sig, unrevealed, false);
      const witness2 = Witness.pseudonym(secretKey);
      const witnesses = new Witnesses(witness1);
      witnesses.add(witness2);

      const proof = CompositeProofG1.generate(proofSpec, witnesses);

      expect(proof.verify(proofSpec).verified).toEqual(true);
    }

    // User using its pseudonym at service provider 2
    {
      const statement1 = buildStatement(sigParams, sigPk, new Map(), false);
      const statement2 = Statement.pseudonym(pseudonym2, base2);
      const statements = new Statements(statement1);
      statements.add(statement2);

      const proofSpec = new ProofSpecG1(statements, new MetaStatements());

      const witness1 = buildWitness(sig, unrevealed, false);
      const witness2 = Witness.pseudonym(secretKey);
      const witnesses = new Witnesses(witness1);
      witnesses.add(witness2);

      const proof = CompositeProofG1.generate(proofSpec, witnesses);

      expect(proof.verify(proofSpec).verified).toEqual(true);
    }
  });
});

describe('Using pseudonym bound to some attributes', () => {
  // User creates a secret key and chooses certain attributes from a credential and creates 3 pseudonyms from those, one for each service provider.
  let secretKey: Uint8Array;

  const scope1 = stringToBytes('Service provider 1');
  // Base for secret key created by service provider 1
  let base1ForSecretKey: Uint8Array;
  // Bases for attributes created by service provider 1
  let bases1ForAttributes: Uint8Array[];
  // Pseudonym used at service provider 1
  let pseudonym1: Pseudonym;
  // attributes bound to pseudonym1
  let attributesPseudonym1: Uint8Array[];

  const scope2 = stringToBytes('Service provider 2');
  // Base for secret key created by service provider 2
  let base2ForSecretKey: Uint8Array;
  // Bases for attributes created by service provider 2
  let bases2ForAttributes: Uint8Array[];
  // Pseudonym used at service provider 2
  let pseudonym2: Pseudonym;
  // attributes bound to pseudonym2
  let attributesPseudonym2: Uint8Array[];

  const scope3 = stringToBytes('Service provider 3');
  // Service provider 3 does not want user to use its secret key but treat the combination of some of its attributes as
  // secret key. This approach however is vulnerable to an brute force attack where the verifier (service provider here)
  // can enumerate over all possible combinations of attributes to guess what they are.
  // Bases for attributes created by service provider 3
  let bases3ForAttributes: Uint8Array[];
  // Pseudonym used at service provider 3
  let pseudonym3: Pseudonym;
  // attributes bound to pseudonym3
  let attributesPseudonym3: Uint8Array[];

  let encodedAttributes: Uint8Array[];

  beforeAll(async () => {
    // Load the WASM module
    await initializeWasm();

    // Service provider 1 creates bases
    base1ForSecretKey = PseudonymBases.generateBaseForSecretKey(scope1);
    // Pseudonym used is bound to 1 credential attribute
    bases1ForAttributes = PseudonymBases.generateBasesForAttributes(1, scope1);

    // Service provider 2 creates bases
    base2ForSecretKey = PseudonymBases.generateBaseForSecretKey(scope2);
    // Pseudonym used is bound to 2 credential attributes
    bases2ForAttributes = PseudonymBases.generateBasesForAttributes(2, scope2);

    // Service provider 3 creates bases and pseudonym used is bound to 2 credential attributes
    bases3ForAttributes = PseudonymBases.generateBasesForAttributes(2, scope3);

    // User creates a secret key
    secretKey = generateRandomFieldElement();
    encodedAttributes = getAttributes();
    attributesPseudonym1 = [encodedAttributes[0]];
    attributesPseudonym2 = [encodedAttributes[0], encodedAttributes[3]];
    attributesPseudonym3 = [encodedAttributes[0], encodedAttributes[3]];

    // User creates pseudonym for service provider 1. This pseudonym is bound to 1 attribute and the secret key
    pseudonym1 = AttributeBoundPseudonym.new(bases1ForAttributes, attributesPseudonym1, base1ForSecretKey, secretKey);

    // User creates pseudonym for service provider 2. This pseudonym is bound to 2 attributes and the secret key
    pseudonym2 = AttributeBoundPseudonym.new(bases2ForAttributes, attributesPseudonym2, base2ForSecretKey, secretKey);

    // User creates pseudonym for service provider 3. This pseudonym is bound only to 2 attributes but not the secret key
    pseudonym3 = AttributeBoundPseudonym.new(bases3ForAttributes, attributesPseudonym3);
  });

  it('Registration of pseudonyms', () => {
    // User registers pseudonym as service provider 1
    registerUsingAttributeBoundPseudonym(
      pseudonym1,
      bases1ForAttributes,
      attributesPseudonym1,
      base1ForSecretKey,
      secretKey
    );

    // User registers pseudonym as service provider 2
    registerUsingAttributeBoundPseudonym(
      pseudonym2,
      bases2ForAttributes,
      attributesPseudonym2,
      base2ForSecretKey,
      secretKey
    );

    // User registers pseudonym as service provider 3
    registerUsingAttributeBoundPseudonym(pseudonym3, bases3ForAttributes, attributesPseudonym3);
  });

  it('Usage along with credential', () => {
    const label = stringToBytes('My sig params in g1');
    const sigParams = SignatureParams.generate(encodedAttributes.length, label);

    // Signers keys
    const sigKeypair = KeyPair.generate(sigParams);
    const sigSk = sigKeypair.secretKey;
    const sigPk = sigKeypair.publicKey;

    const sig = Signature.generate(encodedAttributes, sigSk, sigParams, false);

    // Prover is not revealing 1 attribute
    const revealedIndices = new Set<number>();
    revealedIndices.add(1);
    const [revealed, unrevealed] = getRevealedUnrevealed(encodedAttributes, revealedIndices);

    // User using its pseudonym at service provider 1
    {
      const statement1 = buildStatement(sigParams, sigPk, revealed, false);
      const statement2 = Statement.attributeBoundPseudonym(pseudonym1, bases1ForAttributes, base1ForSecretKey);
      const statements = new Statements();
      statements.add(statement1);
      statements.add(statement2);

      // The 0th attribute in the credential is bound to the pseudonym
      const witnessEq = new WitnessEqualityMetaStatement();
      // Witness ref for 0th attribute in the credential
      witnessEq.addWitnessRef(0, 0);
      // Witness ref for bound attribute
      witnessEq.addWitnessRef(1, 0);

      const metaStatements = new MetaStatements();
      metaStatements.add(MetaStatement.witnessEquality(witnessEq));

      const proofSpec = new ProofSpecG1(statements, metaStatements);

      const witness1 = buildWitness(sig, unrevealed, false);
      const witness2 = Witness.attributeBoundPseudonym(attributesPseudonym1, secretKey);
      const witnesses = new Witnesses(witness1);
      witnesses.add(witness2);

      const proof = CompositeProofG1.generate(proofSpec, witnesses);

      expect(proof.verify(proofSpec).verified).toEqual(true);
    }

    // User using its pseudonym at service provider 2
    {
      const statement1 = buildStatement(sigParams, sigPk, revealed, false);
      const statement2 = Statement.attributeBoundPseudonym(pseudonym2, bases2ForAttributes, base2ForSecretKey);
      const statements = new Statements();
      statements.add(statement1);
      statements.add(statement2);

      // The 0th attribute in the credential is bound to the pseudonym at index 0
      const witnessEq1 = new WitnessEqualityMetaStatement();
      // Witness ref for 0th attribute in the credential
      witnessEq1.addWitnessRef(0, 0);
      // Witness ref for 1st bound attribute
      witnessEq1.addWitnessRef(1, 0);

      // The 3rd attribute in the credential is bound to the pseudonym at index 1
      const witnessEq2 = new WitnessEqualityMetaStatement();
      // Witness ref for 3rd attribute in the credential
      witnessEq2.addWitnessRef(0, 3);
      // Witness ref for 2nd bound attribute
      witnessEq2.addWitnessRef(1, 1);

      const metaStatements = new MetaStatements();
      metaStatements.add(MetaStatement.witnessEquality(witnessEq1));
      metaStatements.add(MetaStatement.witnessEquality(witnessEq2));

      const proofSpec = new ProofSpecG1(statements, metaStatements);

      const witness1 = buildWitness(sig, unrevealed, false);
      const witness2 = Witness.attributeBoundPseudonym(attributesPseudonym2, secretKey);
      const witnesses = new Witnesses(witness1);
      witnesses.add(witness2);

      const proof = CompositeProofG1.generate(proofSpec, witnesses);

      expect(proof.verify(proofSpec).verified).toEqual(true);
    }

    // User using its pseudonym at service provider 3
    {
      const statement1 = buildStatement(sigParams, sigPk, revealed, false);
      const statement2 = Statement.attributeBoundPseudonym(pseudonym3, bases3ForAttributes);
      const statements = new Statements();
      statements.add(statement1);
      statements.add(statement2);

      // The 0th attribute in the credential is bound to the pseudonym at index 0
      const witnessEq1 = new WitnessEqualityMetaStatement();
      // Witness ref for 0th attribute in the credential
      witnessEq1.addWitnessRef(0, 0);
      // Witness ref for 1st bound attribute
      witnessEq1.addWitnessRef(1, 0);

      // The 3rd attribute in the credential is bound to the pseudonym at index 1
      const witnessEq2 = new WitnessEqualityMetaStatement();
      // Witness ref for 3rd attribute in the credential
      witnessEq2.addWitnessRef(0, 3);
      // Witness ref for 2nd bound attribute
      witnessEq2.addWitnessRef(1, 1);

      const metaStatements = new MetaStatements();
      metaStatements.add(MetaStatement.witnessEquality(witnessEq1));
      metaStatements.add(MetaStatement.witnessEquality(witnessEq2));

      const proofSpec = new ProofSpecG1(statements, metaStatements);

      const witness1 = buildWitness(sig, unrevealed, false);
      const witness2 = Witness.attributeBoundPseudonym(attributesPseudonym3);
      const witnesses = new Witnesses(witness1);
      witnesses.add(witness2);

      const proof = CompositeProofG1.generate(proofSpec, witnesses);

      expect(proof.verify(proofSpec).verified).toEqual(true);
    }
  });
});
