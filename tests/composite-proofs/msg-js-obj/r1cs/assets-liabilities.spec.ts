import { generateFieldElementFromNumber, initializeWasm } from '@docknetwork/crypto-wasm';
import { checkResult, getWasmBytes, parseR1CSFile, stringToBytes } from '../../../utils';
import {
  BBSPlusPublicKeyG2,
  CircomInputs, CompositeProofG1, createWitnessEqualityMetaStatement, EncodeFunc,
  Encoder, encodeRevealedMsgs,
  getIndicesForMsgNames,
  getRevealedAndUnrevealed,
  getSigParamsForMsgStructure,
  KeypairG2,
  LegoProvingKeyUncompressed,
  LegoVerifyingKeyUncompressed, MetaStatements,
  ParsedR1CSFile, QuasiProofSpecG1,
  R1CSSnarkSetup, SetupParam,
  SignatureParamsG1,
  SignedMessages,
  signMessageObject, Statement, Statements,
  verifyMessageObject, Witness, WitnessEqualityMetaStatement, Witnesses
} from '../../../../src';
import { checkMapsEqual, defaultEncoder } from '../index';

// Test for a scenario where a user have 20 assets and liabilities, in different credentials (signed documents). The user
// proves that the sum of his assets is greater than sum of liabilities by 10000 without revealing actual values of either.
describe('Proving that sum of assets is greater than sum of liabilities by 10000', () => {
  let encoder: Encoder;

  const label = stringToBytes('Sig params label');
  let sigPk: BBSPlusPublicKeyG2;

  let r1cs: ParsedR1CSFile;
  let wasm: Uint8Array;

  let provingKey: LegoProvingKeyUncompressed, verifyingKey: LegoVerifyingKeyUncompressed;

  // Structure of asset credential
  const assetAttributesStruct = {
    fname: undefined,
    lname: undefined,
    sensitive: {
      email: undefined,
      SSN: undefined,
    },
    assets: {   // 5 different assets, number 5 is arbitrary
      id1: undefined,
      id2: undefined,
      id3: undefined,
      id4: undefined,
      id5: undefined,
    },
  };

  // Structure of liability credential
  const liabilitiesAttributesStruct = {
    fname: undefined,
    lname: undefined,
    sensitive: {
      email: undefined,
      SSN: undefined,
    },
    liabilities: {    // 4 different liabilities, number 4 is arbitrary
      id1: undefined,
      id2: undefined,
      id3: undefined,
      id4: undefined,
    },
  };

  const numAssetCredentials = 4;   // Circuit supports 20 assets, and each asset above has 5 values so 4 credentials (5*4=20)
  const numLiabilityCredentials = 5; // Circuit supports 20 liabilities, and each liability above has 4 values so 5 credentials (5*4=20)

  // Array of assets credentials (unsigned)
  const assetAttributes: object[] = [];
  // Array of liabilities credentials (unsigned)
  const liabilityAttributes: object[] = [];

  // Array of assets credentials (encoded and signed)
  const signedAssets: SignedMessages[] = [];
  // Array of liabilities credentials (encoded and signed)
  const signedLiabilities: SignedMessages[] = [];

  // Minimum expected different between assets and liabilities
  const minDiff = 10000;
  let minDiffEncoded: Uint8Array;

  beforeAll(async () => {
    await initializeWasm();

    // Setup encoder
    const encoders = new Map<string, EncodeFunc>();
    encoders.set('assets.id1', Encoder.positiveIntegerEncoder());
    encoders.set('assets.id2', Encoder.positiveIntegerEncoder());
    encoders.set('assets.id3', Encoder.positiveIntegerEncoder());
    encoders.set('assets.id4', Encoder.positiveIntegerEncoder());
    encoders.set('assets.id5', Encoder.positiveIntegerEncoder());
    encoders.set('liabilities.id1', Encoder.positiveIntegerEncoder());
    encoders.set('liabilities.id2', Encoder.positiveIntegerEncoder());
    encoders.set('liabilities.id3', Encoder.positiveIntegerEncoder());
    encoders.set('liabilities.id4', Encoder.positiveIntegerEncoder());
    encoder = new Encoder(encoders, defaultEncoder);

    // Important to encode the bound with the same encoder as attributes
    minDiffEncoded = Encoder.positiveIntegerEncoder()(minDiff);

    // This should ideally be done by the verifier but the verifier can publish only the Circom program and
    // prover can check that the same R1CS and WASM are generated.
    r1cs = await parseR1CSFile('difference_of_array_sum_20_20.r1cs');
    wasm = getWasmBytes('difference_of_array_sum_20_20.wasm');
  });

  it('verifier generates SNARk proving and verifying key', async () => {
    const pk = R1CSSnarkSetup.fromParsedR1CSFile(r1cs, 40);
    provingKey = pk.decompress();
    verifyingKey = pk.getVerifyingKeyUncompressed();
  });

  it('signers signs attributes', () => {
    // Message count shouldn't matter as `label` is known
    let params = SignatureParamsG1.generate(1, label);
    const keypair = KeypairG2.generate(params);
    const sk = keypair.secretKey;
    sigPk = keypair.publicKey;

    // Generate assets and liabilities
    for (let i = 0; i < numAssetCredentials; i++) {
      assetAttributes.push({
        fname: 'John',
        lname: 'Smith',
        sensitive: {
          email: 'john.smith@example.com',
          SSN: '123-456789-0',
        },
        assets: {
          id1: (i+1)*10000,
          id2: (i+2)*10000,
          id3: (i+3)*10000,
          id4: (i+4)*10000,
          id5: (i+5)*10000,
        },
      });
      signedAssets.push(signMessageObject(assetAttributes[i], sk, label, encoder));
      expect(verifyMessageObject(assetAttributes[i], signedAssets[i].signature, sigPk, label, encoder)).toBe(true);
    }

    for (let i = 0; i < numLiabilityCredentials; i++) {
      liabilityAttributes.push({
        fname: 'John',
        lname: 'Smith',
        sensitive: {
          email: 'john.smith@example.com',
          SSN: '123-456789-0',
        },
        liabilities: {
          id1: (i+1)*100,
          id2: (i+2)*100,
          id3: (i+3)*100,
          id4: (i+4)*100,
        },
      });
      signedLiabilities.push(signMessageObject(liabilityAttributes[i], sk, label, encoder));
      expect(verifyMessageObject(liabilityAttributes[i], signedLiabilities[i].signature, sigPk, label, encoder)).toBe(true);
    }
  });

  it('proof verifies when difference between total assets and total liabilities is more than 10000', () => {
    // Check that the sum of assets - sum of liabilities is greater than expected
    let assets = 0, liabilities = 0;
    for (let i = 0; i < numAssetCredentials; i++) {
      for (let j = 1; j <= 5; j++) {
        // @ts-ignore
        assets += assetAttributes[i].assets['id'+j];
      }
    }
    for (let i = 0; i < numLiabilityCredentials; i++) {
      for (let j = 1; j <= 4; j++) {
        // @ts-ignore
        liabilities += liabilityAttributes[i].liabilities['id'+j];
      }
    }

    expect(assets - liabilities).toBeGreaterThan(minDiff);

    // Reveal first name ("fname" attribute) from all assets and liabilities

    // Prove equality in zero knowledge of last name ("lname" attribute) and Social security number ("SSN" attribute) in all assets and liabilities credentials

    const revealedNames = new Set<string>();
    revealedNames.add('fname');

    const sigParamsAssets = getSigParamsForMsgStructure(assetAttributesStruct, label);
    const sigParamsLiabilities = getSigParamsForMsgStructure(liabilitiesAttributesStruct, label);

    // Prepare revealed and unrevealed attributes
    const revealedMsgs: Map<number, Uint8Array>[] = [];
    const unrevealedMsgs: Map<number, Uint8Array>[] = [];
    const revealedMsgsRaw: object[] = [];

    for (let i = 0; i < numAssetCredentials; i++) {
      const [r, u, rRaw] = getRevealedAndUnrevealed(
        assetAttributes[i],
        revealedNames,
        encoder
      );
      revealedMsgs.push(r);
      unrevealedMsgs.push(u);
      revealedMsgsRaw.push(rRaw);
      expect(rRaw).toEqual({ fname: 'John' });
    }

    for (let i = 0; i < numLiabilityCredentials; i++) {
      const [r, u, rRaw] = getRevealedAndUnrevealed(
        liabilityAttributes[i],
        revealedNames,
        encoder
      );
      revealedMsgs.push(r);
      unrevealedMsgs.push(u);
      revealedMsgsRaw.push(rRaw);
      expect(rRaw).toEqual({ fname: 'John' });
    }

    // Better to create setup params array once as knowledge of a lot of signatures will be proved
    const proverSetupParams: SetupParam[] = [];
    proverSetupParams.push(SetupParam.bbsSignatureParamsG1(sigParamsAssets));
    proverSetupParams.push(SetupParam.bbsSignatureParamsG1(sigParamsLiabilities));
    proverSetupParams.push(SetupParam.bbsSignaturePublicKeyG2(sigPk));
    proverSetupParams.push(SetupParam.r1cs(r1cs));
    proverSetupParams.push(SetupParam.bytes(wasm));
    proverSetupParams.push(SetupParam.legosnarkProvingKeyUncompressed(provingKey));

    const statementsProver = new Statements();

    // Statements to prove possesion of credentials
    const sIdxs: number[] = []
    for (let i = 0; i < numAssetCredentials; i++) {
      sIdxs.push(statementsProver.add(Statement.bbsSignatureFromSetupParamRefs(0, 2, revealedMsgs[i], false)));
    }
    for (let i = numAssetCredentials; i < numAssetCredentials + numLiabilityCredentials; i++) {
      sIdxs.push(statementsProver.add(Statement.bbsSignatureFromSetupParamRefs(1, 2, revealedMsgs[i], false)));
    }

    // For proving the relation between assets and liabilities.
    sIdxs.push(statementsProver.add(Statement.r1csCircomProverFromSetupParamRefs(3, 4, 5)));

    const metaStmtsProver = new MetaStatements();

    // Next 2 are for enforcing equality of last name and SSN in all credentials
    const witnessEq1 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        for (let i = 0; i < numAssetCredentials; i++) {
          m.set(sIdxs[i], [['lname'], assetAttributesStruct]);
        }
        for (let i = numAssetCredentials; i < numAssetCredentials + numLiabilityCredentials; i++) {
          m.set(sIdxs[i], [['lname'], liabilitiesAttributesStruct]);
        }
        return m;
      })()
    );
    metaStmtsProver.addWitnessEquality(witnessEq1);

    const witnessEq2 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        for (let i = 0; i < numAssetCredentials; i++) {
          m.set(sIdxs[i], [['sensitive.SSN'], assetAttributesStruct]);
        }
        for (let i = numAssetCredentials; i < numAssetCredentials + numLiabilityCredentials; i++) {
          m.set(sIdxs[i], [['sensitive.SSN'], liabilitiesAttributesStruct]);
        }
        return m;
      })()
    );
    metaStmtsProver.addWitnessEquality(witnessEq2);

    // Enforce equality of credential attributes (asset/liability amounts) with values in the Circom program
    let counter = 0;
    for (let i = 0; i < numAssetCredentials; i++) {
      for (let j = 1; j <= 5; j++) {
        const witnessEq = new WitnessEqualityMetaStatement();
        witnessEq.addWitnessRef(sIdxs[i], getIndicesForMsgNames(['assets.id'+j], assetAttributesStruct)[0]);
        witnessEq.addWitnessRef(sIdxs[numAssetCredentials + numLiabilityCredentials], counter);
        counter++;
        metaStmtsProver.addWitnessEquality(witnessEq);
      }
    }

    for (let i = numAssetCredentials; i < numAssetCredentials + numLiabilityCredentials; i++) {
      for (let j = 1; j <= 4; j++) {
        const witnessEq = new WitnessEqualityMetaStatement();
        witnessEq.addWitnessRef(sIdxs[i], getIndicesForMsgNames(['liabilities.id'+j], liabilitiesAttributesStruct)[0]);
        witnessEq.addWitnessRef(sIdxs[numAssetCredentials + numLiabilityCredentials], counter);
        counter++;
        metaStmtsProver.addWitnessEquality(witnessEq);
      }
    }

    const proofSpecProver = new QuasiProofSpecG1(statementsProver, metaStmtsProver, proverSetupParams);

    const witnesses = new Witnesses();
    for (let i = 0; i < numAssetCredentials; i++) {
      witnesses.add(Witness.bbsSignature(signedAssets[i].signature, unrevealedMsgs[i], false))
    }
    for (let i = 0; i < numLiabilityCredentials; i++) {
      witnesses.add(Witness.bbsSignature(signedLiabilities[i].signature, unrevealedMsgs[numAssetCredentials+i], false))
    }

    const inputs = new CircomInputs();
    // Add each encoded asset value as the circuit input
    inputs.setPrivateArrayInput('inA', signedAssets.flatMap((s) => {
      const arr: Uint8Array[] = [];
      for (let j = 1; j <= 5; j++) {
       arr.push(s.encodedMessages['assets.id'+j]);
      }
      return arr;
    }));
    // Add each encoded liability value as the circuit input
    inputs.setPrivateArrayInput('inB', signedLiabilities.flatMap((s) => {
      const arr: Uint8Array[] = [];
      for (let j = 1; j <= 4; j++) {
        arr.push(s.encodedMessages['liabilities.id'+j]);
      }
      return arr;
    }));
    inputs.setPublicInput('min', minDiffEncoded);
    witnesses.add(Witness.r1csCircomWitness(inputs));

    const proof = CompositeProofG1.generateUsingQuasiProofSpec(proofSpecProver, witnesses);

    // Verifier independently encodes revealed messages
    const revealedMsgsFromVerifier: Map<number, Uint8Array>[] = [];
    for (let i = 0; i < numAssetCredentials; i++) {
      revealedMsgsFromVerifier.push(encodeRevealedMsgs(revealedMsgsRaw[i], assetAttributesStruct, encoder));
      checkMapsEqual(revealedMsgs[i], revealedMsgsFromVerifier[i]);
    }
    for (let i = numAssetCredentials; i < numAssetCredentials+numLiabilityCredentials; i++) {
      revealedMsgsFromVerifier.push(encodeRevealedMsgs(revealedMsgsRaw[i], liabilitiesAttributesStruct, encoder));
      checkMapsEqual(revealedMsgs[i], revealedMsgsFromVerifier[i]);
    }

    const verifierSetupParams: SetupParam[] = [];
    verifierSetupParams.push(SetupParam.bbsSignatureParamsG1(sigParamsAssets));
    verifierSetupParams.push(SetupParam.bbsSignatureParamsG1(sigParamsLiabilities));
    verifierSetupParams.push(SetupParam.bbsSignaturePublicKeyG2(sigPk));

    // generateFieldElementFromNumber(1) as the condition "sum of assets - sum of liabilities > minDiff" should be true,
    // if "sum of assets - sum of liabilities <= minDiff" was being checked, then use generateFieldElementFromNumber(0)
    verifierSetupParams.push(SetupParam.fieldElementVec([generateFieldElementFromNumber(1), minDiffEncoded]));
    verifierSetupParams.push(SetupParam.legosnarkVerifyingKeyUncompressed(verifyingKey));

    const statementsVerifier = new Statements();

    const sIdxVs: number[] = []
    for (let i = 0; i < numAssetCredentials; i++) {
      sIdxVs.push(statementsVerifier.add(Statement.bbsSignatureFromSetupParamRefs(0, 2, revealedMsgsFromVerifier[i], false)));
    }
    for (let i = numAssetCredentials; i < numAssetCredentials + numLiabilityCredentials; i++) {
      sIdxVs.push(statementsVerifier.add(Statement.bbsSignatureFromSetupParamRefs(1, 2, revealedMsgsFromVerifier[i], false)));
    }

    sIdxVs.push(statementsVerifier.add(Statement.r1csCircomVerifierFromSetupParamRefs(3, 4)));

    const metaStmtsVerifier = new MetaStatements();

    const witnessEq3 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        for (let i = 0; i < numAssetCredentials; i++) {
          m.set(sIdxVs[i], [['lname'], assetAttributesStruct]);
        }
        for (let i = numAssetCredentials; i < numAssetCredentials + numLiabilityCredentials; i++) {
          m.set(sIdxVs[i], [['lname'], liabilitiesAttributesStruct]);
        }
        return m;
      })()
    );
    metaStmtsVerifier.addWitnessEquality(witnessEq3);

    const witnessEq4 = createWitnessEqualityMetaStatement(
      (() => {
        const m = new Map<number, [msgNames: string[], msgStructure: object]>();
        for (let i = 0; i < numAssetCredentials; i++) {
          m.set(sIdxVs[i], [['sensitive.SSN'], assetAttributesStruct]);
        }
        for (let i = numAssetCredentials; i < numAssetCredentials + numLiabilityCredentials; i++) {
          m.set(sIdxVs[i], [['sensitive.SSN'], liabilitiesAttributesStruct]);
        }
        return m;
      })()
    );
    metaStmtsVerifier.addWitnessEquality(witnessEq4);

    counter = 0;
    for (let i = 0; i < numAssetCredentials; i++) {
      for (let j = 1; j <= 5; j++) {
        const witnessEq = new WitnessEqualityMetaStatement();
        witnessEq.addWitnessRef(sIdxVs[i], getIndicesForMsgNames(['assets.id'+j], assetAttributesStruct)[0]);
        witnessEq.addWitnessRef(sIdxVs[numAssetCredentials + numLiabilityCredentials], counter);
        counter++;
        metaStmtsVerifier.addWitnessEquality(witnessEq);
      }
    }

    for (let i = numAssetCredentials; i < numAssetCredentials + numLiabilityCredentials; i++) {
      for (let j = 1; j <= 4; j++) {
        const witnessEq = new WitnessEqualityMetaStatement();
        witnessEq.addWitnessRef(sIdxVs[i], getIndicesForMsgNames(['liabilities.id'+j], liabilitiesAttributesStruct)[0]);
        witnessEq.addWitnessRef(sIdxVs[numAssetCredentials + numLiabilityCredentials], counter);
        counter++;
        metaStmtsVerifier.addWitnessEquality(witnessEq);
      }
    }

    const proofSpecVerifier = new QuasiProofSpecG1(statementsVerifier, metaStmtsVerifier, verifierSetupParams);

    checkResult(proof.verifyUsingQuasiProofSpec(proofSpecVerifier));
  }, 120000);
})