import {
  generateSetupParamForBBSPlusSignatureParametersG1,
  generateSetupParamForBBSSignatureParameters,
  generateSetupParamForPedersenCommitmentKeyG1,
  generateSetupParamForBBSPlusPublicKeyG2,
  generateSetupParamForVbAccumulatorParams,
  generateSetupParamForVbAccumulatorPublicKey,
  generateSetupParamForVbAccumulatorNonMemProvingKey,
  generateSetupParamForSaverCommitmentGens,
  generateSetupParamForSaverEncryptionGens,
  generateSetupParamForVbAccumulatorMemProvingKey,
  generateSetupParamForSaverEncryptionKey,
  generateSetupParamForSaverProvingKey,
  generateSetupParamForSaverVerifyingKey,
  generateSetupParamForLegoProvingKey,
  generateSetupParamForLegoVerifyingKey,
  generateSetupParamForR1CS,
  R1CS,
  generateSetupParamForBytes,
  generateSetupParamForFieldElemVec,
  generateSetupParamForBppParams,
  generateSetupParamForSmcParams,
  generateSetupParamForSmcParamsAndSk
} from '@docknetwork/crypto-wasm';
import { BBSPlusPublicKeyG2, BBSPlusSignatureParamsG1 } from '../bbs-plus';
import {
  SaverChunkedCommitmentKey,
  SaverChunkedCommitmentKeyUncompressed,
  SaverEncryptionGens,
  SaverEncryptionGensUncompressed,
  SaverEncryptionKey,
  SaverEncryptionKeyUncompressed,
  SaverProvingKey,
  SaverVerifyingKey,
  SaverProvingKeyUncompressed,
  SaverVerifyingKeyUncompressed
} from '../saver';
import {
  LegoProvingKey,
  LegoProvingKeyUncompressed,
  LegoVerifyingKey,
  LegoVerifyingKeyUncompressed
} from '../legosnark';
import { AccumulatorParams, AccumulatorPublicKey, MembershipProvingKey, NonMembershipProvingKey } from '../accumulator';
import { BytearrayWrapper } from '../bytearray-wrapper';
import { BBSSignatureParams } from '../bbs';
import { generateSetupParamForPSSignatureParameters } from '@docknetwork/crypto-wasm';
import { PSPublicKey, PSSignatureParams } from '../ps';
import { generateSetupParamForPSPublicKey, generateSetupParamForCommitmentKey } from '@docknetwork/crypto-wasm';
import { getR1CS, ParsedR1CSFile } from '../r1cs/file';
import {
  BoundCheckBppParams,
  BoundCheckBppParamsUncompressed,
  BoundCheckSmcParams,
  BoundCheckSmcParamsUncompressed,
  BoundCheckSmcWithKVVerifierParams,
  BoundCheckSmcWithKVVerifierParamsUncompressed
} from '../bound-check';
import { PederCommKey, PederCommKeyUncompressed } from '../ped-com';

/**
 * Represents (public) setup parameters of different protocols. Different setup parameters can be wrapped in this and
 * then a reference to this is passed to the `Statement`. This is helpful when the same setup parameter needs
 * to be passed to several `Statement`s as it avoids the need of having several copies of the setup parameter.
 */
export class SetupParam extends BytearrayWrapper {
  static bbsPlusSignatureParamsG1(params: BBSPlusSignatureParamsG1): SetupParam {
    return new SetupParam(generateSetupParamForBBSPlusSignatureParametersG1(params.value));
  }

  static bbsSignatureParams(params: BBSSignatureParams): SetupParam {
    return new SetupParam(generateSetupParamForBBSSignatureParameters(params.value));
  }

  static bbsPlusSignaturePublicKeyG2(publicKey: BBSPlusPublicKeyG2): SetupParam {
    return new SetupParam(generateSetupParamForBBSPlusPublicKeyG2(publicKey.value));
  }

  static psSignatureParams(params: PSSignatureParams): SetupParam {
    return new SetupParam(generateSetupParamForPSSignatureParameters(params.value));
  }

  static psSignaturePublicKey(publicKey: PSPublicKey): SetupParam {
    return new SetupParam(generateSetupParamForPSPublicKey(publicKey.value));
  }

  static vbAccumulatorParams(params: AccumulatorParams): SetupParam {
    return new SetupParam(generateSetupParamForVbAccumulatorParams(params.value));
  }

  static vbAccumulatorPublicKey(publicKey: AccumulatorPublicKey): SetupParam {
    return new SetupParam(generateSetupParamForVbAccumulatorPublicKey(publicKey.value));
  }

  static vbAccumulatorMemProvingKey(provingKey: MembershipProvingKey): SetupParam {
    return new SetupParam(generateSetupParamForVbAccumulatorMemProvingKey(provingKey.value));
  }

  static vbAccumulatorNonMemProvingKey(provingKey: NonMembershipProvingKey): SetupParam {
    return new SetupParam(generateSetupParamForVbAccumulatorNonMemProvingKey(provingKey.value));
  }

  static pedersenCommitmentKeyG1(commitmentKey: Uint8Array[]): SetupParam {
    return new SetupParam(generateSetupParamForPedersenCommitmentKeyG1(commitmentKey));
  }

  static saverEncryptionGens(encGens: SaverEncryptionGens): SetupParam {
    return new SetupParam(generateSetupParamForSaverEncryptionGens(encGens.value, false));
  }

  static saverEncryptionGensUncompressed(encGens: SaverEncryptionGensUncompressed): SetupParam {
    return new SetupParam(generateSetupParamForSaverEncryptionGens(encGens.value, true));
  }

  static saverCommitmentKey(commKey: SaverChunkedCommitmentKey): SetupParam {
    return new SetupParam(generateSetupParamForSaverCommitmentGens(commKey.value, false));
  }

  static saverCommitmentKeyUncompressed(commKey: SaverChunkedCommitmentKeyUncompressed): SetupParam {
    return new SetupParam(generateSetupParamForSaverCommitmentGens(commKey.value, true));
  }

  static saverEncryptionKey(key: SaverEncryptionKey): SetupParam {
    return new SetupParam(generateSetupParamForSaverEncryptionKey(key.value, false));
  }

  static saverEncryptionKeyUncompressed(key: SaverEncryptionKeyUncompressed): SetupParam {
    return new SetupParam(generateSetupParamForSaverEncryptionKey(key.value, true));
  }

  static saverProvingKey(key: SaverProvingKey): SetupParam {
    return new SetupParam(generateSetupParamForSaverProvingKey(key.value, false));
  }

  static saverProvingKeyUncompressed(key: SaverProvingKeyUncompressed): SetupParam {
    return new SetupParam(generateSetupParamForSaverProvingKey(key.value, true));
  }

  static saverVerifyingKey(key: SaverVerifyingKey): SetupParam {
    return new SetupParam(generateSetupParamForSaverVerifyingKey(key.value, false));
  }

  static saverVerifyingKeyUncompressed(key: SaverVerifyingKeyUncompressed): SetupParam {
    return new SetupParam(generateSetupParamForSaverVerifyingKey(key.value, true));
  }

  static legosnarkProvingKey(key: LegoProvingKey): SetupParam {
    return new SetupParam(generateSetupParamForLegoProvingKey(key.value, false));
  }

  static legosnarkProvingKeyUncompressed(key: LegoProvingKeyUncompressed): SetupParam {
    return new SetupParam(generateSetupParamForLegoProvingKey(key.value, true));
  }

  static legosnarkVerifyingKey(key: LegoVerifyingKey): SetupParam {
    return new SetupParam(generateSetupParamForLegoVerifyingKey(key.value, false));
  }

  static legosnarkVerifyingKeyUncompressed(key: LegoVerifyingKeyUncompressed): SetupParam {
    return new SetupParam(generateSetupParamForLegoVerifyingKey(key.value, true));
  }

  static r1cs(r1cs: R1CS | ParsedR1CSFile): SetupParam {
    const processedR1cs = getR1CS(r1cs);
    return new SetupParam(
      generateSetupParamForR1CS(
        processedR1cs.curveName,
        processedR1cs.numPublic,
        processedR1cs.numPrivate,
        processedR1cs.constraints
      )
    );
  }

  static bytes(b: Uint8Array): SetupParam {
    return new SetupParam(generateSetupParamForBytes(b));
  }

  static fieldElementVec(arr: Uint8Array[]): SetupParam {
    return new SetupParam(generateSetupParamForFieldElemVec(arr));
  }

  static bppSetupParams(params: BoundCheckBppParams): SetupParam {
    return new SetupParam(generateSetupParamForBppParams(params.value, false));
  }

  static bppSetupParamsUncompressed(params: BoundCheckBppParamsUncompressed): SetupParam {
    return new SetupParam(generateSetupParamForBppParams(params.value, true));
  }

  static smcSetupParams(params: BoundCheckSmcParams): SetupParam {
    return new SetupParam(generateSetupParamForSmcParams(params.value, false));
  }

  static smcSetupParamsUncompressed(params: BoundCheckSmcParamsUncompressed): SetupParam {
    return new SetupParam(generateSetupParamForSmcParams(params.value, true));
  }

  static smcSetupParamsWithSk(params: BoundCheckSmcWithKVVerifierParams): SetupParam {
    return new SetupParam(generateSetupParamForSmcParamsAndSk(params.value, false));
  }

  static smcSetupParamsWithSkUncompressed(params: BoundCheckSmcWithKVVerifierParamsUncompressed): SetupParam {
    return new SetupParam(generateSetupParamForSmcParamsAndSk(params.value, true));
  }

  static pedCommKeyG1(commKey: PederCommKey): SetupParam {
    return new SetupParam(generateSetupParamForCommitmentKey(commKey.value, false));
  }

  static pedCommKeyG1Uncompressed(commKey: PederCommKeyUncompressed): SetupParam {
    return new SetupParam(generateSetupParamForCommitmentKey(commKey.value, true));
  }
}
