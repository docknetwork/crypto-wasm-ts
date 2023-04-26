import {
  generateSetupParamForBBSPlusSignatureParametersG1,
  generateSetupParamForPedersenCommitmentKeyG1,
  generateSetupParamForBBSPublicKey,
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
  generateSetupParamForFieldElemVec
} from '@docknetwork/crypto-wasm';
import { BBSPlusPublicKeyG2, BBSPlusSignatureParamsG1 } from '../bbs-plus';
import {
  SaverChunkedCommitmentGens,
  SaverChunkedCommitmentGensUncompressed,
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
import { getR1CS, ParsedR1CSFile } from '../r1cs';

/**
 * Represents (public) setup parameters of different protocols. Different setup parameters can be wrapped in this and
 * then a reference to this is passed to the `Statement`. This is helpful when the same setup parameter needs
 * to be passed to several `Statement`s as it avoids the need of having several copies of the setup parameter.
 */
export class SetupParam extends BytearrayWrapper {
  static bbsPlusSignatureParamsG1(params: BBSPlusSignatureParamsG1): SetupParam {
    return new SetupParam(generateSetupParamForBBSPlusSignatureParametersG1(params.value));
  }

  static bbsPlusSignaturePublicKeyG2(publicKey: BBSPlusPublicKeyG2): SetupParam {
    return new SetupParam(generateSetupParamForBBSPublicKey(publicKey.value));
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

  static saverCommitmentGens(commGens: SaverChunkedCommitmentGens): SetupParam {
    return new SetupParam(generateSetupParamForSaverCommitmentGens(commGens.value, false));
  }

  static saverCommitmentGensUncompressed(commGens: SaverChunkedCommitmentGensUncompressed): SetupParam {
    return new SetupParam(generateSetupParamForSaverCommitmentGens(commGens.value, true));
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
    let processedR1cs = getR1CS(r1cs);
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
}
