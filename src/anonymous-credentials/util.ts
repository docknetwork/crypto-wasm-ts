import {
  Accumulator,
  AccumulatorParams,
  AccumulatorPublicKey,
  MembershipProvingKey,
  NonMembershipProvingKey
} from '../accumulator';
import {
  ACCUMULATOR_PARAMS_LABEL_BYTES,
  ACCUMULATOR_PROVING_KEY_LABEL_BYTES,
  AttributeEquality,
  BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES,
  BBS_SIGNATURE_PARAMS_LABEL_BYTES,
  FlattenedSchema,
  MEM_CHECK_STR,
  PS_SIGNATURE_PARAMS_LABEL_BYTES,
  PredicateParamType,
  PublicKey,
  SAVER_ENCRYPTION_GENS_BYTES,
  Signature,
  SignatureParams,
  SignatureParamsClass
} from './types-and-consts';
import {
  SaverChunkedCommitmentGens,
  SaverChunkedCommitmentGensUncompressed,
  SaverEncryptionGens,
  SaverEncryptionGensUncompressed,
  SaverEncryptionKey,
  SaverEncryptionKeyUncompressed,
  SaverProvingKey,
  SaverProvingKeyUncompressed,
  SaverVerifyingKey,
  SaverVerifyingKeyUncompressed
} from '../saver';
import { flatten } from 'flat';
import { PresentationSpecification } from './presentation-specification';
import { ValueType, ValueTypes } from './schema';
import {
  BBSPlusPublicKeyG2,
  BBSPlusSignatureG1,
  BBSPlusSignatureParamsG1,
  Encoder
} from '../bbs-plus';
import { SetupParam, Statement, Witness, WitnessEqualityMetaStatement } from '../composite-proof';
import { SetupParamsTracker } from './setup-params-tracker';
import { BBSPublicKey, BBSSignature, BBSSignatureParams } from '../bbs';
import { PSPublicKey, PSSignature, PSSignatureParams } from '../ps';

export function dockAccumulatorParams(): AccumulatorParams {
  return Accumulator.generateParams(ACCUMULATOR_PARAMS_LABEL_BYTES);
}

export function dockAccumulatorMemProvingKey(): MembershipProvingKey {
  return MembershipProvingKey.generate(ACCUMULATOR_PROVING_KEY_LABEL_BYTES);
}

export function dockAccumulatorNonMemProvingKey(): NonMembershipProvingKey {
  return NonMembershipProvingKey.generate(ACCUMULATOR_PROVING_KEY_LABEL_BYTES);
}

export function dockSaverEncryptionGens(): SaverEncryptionGens {
  return SaverEncryptionGens.generate(SAVER_ENCRYPTION_GENS_BYTES);
}

export function dockSaverEncryptionGensUncompressed(): SaverEncryptionGensUncompressed {
  return SaverEncryptionGens.generate(SAVER_ENCRYPTION_GENS_BYTES).decompress();
}

export function flattenTill2ndLastKey(obj: object): [string[], object[]] {
  const flattened = {};
  const temp = flatten(obj) as object;
  for (const k of Object.keys(temp)) {
    // taken from https://stackoverflow.com/a/5555607
    const pos = k.lastIndexOf('.');
    const name = k.substring(0, pos);
    const t = k.substring(pos + 1);

    if (flattened[name] === undefined) {
      flattened[name] = {};
    }
    flattened[name][t] = temp[k];
  }
  const keys = Object.keys(flattened).sort();
  // @ts-ignore
  const values = keys.map((k) => flattened[k]);
  return [keys, values];
}

/**
 * The context passed to the proof contains the version and the presentation spec as well. This is done to bind the
 * presentation spec and the version cryptographically to the proof.
 * @param version
 * @param presSpec
 * @param context
 */
export function buildContextForProof(
  version: string,
  presSpec: PresentationSpecification,
  context?: string | Uint8Array
): Uint8Array {
  const te = new TextEncoder();
  let ctx = Array.from(te.encode(version));
  if (context !== undefined) {
    if (typeof context === 'string') {
      ctx = ctx.concat(Array.from(te.encode(context)));
    } else {
      ctx = ctx.concat(Array.from(context));
    }
  }
  ctx = ctx.concat(Array.from(te.encode(presSpec.toJSON())));
  return new Uint8Array(ctx);
}

export function getTransformedMinMax(name: string, valTyp: ValueTypes, min: number, max: number): [number, number] {
  let transformedMin, transformedMax;
  switch (valTyp.type) {
    case ValueType.PositiveInteger:
      transformedMin = min;
      transformedMax = max;
      break;
    case ValueType.Integer:
      transformedMin = Encoder.integerToPositiveInt(valTyp.minimum)(min);
      transformedMax = Encoder.integerToPositiveInt(valTyp.minimum)(max);
      break;
    case ValueType.PositiveNumber:
      transformedMin = Encoder.positiveDecimalNumberToPositiveInt(valTyp.decimalPlaces)(min);
      transformedMax = Encoder.positiveDecimalNumberToPositiveInt(valTyp.decimalPlaces)(max);
      break;
    case ValueType.Number:
      transformedMin = Encoder.decimalNumberToPositiveInt(valTyp.minimum, valTyp.decimalPlaces)(min);
      transformedMax = Encoder.decimalNumberToPositiveInt(valTyp.minimum, valTyp.decimalPlaces)(max);
      break;
    default:
      throw new Error(`${name} should be of numeric type as per schema but was ${valTyp}`);
  }
  return [transformedMin, transformedMax];
}

export function createWitEq(eql: AttributeEquality, flattenedSchemas: FlattenedSchema[]): WitnessEqualityMetaStatement {
  const witnessEq = new WitnessEqualityMetaStatement();
  for (const [cIdx, name] of eql) {
    const i = flattenedSchemas[cIdx][0].indexOf(name);
    if (i === -1) {
      throw new Error(`Attribute name ${name} was not found`);
    }
    witnessEq.addWitnessRef(cIdx, i);
  }
  return witnessEq;
}

export function deepClone(obj: unknown): unknown {
  return JSON.parse(JSON.stringify(obj));
}

export function paramsClassBySignature(signature: Signature): SignatureParamsClass | null {
  if (signature instanceof BBSSignature) {
    return BBSSignatureParams;
  } else if (signature instanceof BBSPlusSignatureG1) {
    return BBSPlusSignatureParamsG1;
  } else if (signature instanceof PSSignature) {
    return PSSignatureParams;
  } else {
    return null;
  }
}

export function paramsClassByPublicKey(pk: PublicKey): SignatureParamsClass | null {
  if (pk instanceof BBSPublicKey) {
    return BBSSignatureParams;
  } else if (pk instanceof BBSPlusPublicKeyG2) {
    return BBSPlusSignatureParamsG1;
  } else if (pk instanceof PSPublicKey) {
    return PSSignatureParams;
  } else {
    return null;
  }
}

export function buildSignatureStatementFromParamsRef(
  setupParamsTrk: SetupParamsTracker,
  sigParams: SignatureParams,
  pk: PublicKey,
  messageCount: number,
  revealedMessages: Map<number, Uint8Array>
): Uint8Array {
  if (paramsClassByPublicKey(pk) !== sigParams.constructor) {
    throw new Error(`Public key and params have different schemes: ${pk}, ${sigParams}`);
  }
  let setupParams: SetupParam,
    setupPK: SetupParam,
    buildStatement: (
      sigParamsRef: number,
      publicKeyRef: number,
      revealedMessages: Map<number, Uint8Array>,
      encodeMessages: boolean
    ) => Uint8Array;

  switch (sigParams.constructor) {
    case BBSSignatureParams:
      setupParams = SetupParam.bbsSignatureParams(sigParams.adapt(messageCount) as BBSSignatureParams);
      setupPK = SetupParam.bbsPlusSignaturePublicKeyG2(pk);
      buildStatement = Statement.bbsSignatureFromSetupParamRefs;
      break;
    case BBSPlusSignatureParamsG1:
      setupPK = SetupParam.bbsPlusSignaturePublicKeyG2(pk);
      setupParams = SetupParam.bbsPlusSignatureParamsG1(sigParams.adapt(messageCount) as BBSPlusSignatureParamsG1);

      buildStatement = Statement.bbsPlusSignatureFromSetupParamRefs;
      break;
    case PSSignatureParams:
      let psPK = pk as PSPublicKey;
      const supported = psPK.supportedMessageCount();
      if (messageCount !== supported)
        if (messageCount < supported) {
          psPK = psPK.adaptForLess(messageCount);
        } else {
          throw new Error(`Unsupported message count: supported = ${supported}, received = ${messageCount}`);
        }

      setupPK = SetupParam.psSignaturePublicKey(psPK);
      setupParams = SetupParam.psSignatureParams(sigParams as PSSignatureParams);

      buildStatement = Statement.psSignatureFromSetupParamRefs;
      break;
    default:
      throw new Error(`Signature params are invalid ${sigParams}`);
  }

  return buildStatement(setupParamsTrk.add(setupParams), setupParamsTrk.add(setupPK), revealedMessages, false);
}

/**
 * Returns default label bytes for the signature params class (if any).
 * @param signatureParamsClass
 * @returns
 */
export function getDefaultLabelBytesForSignatureParams(signatureParamsClass: SignatureParamsClass): Uint8Array | null {
  switch (signatureParamsClass) {
    case BBSSignatureParams:
      return BBS_SIGNATURE_PARAMS_LABEL_BYTES;
    case BBSPlusSignatureParamsG1:
      return BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES;
    case PSSignatureParams:
      return PS_SIGNATURE_PARAMS_LABEL_BYTES;
    default:
      return null;
  }
}

export function buildWitness(signature: Signature, unrevealedMessages: Map<number, Uint8Array>): Uint8Array {
  if (signature instanceof BBSSignature) {
    return Witness.bbsSignature(signature, unrevealedMessages, false);
  } else if (signature instanceof BBSPlusSignatureG1) {
    return Witness.bbsPlusSignature(signature, unrevealedMessages, false);
  } else if (signature instanceof PSSignature) {
    return Witness.psSignature(signature, unrevealedMessages);
  } else {
    throw new Error(`Signature is invalid ${signature}`);
  }
}

/**
 * Returns signature params adapted for the provided message count reusing them from the provided map.
 * @param sigParamsByScheme
 * @param paramsClass
 * @param msgCount
 */
export const getSignatureParamsForMsgCount = (
  sigParamsByScheme: Map<SignatureParamsClass, { params: SignatureParams; msgCount: number }>,
  paramsClass: SignatureParamsClass,
  msgCount: number
): SignatureParams => {
  let sigParamsEntry = sigParamsByScheme.get(paramsClass);
  if (sigParamsEntry == null) {
    const labelBytes = getDefaultLabelBytesForSignatureParams(paramsClass);
    if (labelBytes == null) {
      throw new Error(`Failed to get default label bytes for signature params: ${paramsClass}`);
    }

    sigParamsEntry = {
      params: paramsClass.generate(msgCount, labelBytes),
      msgCount
    };
    sigParamsByScheme.set(paramsClass, sigParamsEntry);

    return sigParamsEntry.params;
  }

  const currentMsgCount = sigParamsEntry.msgCount;
  if (msgCount !== currentMsgCount) {
    sigParamsEntry = { params: sigParamsEntry.params.adapt(msgCount), msgCount };
    if (msgCount > currentMsgCount) {
      sigParamsByScheme.set(paramsClass, sigParamsEntry);
    }
  }

  return sigParamsEntry.params;
};

export function accumulatorStatement(
  checkType: string,
  pk: AccumulatorPublicKey,
  accumulated: Uint8Array,
  setupParamsTrk: SetupParamsTracker
): Uint8Array {
  let statement: Uint8Array;
  if (!setupParamsTrk.hasAccumulatorParams()) {
    setupParamsTrk.addAccumulatorParams();
  }
  if (checkType === MEM_CHECK_STR) {
    if (!setupParamsTrk.hasAccumulatorMemProvingKey()) {
      setupParamsTrk.addAccumulatorMemProvingKey();
    }
    statement = Statement.accumulatorMembershipFromSetupParamRefs(
      setupParamsTrk.accumParamsIdx,
      setupParamsTrk.add(SetupParam.vbAccumulatorPublicKey(pk)),
      setupParamsTrk.memPrkIdx,
      accumulated
    );
  } else {
    if (!setupParamsTrk.hasAccumulatorNonMemProvingKey()) {
      setupParamsTrk.addAccumulatorNonMemProvingKey();
    }
    statement = Statement.accumulatorNonMembershipFromSetupParamRefs(
      setupParamsTrk.accumParamsIdx,
      setupParamsTrk.add(SetupParam.vbAccumulatorPublicKey(pk)),
      setupParamsTrk.nonMemPrkIdx,
      accumulated
    );
  }
  return statement;
}

export function saverStatement(
  forProver: boolean,
  chunkBitSize: number,
  commGensId: string,
  encKeyId: string,
  snarkKeyId: string,
  commGens: PredicateParamType,
  encKey: PredicateParamType,
  snarkKey: PredicateParamType,
  setupParamsTrk: SetupParamsTracker
): Uint8Array {
  if (
    commGens instanceof SaverChunkedCommitmentGensUncompressed &&
    encKey instanceof SaverEncryptionKeyUncompressed &&
    ((forProver && snarkKey instanceof SaverProvingKeyUncompressed) ||
      (!forProver && snarkKey instanceof SaverVerifyingKeyUncompressed))
  ) {
    if (!setupParamsTrk.hasEncryptionGensUncompressed()) {
      setupParamsTrk.addEncryptionGensUncompressed();
    }
    if (!setupParamsTrk.isTrackingParam(commGensId)) {
      setupParamsTrk.addForParamId(commGensId, SetupParam.saverCommitmentGensUncompressed(commGens));
    }
    if (!setupParamsTrk.isTrackingParam(encKeyId)) {
      setupParamsTrk.addForParamId(encKeyId, SetupParam.saverEncryptionKeyUncompressed(encKey));
    }
    if (!setupParamsTrk.isTrackingParam(snarkKeyId)) {
      setupParamsTrk.addForParamId(
        snarkKeyId,
        forProver
          ? SetupParam.saverProvingKeyUncompressed(snarkKey)
          : SetupParam.saverVerifyingKeyUncompressed(snarkKey)
      );
    }
  } else if (
    commGens instanceof SaverChunkedCommitmentGens &&
    encKey instanceof SaverEncryptionKey &&
    ((forProver && snarkKey instanceof SaverProvingKey) || (!forProver && snarkKey instanceof SaverVerifyingKey))
  ) {
    if (!setupParamsTrk.hasEncryptionGensCompressed()) {
      setupParamsTrk.addEncryptionGensCompressed();
    }
    if (!setupParamsTrk.isTrackingParam(commGensId)) {
      setupParamsTrk.addForParamId(commGensId, SetupParam.saverCommitmentGens(commGens));
    }
    if (!setupParamsTrk.isTrackingParam(encKeyId)) {
      setupParamsTrk.addForParamId(encKeyId, SetupParam.saverEncryptionKey(encKey));
    }
    if (!setupParamsTrk.isTrackingParam(snarkKeyId)) {
      setupParamsTrk.addForParamId(
        snarkKeyId,
        forProver ? SetupParam.saverProvingKey(snarkKey as SaverProvingKey) : SetupParam.saverVerifyingKey(snarkKey)
      );
    }
  } else {
    throw new Error('All SAVER parameters should either be compressed in uncompressed');
  }
  return forProver
    ? Statement.saverProverFromSetupParamRefs(
        setupParamsTrk.encGensIdx,
        setupParamsTrk.indexForParam(commGensId),
        setupParamsTrk.indexForParam(encKeyId),
        setupParamsTrk.indexForParam(snarkKeyId),
        chunkBitSize
      )
    : Statement.saverVerifierFromSetupParamRefs(
        setupParamsTrk.encGensIdx,
        setupParamsTrk.indexForParam(commGensId),
        setupParamsTrk.indexForParam(encKeyId),
        setupParamsTrk.indexForParam(snarkKeyId),
        chunkBitSize
      );
}
