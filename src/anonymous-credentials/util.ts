import { flatten } from 'flat';
import { BBSPublicKey, BBSSignature, BBSSignatureParams } from '../bbs';
import { BBSPlusPublicKeyG2, BBSPlusSignatureG1, BBSPlusSignatureParamsG1 } from '../bbs-plus';
import { BDDT16Mac, BDDT16MacParams, BDDT16MacSecretKey } from '../bddt16-mac';
import { SetupParam, Statement, Witness, WitnessEqualityMetaStatement } from '../composite-proof';
import { PSPublicKey, PSSignature, PSSignatureParams } from '../ps';
import {
  SaverChunkedCommitmentKey,
  SaverChunkedCommitmentKeyUncompressed,
  SaverEncryptionKey,
  SaverEncryptionKeyUncompressed,
  SaverProvingKey,
  SaverProvingKeyUncompressed,
  SaverVerifyingKey,
  SaverVerifyingKeyUncompressed
} from '../saver';
import { SetupParamsTracker } from './setup-params-tracker';
import {
  AttributeEquality,
  AttributeRef,
  BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES,
  BBS_SIGNATURE_PARAMS_LABEL_BYTES,
  BDDT16_MAC_PARAMS_LABEL_BYTES,
  CredentialVerificationParam,
  FlattenedSchema,
  PredicateParamType,
  PS_SIGNATURE_PARAMS_LABEL_BYTES,
  PublicKey,
  Signature,
  SignatureParams,
  SignatureParamsClass
} from './types-and-consts';

export function isValueDate(value: string): boolean {
  // YYYY-MM-DD
  const datePattern = /^\d{4}-([0]\d|1[0-2])-([0-2]\d|3[01])$/;
  return datePattern.test(value);
}

export function isValueDateTime(value: string): boolean {
  // ISO 8601
  const dateTimePattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|(\+|-)\d{2}:\d{2})?$/;
  return dateTimePattern.test(value);
}

export function flattenTill2ndLastKey(obj: object): [string[], object[]] {
  const flattened = {};
  const temp = flatten(obj) as object;
  for (const k of Object.keys(temp)) {
    // Get 2nd last key, taken from https://stackoverflow.com/a/5555607
    const pos = k.lastIndexOf('.');
    const secondLast = k.substring(0, pos);
    const last = k.substring(pos + 1);

    if (flattened[secondLast] === undefined) {
      flattened[secondLast] = {};
    }
    flattened[secondLast][last] = temp[k];
  }
  const keys = Object.keys(flattened).sort();
  // @ts-ignore
  const values = keys.map((k) => flattened[k]);
  return [keys, values];
}

/**
 * flatten till 2nd last key where the last key is an array of un-nested object
 * @param obj
 */
export function flattenPredicatesInSpec(obj: object): [string[], object[][]] {
  // matches text of form `<string>.<number>.<string>`
  const re = /(.+)\.(\d+)\.(.+)/i;
  const flattened = {};
  const temp = flatten(obj) as object;
  const tempMap: Map<string, [Map<number, Map<string, any>>, number]> = new Map();
  for (const k of Object.keys(temp)) {
    let matched = k.match(re);
    if (!Array.isArray(matched)) {
      if (temp[k] !== null && temp[k] !== undefined) {
        // If temp[k] is null or undefined then encountered an array item which had no predicate
        throw new Error(`Regex couldn't match key ${k}`);
      }
    } else {
      const key = matched[1];
      const arrayIdx = parseInt(matched[2]);
      const innerObjKey = matched[3];
      const tempMapValue = tempMap.get(key);
      if (tempMapValue === undefined) {
        const m = new Map();
        const m1 = new Map();
        m1.set(innerObjKey, temp[k]);
        m.set(arrayIdx, m1);
        tempMap.set(key, [m, arrayIdx]);
      } else {
        if (arrayIdx > tempMapValue[1]) {
          tempMapValue[1] = arrayIdx;
        }
        const m1 = tempMapValue[0].get(arrayIdx);
        if (m1 === undefined) {
          const m1 = new Map();
          m1.set(innerObjKey, temp[k]);
          tempMapValue[0].set(arrayIdx, m1);
        } else {
          m1.set(innerObjKey, temp[k]);
        }
      }
    }
  }

  for (const [key, val] of tempMap.entries()) {
    const arr: object[] = new Array(val[1]);
    for (const [idx, inner] of val[0].entries()) {
      const obj = {};
      for (const [ik, iv] of inner.entries()) {
        obj[ik] = iv;
      }
      arr[idx] = obj;
    }
    flattened[key] = arr;
  }

  const keys = Object.keys(flattened).sort();
  // @ts-ignore
  const values = keys.map((k) => flattened[k]);
  return [keys, values];
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

export function createWitEqForBlindedCred(
  statementIdx: number,
  attrIdx: number,
  attrRefs: AttributeRef[],
  flattenedSchemas: FlattenedSchema[]
): WitnessEqualityMetaStatement {
  const witnessEq = new WitnessEqualityMetaStatement();
  witnessEq.addWitnessRef(statementIdx, attrIdx);
  for (const [cIdx, name] of attrRefs) {
    const i = flattenedSchemas[cIdx][0].indexOf(name);
    if (i === -1) {
      throw new Error(`Attribute name ${name} was not found`);
    }
    witnessEq.addWitnessRef(cIdx, i);
  }
  return witnessEq;
}

export function paramsClassBySignature(signature: Signature): SignatureParamsClass | null {
  if (signature instanceof BBSSignature) {
    return BBSSignatureParams;
  } else if (signature instanceof BBSPlusSignatureG1) {
    return BBSPlusSignatureParamsG1;
  } else if (signature instanceof PSSignature) {
    return PSSignatureParams;
  } else if (signature instanceof BDDT16Mac) {
    return BDDT16MacParams;
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

export function buildSignatureVerifierStatementFromParamsRef(
  setupParamsTrk: SetupParamsTracker,
  sigParams: SignatureParams,
  messageCount: number,
  revealedMessages: Map<number, Uint8Array>,
  credVerParam?: CredentialVerificationParam,
  useConstantTimeEncoding = true,
): Uint8Array {
  let setupSigP: SetupParam,
    setupPK: SetupParam | undefined,
    buildStatement:
      | ((
          sigParamsRef: number,
          publicKeyRef: number,
          revealedMessages: Map<number, Uint8Array>,
          encodeMessages: boolean
        ) => Uint8Array)
      | ((sigParamsRef: number, revealedMessages: Map<number, Uint8Array>, encodeMessages: boolean) => Uint8Array);

  function getPk(): PublicKey {
    if (credVerParam === undefined) {
      throw new Error('Public key needs to be provided for BBS signatures');
    }
    const pk = credVerParam as PublicKey;
    if (paramsClassByPublicKey(pk) !== sigParams.constructor) {
      throw new Error(`Public key and params have different schemes: ${credVerParam}, ${sigParams}`);
    }
    return pk;
  }

  switch (sigParams.constructor) {
    case BBSSignatureParams:
      setupSigP = SetupParam.bbsSignatureParams(sigParams.adapt(messageCount) as BBSSignatureParams);
      setupPK = SetupParam.bbsPlusSignaturePublicKeyG2(getPk());
      buildStatement = useConstantTimeEncoding ? Statement.bbsSignatureVerifierFromSetupParamRefsConstantTime : Statement.bbsSignatureVerifierFromSetupParamRefs;
      return buildStatement(setupParamsTrk.add(setupSigP), setupParamsTrk.add(setupPK), revealedMessages, false);
    case BBSPlusSignatureParamsG1:
      setupPK = SetupParam.bbsPlusSignaturePublicKeyG2(getPk());
      setupSigP = SetupParam.bbsPlusSignatureParamsG1(sigParams.adapt(messageCount) as BBSPlusSignatureParamsG1);
      buildStatement = useConstantTimeEncoding ? Statement.bbsPlusSignatureVerifierFromSetupParamRefsConstantTime : Statement.bbsPlusSignatureVerifierFromSetupParamRefs;
      return buildStatement(setupParamsTrk.add(setupSigP), setupParamsTrk.add(setupPK), revealedMessages, false);
    case PSSignatureParams:
      let psPK = getPk() as PSPublicKey;
      const supported = psPK.supportedMessageCount();
      if (messageCount !== supported) {
        if (messageCount < supported) {
          psPK = psPK.adaptForLess(messageCount);
        } else {
          throw new Error(`Unsupported message count - supported up to ${supported}, received = ${messageCount}`);
        }
      }
      setupPK = SetupParam.psSignaturePublicKey(psPK);
      setupSigP = SetupParam.psSignatureParams(sigParams.adapt(messageCount) as PSSignatureParams);
      buildStatement = useConstantTimeEncoding ? Statement.psSignatureFromSetupParamRefsConstantTime : Statement.psSignatureFromSetupParamRefs;
      return buildStatement(setupParamsTrk.add(setupSigP), setupParamsTrk.add(setupPK), revealedMessages, false);
    case BDDT16MacParams:
      setupSigP = SetupParam.bddt16MacParams(sigParams.adapt(messageCount) as BDDT16MacParams);
      if (credVerParam instanceof BDDT16MacSecretKey) {
        return useConstantTimeEncoding ? Statement.bddt16MacFullVerifierFromSetupParamRefsConstantTime(
          setupParamsTrk.add(setupSigP),
          credVerParam,
          revealedMessages,
          false
        ) : Statement.bddt16MacFullVerifierFromSetupParamRefs(
          setupParamsTrk.add(setupSigP),
          credVerParam,
          revealedMessages,
          false
        );
      } else {
        return useConstantTimeEncoding ? Statement.bddt16MacFromSetupParamRefsConstantTime(setupParamsTrk.add(setupSigP), revealedMessages, false) : Statement.bddt16MacFromSetupParamRefs(setupParamsTrk.add(setupSigP), revealedMessages, false);
      }
    default:
      throw new Error(`Signature params are invalid ${sigParams}`);
  }
}

export function buildSignatureProverStatementFromParamsRef(
  setupParamsTrk: SetupParamsTracker,
  sigParams: SignatureParams,
  messageCount: number,
  revealedMessages: Map<number, Uint8Array>,
  pk?: PublicKey
): Uint8Array {
  if (pk !== undefined && paramsClassByPublicKey(pk) !== sigParams.constructor) {
    throw new Error(`Public key and params have different schemes: ${pk}, ${sigParams}`);
  }
  let setupParams: SetupParam,
    setupPK: SetupParam | undefined,
    buildStatement:
      | ((
          sigParamsRef: number,
          publicKeyRef: number,
          revealedMessages: Map<number, Uint8Array>,
          encodeMessages: boolean
        ) => Uint8Array)
      | ((sigParamsRef: number, revealedMessages: Map<number, Uint8Array>, encodeMessages: boolean) => Uint8Array);

  switch (sigParams.constructor) {
    case BBSSignatureParams:
      setupParams = SetupParam.bbsSignatureParams(sigParams.adapt(messageCount) as BBSSignatureParams);
      buildStatement = Statement.bbsSignatureProverFromSetupParamRefsConstantTime;
      break;
    case BBSPlusSignatureParamsG1:
      setupParams = SetupParam.bbsPlusSignatureParamsG1(sigParams.adapt(messageCount) as BBSPlusSignatureParamsG1);
      buildStatement = Statement.bbsPlusSignatureProverFromSetupParamRefsConstantTime;
      break;
    case PSSignatureParams:
      if (pk === undefined) {
        throw new Error('Public key should be provided for PS signature');
      }
      let psPK = pk as PSPublicKey;
      const supported = psPK.supportedMessageCount();
      if (messageCount !== supported) {
        if (messageCount < supported) {
          psPK = psPK.adaptForLess(messageCount);
        } else {
          throw new Error(`Unsupported message count - supported up to ${supported}, received = ${messageCount}`);
        }
      }
      setupPK = SetupParam.psSignaturePublicKey(psPK);
      setupParams = SetupParam.psSignatureParams(sigParams.adapt(messageCount) as PSSignatureParams);
      buildStatement = Statement.psSignatureFromSetupParamRefsConstantTime;
      break;
    case BDDT16MacParams:
      setupParams = SetupParam.bddt16MacParams(sigParams.adapt(messageCount) as BDDT16MacParams);
      buildStatement = Statement.bddt16MacFromSetupParamRefsConstantTime;
      break;
    default:
      throw new Error(`${sigParams.constructor.name} signature params are invalid`);
  }

  return setupPK !== undefined
    ? // @ts-ignore
      buildStatement(setupParamsTrk.add(setupParams), setupParamsTrk.add(setupPK), revealedMessages, false)
    : // @ts-ignore
      buildStatement(setupParamsTrk.add(setupParams), revealedMessages, false);
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
    case BDDT16MacParams:
      return BDDT16_MAC_PARAMS_LABEL_BYTES;
    default:
      return null;
  }
}

export function buildWitness(signature: Signature, unrevealedMessages: Map<number, Uint8Array>): Uint8Array {
  if (signature instanceof BBSSignature) {
    return Witness.bbsSignatureConstantTime(signature, unrevealedMessages, false);
  } else if (signature instanceof BBSPlusSignatureG1) {
    return Witness.bbsPlusSignatureConstantTime(signature, unrevealedMessages, false);
  } else if (signature instanceof PSSignature) {
    return Witness.psSignatureConstantTime(signature, unrevealedMessages);
  } else if (signature instanceof BDDT16Mac) {
    return Witness.bddt16MacConstantTime(signature, unrevealedMessages, false);
  } else {
    // @ts-ignore
    throw new Error(`${signature.constructor.name} signature is invalid`);
  }
}

/**
 * Returns signature params adapted for the provided message count reusing them from the provided map. Acts as a cache lookup
 * and can update the cache.
 * @param sigParamsByScheme - The cache of signature params
 * @param paramsClass
 * @param msgCount
 */
export const getSignatureParamsForMsgCount = (
  sigParamsByScheme: Map<SignatureParamsClass, { params: SignatureParams; msgCount: number }>,
  paramsClass: SignatureParamsClass,
  msgCount: number
): SignatureParams => {
  let sigParamsEntry = sigParamsByScheme.get(paramsClass);
  if (sigParamsEntry === void 0) {
    const labelBytes = getDefaultLabelBytesForSignatureParams(paramsClass);
    if (labelBytes === null) {
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

export function saverStatement(
  forProver: boolean,
  chunkBitSize: number,
  commKeyId: string,
  encKeyId: string,
  snarkKeyId: string,
  commKeys: PredicateParamType,
  encKey: PredicateParamType,
  snarkKey: PredicateParamType,
  setupParamsTrk: SetupParamsTracker
): Uint8Array {
  if (
    commKeys instanceof SaverChunkedCommitmentKeyUncompressed &&
    encKey instanceof SaverEncryptionKeyUncompressed &&
    ((forProver && snarkKey instanceof SaverProvingKeyUncompressed) ||
      (!forProver && snarkKey instanceof SaverVerifyingKeyUncompressed))
  ) {
    if (!setupParamsTrk.hasEncryptionGensUncompressed()) {
      setupParamsTrk.addEncryptionGensUncompressed();
    }
    if (!setupParamsTrk.isTrackingParam(commKeyId)) {
      setupParamsTrk.addForParamId(commKeyId, SetupParam.saverCommitmentKeyUncompressed(commKeys));
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
    commKeys instanceof SaverChunkedCommitmentKey &&
    encKey instanceof SaverEncryptionKey &&
    ((forProver && snarkKey instanceof SaverProvingKey) || (!forProver && snarkKey instanceof SaverVerifyingKey))
  ) {
    if (!setupParamsTrk.hasEncryptionGensCompressed()) {
      setupParamsTrk.addEncryptionGensCompressed();
    }
    if (!setupParamsTrk.isTrackingParam(commKeyId)) {
      setupParamsTrk.addForParamId(commKeyId, SetupParam.saverCommitmentKey(commKeys));
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
        setupParamsTrk.indexForParam(commKeyId),
        setupParamsTrk.indexForParam(encKeyId),
        setupParamsTrk.indexForParam(snarkKeyId),
        chunkBitSize
      )
    : Statement.saverVerifierFromSetupParamRefs(
        setupParamsTrk.encGensIdx,
        setupParamsTrk.indexForParam(commKeyId),
        setupParamsTrk.indexForParam(encKeyId),
        setupParamsTrk.indexForParam(snarkKeyId),
        chunkBitSize
      );
}
