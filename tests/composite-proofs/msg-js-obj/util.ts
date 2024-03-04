import {
  adaptKeyForParams,
  buildProverStatement, buildProverStatementFromSetupParamsRef,
  buildVerifierStatement, buildVerifierStatementFromSetupParamsRef,
  isKvac, isPS, PublicKey,
  Signature,
  SignatureParams
} from '../../scheme';
import { checkResult } from '../../utils';

export function signAndVerify(messages, encoder, label, sk, pk) {
  const signed = Signature.signMessageObject(messages, sk, label, encoder);
  checkResult(isKvac() ? signed.signature.verifyMessageObject(messages, sk, label, encoder) : signed.signature.verifyMessageObject(messages, pk, label, encoder));
  return signed;
}

export function proverStmt(params: SignatureParams, revealedMsgs: Map<number, Uint8Array>, pk?: PublicKey, encode = false) {
  return !isPS() ? buildProverStatement(
    params,
    revealedMsgs,
    encode
  ) : buildProverStatement(
    params,
    adaptKeyForParams(pk, params),
    revealedMsgs,
    encode
  )
}

export function verifierStmt(params: SignatureParams, revealedMsgs: Map<number, Uint8Array>, pk?: PublicKey, encode = false) {
  return isKvac() ? buildVerifierStatement(
    params,
    revealedMsgs,
    encode
  ): buildVerifierStatement(
    params,
    adaptKeyForParams(pk, params),
    revealedMsgs,
    encode
  )
}

export function proverStmtFromSetupParamsRef(paramsRef: number, revealedMsgs: Map<number, Uint8Array>, pkRef?: number, encode = false) {
  return !isPS() ? buildProverStatementFromSetupParamsRef(
    paramsRef,
    revealedMsgs,
    encode
  ) : buildProverStatementFromSetupParamsRef(
    paramsRef,
    pkRef,
    revealedMsgs,
    encode
  )
}

export function verifierStmtFromSetupParamsRef(paramsRef: number, revealedMsgs: Map<number, Uint8Array>, pkRef?: PublicKey, encode = false) {
  return isKvac() ? buildVerifierStatementFromSetupParamsRef(
    paramsRef,
    revealedMsgs,
    encode
  ): buildVerifierStatementFromSetupParamsRef(
    paramsRef,
    pkRef,
    revealedMsgs,
    encode
  )
}

export function adaptedSigParams(attributesStruct, label) {
  return isKvac() ? SignatureParams.getMacParamsForMsgStructure(attributesStruct, label) : SignatureParams.getSigParamsForMsgStructure(attributesStruct, label);
}