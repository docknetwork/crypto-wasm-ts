import { encodeMessageForSigning, encodeMessageForSigningInConstantTime } from 'crypto-wasm-new';
import {
  BBSBlindSignature,
  BBSCredential,
  BBSCredentialBuilder,
  BBSKeypair,
  BBSPlusBlindSignatureG1,
  BBSPlusCredential,
  BBSPlusCredentialBuilder,
  BBSPlusKeypairG2,
  BBSPlusPoKSignatureProtocol,
  BBSPlusPublicKeyG2,
  BBSPlusSecretKey,
  BBSPlusSignatureG1,
  BBSPlusSignatureParamsG1,
  BBSPoKSignatureProtocol,
  BBSPublicKey,
  BBSSecretKey,
  BBSSignature,
  BBSSignatureParams,
  PSBlindSignature,
  PSCredential,
  PSCredentialBuilder,
  PSKeypair,
  PSPoKSignatureProtocol,
  PSPublicKey,
  PSSecretKey,
  PSSignature,
  PSSignatureParams,
  SetupParam,
  Statement,
  Witness,
  getBBSPlusStatementForBlindSigRequest,
  getBBSPlusWitnessForBlindSigRequest,
  getBBSStatementForBlindSigRequest,
  getBBSWitnessForBlindSigRequest,
  getPSStatementsForBlindSigRequest,
  getPSWitnessesForBlindSigRequest,
  BBS_SIGNATURE_PARAMS_LABEL_BYTES,
  BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES,
  PS_SIGNATURE_PARAMS_LABEL_BYTES,
  BDDT16_MAC_PARAMS_LABEL_BYTES,
  getBDDT16StatementForBlindMacRequest,
  getBDDT16WitnessForBlindMacRequest, BDDT16CredentialBuilder, BDDT16Credential, BDDT16KeypairG1, BDDT16MacPublicKeyG1
} from '../src';
import { BDDT16BlindMac, BDDT16Mac, BDDT16MacParams, BDDT16MacSecretKey } from '../src/bddt16-mac';

export { Presentation } from '../src/anonymous-credentials/presentation';
export { PresentationBuilder } from '../src/anonymous-credentials/presentation-builder';

export let Scheme: string = process.env.TEST_SIGNATURE_SCHEME || 'BBS',
  SignatureLabelBytes: Uint8Array,
  PublicKey,
  SecretKey,
  Signature,
  KeyPair,
  BlindSignature,
  SignatureParams,
  PoKSignatureProtocol,
  getStatementForBlindSigRequest,
  getWitnessForBlindSigRequest,
  buildWitness,
  buildProverStatement,
  buildVerifierStatement,
  buildPublicKeySetupParam,
  buildSignatureParamsSetupParam,
  buildProverStatementFromSetupParamsRef,
  buildVerifierStatementFromSetupParamsRef,
  CredentialBuilder,
  Credential,
  encodeMessageForSigningIfPS: (msg: Uint8Array) => Uint8Array,
  encodeMessageForSigningIfNotPS: (msg: Uint8Array) => Uint8Array,
  isBBS = () => false,
  isBBSPlus = () => false,
  isPS = () => false,
  isBDDT16 = () => false,
  isKvac = () => false,
  adaptKeyForParams = (key, _params) => key;

switch (Scheme) {
  case 'BBS':
    PublicKey = BBSPublicKey;
    SecretKey = BBSSecretKey;
    Signature = BBSSignature;
    BlindSignature = BBSBlindSignature;
    KeyPair = BBSKeypair;
    SignatureParams = BBSSignatureParams;
    PoKSignatureProtocol = BBSPoKSignatureProtocol;
    buildWitness = Witness.bbsSignatureConstantTime;
    buildProverStatement = Statement.bbsSignatureProverConstantTime;
    buildVerifierStatement = Statement.bbsSignatureVerifierConstantTime;
    buildPublicKeySetupParam = SetupParam.bbsPlusSignaturePublicKeyG2;
    buildSignatureParamsSetupParam = SetupParam.bbsSignatureParams;
    buildProverStatementFromSetupParamsRef = Statement.bbsSignatureProverFromSetupParamRefsConstantTime;
    buildVerifierStatementFromSetupParamsRef = Statement.bbsSignatureVerifierFromSetupParamRefsConstantTime;
    getStatementForBlindSigRequest = getBBSStatementForBlindSigRequest;
    getWitnessForBlindSigRequest = getBBSWitnessForBlindSigRequest;
    CredentialBuilder = BBSCredentialBuilder;
    Credential = BBSCredential;
    encodeMessageForSigningIfPS = (msg) => msg;
    encodeMessageForSigningIfNotPS = encodeMessageForSigningInConstantTime;
    SignatureLabelBytes = BBS_SIGNATURE_PARAMS_LABEL_BYTES;
    isBBS = () => true;
    break;
  case 'BBS+':
    PublicKey = BBSPlusPublicKeyG2;
    SecretKey = BBSPlusSecretKey;
    Signature = BBSPlusSignatureG1;
    BlindSignature = BBSPlusBlindSignatureG1;
    KeyPair = BBSPlusKeypairG2;
    SignatureParams = BBSPlusSignatureParamsG1;
    PoKSignatureProtocol = BBSPlusPoKSignatureProtocol;
    buildWitness = Witness.bbsPlusSignatureConstantTime;
    buildProverStatement = Statement.bbsPlusSignatureProverConstantTime;
    buildVerifierStatement = Statement.bbsPlusSignatureVerifierConstantTime;
    buildPublicKeySetupParam = SetupParam.bbsPlusSignaturePublicKeyG2;
    buildSignatureParamsSetupParam = SetupParam.bbsPlusSignatureParamsG1;
    buildProverStatementFromSetupParamsRef = Statement.bbsPlusSignatureProverFromSetupParamRefsConstantTime;
    buildVerifierStatementFromSetupParamsRef = Statement.bbsPlusSignatureVerifierFromSetupParamRefsConstantTime;
    getStatementForBlindSigRequest = getBBSPlusStatementForBlindSigRequest;
    getWitnessForBlindSigRequest = getBBSPlusWitnessForBlindSigRequest;
    CredentialBuilder = BBSPlusCredentialBuilder;
    Credential = BBSPlusCredential;
    SignatureLabelBytes = BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES;
    encodeMessageForSigningIfPS = (msg) => msg;
    encodeMessageForSigningIfNotPS = encodeMessageForSigningInConstantTime;
    isBBSPlus = () => true;
    break;
  case 'PS':
    PublicKey = PSPublicKey;
    SecretKey = PSSecretKey;
    Signature = PSSignature;
    KeyPair = PSKeypair;
    BlindSignature = PSBlindSignature;
    SignatureParams = PSSignatureParams;
    PoKSignatureProtocol = PSPoKSignatureProtocol;
    buildWitness = Witness.psSignatureConstantTime;
    buildProverStatement = Statement.psSignatureConstantTime;
    buildVerifierStatement = Statement.psSignatureConstantTime;
    buildPublicKeySetupParam = SetupParam.psSignaturePublicKey;
    buildSignatureParamsSetupParam = SetupParam.psSignatureParams;
    buildProverStatementFromSetupParamsRef = Statement.psSignatureFromSetupParamRefsConstantTime;
    buildVerifierStatementFromSetupParamsRef = Statement.psSignatureFromSetupParamRefsConstantTime;
    getStatementForBlindSigRequest = getPSStatementsForBlindSigRequest;
    getWitnessForBlindSigRequest = getPSWitnessesForBlindSigRequest;
    CredentialBuilder = PSCredentialBuilder;
    Credential = PSCredential;
    SignatureLabelBytes = PS_SIGNATURE_PARAMS_LABEL_BYTES;
    encodeMessageForSigningIfPS = encodeMessageForSigningInConstantTime;
    encodeMessageForSigningIfNotPS = (msg) => msg;
    isPS = () => true;
    adaptKeyForParams = (key, params) => key.adaptForLess(params.supportedMessageCount());
    break;
  case 'BDDT16':
    PublicKey = BDDT16MacPublicKeyG1;
    SecretKey = BDDT16MacSecretKey;
    Signature = BDDT16Mac;
    BlindSignature = BDDT16BlindMac;
    KeyPair = BDDT16KeypairG1;
    SignatureParams = BDDT16MacParams;
    PoKSignatureProtocol = undefined;
    buildWitness = Witness.bddt16MacConstantTime;
    buildProverStatement = Statement.bddt16MacConstantTime;
    buildVerifierStatement = Statement.bddt16MacConstantTime;
    buildPublicKeySetupParam = undefined;
    buildSignatureParamsSetupParam = SetupParam.bddt16MacParams;
    buildProverStatementFromSetupParamsRef = Statement.bddt16MacFromSetupParamRefsConstantTime;
    buildVerifierStatementFromSetupParamsRef = Statement.bddt16MacFromSetupParamRefsConstantTime;
    getStatementForBlindSigRequest = getBDDT16StatementForBlindMacRequest;
    getWitnessForBlindSigRequest = getBDDT16WitnessForBlindMacRequest;
    CredentialBuilder = BDDT16CredentialBuilder;
    Credential = BDDT16Credential;
    SignatureLabelBytes = BDDT16_MAC_PARAMS_LABEL_BYTES;
    encodeMessageForSigningIfPS = (msg) => msg;
    encodeMessageForSigningIfNotPS = encodeMessageForSigningInConstantTime;
    isBDDT16 = () => true,
    isKvac = () => true;
    break;
  default:
    throw new Error(
      `Unknown signature scheme provided in \`TEST_SIGNATURE_SCHEME\`: ${Scheme}, expected either \`BBS\`, \`BBS+\`, \`PS\` or BDDT16`
    );
}

export type PublicKey = typeof PublicKey;
export type KeyPair = typeof KeyPair;
export type SecretKey = typeof SecretKey;
export type Signature = typeof Signature;
export type BlindSignature = typeof BlindSignature;
export type SignatureParams = typeof SignatureParams;
export type PoKSignatureProtocol = typeof PoKSignatureProtocol;
export type buildWitness = typeof buildWitness;
export type buildProverStatement = typeof buildProverStatement;
export type buildVerifierStatement = typeof buildVerifierStatement;
export type buildPublicKeySetupParam = typeof buildPublicKeySetupParam;
export type buildSignatureParamsSetupParam = typeof buildSignatureParamsSetupParam;
export type buildProverStatementFromSetupParamsRef = typeof buildProverStatementFromSetupParamsRef;
export type buildVerifierStatementFromSetupParamsRef = typeof buildVerifierStatementFromSetupParamsRef;
export type getStatementForBlindSigRequest = typeof getStatementForBlindSigRequest;
export type getWitnessForBlindSigRequest = typeof getWitnessForBlindSigRequest;
export type CredentialBuilder = typeof CredentialBuilder;
export type Credential = typeof Credential;
