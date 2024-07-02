import { encodeMessageForSigning } from 'crypto-wasm-new';
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
  BBDT16_MAC_PARAMS_LABEL_BYTES,
  getBBDT16StatementForBlindMacRequest,
  getBBDT16WitnessForBlindMacRequest, BBDT16CredentialBuilder, BBDT16Credential, BBDT16KeypairG1, BBDT16MacPublicKeyG1
} from '../src';
import { BBDT16BlindMac, BBDT16Mac, BBDT16MacParams, BBDT16MacSecretKey } from '../src/bbdt16-mac';

export { Presentation } from '../src/anonymous-credentials/presentation';
export { PresentationBuilder } from '../src/anonymous-credentials/presentation-builder';

export let Scheme: string = process.env.TEST_SIGNATURE_SCHEME || 'BBDT16',
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
  isBBDT16 = () => false,
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
    buildWitness = Witness.bbsSignature;
    buildProverStatement = Statement.bbsSignatureProver;
    buildVerifierStatement = Statement.bbsSignatureVerifier;
    buildPublicKeySetupParam = SetupParam.bbsPlusSignaturePublicKeyG2;
    buildSignatureParamsSetupParam = SetupParam.bbsSignatureParams;
    buildProverStatementFromSetupParamsRef = Statement.bbsSignatureProverFromSetupParamRefs;
    buildVerifierStatementFromSetupParamsRef = Statement.bbsSignatureVerifierFromSetupParamRefs;
    getStatementForBlindSigRequest = getBBSStatementForBlindSigRequest;
    getWitnessForBlindSigRequest = getBBSWitnessForBlindSigRequest;
    CredentialBuilder = BBSCredentialBuilder;
    Credential = BBSCredential;
    encodeMessageForSigningIfPS = (msg) => msg;
    encodeMessageForSigningIfNotPS = encodeMessageForSigning;
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
    buildWitness = Witness.bbsPlusSignature;
    buildProverStatement = Statement.bbsPlusSignatureProver;
    buildVerifierStatement = Statement.bbsPlusSignatureVerifier;
    buildPublicKeySetupParam = SetupParam.bbsPlusSignaturePublicKeyG2;
    buildSignatureParamsSetupParam = SetupParam.bbsPlusSignatureParamsG1;
    buildProverStatementFromSetupParamsRef = Statement.bbsPlusSignatureProverFromSetupParamRefs;
    buildVerifierStatementFromSetupParamsRef = Statement.bbsPlusSignatureVerifierFromSetupParamRefs;
    getStatementForBlindSigRequest = getBBSPlusStatementForBlindSigRequest;
    getWitnessForBlindSigRequest = getBBSPlusWitnessForBlindSigRequest;
    CredentialBuilder = BBSPlusCredentialBuilder;
    Credential = BBSPlusCredential;
    SignatureLabelBytes = BBS_PLUS_SIGNATURE_PARAMS_LABEL_BYTES;
    encodeMessageForSigningIfPS = (msg) => msg;
    encodeMessageForSigningIfNotPS = encodeMessageForSigning;
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
    buildWitness = Witness.psSignature;
    buildProverStatement = Statement.psSignature;
    buildVerifierStatement = Statement.psSignature;
    buildPublicKeySetupParam = SetupParam.psSignaturePublicKey;
    buildSignatureParamsSetupParam = SetupParam.psSignatureParams;
    buildProverStatementFromSetupParamsRef = Statement.psSignatureFromSetupParamRefs;
    buildVerifierStatementFromSetupParamsRef = Statement.psSignatureFromSetupParamRefs;
    getStatementForBlindSigRequest = getPSStatementsForBlindSigRequest;
    getWitnessForBlindSigRequest = getPSWitnessesForBlindSigRequest;
    CredentialBuilder = PSCredentialBuilder;
    Credential = PSCredential;
    SignatureLabelBytes = PS_SIGNATURE_PARAMS_LABEL_BYTES;
    encodeMessageForSigningIfPS = encodeMessageForSigning;
    encodeMessageForSigningIfNotPS = (msg) => msg;
    isPS = () => true;
    adaptKeyForParams = (key, params) => key.adaptForLess(params.supportedMessageCount());
    break;
  case 'BBDT16':
    PublicKey = BBDT16MacPublicKeyG1;
    SecretKey = BBDT16MacSecretKey;
    Signature = BBDT16Mac;
    BlindSignature = BBDT16BlindMac;
    KeyPair = BBDT16KeypairG1;
    SignatureParams = BBDT16MacParams;
    PoKSignatureProtocol = undefined;
    buildWitness = Witness.bbdt16Mac;
    buildProverStatement = Statement.bbdt16Mac;
    buildVerifierStatement = Statement.bbdt16Mac;
    buildPublicKeySetupParam = undefined;
    buildSignatureParamsSetupParam = SetupParam.bbdt16MacParams;
    buildProverStatementFromSetupParamsRef = Statement.bbdt16MacFromSetupParamRefs;
    buildVerifierStatementFromSetupParamsRef = Statement.bbdt16MacFromSetupParamRefs;
    getStatementForBlindSigRequest = getBBDT16StatementForBlindMacRequest;
    getWitnessForBlindSigRequest = getBBDT16WitnessForBlindMacRequest;
    CredentialBuilder = BBDT16CredentialBuilder;
    Credential = BBDT16Credential;
    SignatureLabelBytes = BBDT16_MAC_PARAMS_LABEL_BYTES;
    encodeMessageForSigningIfPS = (msg) => msg;
    encodeMessageForSigningIfNotPS = encodeMessageForSigning;
    isBBDT16 = () => true,
    isKvac = () => true;
    break;
  default:
    throw new Error(
      `Unknown signature scheme provided in \`TEST_SIGNATURE_SCHEME\`: ${Scheme}, expected either \`BBS\`, \`BBS+\`, \`PS\` or BBDT16`
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
