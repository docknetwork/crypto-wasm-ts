import { encodeMessageForSigning } from '@docknetwork/crypto-wasm';
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
  PS_SIGNATURE_PARAMS_LABEL_BYTES
} from '../src';

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
  buildStatement,
  buildPublicKeySetupParam,
  buildSignatureParamsSetupParam,
  buildStatementFromSetupParamsRef,
  CredentialBuilder,
  Credential,
  encodeMessageForSigningIfPS: (msg: Uint8Array) => Uint8Array,
  encodeMessageForSigningIfNotPS: (msg: Uint8Array) => Uint8Array,
  isBBS = () => false,
  isBBSPlus = () => false,
  isPS = () => false,
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
    buildStatement = Statement.bbsSignature;
    buildPublicKeySetupParam = SetupParam.bbsPlusSignaturePublicKeyG2;
    buildSignatureParamsSetupParam = SetupParam.bbsSignatureParams;
    buildStatementFromSetupParamsRef = Statement.bbsSignatureFromSetupParamRefs;
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
    buildStatement = Statement.bbsPlusSignature;
    buildPublicKeySetupParam = SetupParam.bbsPlusSignaturePublicKeyG2;
    buildSignatureParamsSetupParam = SetupParam.bbsPlusSignatureParamsG1;
    buildStatementFromSetupParamsRef = Statement.bbsPlusSignatureFromSetupParamRefs;
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
    buildStatement = Statement.psSignature;
    buildPublicKeySetupParam = SetupParam.psSignaturePublicKey;
    buildSignatureParamsSetupParam = SetupParam.psSignatureParams;
    buildStatementFromSetupParamsRef = Statement.psSignatureFromSetupParamRefs;
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
  default:
    throw new Error(
      `Unknown signature scheme provided in \`TEST_SIGNATURE_SCHEME\`: ${Scheme}, expected either \`BBS\`, \`BBS+\` or \`PS\``
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
export type buildStatement = typeof buildStatement;
export type buildPublicKeySetupParam = typeof buildPublicKeySetupParam;
export type buildSignatureParamsSetupParam = typeof buildSignatureParamsSetupParam;
export type buildStatementFromSetupParamsRef = typeof buildStatementFromSetupParamsRef;
export type getStatementForBlindSigRequest = typeof getStatementForBlindSigRequest;
export type getWitnessForBlindSigRequest = typeof getWitnessForBlindSigRequest;
export type CredentialBuilder = typeof CredentialBuilder;
export type Credential = typeof Credential;
