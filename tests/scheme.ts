import {
  BBSBlindSignature,
  BBSKeypair,
  BBSPlusBlindSignatureG1,
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
  getPSWitnessesForBlindSigRequest
} from '../src';

export let PublicKey,
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
  isBBS = () => false,
  isBBSPlus = () => false,
  isPS = () => false;

switch (process.env.TEST_SIGNATURE_SCHEME || 'BBS') {
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
    isPS = () => true;
    break;
  default:
    throw new Error('Unknown signature scheme');
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