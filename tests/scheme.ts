import {
  BBSBlindSignature,
  BBSKeypair,
  BBSPlusBlindSignatureG1,
  BBSPlusKeypair,
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
  Statement,
  Witness,
  getBBSPlusStatementForBlindSigRequest,
  getBBSStatementForBlindSigRequest,
  getPSStatementsForBlindSigRequest
} from '../src';

export let PublicKey,
  SecretKey,
  Signature,
  KeyPair,
  BlindSignature,
  SignatureParams,
  PoKSignatureProtocol,
  getStatementForBlindSigRequest,
  buildWitness,
  buildStatement;

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
    getStatementForBlindSigRequest = getBBSStatementForBlindSigRequest;
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
    getStatementForBlindSigRequest = getBBSPlusStatementForBlindSigRequest;
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
    getStatementForBlindSigRequest = getPSStatementsForBlindSigRequest;
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
export type getStatementForBlindSigRequest = typeof getStatementForBlindSigRequest;
