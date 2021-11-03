import {generateBBSKeyPairG1, generateBBSKeyPairG2, generateBBSPublicKeyG2, generateBBSPublicKeyG1, isBBSPublicKeyG2Valid, isBBSPublicKeyG1Valid} from "@docknetwork/crypto-wasm";
import {SignatureParamsG1, SignatureParamsG2} from "./params";

export abstract class Keypair {
    sk: Uint8Array;
    pk: Uint8Array;

    constructor(sk: Uint8Array, pk: Uint8Array) {
        this.sk = sk;
        this.pk = pk;
    }

    get secretKey(): Uint8Array {
        return this.sk
    }

    get publicKey(): Uint8Array {
        return this.pk
    }
}

export class KeypairG1 extends Keypair {
    static generate(params: SignatureParamsG2, seed?: Uint8Array): KeypairG1 {
        const keypair = generateBBSKeyPairG1(params.value, seed);
        return new KeypairG1(keypair.secret_key, keypair.public_key);
    }

    static generatePublicKeyFromSecretKey(secretKey: Uint8Array, params: SignatureParamsG2): Uint8Array {
        return generateBBSPublicKeyG1(secretKey, params.value)
    }

    static isPublicKeyValid(publicKey: Uint8Array): boolean {
        return isBBSPublicKeyG1Valid(publicKey);
    }
}

export class KeypairG2 extends Keypair {
    static generate(params: SignatureParamsG1, seed?: Uint8Array): KeypairG2 {
        const keypair = generateBBSKeyPairG2(params.value, seed);
        return new KeypairG2(keypair.secret_key, keypair.public_key);
    }

    static generatePublicKeyFromSecretKey(secretKey: Uint8Array, params: SignatureParamsG1): Uint8Array {
        return generateBBSPublicKeyG2(secretKey, params.value)
    }

    static isPublicKeyValid(publicKey: Uint8Array): boolean {
        return isBBSPublicKeyG2Valid(publicKey);
    }
}
