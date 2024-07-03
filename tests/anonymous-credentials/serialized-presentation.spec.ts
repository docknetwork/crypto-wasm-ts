import * as fs from 'fs';
import { generateFieldElementFromNumber } from 'crypto-wasm-new';
import { Credential, isKvac, Presentation, PresentationBuilder, PublicKey, Scheme, SecretKey } from '../scheme';
import { checkResult, getWasmBytes, parseR1CSFile, stringToBytes } from '../utils';
import { checkCiphertext } from './utils';
import {
  AccumulatorPublicKey,
  getR1CS,
  initializeWasm,
  LegoVerifyingKeyUncompressed,
  SaverChunkedCommitmentKey,
  SaverDecryptionKeyUncompressed,
  SaverEncryptionKeyUncompressed,
  SaverSecretKey,
  SaverVerifyingKeyUncompressed
} from '../../src';

describe(`${Scheme} Presentation creation and verification from JSON`, () => {
  const fileNamePrefix = Scheme.toLowerCase();
  const chunkBitSize = 16;

  beforeAll(async () => {
    await initializeWasm();
  });

  function check(credVersion: string, presVersion: string, boundCheckVkName: string) {
    const boundCheckSnarkId = 'random';
    const commKeyId = 'random-1';
    const ekId = 'random-2';
    const snarkPkId = 'random-3';
    const ck = SaverChunkedCommitmentKey.generate(stringToBytes('a new nonce'));
    const commKey = ck.decompress();

    const pk1Bin = isKvac() ? undefined : fs.readFileSync(`${__dirname}/serialized-objects/${fileNamePrefix}_pk1.bin`);
    const pk2Bin = isKvac() ? undefined : fs.readFileSync(`${__dirname}/serialized-objects/${fileNamePrefix}_pk2.bin`);
    const pk3Bin = isKvac() ? undefined : fs.readFileSync(`${__dirname}/serialized-objects/${fileNamePrefix}_pk3.bin`);
    const sk1Bin = !isKvac() ? undefined : fs.readFileSync(`${__dirname}/serialized-objects/${fileNamePrefix}_sk1.bin`);
    const sk2Bin = !isKvac() ? undefined : fs.readFileSync(`${__dirname}/serialized-objects/${fileNamePrefix}_sk2.bin`);
    const sk3Bin = !isKvac() ? undefined : fs.readFileSync(`${__dirname}/serialized-objects/${fileNamePrefix}_sk3.bin`);

    const accPkBin = fs.readFileSync(`${__dirname}/serialized-objects/accumulator_pk.bin`);
    const boundCheckVkBin = fs.readFileSync(`${__dirname}/serialized-objects/${boundCheckVkName}.bin`);
    const saverVkBin = fs.readFileSync(`${__dirname}/serialized-objects/saver-vk.bin`);
    const saverEkBin = fs.readFileSync(`${__dirname}/serialized-objects/saver-ek.bin`);
    const saverDkBin = fs.readFileSync(`${__dirname}/serialized-objects/saver-dk.bin`);
    const saverSkBin = fs.readFileSync(`${__dirname}/serialized-objects/saver-sk.bin`);
    let credential1Json = fs.readFileSync(
      `${__dirname}/serialized-objects/${fileNamePrefix}_credential1-${credVersion}.json`,
      'utf8'
    );
    let credential2Json = fs.readFileSync(
      `${__dirname}/serialized-objects/${fileNamePrefix}_credential2-${credVersion}.json`,
      'utf8'
    );
    let credential3Json = fs.readFileSync(
      `${__dirname}/serialized-objects/${fileNamePrefix}_credential3-${credVersion}.json`,
      'utf8'
    );

    let presJson = fs.readFileSync(
      `${__dirname}/serialized-objects/${fileNamePrefix}-presentation-${presVersion}.json`,
      'utf8'
    );
    const pk1 = isKvac() ? undefined : PublicKey.fromBytes(pk1Bin);
    const pk2 = isKvac() ? undefined : PublicKey.fromBytes(pk2Bin);
    const pk3 = isKvac() ? undefined : PublicKey.fromBytes(pk3Bin);
    const sk1 = !isKvac() ? undefined : SecretKey.fromBytes(sk1Bin);
    const sk2 = !isKvac() ? undefined : SecretKey.fromBytes(sk2Bin);
    const sk3 = !isKvac() ? undefined : SecretKey.fromBytes(sk3Bin);
    const accPk = AccumulatorPublicKey.fromBytes(accPkBin);
    const boundCheckVk = LegoVerifyingKeyUncompressed.fromBytes(boundCheckVkBin);
    const saverVk = SaverVerifyingKeyUncompressed.fromBytes(saverVkBin);
    const saverEk = SaverEncryptionKeyUncompressed.fromBytes(saverEkBin);
    const saverDk = SaverDecryptionKeyUncompressed.fromBytes(saverDkBin);
    const saverSk = SaverSecretKey.fromBytes(saverSkBin);
    credential1Json = JSON.parse(credential1Json);
    const cred1 = Credential.fromJSON(credential1Json);
    credential2Json = JSON.parse(credential2Json);
    const cred2 = Credential.fromJSON(credential2Json);
    credential3Json = JSON.parse(credential3Json);
    const cred3 = Credential.fromJSON(credential3Json);

    checkResult(isKvac() ? cred1.verifyUsingSecretKey(sk1) : cred1.verify(pk1));
    checkResult(isKvac() ? cred2.verifyUsingSecretKey(sk2) : cred2.verify(pk2));
    checkResult(isKvac() ? cred3.verifyUsingSecretKey(sk3) : cred3.verify(pk3));

    presJson = JSON.parse(presJson);

    // @ts-ignore
    const pres = Presentation.fromJSON(presJson);

    const acc = new Map();
    acc.set(2, accPk);

    const pp = new Map();
    pp.set(boundCheckSnarkId, boundCheckVk);
    pp.set(commKeyId, commKey);
    pp.set(ekId, saverEk);
    pp.set(snarkPkId, saverVk);
    checkResult(pres.verify([pk1, pk2, pk3], acc, pp));
    expect(presJson).toEqual(pres.toJSON());

    if (isKvac()) {
      checkResult(pres.verify([sk1, sk2, sk3], acc, pp));
    }

    // @ts-ignore
    expect(pres.attributeCiphertexts.size).toEqual(2);
    // @ts-ignore
    expect(pres.attributeCiphertexts.get(0)).toBeDefined();
    // @ts-ignore
    expect(pres.attributeCiphertexts.get(1)).toBeDefined();

    expect(
      // @ts-ignore
      checkCiphertext(cred1, pres.attributeCiphertexts?.get(0), 'SSN', saverSk, saverDk, saverVk, chunkBitSize)
    ).toEqual(1);

    expect(
      checkCiphertext(
        cred2,
        // @ts-ignore
        pres.attributeCiphertexts?.get(1),
        'sensitive.userId',
        saverSk,
        saverDk,
        saverVk,
        chunkBitSize
      )
    ).toEqual(1);
  }

  async function checkCircom(presVersion: string, circomVkName: string) {
    const r1csGrade = await parseR1CSFile('set_membership_5_public.r1cs');
    const wasmGrade = getWasmBytes('set_membership_5_public.wasm');

    const pk1Bin = isKvac() ? undefined : fs.readFileSync(`${__dirname}/serialized-objects/${fileNamePrefix}_pk1.bin`);
    const circomVkBin = fs.readFileSync(`${__dirname}/serialized-objects/${circomVkName}.bin`);
    let pres1Json = fs.readFileSync(
      `${__dirname}/serialized-objects/${fileNamePrefix}-circom-presentation1-${presVersion}.json`,
      'utf8'
    );
    let pres2Json = fs.readFileSync(
      `${__dirname}/serialized-objects/${fileNamePrefix}-circom-presentation2-${presVersion}.json`,
      'utf8'
    );

    const pk1 = isKvac() ? undefined : PublicKey.fromBytes(pk1Bin);
    const circomVk = LegoVerifyingKeyUncompressed.fromBytes(circomVkBin);
    pres1Json = JSON.parse(pres1Json);
    // @ts-ignore
    const pres1 = Presentation.fromJSON(pres1Json);
    pres2Json = JSON.parse(pres2Json);
    // @ts-ignore
    const pres2 = Presentation.fromJSON(pres2Json);

    const pkId = 'random1';
    const circuitId = 'random2';

    const pp = new Map();
    pp.set(pkId, circomVk);
    pp.set(PresentationBuilder.r1csParamId(circuitId), getR1CS(r1csGrade));
    pp.set(PresentationBuilder.wasmParamId(circuitId), wasmGrade);
    const circomOutputs = new Map();
    circomOutputs.set(0, [[generateFieldElementFromNumber(1)]]);
    checkResult(pres1.verify([pk1], undefined, pp, circomOutputs));
    expect(pres1Json).toEqual(pres1.toJSON());

    const pp1 = new Map();
    pp1.set(pkId, circomVk);
    pp1.set(PresentationBuilder.r1csParamId(circuitId), getR1CS(r1csGrade));
    pp1.set(PresentationBuilder.wasmParamId(circuitId), wasmGrade);

    const circomOutputs1 = new Map();
    circomOutputs1.set(0, [[generateFieldElementFromNumber(0)]]);
    checkResult(pres2.verify([pk1], undefined, pp1, circomOutputs1));
    expect(pres2Json).toEqual(pres2.toJSON());
  }

  const skipIfKvac = isKvac() ? it.skip : it;

  skipIfKvac('check version 0.6.0', () => {
    // Legosnark keys changed due type of certain values changed from `u64` to `u32`
    check('0.4.0', '0.6.0', 'bound-check-legogroth16-vk2');
  });

  skipIfKvac('check version 0.6.0 with circom predicates', async () => {
    await checkCircom('0.6.0', 'circom-set_membership_5_public-2-vk');
  });

  skipIfKvac('check version 0.7.0', () => {
    // Legosnark keys changed due type of certain values changed from `u64` to `u32`
    check('0.5.0', '0.7.0', 'bound-check-legogroth16-vk2');
  });

  it('check version 0.8.0', () => {
    // Legosnark keys changed due type of certain values changed from `u64` to `u32`
    check('0.6.0', '0.8.0', 'bound-check-legogroth16-vk2');
  });
});
