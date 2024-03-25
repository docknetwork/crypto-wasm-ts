import { generateRandomFieldElement } from 'crypto-wasm-new';
import {
  initializeWasm,
  IInitialElementsStore,
  Accumulator,
  PositiveAccumulator,
  UniversalAccumulator,
  VBMembershipWitness,
  VBWitnessUpdateInfo,
  AccumulatorParams,
  AccumulatorKeypair,
} from '../src';
import {
  InMemoryInitialElementsStore, InMemoryKBUniversalState,
  InMemoryState,
  InMemoryUniversalState
} from '../src/accumulator/in-memory-persistence';
import { KBUniversalMembershipWitness } from '../src/accumulator/kb-acccumulator-witness';
import { KBUniversalAccumulator } from '../src/accumulator/kb-universal-accumulator';
import { KBUniversalMembershipWitnessUpdateInfo } from '../src/accumulator/witness-update-info';
import { areUint8ArraysEqual, stringToBytes } from './utils';

function getAccum(accumulator: any): PositiveAccumulator | UniversalAccumulator | KBUniversalAccumulator {
  const accumulated = accumulator.accumulated;
  let tempAccumulator;
  if (accumulator instanceof PositiveAccumulator) {
    tempAccumulator = PositiveAccumulator.fromAccumulated(accumulated);
  } else if (accumulator instanceof UniversalAccumulator) {
    tempAccumulator = UniversalAccumulator.fromAccumulated(accumulated);
  } else {
    tempAccumulator = KBUniversalAccumulator.fromAccumulated(accumulated);
  }
  return tempAccumulator;
}

async function runCommonTestsForMembership(
  keypair: AccumulatorKeypair,
  params: AccumulatorParams,
  accumulator: PositiveAccumulator | UniversalAccumulator | KBUniversalAccumulator,
  state: InMemoryState | InMemoryKBUniversalState,
  members: Uint8Array[],
  store?: IInitialElementsStore
) {
  const sk = keypair.sk;
  const pk = keypair.pk;

  let witClass, witUpdClass;
  if (accumulator instanceof PositiveAccumulator) {
    witClass = VBMembershipWitness;
    witUpdClass = VBWitnessUpdateInfo;
  } else if (accumulator instanceof UniversalAccumulator) {
    witClass = VBMembershipWitness;
    witUpdClass = VBWitnessUpdateInfo;
  } else {
    witClass = KBUniversalMembershipWitness;
    witUpdClass = KBUniversalMembershipWitnessUpdateInfo;
  }

  const e1 = members.pop() as Uint8Array;
  const e2 = members.pop() as Uint8Array;

  expect(state.size).toEqual(0);
  await expect(state.has(e1)).resolves.toEqual(false);

  // @ts-ignore
  await accumulator.add(e1, sk, state, store);

  expect(state.size).toEqual(1);
  await expect(state.has(e1)).resolves.toEqual(true);

  // @ts-ignore
  await expect(accumulator.add(e1, sk, state, store)).rejects.toThrow();

  // @ts-ignore
  await expect(accumulator.remove(e2, sk, state)).rejects.toThrow();

  // @ts-ignore
  await accumulator.add(e2, sk, state, store);

  expect(state.size).toEqual(2);
  await expect(state.has(e2)).resolves.toEqual(true);

  // @ts-ignore
  await accumulator.remove(e2, sk, state, store);

  expect(state.size).toEqual(1);
  await expect(state.has(e2)).resolves.toEqual(false);

  const e3 = members.pop() as Uint8Array;
  const e4 = members.pop() as Uint8Array;

  // @ts-ignore
  await accumulator.addBatch([e3, e4], sk, state, store);

  expect(state.size).toEqual(3);
  await expect(state.has(e3)).resolves.toEqual(true);
  await expect(state.has(e4)).resolves.toEqual(true);

  // @ts-ignore
  await expect(accumulator.addBatch([e3, e4], sk, state, store)).rejects.toThrow();

  expect(state.size).toEqual(3);

  // @ts-ignore
  await accumulator.removeBatch([e3, e4], sk, state, store);
  expect(state.size).toEqual(1);
  await expect(state.has(e3)).resolves.toEqual(false);
  await expect(state.has(e4)).resolves.toEqual(false);

  // @ts-ignore
  await expect(accumulator.removeBatch([e3, e4], sk, state, store)).rejects.toThrow();
  expect(state.size).toEqual(1);

  const e5 = members.pop() as Uint8Array;
  const e6 = members.pop() as Uint8Array;

  // @ts-ignore
  await accumulator.addRemoveBatches([e5, e6], [e1], sk, state, store);
  expect(state.size).toEqual(2);
  await expect(state.has(e5)).resolves.toEqual(true);
  await expect(state.has(e6)).resolves.toEqual(true);
  await expect(state.has(e1)).resolves.toEqual(false);

  const accumulated = accumulator.accumulated;
  let tempAccumulator = getAccum(accumulator);

  expect(
    // @ts-ignore
    tempAccumulator.verifyMembershipWitness(e5, await accumulator.membershipWitness(e5, sk, state), pk, params)
  ).toEqual(true);
  expect(
    // @ts-ignore
    tempAccumulator.verifyMembershipWitness(e6, await accumulator.membershipWitness(e6, sk, state), pk, params)
  ).toEqual(true);

  // @ts-ignore
  const wits = await accumulator.membershipWitnessesForBatch([e5, e6], sk, state);
  // @ts-ignore
  expect(tempAccumulator.verifyMembershipWitness(e5, wits[0], pk, params)).toEqual(true);
  // @ts-ignore
  expect(tempAccumulator.verifyMembershipWitness(e6, wits[1], pk, params)).toEqual(true);

  const e7 = members.pop() as Uint8Array;
  const e8 = members.pop() as Uint8Array;

  // @ts-ignore
  await accumulator.addBatch([e7, e8], sk, state, store);

  // Witness updates by accumulator manager using secret key
  // @ts-ignore
  const newWits = witClass.updateMultiplePostBatchUpdates(wits, [e5, e6], [e7, e8], [], accumulated, sk);

  tempAccumulator = getAccum(accumulator);
  // @ts-ignore
  expect(tempAccumulator.verifyMembershipWitness(e5, newWits[0], pk, params)).toEqual(true);
  // @ts-ignore
  expect(tempAccumulator.verifyMembershipWitness(e6, newWits[1], pk, params)).toEqual(true);

  // Witness update info created by accumulator manager
  // @ts-ignore
  const witnessUpdInfo = witUpdClass.new(accumulated, [e7, e8], [], sk);

  // Witness can be updated without secret key using public info
  wits[0].updateUsingPublicInfoPostBatchUpdate(e5, [e7, e8], [], witnessUpdInfo);
  wits[1].updateUsingPublicInfoPostBatchUpdate(e6, [e7, e8], [], witnessUpdInfo);

  // @ts-ignore
  expect(tempAccumulator.verifyMembershipWitness(e5, wits[0], pk, params)).toEqual(true);
  // @ts-ignore
  expect(tempAccumulator.verifyMembershipWitness(e6, wits[1], pk, params)).toEqual(true);

  // @ts-ignore
  const e5Wit = await accumulator.membershipWitness(e5, sk, state);
  // @ts-ignore
  const e6Wit = await accumulator.membershipWitness(e6, sk, state);

  let e5WitTemp = new witClass(e5Wit.value);
  let e6WitTemp = new witClass(e6Wit.value);

  const e9 = members.pop() as Uint8Array;
  const e10 = members.pop() as Uint8Array;
  const e11 = members.pop() as Uint8Array;
  const e12 = members.pop() as Uint8Array;
  const e13 = members.pop() as Uint8Array;
  const e14 = members.pop() as Uint8Array;
  const e15 = members.pop() as Uint8Array;

  const additions = [
    [e9, e10],
    [e11, e12],
    [e13, e14, e15]
  ];
  const removals = [[e7, e8], [e9], []];

  // @ts-ignore
  const witUpd1 = witUpdClass.new(accumulator.accumulated, additions[0], removals[0], sk);
  // @ts-ignore
  await accumulator.addRemoveBatches(additions[0], removals[0], sk, state);

  tempAccumulator = getAccum(accumulator);
  e5WitTemp.updateUsingPublicInfoPostBatchUpdate(e5, additions[0], removals[0], witUpd1);
  e6WitTemp.updateUsingPublicInfoPostBatchUpdate(e6, additions[0], removals[0], witUpd1);
  // @ts-ignore
  expect(tempAccumulator.verifyMembershipWitness(e5, e5WitTemp, pk, params)).toEqual(true);
  // @ts-ignore
  expect(tempAccumulator.verifyMembershipWitness(e6, e6WitTemp, pk, params)).toEqual(true);

  // @ts-ignore
  const witUpd2 = witUpdClass.new(accumulator.accumulated, additions[1], removals[1], sk);
  // @ts-ignore
  await accumulator.addRemoveBatches(additions[1], removals[1], sk, state);

  tempAccumulator = getAccum(accumulator);
  e5WitTemp.updateUsingPublicInfoPostBatchUpdate(e5, additions[1], removals[1], witUpd2);
  e6WitTemp.updateUsingPublicInfoPostBatchUpdate(e6, additions[1], removals[1], witUpd2);
  // @ts-ignore
  expect(tempAccumulator.verifyMembershipWitness(e5, e5WitTemp, pk, params)).toEqual(true);
  // @ts-ignore
  expect(tempAccumulator.verifyMembershipWitness(e6, e6WitTemp, pk, params)).toEqual(true);

  // @ts-ignore
  const witUpd3 = witUpdClass.new(accumulator.accumulated, additions[2], removals[2], sk);
  // @ts-ignore
  await accumulator.addRemoveBatches(additions[2], removals[2], sk, state);

  tempAccumulator = getAccum(accumulator);
  e5WitTemp.updateUsingPublicInfoPostBatchUpdate(e5, additions[2], removals[2], witUpd3);
  e6WitTemp.updateUsingPublicInfoPostBatchUpdate(e6, additions[2], removals[2], witUpd3);
  // @ts-ignore
  expect(tempAccumulator.verifyMembershipWitness(e5, e5WitTemp, pk, params)).toEqual(true);
  // @ts-ignore
  expect(tempAccumulator.verifyMembershipWitness(e6, e6WitTemp, pk, params)).toEqual(true);

  const witUpds = [witUpd1, witUpd2, witUpd3];

  e5Wit.updateUsingPublicInfoPostMultipleBatchUpdates(e5, additions, removals, witUpds);
  e6Wit.updateUsingPublicInfoPostMultipleBatchUpdates(e6, additions, removals, witUpds);

  tempAccumulator = getAccum(accumulator);

  // @ts-ignore
  expect(tempAccumulator.verifyMembershipWitness(e5, e5Wit, pk, params)).toEqual(true);
  // @ts-ignore
  expect(tempAccumulator.verifyMembershipWitness(e6, e6Wit, pk, params)).toEqual(true);
}

describe('Accumulators type', () => {

  beforeAll(async () => {
    await initializeWasm();
  });

  it('State update', async () => {
    const params = PositiveAccumulator.generateParams();
    const keypair = PositiveAccumulator.generateKeypair(params);

    const posAccumulator = PositiveAccumulator.initialize(params);
    const posState = new InMemoryState();

    const uniState = new InMemoryKBUniversalState();
    const domain = [generateRandomFieldElement(), generateRandomFieldElement(), generateRandomFieldElement(), generateRandomFieldElement(), generateRandomFieldElement()];
    const uniAccumulator = await KBUniversalAccumulator.initialize(domain, params, keypair.secretKey, uniState);

    for (const d of domain) {
      expect(await uniState.inDomain(d)).toEqual(true);
    }

    async function check(accum: PositiveAccumulator | KBUniversalAccumulator, state, members1: Uint8Array[], members2: Uint8Array[]) {
      for (let i = 0; i < members1.length; i++) {
        expect(await state.has(members1[i])).toEqual(false);
      }
      await accum.addBatch(members1, keypair.secretKey, state);
      for (let i = 0; i < members1.length; i++) {
        expect(await state.has(members1[i])).toEqual(true);
      }

      for (let i = 0; i < members2.length; i++) {
        expect(await state.has(members2[i])).toEqual(false);
      }
      await accum.addRemoveBatches(members2, members1, keypair.secretKey, state);
      for (let i = 0; i < members2.length; i++) {
        expect(await state.has(members2[i])).toEqual(true);
      }
      for (let i = 0; i < members1.length; i++) {
        expect(await state.has(members1[i])).toEqual(false);
      }
    }

    await check(posAccumulator, posState, [generateRandomFieldElement(), generateRandomFieldElement(), generateRandomFieldElement()], [generateRandomFieldElement(), generateRandomFieldElement()]);
    await check(uniAccumulator, uniState, domain.slice(0, 3), domain.slice(3));

    // Cannot add element not part of the domain
    const oldSize = uniState.size;
    const newElement = generateRandomFieldElement();
    expect(uniAccumulator.add(newElement, keypair.secretKey, uniState)).rejects.toThrow();
    expect(await uniState.inDomain(newElement)).toEqual(false);
    expect(await uniState.has(newElement)).toEqual(false);
    expect(uniState.size).toEqual(oldSize);
    // Add to domain
    await uniAccumulator.extend([newElement], keypair.secretKey, uniState);
    // Now it works
    await uniAccumulator.add(newElement, keypair.secretKey, uniState);
    expect(await uniState.inDomain(newElement)).toEqual(true);
    expect(await uniState.has(newElement)).toEqual(true);
    expect(uniState.size).toEqual(oldSize + 1);

    // Cannot extend the domain with an existing element
    expect(() => uniAccumulator.extend([newElement], keypair.secretKey, uniState)).rejects.toThrow();

    const newElements = [generateRandomFieldElement(), generateRandomFieldElement(), generateRandomFieldElement()];
    for (const e of newElements) {
      expect(await uniState.inDomain(e)).toEqual(false);
    }
    await uniAccumulator.extend(newElements, keypair.secretKey, uniState);
    for (const e of newElements) {
      expect(await uniState.inDomain(e)).toEqual(true);
    }

    // Cannot extend the domain with existing elements
    expect(() => uniAccumulator.extend(newElements, keypair.secretKey, uniState)).rejects.toThrow();
  });

  it('Positive accumulator', async () => {
    const label = stringToBytes('Accumulator params');
    const params = PositiveAccumulator.generateParams(label);
    const keypair = PositiveAccumulator.generateKeypair(params);
    const accumulator = PositiveAccumulator.initialize(params);
    const state = new InMemoryState();
    const domain = Array.from(Array(20).keys()).map((i) => Accumulator.encodePositiveNumberAsAccumulatorMember(100 + i));
    await runCommonTestsForMembership(keypair, params, accumulator, state, domain);
  });

  it('VB universal accumulator', async () => {
    const params = UniversalAccumulator.generateParams();
    const keypair = UniversalAccumulator.generateKeypair(params);
    const store = new InMemoryInitialElementsStore();
    const maxSize = 20;
    const accumulator1 = await UniversalAccumulator.initialize(maxSize, params, keypair.secretKey, store);

    const fixed = UniversalAccumulator.fixedInitialElements();
    expect(store.store.size).toEqual(maxSize + fixed.length + 1);
    for (const i of fixed) {
      await expect(store.has(i)).resolves.toEqual(true);
    }
    const state1 = new InMemoryUniversalState();
    const domain = Array.from(Array(20).keys()).map((i) => Accumulator.encodePositiveNumberAsAccumulatorMember(100 + i));
    await runCommonTestsForMembership(keypair, params, accumulator1, state1, domain, store);

    const nm1 = Accumulator.encodePositiveNumberAsAccumulatorMember(500);
    const nm1Wit = await accumulator1.nonMembershipWitness(nm1, state1, keypair.secretKey, params, store, 2);

    let tempAccumulator = getAccum(accumulator1) as UniversalAccumulator;
    expect(tempAccumulator.verifyNonMembershipWitness(nm1, nm1Wit, keypair.publicKey, params)).toEqual(true);

    const nm2 = Accumulator.encodePositiveNumberAsAccumulatorMember(501);
    const nm3 = Accumulator.encodePositiveNumberAsAccumulatorMember(502);

    const [nm2Wit, nm3Wit] = await accumulator1.nonMembershipWitnessesForBatch(
      [nm2, nm3],
      state1,
      keypair.secretKey,
      params,
      store,
      3
    );
    expect(tempAccumulator.verifyNonMembershipWitness(nm2, nm2Wit, keypair.publicKey, params)).toEqual(true);
    expect(tempAccumulator.verifyNonMembershipWitness(nm3, nm3Wit, keypair.publicKey, params)).toEqual(true);
  });

  it('KB universal accumulator', async () => {
    const label = stringToBytes('Accumulator params');
    const params = KBUniversalAccumulator.generateParams(label);
    const keypair = KBUniversalAccumulator.generateKeypair(params);
    const state = new InMemoryKBUniversalState();
    const domain = Array.from(Array(20).keys()).map((i) => Accumulator.encodePositiveNumberAsAccumulatorMember(100 + i));
    const accumulator = await KBUniversalAccumulator.initialize(domain, params, keypair.secretKey, state);
    await runCommonTestsForMembership(keypair, params, accumulator, state, domain);

    async function check(nonMember: Uint8Array) {
      expect(await state.has(nonMember)).toEqual(false);
      expect(await state.inDomain(nonMember)).toEqual(true);
      const wit = await accumulator.nonMembershipWitness(nonMember, keypair.secretKey, state);
      let tempAccumulator = getAccum(accumulator) as KBUniversalAccumulator;
      expect(tempAccumulator.verifyNonMembershipWitness(nonMember, wit, keypair.publicKey, params)).toEqual(true);
      return wit
    }

    const nm1Wit = await check(domain[0]);
    const nm2Wit = await check(domain[1]);
    const nm3Wit = await check(domain[2]);

    const [nm1Wit_, nm2Wit_, nm3Wit_] = await accumulator.nonMembershipWitnessesForBatch(
      [domain[0], domain[1], domain[2]],
      keypair.secretKey,
      state,
    );
    expect(areUint8ArraysEqual(nm1Wit.value, nm1Wit_.value)).toEqual(true);
    expect(areUint8ArraysEqual(nm2Wit.value, nm2Wit_.value)).toEqual(true);
    expect(areUint8ArraysEqual(nm3Wit.value, nm3Wit_.value)).toEqual(true);
  });
});
