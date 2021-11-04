import {AccumulatorParams, IKeypair, initializeWasm} from "@docknetwork/crypto-wasm";
import {
    IInitialElementsStore,
    Accumulator,
    PositiveAccumulator,
    UniversalAccumulator,
    MembershipWitness, WitnessUpdatePublicInfo
} from '../src';
import {
    InMemoryInitialElementsStore,
    InMemoryState,
    InMemoryUniversalState
} from "../src/accumulator/in-memory-persistence";
import {stringToBytes} from "./utils";

async function runCommonTests(keypair: IKeypair, params: AccumulatorParams, accumulator: PositiveAccumulator | UniversalAccumulator, state: InMemoryState, store?: IInitialElementsStore) {
    const sk = keypair.secret_key;
    const pk = keypair.public_key;

    const e1 = Accumulator.encodePositiveNumberAsAccumulatorMember(101);
    const e2 = Accumulator.encodePositiveNumberAsAccumulatorMember(102);

    expect(state.state.size).toEqual(0);
    expect(state.state.has(e1)).toEqual(false);

    await accumulator.add(e1, sk, state, store);

    expect(state.state.size).toEqual(1);
    expect(state.state.has(e1)).toEqual(true);

    await expect(accumulator.add(e1, sk, state, store)).rejects.toThrow();

    await expect(accumulator.remove(e2, sk, state)).rejects.toThrow();

    await accumulator.add(e2, sk, state, store);

    expect(state.state.size).toEqual(2);
    expect(state.state.has(e2)).toEqual(true);

    await accumulator.remove(e2, sk, state, store);

    expect(state.state.size).toEqual(1);
    expect(state.state.has(e2)).toEqual(false);

    const e3 = Accumulator.encodePositiveNumberAsAccumulatorMember(103);
    const e4 = Accumulator.encodePositiveNumberAsAccumulatorMember(104);

    await accumulator.addBatch([e3, e4], sk, state, store);

    expect(state.state.size).toEqual(3);
    expect(state.state.has(e3)).toEqual(true);
    expect(state.state.has(e4)).toEqual(true);

    await expect(accumulator.addBatch([e3, e4], sk, state, store)).rejects.toThrow();

    expect(state.state.size).toEqual(3);

    await accumulator.removeBatch([e3, e4], sk, state, store);
    expect(state.state.size).toEqual(1);
    expect(state.state.has(e3)).toEqual(false);
    expect(state.state.has(e4)).toEqual(false);

    await expect(accumulator.removeBatch([e3, e4], sk, state, store)).rejects.toThrow();
    expect(state.state.size).toEqual(1);

    const e5 = Accumulator.encodePositiveNumberAsAccumulatorMember(105);
    const e6 = Accumulator.encodePositiveNumberAsAccumulatorMember(106);

    await accumulator.addRemoveBatches([e5, e6], [e1], sk, state, store);
    expect(state.state.size).toEqual(2);
    expect(state.state.has(e5)).toEqual(true);
    expect(state.state.has(e6)).toEqual(true);
    expect(state.state.has(e1)).toEqual(false);

    const accumulated = accumulator.accumulated;
    let tempAccumulator;
    if (accumulator instanceof PositiveAccumulator) {
        tempAccumulator = PositiveAccumulator.fromAccumulated(accumulated);
    } else {
        tempAccumulator = UniversalAccumulator.fromAccumulated(accumulated);
    }

    expect(tempAccumulator.verifyMembershipWitness(e5, await accumulator.membershipWitness(e5, sk, state), pk, params)).toEqual(true);
    expect(tempAccumulator.verifyMembershipWitness(e6, await accumulator.membershipWitness(e6, sk, state), pk, params)).toEqual(true);

    const wits = await accumulator.membershipWitnessesForBatch([e5, e6], sk, state);
    expect(tempAccumulator.verifyMembershipWitness(e5, wits[0], pk, params)).toEqual(true);
    expect(tempAccumulator.verifyMembershipWitness(e6, wits[1], pk, params)).toEqual(true);

    const e7 = Accumulator.encodePositiveNumberAsAccumulatorMember(107);
    const e8 = Accumulator.encodePositiveNumberAsAccumulatorMember(108);

    await accumulator.addBatch([e7, e8], sk, state, store);

    const accumulatedNew = accumulator.accumulated;

    // Witness update by accumulator manager using secret key
    const newWits = MembershipWitness.updateMultiplePostBatchUpdates(wits, [e5, e6], [e7, e8], [], accumulated, sk);

    if (accumulator instanceof PositiveAccumulator) {
        tempAccumulator = PositiveAccumulator.fromAccumulated(accumulatedNew);
    } else {
        tempAccumulator = UniversalAccumulator.fromAccumulated(accumulatedNew);
    }
    expect(tempAccumulator.verifyMembershipWitness(e5, newWits[0], pk, params)).toEqual(true);
    expect(tempAccumulator.verifyMembershipWitness(e6, newWits[1], pk, params)).toEqual(true);

    // Witness update info created by accumulator manager
    const witnessUpdInfo = WitnessUpdatePublicInfo.new(accumulated, [e7, e8], [], sk);

    // Witness can be updated without secret key using public info
    wits[0].updateUsingPublicInfoPostBatchUpdate(e5, [e7, e8], [], witnessUpdInfo);
    wits[1].updateUsingPublicInfoPostBatchUpdate(e6, [e7, e8], [], witnessUpdInfo);

    expect(tempAccumulator.verifyMembershipWitness(e5, wits[0], pk, params)).toEqual(true);
    expect(tempAccumulator.verifyMembershipWitness(e6, wits[1], pk, params)).toEqual(true);
}

describe("Accumulators type", () => {
    beforeAll(async () => {
        await initializeWasm();
    });

    it("Positive accumulator should run", async () => {
        const label = stringToBytes("Accumulator params");
        const params = PositiveAccumulator.generateParams(label);
        const keypair = PositiveAccumulator.generateKeypair(params);
        const accumulator = PositiveAccumulator.initialize(params);
        const state = new InMemoryState();
        await runCommonTests(keypair, params, accumulator, state);
    });

    it("Universal accumulator", async () => {
        const params1 = UniversalAccumulator.generateParams();
        const keypair1 = UniversalAccumulator.generateKeypair(params1);
        const store = new InMemoryInitialElementsStore();
        const accumulator1 = await UniversalAccumulator.initialize(20, params1, keypair1.secret_key, store);
        const state1 = new InMemoryUniversalState();
        await runCommonTests(keypair1, params1, accumulator1, state1, store);
    });
});
