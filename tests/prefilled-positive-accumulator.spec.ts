import {
  Accumulator,
  AccumulatorKeypair,
  AccumulatorParams,
  initializeWasm,
  PositiveAccumulator,
  VBMembershipWitness,
  VBWitnessUpdatePublicInfo
} from '../src';
import { InMemoryState } from '../src/accumulator/in-memory-persistence';
import { stringToBytes } from './utils';

describe('Prefilled positive accumulator', () => {
  // Incase updating an accumulator is expensive like making a blockchain txn, a cheaper strategy
  // is to add the members to the accumulator beforehand but not giving out the witnesses yet.
  // Eg. accumulator manager wants to add a million members over an year, rather than publishing
  // the new accumulator after each addition, the manager can initialize the accumulator with a million
  // member ids (member ids are either predictable like monotonically increasing numbers or the manager
  // can internally keep a map of random ids like UUIDs to a number). Now when the manager actually
  // wants to allow a member to prove membership, he can create a witness for that member but the
  // accumulator value remains same and thus the witness for existing members also remain same. It
  // should be noted though that changing the accumulator
  // value causes change in all existing witnesses and thus its better to make a good estimate
  // of the number of members during prefill stage

  // Manager estimates that he will have `total_members` members over the course of time
  const totalMembers = 100;

  const members: Uint8Array[] = [];
  let params: AccumulatorParams, keypair: AccumulatorKeypair, accumulator: PositiveAccumulator, state: InMemoryState;

  beforeAll(async () => {
    await initializeWasm();

    const label = stringToBytes('Accumulator params');
    params = PositiveAccumulator.generateParams(label);
    keypair = PositiveAccumulator.generateKeypair(params);
    accumulator = PositiveAccumulator.initialize(params);
    state = new InMemoryState();
  });

  it('prefill', async () => {
    for (let i = 1; i <= totalMembers; i++) {
      members.push(Accumulator.encodePositiveNumberAsAccumulatorMember(i));
    }
    // Adding a single batch as `totalMembers` is fairly small (100s) in this test but in practice choose a reasonable
    // batch size to not take up complete system's memory
    await accumulator.addBatch(members, keypair.secretKey, state);
    expect(state.state.size).toEqual(totalMembers);
  });

  it('Witness creation, verification should work', async () => {
    let verifAccumulator = PositiveAccumulator.fromAccumulated(accumulator.accumulated);

    const member1 = members[10];
    const witness1 = await accumulator.membershipWitness(member1, keypair.secretKey, state);
    expect(verifAccumulator.verifyMembershipWitness(member1, witness1, keypair.publicKey, params)).toEqual(true);

    const member2 = members[25];
    const witness2 = await accumulator.membershipWitness(member2, keypair.secretKey, state);
    expect(verifAccumulator.verifyMembershipWitness(member2, witness2, keypair.publicKey, params)).toEqual(true);

    const member3 = members[60];
    const witness3 = await accumulator.membershipWitness(member3, keypair.secretKey, state);
    expect(verifAccumulator.verifyMembershipWitness(member3, witness3, keypair.publicKey, params)).toEqual(true);

    // Previous users' witness still works
    expect(verifAccumulator.verifyMembershipWitness(member1, witness1, keypair.publicKey, params)).toEqual(true);
    expect(verifAccumulator.verifyMembershipWitness(member2, witness2, keypair.publicKey, params)).toEqual(true);

    // Manager decides to remove a member, the new accumulated value will be published along with witness update info
    const witnessUpdInfo = VBWitnessUpdatePublicInfo.new(accumulator.accumulated, [], [member2], keypair.secretKey);
    await accumulator.remove(member2, keypair.secretKey, state);

    verifAccumulator = PositiveAccumulator.fromAccumulated(accumulator.accumulated);

    const member4 = members[4];
    const witness4 = await accumulator.membershipWitness(member4, keypair.secretKey, state);
    expect(verifAccumulator.verifyMembershipWitness(member4, witness4, keypair.publicKey, params)).toEqual(true);

    // Older witnesses need to be updated

    // Update using knowledge of new accumulator and removed member only
    const witness1OldJson = witness1.toJSON();
    witness1.updatePostRemove(member2, member1, accumulator.accumulated);
    expect(verifAccumulator.verifyMembershipWitness(member1, witness1, keypair.publicKey, params)).toEqual(true);

    const witness3OldJson = witness3.toJSON();
    witness3.updatePostRemove(member2, member3, accumulator.accumulated);
    expect(verifAccumulator.verifyMembershipWitness(member3, witness3, keypair.publicKey, params)).toEqual(true);

    // Update using knowledge of witness info
    const witness1Old = VBMembershipWitness.fromJSON(witness1OldJson);
    witness1Old.updateUsingPublicInfoPostBatchUpdate(member1, [], [member2], witnessUpdInfo);
    expect(verifAccumulator.verifyMembershipWitness(member1, witness1Old, keypair.publicKey, params)).toEqual(true);

    const witness3Old = VBMembershipWitness.fromJSON(witness3OldJson);
    witness3Old.updateUsingPublicInfoPostBatchUpdate(member3, [], [member2], witnessUpdInfo);
    expect(verifAccumulator.verifyMembershipWitness(member3, witness3Old, keypair.publicKey, params)).toEqual(true);
  });
});
