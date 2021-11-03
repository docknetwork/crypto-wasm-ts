import {
    publicInfoForWitnessUpdate,
    updateMembershipWitnessesPostBatchUpdates,
    updateMembershipWitnessPostAdd,
    updateMembershipWitnessPostRemove,
    updateMembershipWitnessUsingPublicInfoAfterBatchUpdate,
    updateMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates,
    updateNonMembershipWitnessesPostBatchUpdates,
    updateNonMembershipWitnessPostAdd,
    updateNonMembershipWitnessPostRemove,
    updateNonMembershipWitnessUsingPublicInfoAfterBatchUpdate,
    updateNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates,
} from "../../../crypto-wasm/src/js";
import {getUint8ArraysFromObject, jsonObjToUint8Array} from "../util";

export abstract class AccumulatorWitness {
    value: Uint8Array | object;

    constructor(value: Uint8Array | object) {
        this.value = value;
    }

    abstract updatePostAdd(addition: Uint8Array, element: Uint8Array, accumulatorValueBeforeAddition: Uint8Array): void;
    abstract updatePostRemove(removal: Uint8Array, element: Uint8Array, accumulatorValueAfterRemoval: Uint8Array): void;
    abstract updateUsingPublicInfoPostBatchUpdate(element: Uint8Array, additions: Uint8Array[], removals: Uint8Array[], publicInfo: WitnessUpdatePublicInfo): void;
    abstract updateUsingPublicInfoPostMultipleBatchUpdates(element: Uint8Array, additions: Uint8Array[][], removals: Uint8Array[][], publicInfo: WitnessUpdatePublicInfo[]): void;
}

export class MembershipWitness extends AccumulatorWitness {
    // @ts-ignore
    value: Uint8Array;

    /**
     * Update a membership witness after an element is added to the accumulator
     * @param addition - new addition to the accumulator
     * @param member - whose witness is being updated
     * @param accumulatorValueBeforeAddition - accumulator value before the addition was done.
     */
    async updatePostAdd(addition: Uint8Array, member: Uint8Array, accumulatorValueBeforeAddition: Uint8Array) {
        this.value = updateMembershipWitnessPostAdd(this.value, member, addition, accumulatorValueBeforeAddition);
    }

    /**
     * Update a membership witness after an element is removed from the accumulator.
     * @param removal - removal from the accumulator
     * @param member - whose witness is being updated
     * @param accumulatorValueAfterRemoval - accumulator value after the removal was done.
     */
    async updatePostRemove(removal: Uint8Array, member: Uint8Array, accumulatorValueAfterRemoval: Uint8Array) {
        this.value = updateMembershipWitnessPostRemove(this.value, member, removal, accumulatorValueAfterRemoval);
    }

    /**
     * Compute an update to the membership witness after adding and removing batches of elements from the accumulator.
     * @param member - the member whose witness is to be updated
     * @param additions - array of additions
     * @param removals - array of removals
     * @param publicInfo - witness update info published by the accumulator manager
     */
    async updateUsingPublicInfoPostBatchUpdate(member: Uint8Array, additions: Uint8Array[], removals: Uint8Array[], publicInfo: WitnessUpdatePublicInfo) {
        this.value = updateMembershipWitnessUsingPublicInfoAfterBatchUpdate(this.value, member, additions, removals, publicInfo.value);
    }

    /**
     * Compute an update to the membership witness after adding and removing several batches of elements from the accumulator.
     * For each batch of updates, additions, removals and witness update info are provided.
     * @param member - the member whose witness is to be updated
     * @param additions - array of arrays of additions
     * @param removals - array of arrays of removals
     * @param publicInfo - array of witness update info
     */
    async updateUsingPublicInfoPostMultipleBatchUpdates(member: Uint8Array, additions: Uint8Array[][], removals: Uint8Array[][], publicInfo: WitnessUpdatePublicInfo[]) {
        const info = publicInfo.map(i => i.value);
        this.value = updateMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(this.value, member, additions, removals, info);
    }

    /**
     * Compute an update to several membership witnesses after adding and removing batches of elements from the accumulator.
     * @param witnesses - membership witnesses to update
     * @param members - members corresponding to the witnesses
     * @param additions
     * @param removals
     * @param accumulatorValueBeforeUpdates - accumulator value before the updates
     * @param secretKey
     */
    static async updateMultiplePostBatchUpdates(witnesses: MembershipWitness[], members: Uint8Array[], additions: Uint8Array[], removals: Uint8Array[], accumulatorValueBeforeUpdates: Uint8Array, secretKey: Uint8Array): Promise<MembershipWitness[]> {
        const wits = witnesses.map(m => m.value);
        return updateMembershipWitnessesPostBatchUpdates(wits, members, additions, removals, accumulatorValueBeforeUpdates, secretKey).map(m => new MembershipWitness(m));
    }

    toJSON(): string {
        return JSON.stringify({
            value: Array.from(this.value)
        })
    }

    static fromJSON(json: string): MembershipWitness {
        const obj = JSON.parse(json);
        const [value] = getUint8ArraysFromObject(obj, ['value']);
        return new MembershipWitness(value)
    }
}

export class NonMembershipWitness extends AccumulatorWitness {
    // @ts-ignore
    value: { d: Uint8Array, C: Uint8Array };

    /**
     * Update a non-membership witness after an element is added to the accumulator
     * @param addition - new addition to the accumulator
     * @param nonMember - whose witness is being updated
     * @param accumulatorValueBeforeAddition - accumulator value before the addition was done.
     */
    async updatePostAdd(addition: Uint8Array, nonMember: Uint8Array, accumulatorValueBeforeAddition: Uint8Array) {
        this.value = updateNonMembershipWitnessPostAdd(this.value, nonMember, addition, accumulatorValueBeforeAddition);
    }

    /**
     * Update a non-membership witness after an element is removed from the accumulator.
     * @param removal - removal from the accumulator
     * @param nonMember - whose witness is being updated
     * @param accumulatorValueAfterRemoval - accumulator value after the removal was done.
     */
    async updatePostRemove(removal: Uint8Array, nonMember: Uint8Array, accumulatorValueAfterRemoval: Uint8Array) {
        this.value = updateNonMembershipWitnessPostRemove(this.value, nonMember, removal, accumulatorValueAfterRemoval);
    }

    /**
     * Compute an update to the non-membership witness after adding and removing batches of elements from the accumulator.
     * @param nonMember - the non-member whose witness is to be updated
     * @param additions - array of additions
     * @param removals - array of removals
     * @param publicInfo - witness update info published by the accumulator manager
     */
    async updateUsingPublicInfoPostBatchUpdate(nonMember: Uint8Array, additions: Uint8Array[], removals: Uint8Array[], publicInfo: WitnessUpdatePublicInfo) {
        this.value = updateNonMembershipWitnessUsingPublicInfoAfterBatchUpdate(this.value, nonMember, additions, removals, publicInfo.value);
    }

    /**
     * Compute an update to the non-membership witness after adding and removing several batches of elements from the accumulator.
     * For each batch of updates, additions, removals and witness update info are provided.
     * @param nonMember - the non-member whose witness is to be updated
     * @param additions - array of arrays of additions
     * @param removals - array of arrays of removals
     * @param publicInfo - array of witness update info
     */
    async updateUsingPublicInfoPostMultipleBatchUpdates(nonMember: Uint8Array, additions: Uint8Array[][], removals: Uint8Array[][], publicInfo: WitnessUpdatePublicInfo[]) {
        const info = publicInfo.map(i => i.value);
        this.value = updateNonMembershipWitnessUsingPublicInfoAfterMultipleBatchUpdates(this.value, nonMember, additions, removals, info);
    }

    /**
     * Compute an update to several non-membership witnesses after adding and removing batches of elements from the accumulator.
     * @param witnesses - non-membership witnesses to update
     * @param nonMembers - nonMembers corresponding to the witnesses
     * @param additions
     * @param removals
     * @param accumulatorValueBeforeUpdates - accumulator value before the updates
     * @param secretKey
     */
    static async updateMultiplePostBatchUpdates(witnesses: NonMembershipWitness[], nonMembers: Uint8Array[], additions: Uint8Array[], removals: Uint8Array[], accumulatorValueBeforeUpdates: Uint8Array, secretKey: Uint8Array): Promise<NonMembershipWitness[]> {
        const wits = witnesses.map(w => w.value);
        return updateNonMembershipWitnessesPostBatchUpdates(wits, nonMembers, additions, removals, accumulatorValueBeforeUpdates, secretKey).map(m => new NonMembershipWitness(m));
    }

    toJSON(): string {
        return JSON.stringify({
            value: {d: Array.from(this.value.d), C: Array.from(this.value.C)}
        })
    }

    static fromJSON(json: string): NonMembershipWitness {
        const obj = JSON.parse(json);
        const [d, C] = getUint8ArraysFromObject(obj.value, ['d', 'C']);
        return new NonMembershipWitness({d, C})
    }
}

/**
 * Public info published by the accumulator manager used to update witnesses after several additions and removals.
 */
export class WitnessUpdatePublicInfo {
    value: Uint8Array;

    constructor(info: Uint8Array) {
        this.value = info;
    }

    toJSON(): string {
        return JSON.stringify({
            value: this.value
        })
    }

    fromJSON(json: string): WitnessUpdatePublicInfo {
        return new WitnessUpdatePublicInfo(jsonObjToUint8Array(json));
    }

    /**
     * Accumulator manager creates the witness update info corresponding to the additions and removals.
     * @param accumulatorValueBeforeUpdates - accumulator value before the additions and removals
     * @param additions
     * @param removals
     * @param sk
     */
    static async new(accumulatorValueBeforeUpdates: Uint8Array, additions: Uint8Array[], removals: Uint8Array[], sk: Uint8Array): Promise<WitnessUpdatePublicInfo> {
        const value = publicInfoForWitnessUpdate(accumulatorValueBeforeUpdates, additions, removals, sk);
        return new WitnessUpdatePublicInfo(value);
    }
}
