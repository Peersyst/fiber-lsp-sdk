import type { ChannelPolicyRecord, ISignerStorage, SignSlot } from "../../src/policy";
import { SignerStore } from "../../src/policy";

// Test-only: emulates Fiber's pending nonce fix (three signatures under one nonce reveal the funding key); never in src.
export async function forgetSecondSession(storage: ISignerStorage, channelIndex: number, slot: SignSlot): Promise<void> {
    await new SignerStore(storage).updateChannelRecord(channelIndex, (current) => {
        if (current === null) throw new Error(`channel index ${channelIndex} holds no record`);
        if (current.nonceReuse[slot] === undefined) throw new Error(`slot ${slot} served no second session`);
        const nonceReuse: ChannelPolicyRecord["nonceReuse"] = { ...current.nonceReuse };
        delete nonceReuse[slot];
        return { ...current, nonceReuse };
    });
}
