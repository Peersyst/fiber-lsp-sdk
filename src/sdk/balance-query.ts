import type { SignerStore } from "../policy";
import type { FiberRpcClient } from "../rpc";
import { listSdkChannels } from "./channel-listing";

/**
 * Sums what this device can spend: each ready channel it registered, its offered TLCs taken out, none below zero.
 * @param rpc The node's client.
 * @param store The store of the channels this device registered.
 * @returns The balance, in decimal shannons.
 */
export async function getSdkBalance(rpc: FiberRpcClient, store: SignerStore): Promise<string> {
    const channels = await listSdkChannels(rpc, store);
    return channels
        .filter(({ state, hasRecord }) => state === "ready" && hasRecord)
        .reduce((balance, { localBalanceShannons, offeredTlcBalanceShannons }) => {
            // Fiber keeps an offered TLC inside the local balance until it is fulfilled.
            const spendable = BigInt(localBalanceShannons) - BigInt(offeredTlcBalanceShannons);
            return spendable > 0n ? balance + spendable : balance;
        }, 0n)
        .toString();
}
