import type { SignerStore } from "../policy";
import type { FiberRpcClient, RpcChannelStateName } from "../rpc";
import type { SdkChannelInfo, SdkChannelState } from "./sdk.types";

// Keyed by every fiber state, so one added to `RPC_CHANNEL_STATE_NAMES` alone fails to compile.
const SDK_CHANNEL_STATE_OF = {
    NegotiatingFunding: "opening",
    CollaboratingFundingTx: "opening",
    SigningCommitment: "opening",
    AwaitingTxSignatures: "opening",
    AwaitingChannelReady: "opening",
    ChannelReady: "ready",
    ShuttingDown: "closing",
    Closed: "closed",
    Stale: "stale",
} as const satisfies Record<RpcChannelStateName, SdkChannelState>;

/**
 * Lists the node's channels, closed ones included, as a wallet shows them.
 * @param rpc The node's client.
 * @param store The store that tells the channels this device registered.
 * @returns The channels, in the node's order.
 */
export async function listSdkChannels(rpc: FiberRpcClient, store: SignerStore): Promise<SdkChannelInfo[]> {
    const channels = await rpc.listChannels({ filter: "include_closed" });
    return Promise.all(
        channels.map(async (channel) => ({
            channelId: channel.channelId,
            state: SDK_CHANNEL_STATE_OF[channel.state.name],
            localBalanceShannons: channel.localBalanceShannons,
            remoteBalanceShannons: channel.remoteBalanceShannons,
            offeredTlcBalanceShannons: channel.offeredTlcBalanceShannons,
            receivedTlcBalanceShannons: channel.receivedTlcBalanceShannons,
            hasRecord: (await store.resolveChannelIndex(channel.channelId)) !== null,
        })),
    );
}
