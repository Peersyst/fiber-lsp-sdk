import type { FiberRpcClient, RpcListedChannelState } from "../rpc";
import type { ActivityTracker } from "./activity";
import type { PendingOpeningStore } from "./pending-opening";
import type { PollRun, PollStep } from "./poller";
import type { ActivityEntry, SdkEvent } from "./sdk.types";
import { answerEachPolled, deliverStepEvent } from "./utils";

export type ChannelStepOptions = {
    rpc: FiberRpcClient;
    activity: ActivityTracker;
    openings: PendingOpeningStore;
    emit: (event: SdkEvent) => void;
};

type WatchedChannels = Record<string, ActivityEntry<"channel">>;

const POLL = "channel";

/**
 * Builds the poll step that announces when a watched channel turns ready or closed.
 * @param options The node's client, the activity list, the pending opening and the emitter.
 * @returns The step; it rejects only when the watched channels or the node's listing of them cannot be read.
 */
export function buildChannelStep(options: ChannelStepOptions): PollStep {
    const { rpc, activity, openings, emit } = options;

    /**
     * Announces a watched channel's state if it is ready or closed and was not announced so, then records it.
     * @param run The run.
     * @param channel The channel, as the node lists it.
     * @param entry What was last announced for it.
     */
    const settle = async (run: PollRun, channel: RpcListedChannelState, entry: ActivityEntry<"channel">): Promise<void> => {
        const { channelId, stateName } = channel;
        if (stateName === "ChannelReady" && entry.status !== "ChannelReady") {
            deliverStepEvent(run, emit, { type: "CHANNEL_READY", channelId });
            if (run.abandoned) return;
            await openings.clear(channelId);
            await activity.mark("channel", channelId, "ChannelReady");
        } else if (stateName === "Closed") {
            deliverStepEvent(run, emit, { type: "CHANNEL_CLOSED", channelId });
            if (run.abandoned) return;
            await openings.clear(channelId);
            await activity.forget("channel", channelId);
        }
    };

    /**
     * Settles each listed channel that is watched, in the node's order.
     * @param run The run.
     * @param channels The channels, as the node lists them.
     * @param watched The watched channels and what was last announced for each.
     */
    const settleListed = async (run: PollRun, channels: readonly RpcListedChannelState[], watched: WatchedChannels): Promise<void> => {
        const listed = channels.flatMap((channel) => {
            const entry = watched[channel.channelId];
            return entry === undefined ? [] : [{ ...channel, entry }];
        });
        await answerEachPolled(
            run,
            emit,
            POLL,
            listed,
            (channel) => channel.channelId,
            (channel) => settle(run, channel, channel.entry),
        );
    };

    return async (run) => {
        const watched = (await activity.read()).channels;
        if (Object.keys(watched).length === 0) return;
        const channels = await rpc.listChannelStates({ filter: "include_closed" });
        await settleListed(run, channels, watched);
        // Fiber drops an opening that was never funded from this listing, and lists it, closed, only among the pending ones.
        const absent = Object.fromEntries(
            Object.entries(watched).filter(([channelId]) => !channels.some((channel) => channel.channelId === channelId)),
        );
        if (Object.keys(absent).length === 0 || run.abandoned) return;
        await settleListed(run, await rpc.listChannelStates({ filter: "only_pending" }), absent);
    };
}
