import type { PolicyEngine, SignerStore } from "../policy";
import type { FiberRpcClient, RpcListedChannelState, RpcSigningStatusResult } from "../rpc";
import { RpcError } from "../rpc";
import type { SignerDispatch, WatchtowerDispatchOutcome } from "../signer";
import type { PollRun, PollStep } from "./poller";
import { WATCHTOWER_UNWATCHED_CLOSE_FLAGS, WATCHTOWER_UNWATCHED_ERROR } from "./sdk.constants";
import type { SdkEvent } from "./sdk.types";
import { answerEachPolled, deliverStepEvent, encodeSdkRequestId, misansweredStatusRefusal, reportStepFailure } from "./utils";

export type WatchtowerSigningStepOptions = {
    rpc: FiberRpcClient;
    store: SignerStore;
    policy: PolicyEngine;
    dispatch: SignerDispatch;
    emit: (event: SdkEvent) => void;
};

type SignedWatchtowerOutcome = Extract<WatchtowerDispatchOutcome, { kind: "signed" }>;

const POLL = "watchtower signing";

/**
 * Tells whether fiber's watchtower no longer watches a channel, or never did.
 * @param channel The channel as the node lists it.
 * @returns Whether the step skips it.
 */
function isUnwatchedChannel(channel: RpcListedChannelState): boolean {
    const unwatched: readonly string[] = WATCHTOWER_UNWATCHED_CLOSE_FLAGS;
    return channel.stateName === "Closed" && channel.stateFlags.some((flag) => unwatched.includes(flag));
}

/**
 * Reads a channel's watchtower signing status, `null` while an open channel has no watch row yet.
 * @param rpc The node's client.
 * @param channel The channel as the node lists it.
 * @returns The status, or `null`.
 */
async function readWatchtowerStatus(rpc: FiberRpcClient, channel: RpcListedChannelState): Promise<RpcSigningStatusResult | null> {
    try {
        return await rpc.getWatchtowerSigningStatus({ channelId: channel.channelId });
    } catch (error) {
        const { code, message } = WATCHTOWER_UNWATCHED_ERROR;
        if (channel.stateName !== "Closed" && error instanceof RpcError && error.code === code && error.message === message) return null;
        throw error;
    }
}

/**
 * Builds the poll step that answers the watchtower's signing requests of every registered channel it may still watch.
 * @param options The node's client, the store, the policy gate, the dispatch and the emitter.
 * @returns The step; it rejects only when the node's channels cannot be listed.
 */
export function buildWatchtowerSigningStep(options: WatchtowerSigningStepOptions): PollStep {
    const { rpc, store, policy, dispatch, emit } = options;

    /**
     * Submits a signature, marks its spend applied, then announces it.
     * @param run The run.
     * @param channelId The channel.
     * @param outcome The signature.
     */
    const submit = async (run: PollRun, channelId: string, outcome: SignedWatchtowerOutcome): Promise<void> => {
        if (run.abandoned) return;
        const { requestId, purpose, signature } = outcome;
        // Both answers are success: `AlreadyApplied` is the node holding this very signature.
        await rpc.submitWatchtowerSignature({ channelId, requestId, signature });
        // Even once abandoned: fiber never serves an applied request again, so a mark skipped here would never come.
        if (outcome.claimed) await policy.markWatchtowerSpendApplied(channelId, requestId);
        deliverStepEvent(run, emit, {
            type: "WATCHTOWER_SIGNING",
            channelId,
            requestId: encodeSdkRequestId(requestId),
            purpose,
            outcome: "signed",
        });
    };

    /**
     * Answers one channel's watchtower signing status, if it is registered on this device.
     * @param run The run.
     * @param channel The channel, as the node lists it.
     */
    const answer = async (run: PollRun, channel: RpcListedChannelState): Promise<void> => {
        const { channelId } = channel;
        if ((await store.resolveChannelIndex(channelId)) === null) return;
        const result = await readWatchtowerStatus(rpc, channel);
        if (result === null) return;
        if (result.channelId !== channelId) {
            deliverStepEvent(run, emit, {
                type: "WATCHTOWER_SIGNING",
                channelId,
                requestId: null,
                purpose: null,
                outcome: "refused",
                error: misansweredStatusRefusal(POLL, channelId, result.channelId),
            });
            return;
        }
        if (run.abandoned) return;
        const outcome = await dispatch.handleWatchtower(channelId, result.status);
        if (outcome.kind === "signed") {
            await submit(run, channelId, outcome);
        } else if (outcome.kind === "refused") {
            deliverStepEvent(run, emit, {
                type: "WATCHTOWER_SIGNING",
                channelId,
                requestId: outcome.requestId === null ? null : encodeSdkRequestId(outcome.requestId),
                purpose: outcome.purpose,
                outcome: "refused",
                error: { code: outcome.error.code, message: outcome.error.message },
            });
        } else if (outcome.kind === "fault") {
            reportStepFailure(run, emit, POLL, channelId, outcome.cause);
        }
    };

    return async (run) => {
        // A force-closed channel is the one the watchtower spends from, and the default listing leaves it out.
        const channels = await rpc.listChannelStates({ filter: "include_closed" });
        const watched = channels.filter((channel) => !isUnwatchedChannel(channel));
        await answerEachPolled(
            run,
            emit,
            POLL,
            watched,
            (channel) => channel.channelId,
            (channel) => answer(run, channel),
        );
    };
}
