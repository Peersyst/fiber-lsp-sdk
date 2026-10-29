import type { PolicyEngine, SignerStore } from "../policy";
import type { FiberRpcClient, RpcSigningStatusResult } from "../rpc";
import type { SignerDispatch, WatchtowerDispatchOutcome } from "../signer";
import type { ActivityTracker } from "./activity";
import type { DeviceChannelList } from "./device-channels";
import type { PollRun, PollStep } from "./poller";
import { WATCHTOWER_UNWATCHED_ERROR } from "./sdk.constants";
import type { SdkEvent } from "./sdk.types";
import {
    answerEachPolled,
    deliverStepEvent,
    encodeSdkRequestId,
    isFiberRefusal,
    misansweredStatusRefusal,
    reportStepFailure,
} from "./utils";

export type WatchtowerSigningStepOptions = {
    rpc: FiberRpcClient;
    store: SignerStore;
    policy: PolicyEngine;
    dispatch: SignerDispatch;
    activity: ActivityTracker;
    channels: DeviceChannelList;
    emit: (event: SdkEvent) => void;
};

type SignedWatchtowerOutcome = Extract<WatchtowerDispatchOutcome, { kind: "signed" }>;

const POLL = "watchtower signing";

/**
 * Reads a channel's watchtower signing status, `null` while fiber holds no watch row for it.
 * @param rpc The node's client.
 * @param channelId The channel.
 * @returns The status, or `null`.
 */
async function readWatchtowerStatus(rpc: FiberRpcClient, channelId: string): Promise<RpcSigningStatusResult | null> {
    try {
        return await rpc.getWatchtowerSigningStatus({ channelId });
    } catch (error) {
        if (isFiberRefusal(error, WATCHTOWER_UNWATCHED_ERROR)) return null;
        throw error;
    }
}

/**
 * Builds the poll step that answers the watchtower's signing requests of every channel the device opened, dropping one it is done with.
 * @param options The node's client, the store, the policy gate, the dispatch, the activity list, the device's channels and the emitter.
 * @returns The step; it rejects only when the activity list or the device's channels cannot be read.
 */
export function buildWatchtowerSigningStep(options: WatchtowerSigningStepOptions): PollStep {
    const { rpc, store, policy, dispatch, activity, channels, emit } = options;

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
     * Answers one channel's watchtower signing status, if it is registered on this device, or drops a closed one fiber stopped watching.
     * @param run The run.
     * @param channelId The channel, as fiber names it.
     * @param open Whether the device has not seen it closed.
     */
    const answer = async (run: PollRun, channelId: string, open: boolean): Promise<void> => {
        if ((await store.resolveChannelIndex(channelId)) === null) return;
        const result = await readWatchtowerStatus(rpc, channelId);
        if (result === null) {
            // An open channel's row may come yet; a closed one's never comes back once deleted, nor comes at all after.
            if (!open && !run.abandoned) await channels.remove(channelId);
            return;
        }
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
        // Never `list_channels`: fiber wakes an evicted tenant for it, and not for a watchtower status (`rpc/watchtower.rs:379-400`).
        // The list before the activity: an opening is watched before it is listed, so one listed and unwatched was seen closed.
        const listed = await channels.read();
        const open = (await activity.read()).channels;
        await answerEachPolled(
            run,
            emit,
            POLL,
            listed,
            (channelId) => channelId,
            (channelId) => answer(run, channelId, Object.hasOwn(open, channelId)),
        );
    };
}
