import type { SignerStore } from "../policy";
import type { FiberRpcClient } from "../rpc";
import type { DispatchOutcome, SignerDispatch } from "../signer";
import type { PollRun, PollStep } from "./poller";
import type { SdkEvent } from "./sdk.types";
import { answerEachChannel, deliverStepEvent, encodeSdkRequestId, misansweredStatusRefusal, reportStepFailure } from "./utils";

export type ChannelSigningStepOptions = {
    rpc: FiberRpcClient;
    store: SignerStore;
    dispatch: SignerDispatch;
    emit: (event: SdkEvent) => void;
};

type SignedDispatchOutcome = Extract<DispatchOutcome, { kind: "signed" }>;

const POLL = "signing";

/**
 * Builds the poll step that answers the signing requests of every registered channel the node lists.
 * @param options The node's client, the store, the dispatch and the emitter.
 * @returns The step; it rejects only when the node's channels cannot be listed.
 */
export function buildChannelSigningStep(options: ChannelSigningStepOptions): PollStep {
    const { rpc, store, dispatch, emit } = options;

    /**
     * Submits a signature, then announces it.
     * @param run The run.
     * @param channelId The channel.
     * @param outcome The signature.
     */
    const submit = async (run: PollRun, channelId: string, outcome: SignedDispatchOutcome): Promise<void> => {
        if (run.abandoned) return;
        const { requestId, partialSignature, nextMaterial, transition } = outcome;
        // Both answers are success: `Applied` again while the request is pending, `AlreadyApplied` once it completed.
        await rpc.submitChannelSignature({ channelId, requestId, partialSignature, nextMaterial });
        deliverStepEvent(run, emit, {
            type: "SIGNING",
            channelId,
            requestId: encodeSdkRequestId(requestId),
            transition,
            outcome: outcome.warnings.length === 0 ? "signed" : "warning",
        });
    };

    /**
     * Answers one channel's signing status, if it is registered on this device.
     * @param run The run.
     * @param channelId The channel, as the node lists it.
     */
    const answer = async (run: PollRun, channelId: string): Promise<void> => {
        if ((await store.resolveChannelIndex(channelId)) === null) return;
        const result = await rpc.getChannelSigningStatus({ channelId });
        if (result.channelId !== channelId) {
            deliverStepEvent(run, emit, {
                type: "SIGNING",
                channelId,
                requestId: null,
                transition: null,
                outcome: "refused",
                error: misansweredStatusRefusal(POLL, channelId, result.channelId),
            });
            return;
        }
        if (run.abandoned) return;
        const outcome = await dispatch.handle(channelId, result.status);
        if (outcome.kind === "signed") {
            await submit(run, channelId, outcome);
        } else if (outcome.kind === "refused") {
            deliverStepEvent(run, emit, {
                type: "SIGNING",
                channelId,
                requestId: outcome.requestId === null ? null : encodeSdkRequestId(outcome.requestId),
                transition: outcome.transition,
                outcome: "refused",
                error: { code: outcome.error.code, message: outcome.error.message },
            });
        } else if (outcome.kind === "fault") {
            reportStepFailure(run, emit, POLL, channelId, outcome.cause);
        }
    };

    return async (run) => {
        const channelIds = await rpc.listChannelIds();
        await answerEachChannel(run, emit, POLL, channelIds, (channelId) => answer(run, channelId));
    };
}
