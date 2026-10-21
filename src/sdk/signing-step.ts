import { HASH256_LENGTH } from "../common";
import type { SignerStore } from "../policy";
import type { FiberRpcClient } from "../rpc";
import type { DispatchOutcome, SignerDispatch } from "../signer";
import { encodeHexBytes } from "../wire";
import type { PollRun, PollStep } from "./poller";
import type { SdkEvent } from "./sdk.types";
import { emitPollFailure, emitSdkEvent } from "./utils";

export type ChannelSigningStepOptions = {
    rpc: FiberRpcClient;
    store: SignerStore;
    dispatch: SignerDispatch;
    emit: (event: SdkEvent) => void;
};

type SignedDispatchOutcome = Extract<DispatchOutcome, { kind: "signed" }>;

/**
 * Writes a request id as the `SIGNING` event carries it.
 * @param requestId The request id.
 * @returns The wire hex.
 */
function signingRequestIdHex(requestId: Uint8Array): string {
    return encodeHexBytes("requestId", requestId, HASH256_LENGTH);
}

/**
 * Builds the poll step that answers the signing requests of every registered channel the node lists.
 * @param options The node's client, the store, the dispatch and the emitter.
 * @returns The step; it rejects only when the node's channels cannot be listed.
 */
export function buildChannelSigningStep(options: ChannelSigningStepOptions): PollStep {
    const { rpc, store, dispatch, emit } = options;

    /**
     * Emits an event unless the run was abandoned.
     * @param run The run.
     * @param event The event.
     */
    const deliver = (run: PollRun, event: SdkEvent): void => {
        if (run.abandoned) return;
        emitSdkEvent(emit, event);
    };

    /**
     * Reports a channel's failure as a `poll_failed` error naming it.
     * @param run The run.
     * @param channelId The channel.
     * @param cause What failed.
     */
    const fail = (run: PollRun, channelId: string, cause: unknown): void => {
        if (run.abandoned) return;
        emitPollFailure(emit, `the signing poll of ${channelId} failed`, cause);
    };

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
        deliver(run, {
            type: "SIGNING",
            channelId,
            requestId: signingRequestIdHex(requestId),
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
        // Another channel's status is never signed under this one's name.
        if (result.channelId !== channelId) {
            deliver(run, {
                type: "SIGNING",
                channelId,
                requestId: null,
                transition: null,
                outcome: "refused",
                error: {
                    code: "malformed",
                    message: `the node answered the signing status of ${channelId} with that of ${result.channelId}`,
                },
            });
            return;
        }
        if (run.abandoned) return;
        const outcome = await dispatch.handle(channelId, result.status);
        if (outcome.kind === "signed") {
            await submit(run, channelId, outcome);
        } else if (outcome.kind === "refused") {
            deliver(run, {
                type: "SIGNING",
                channelId,
                requestId: outcome.requestId === null ? null : signingRequestIdHex(outcome.requestId),
                transition: outcome.transition,
                outcome: "refused",
                error: { code: outcome.error.code, message: outcome.error.message },
            });
        } else if (outcome.kind === "fault") {
            fail(run, channelId, outcome.cause);
        }
    };

    return async (run) => {
        const channelIds = await rpc.listChannelIds();
        for (const channelId of channelIds) {
            if (run.abandoned) return;
            try {
                await answer(run, channelId);
            } catch (cause) {
                fail(run, channelId, cause);
            }
        }
    };
}
