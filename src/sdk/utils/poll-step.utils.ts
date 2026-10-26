import type { SignerRefusal } from "../../signer";
import type { PollRun } from "../poller";
import type { SdkEvent } from "../sdk.types";
import { emitPollFailure, emitSdkEvent } from "./failure.utils";

/**
 * Emits a step's event unless its run was abandoned.
 * @param run The run.
 * @param emit The host's emitter.
 * @param event The event.
 */
export function deliverStepEvent(run: PollRun, emit: (event: SdkEvent) => void, event: SdkEvent): void {
    if (run.abandoned) return;
    emitSdkEvent(emit, event);
}

/**
 * Reports a channel's failure as a `poll_failed` error naming it, unless the run was abandoned.
 * @param run The run.
 * @param emit The host's emitter.
 * @param poll What the step polls, as its messages name it.
 * @param channelId The channel.
 * @param cause What failed.
 */
export function reportStepFailure(run: PollRun, emit: (event: SdkEvent) => void, poll: string, channelId: string, cause: unknown): void {
    if (run.abandoned) return;
    emitPollFailure(emit, `the ${poll} poll of ${channelId} failed`, cause);
}

/**
 * Writes the refusal of a status the node answered for another channel than the one asked, which is never signed under its name.
 * @param poll What the step polls, as its messages name it.
 * @param channelId The channel asked.
 * @param answeredId The channel the node answered for.
 * @returns The refusal, malformed.
 */
export function misansweredStatusRefusal(poll: string, channelId: string, answeredId: string): SignerRefusal {
    return { code: "malformed", message: `the node answered the ${poll} status of ${channelId} with that of ${answeredId}` };
}

/**
 * Answers each channel in turn while the run lives, reporting each one's failure.
 * @param run The run.
 * @param emit The host's emitter.
 * @param poll What the step polls, as its messages name it.
 * @param channels The channels, their ids or their listings.
 * @param answer Answers one channel.
 */
export async function answerEachChannel<Channel extends string | { channelId: string }>(
    run: PollRun,
    emit: (event: SdkEvent) => void,
    poll: string,
    channels: readonly Channel[],
    answer: (channel: Channel) => Promise<void>,
): Promise<void> {
    for (const channel of channels) {
        if (run.abandoned) return;
        try {
            await answer(channel);
        } catch (cause) {
            reportStepFailure(run, emit, poll, typeof channel === "string" ? channel : channel.channelId, cause);
        }
    }
}
