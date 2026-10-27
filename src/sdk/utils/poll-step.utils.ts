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
 * Reports one polled item's failure as a `poll_failed` error naming it, unless the run was abandoned.
 * @param run The run.
 * @param emit The host's emitter.
 * @param poll What the step polls, as its messages name it.
 * @param id The failed item's id.
 * @param cause What failed.
 */
export function reportStepFailure(run: PollRun, emit: (event: SdkEvent) => void, poll: string, id: string, cause: unknown): void {
    if (run.abandoned) return;
    emitPollFailure(emit, `the ${poll} poll of ${id} failed`, cause);
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
 * Answers each polled item in turn while the run lives, reporting each one's failure.
 * @param run The run.
 * @param emit The host's emitter.
 * @param poll What the step polls, as its messages name it.
 * @param items The polled items.
 * @param idOf Names one in its failure.
 * @param answer Answers one.
 */
export async function answerEachPolled<Item>(
    run: PollRun,
    emit: (event: SdkEvent) => void,
    poll: string,
    items: readonly Item[],
    idOf: (item: Item) => string,
    answer: (item: Item) => Promise<void>,
): Promise<void> {
    for (const item of items) {
        if (run.abandoned) return;
        try {
            await answer(item);
        } catch (cause) {
            reportStepFailure(run, emit, poll, idOf(item), cause);
        }
    }
}
