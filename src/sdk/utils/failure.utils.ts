import { SdkError } from "../sdk.error";
import type { SdkEvent } from "../sdk.types";

/**
 * Writes a failure's message: what failed, then the cause's own words when it has any.
 * @param what What failed.
 * @param cause What was thrown.
 * @returns The message.
 */
export function describeSdkFailure(what: string, cause: unknown): string {
    if (cause instanceof Error) return `${what}: ${cause.message}`;
    return what;
}

/**
 * Hands an event to the host's emitter; an emitter that throws never breaks the poll.
 * @param emit The host's emitter.
 * @param event The event.
 */
export function emitSdkEvent(emit: (event: SdkEvent) => void, event: SdkEvent): void {
    try {
        emit(event);
    } catch {
        // The emitter's failure is the host's.
    }
}

/**
 * Reports a poll's failure to the host as a `poll_failed` error.
 * @param emit The host's emitter.
 * @param what What failed.
 * @param cause What was thrown.
 */
export function emitPollFailure(emit: (event: SdkEvent) => void, what: string, cause: unknown): void {
    emitSdkEvent(emit, { type: "ERROR", error: new SdkError("poll_failed", describeSdkFailure(what, cause), { cause }) });
}
