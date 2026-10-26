import type { SdkEvent } from "../../src/sdk";
import type { SignerDispatch } from "../../src/signer";
import type { InMemorySignerStorage } from "../mocks/policy";

export type StepRun = { abandoned: boolean };

export function live(): StepRun {
    return { abandoned: false };
}

// The run is abandoned once the dispatch's next answer is in, as a stop arriving while the device signs.
export function abandonAfterHandle(dispatch: SignerDispatch, run: StepRun): void {
    jest.spyOn(dispatch, "handle").mockImplementationOnce(abandoningAfter(dispatch.handle.bind(dispatch), run));
}

export function abandonAfterHandleWatchtower(dispatch: SignerDispatch, run: StepRun): void {
    jest.spyOn(dispatch, "handleWatchtower").mockImplementationOnce(abandoningAfter(dispatch.handleWatchtower.bind(dispatch), run));
}

export function pollFailedEvent(message: string, cause: unknown): unknown {
    return { type: "ERROR", code: "poll_failed", message, cause };
}

// Each error event as its fields, so a cause compares by matcher.
export function summarized(events: SdkEvent[]): unknown[] {
    return events.map((event) =>
        event.type === "ERROR" ? { type: "ERROR", code: event.error.code, message: event.error.message, cause: event.error.cause } : event,
    );
}

export function writesOf(owner: { storage: InMemorySignerStorage }): string[] {
    return owner.storage.ops.filter((op) => op.startsWith("set "));
}

function abandoningAfter<Args extends unknown[], Result>(
    handle: (...args: Args) => Promise<Result>,
    run: StepRun,
): (...args: Args) => Promise<Result> {
    return async (...args) => {
        const outcome = await handle(...args);
        run.abandoned = true;
        return outcome;
    };
}
