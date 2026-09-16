import { ProtocolError } from "../../src/protocol";
import { WireError } from "../../src/wire";

/**
 * Runs a decode step that must refuse, and returns the refusal.
 * @param step Step to run.
 * @returns The wire refusal it threw; anything else it throws propagates.
 */
export function refusal(step: () => unknown): WireError {
    try {
        step();
    } catch (error) {
        if (error instanceof WireError) return error;
        throw error;
    }
    throw new Error("the step did not refuse");
}

/**
 * Runs a decode step that must refuse with a request id to answer with, and returns the refusal.
 * @param step Step to run.
 * @returns The answerable refusal it threw.
 */
export function answerableRefusal(step: () => unknown): ProtocolError {
    const error = refusal(step);
    if (!(error instanceof ProtocolError)) throw new Error("the refusal carries no request id to answer with");
    return error;
}
