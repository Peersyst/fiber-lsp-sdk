import { InvoiceError } from "../../src/invoice";
import { PolicyRefusalError } from "../../src/policy";
import { SdkError } from "../../src/sdk";
import type { WireError } from "../../src/wire";
import { asWireError } from "../../src/wire";

export function refusal(step: () => unknown): WireError {
    try {
        step();
    } catch (error) {
        return asWireError(error);
    }
    throw new Error("the step did not refuse");
}

export function refusalOf<Refusal extends Error>(errorClass: abstract new (...args: never[]) => Refusal, step: () => unknown): Refusal {
    try {
        step();
    } catch (error) {
        if (error instanceof errorClass) return error;
        throw error;
    }
    throw new Error("the step did not refuse");
}

export function invoiceRefusal(step: () => unknown): InvoiceError {
    return refusalOf(InvoiceError, step);
}

export function policyRefusal(step: () => unknown): PolicyRefusalError {
    return refusalOf(PolicyRefusalError, step);
}

export function sdkRefusal(step: () => unknown): SdkError {
    return refusalOf(SdkError, step);
}

// The device's refusal of each watchtower variant fiber refuses, its record holding both views' commitments.
export const WATCHTOWER_VARIANT_REFUSALS: Readonly<Record<string, string>> = {
    "foreign destination": "watchtower destination: output 1 must pay the approved destination, with no type and no data",
    "altered remainder": "watchtower remainder: output 0 is not the remainder fiber's watchtower leaves",
    "foreign TLC":
        "watchtower source: input 0, spent with a since, must be the cell of the last local or remote commitment signed, or of the " +
        "remote one before it, and the settlement body is none of theirs",
    "key of another number": "watchtower key: TLC 0 does not settle to the device's TLC key at commitment number 5",
    "moved balance":
        "watchtower source: input 0, spent with a zero since, is no cell descending from a signed commitment: the remote view's commitment " +
        "holds another balance 0 than the settlement body, which has not settled it, and the local view's commitment holds another " +
        "balance 0 than the settlement body, which has not settled it",
    // A descendant's body is the lock's to hold against its args: the remainder, which commits the next body, is the device's.
    "uncommitted witness": "watchtower remainder: output 0 is not the remainder fiber's watchtower leaves",
    "remainder paid out": "watchtower remainder: output 0 is not the remainder fiber's watchtower leaves",
};
