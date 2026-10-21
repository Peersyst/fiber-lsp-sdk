import { InvoiceError } from "../../src/invoice";
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

export function invoiceRefusal(step: () => unknown): InvoiceError {
    try {
        step();
    } catch (error) {
        if (error instanceof InvoiceError) return error;
        throw error;
    }
    throw new Error("the step did not refuse");
}
