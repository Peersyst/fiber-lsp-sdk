import { hexToBytes } from "@noble/hashes/utils.js";
import type { Invoice } from "../../../../src/invoice";
import { computeSdkInvoiceExpiryMs } from "../../../../src/sdk";

// The checks after the decoder read no signature, so none is made here.
const INVOICE: Invoice = {
    currency: "Fibt",
    amountShannons: "250000000",
    timestampMs: 1_791_367_200_000n,
    paymentHash: hexToBytes("5a".repeat(32)),
    attributes: [
        { type: "description", text: "coffee" },
        { type: "expiryTime", seconds: 3600n },
    ],
    signature: new Uint8Array(65),
};

describe("computeSdkInvoiceExpiryMs", () => {
    it("counts the expiry from the timestamp, in milliseconds", () => {
        expect(computeSdkInvoiceExpiryMs(INVOICE)).toBe(1_791_370_800_000n);
    });

    it("ends an invoice of an expiry of zero at its timestamp", () => {
        const invoice: Invoice = { ...INVOICE, attributes: [{ type: "expiryTime", seconds: 0n }] };
        expect(computeSdkInvoiceExpiryMs(invoice)).toBe(1_791_367_200_000n);
    });

    it("is null without an expiry, which fiber reads as never", () => {
        const invoice: Invoice = { ...INVOICE, attributes: [{ type: "description", text: "coffee" }] };
        expect(computeSdkInvoiceExpiryMs(invoice)).toBeNull();
    });

    it("reads the first expiry, as fiber does", () => {
        const invoice: Invoice = {
            ...INVOICE,
            attributes: [
                { type: "expiryTime", seconds: 60n },
                { type: "expiryTime", seconds: 3600n },
            ],
        };
        expect(computeSdkInvoiceExpiryMs(invoice)).toBe(1_791_367_260_000n);
    });
});
