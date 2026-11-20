import { hexToBytes } from "@noble/hashes/utils.js";
import type { UnsignedInvoice } from "../../../src/invoice";
import { encodeInvoice } from "../../../src/invoice";
import { SdkError, readSdkPayableInvoice } from "../../../src/sdk";
import { signInvoice } from "../../utils/invoice-signing";

const PAYEE_SECRET_KEY = hexToBytes("11".repeat(32));
const PAYEE_PUBKEY = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
const PAYMENT_HASH = "5a".repeat(32);
// An hour past the invoice's timestamp.
const EXPIRES_AT_MS = 1_791_370_800_000;
// A minute past the timestamp.
const NOW_MS = 1_791_367_260_000;

// Another tenant's testnet invoice of 2.5 CKB, described, valid for an hour.
const INVOICE: UnsignedInvoice = {
    currency: "Fibt",
    amountShannons: "250000000",
    timestampMs: 1_791_367_200_000n,
    paymentHash: hexToBytes(PAYMENT_HASH),
    attributes: [
        { type: "expiryTime", seconds: 3600n },
        { type: "description", text: "coffee for two" },
        { type: "payeePublicKey", publicKey: hexToBytes(PAYEE_PUBKEY) },
    ],
};

function stringOf(invoice: UnsignedInvoice): string {
    return encodeInvoice(signInvoice(invoice, PAYEE_SECRET_KEY));
}

function refusalOf(call: () => unknown): unknown {
    try {
        call();
    } catch (error) {
        return error;
    }
    throw new Error("expected a refusal");
}

describe("readSdkPayableInvoice", () => {
    it("hands back the hash as the events carry it, the amount, the description and the expiry", () => {
        expect(readSdkPayableInvoice(stringOf(INVOICE), "testnet", NOW_MS)).toStrictEqual({
            paymentHashHex: `0x${PAYMENT_HASH}`,
            amountShannons: "250000000",
            description: "coffee for two",
            expiresAtMs: BigInt(EXPIRES_AT_MS),
        });
    });

    it("hands back null for an invoice that carries no description and never expires", () => {
        const bare: UnsignedInvoice = { ...INVOICE, attributes: [{ type: "payeePublicKey", publicKey: hexToBytes(PAYEE_PUBKEY) }] };
        expect(readSdkPayableInvoice(stringOf(bare), "testnet", NOW_MS)).toMatchObject({ description: null, expiresAtMs: null });
    });

    it("checks the network's own currency: a testnet invoice is refused on mainnet", () => {
        const refusal = refusalOf(() => readSdkPayableInvoice(stringOf(INVOICE), "mainnet", NOW_MS));
        expect(refusal).toBeInstanceOf(SdkError);
        expect(refusal).toMatchObject({
            code: "invoice_unpayable",
            message: "the invoice cannot be paid: currency is Fibt, not the network's Fibb",
        });
    });

    it("pays a mainnet invoice on mainnet", () => {
        expect(readSdkPayableInvoice(stringOf({ ...INVOICE, currency: "Fibb" }), "mainnet", NOW_MS)).toMatchObject({
            amountShannons: "250000000",
        });
    });

    it.each<[string, UnsignedInvoice]>([
        ["no amount", { ...INVOICE, amountShannons: null }],
        ["no payee", { ...INVOICE, attributes: INVOICE.attributes.filter(({ type }) => type !== "payeePublicKey") }],
    ])("refuses an invoice with %s as invoice_unpayable", (_, invoice) => {
        expect(refusalOf(() => readSdkPayableInvoice(stringOf(invoice), "testnet", NOW_MS))).toMatchObject({ code: "invoice_unpayable" });
    });

    it("refuses an invoice whose expiry is the clock's reading", () => {
        expect(refusalOf(() => readSdkPayableInvoice(stringOf(INVOICE), "testnet", EXPIRES_AT_MS))).toMatchObject({
            code: "invoice_unpayable",
            message: `the invoice cannot be paid: expiryTime ran out at ${EXPIRES_AT_MS}, the device's clock reading ${EXPIRES_AT_MS}`,
        });
    });

    it("reads the host's clock by default", () => {
        const now = jest.spyOn(Date, "now").mockReturnValue(EXPIRES_AT_MS);
        try {
            expect(refusalOf(() => readSdkPayableInvoice(stringOf(INVOICE), "testnet"))).toMatchObject({ code: "invoice_unpayable" });
            expect(now).toHaveBeenCalledTimes(1);
        } finally {
            now.mockRestore();
        }
    });

    it("refuses a string that is no invoice as invoice_unpayable", () => {
        expect(refusalOf(() => readSdkPayableInvoice("fibt1nothing", "testnet", NOW_MS))).toMatchObject({ code: "invoice_unpayable" });
    });

    it.each<[string, () => unknown, ErrorConstructor, string]>([
        ["a non-string invoice", () => readSdkPayableInvoice(1 as unknown as string, "testnet", NOW_MS), TypeError, "encodedInvoice"],
        ["an unknown network", () => readSdkPayableInvoice(stringOf(INVOICE), "devnet" as never, NOW_MS), TypeError, "network"],
        ["a negative clock", () => readSdkPayableInvoice(stringOf(INVOICE), "testnet", -1), RangeError, "nowMs"],
        ["a fractional clock", () => readSdkPayableInvoice(stringOf(INVOICE), "testnet", 1.5), RangeError, "nowMs"],
    ])("refuses %s before reading anything", (_, call, kind, name) => {
        const refusal = refusalOf(call);
        expect(refusal).toBeInstanceOf(kind);
        expect((refusal as Error).message).toContain(name);
    });
});
