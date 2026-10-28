import { hexToBytes } from "@noble/hashes/utils.js";
import type { InvoiceAttribute, InvoiceAttributeType, UnsignedInvoice } from "../../../../src/invoice";
import { InvoiceError, encodeInvoice } from "../../../../src/invoice";
import { SdkError, checkPayableInvoice } from "../../../../src/sdk";
import { signInvoice } from "../../../utils/invoice-signing";
import { sdkRefusal } from "../../../utils/refusal";

// The payee, another tenant of the LSP: its secret and its public key.
const PAYEE_SECRET_KEY = hexToBytes("11".repeat(32));
const PAYEE_PUBKEY = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
// The public key of the secret 0x22 repeated: the LSP.
const LSP_PUBKEY = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";
const OTHER_SECRET_KEY = hexToBytes("33".repeat(32));
const PAYMENT_HASH = "5a".repeat(32);
const TIMESTAMP_MS = 1_791_367_200_000;
// An hour past the invoice's timestamp.
const EXPIRES_AT_MS = 1_791_370_800_000;
// A minute past the timestamp.
const NOW_MS = 1_791_367_260_000;

// Another tenant's invoice of 2.5 CKB, as fiber writes a tenant's.
const INVOICE: UnsignedInvoice = {
    currency: "Fibt",
    amountShannons: "250000000",
    timestampMs: 1_791_367_200_000n,
    paymentHash: hexToBytes(PAYMENT_HASH),
    attributes: [
        { type: "expiryTime", seconds: 3600n },
        { type: "feature", bits: Uint8Array.of(0x20) },
        { type: "trampolineRouteHint", nodeId: hexToBytes(LSP_PUBKEY) },
        { type: "finalHtlcMinimumExpiryDelta", milliseconds: 86_400_000n },
        { type: "hashAlgorithm", algorithm: "ckb-hash" },
        { type: "payeePublicKey", publicKey: hexToBytes(PAYEE_PUBKEY) },
    ],
};

// The invoice vectors' unsigned hold invoice, which fiber's encoder writes with the unsigned flag.
const UNSIGNED_STRING =
    "fibt2500000001qdjfkey7cyxgfw0pnm6vk9qxlq05hrw0kxr4pcy3z9ud2lzdl0m0edm3v5e2cfajyjek5344ucax72vv6xn2rhylq0dmat06lgt2uplcexsqgu2y3";

function stringOf(invoice: UnsignedInvoice, secretKey: Uint8Array = PAYEE_SECRET_KEY): string {
    return encodeInvoice(signInvoice(invoice, secretKey));
}

function withAttribute(attribute: InvoiceAttribute, invoice: UnsignedInvoice = INVOICE): UnsignedInvoice {
    const at = invoice.attributes.findIndex((existing) => existing.type === attribute.type);
    const attributes =
        at === -1 ? [...invoice.attributes, attribute] : invoice.attributes.map((existing, i) => (i === at ? attribute : existing));
    return { ...invoice, attributes };
}

function withoutAttribute(type: InvoiceAttributeType, invoice: UnsignedInvoice = INVOICE): UnsignedInvoice {
    return { ...invoice, attributes: invoice.attributes.filter((attribute) => attribute.type !== type) };
}

function unpayable(detail: string): SdkError {
    return new SdkError("invoice_unpayable", `the invoice cannot be paid: ${detail}`);
}

describe("checkPayableInvoice", () => {
    it("hands back the payment hash, the amount and the payee's key", () => {
        expect(checkPayableInvoice(stringOf(INVOICE), "Fibt", NOW_MS)).toStrictEqual({
            paymentHash: hexToBytes(PAYMENT_HASH),
            amountShannons: "250000000",
            payeePublicKey: hexToBytes(PAYEE_PUBKEY),
        });
    });

    it("pays any node's invoice: one with its payee alone, no hint, no feature, no algorithm, no expiry", () => {
        const bare: UnsignedInvoice = { ...INVOICE, attributes: [{ type: "payeePublicKey", publicKey: hexToBytes(PAYEE_PUBKEY) }] };
        expect(checkPayableInvoice(stringOf(bare), "Fibt", NOW_MS)).toStrictEqual({
            paymentHash: hexToBytes(PAYMENT_HASH),
            amountShannons: "250000000",
            payeePublicKey: hexToBytes(PAYEE_PUBKEY),
        });
    });

    it.each<[string, string]>([
        ["one shannon", "1"],
        ["a u128's whole range", "340282366920938463463374607431768211455"],
    ])("hands back an amount of %s as it is", (_, amountShannons) => {
        expect(checkPayableInvoice(stringOf({ ...INVOICE, amountShannons }), "Fibt", NOW_MS)).toMatchObject({ amountShannons });
    });

    it("checks the currency the network names, a development chain's included", () => {
        expect(() => checkPayableInvoice(stringOf({ ...INVOICE, currency: "Fibd" }), "Fibd", NOW_MS)).not.toThrow();
    });

    describe("the expiry", () => {
        it("accepts the invoice a millisecond before it runs out", () => {
            expect(() => checkPayableInvoice(stringOf(INVOICE), "Fibt", EXPIRES_AT_MS - 1)).not.toThrow();
        });

        it.each<[string, number]>([
            ["at the very millisecond it runs out, one before fiber would", EXPIRES_AT_MS],
            ["a millisecond later", EXPIRES_AT_MS + 1],
        ])("refuses the invoice %s", (_, nowMs) => {
            const error = sdkRefusal(() => checkPayableInvoice(stringOf(INVOICE), "Fibt", nowMs));
            expect(error).toEqual(unpayable(`expiryTime ran out at ${EXPIRES_AT_MS}, the device's clock reading ${nowMs}`));
            expect(error.code).toBe("invoice_unpayable");
            expect(error.cause).toBeUndefined();
        });

        it("runs out at the timestamp itself under an expiry of zero", () => {
            const invoice = stringOf(withAttribute({ type: "expiryTime", seconds: 0n }));
            expect(() => checkPayableInvoice(invoice, "Fibt", TIMESTAMP_MS - 1)).not.toThrow();
            expect(sdkRefusal(() => checkPayableInvoice(invoice, "Fibt", TIMESTAMP_MS))).toEqual(
                unpayable(`expiryTime ran out at ${TIMESTAMP_MS}, the device's clock reading ${TIMESTAMP_MS}`),
            );
        });

        it("never runs out without an expiry, as in fiber", () => {
            expect(() => checkPayableInvoice(stringOf(withoutAttribute("expiryTime")), "Fibt", Number.MAX_SAFE_INTEGER)).not.toThrow();
        });
    });

    describe("refuses", () => {
        it.each<[string, UnsignedInvoice, string]>([
            ["mainnet's currency", { ...INVOICE, currency: "Fibb" }, "currency is Fibb, not the network's Fibt"],
            ["a development chain's currency", { ...INVOICE, currency: "Fibd" }, "currency is Fibd, not the network's Fibt"],
            ["no amount, which leaves it to the payer", { ...INVOICE, amountShannons: null }, "amountShannons is missing"],
            ["an amount of zero", { ...INVOICE, amountShannons: "0" }, "amountShannons is 0"],
            [
                "a UDT script",
                withAttribute({
                    type: "udtScript",
                    script: { codeHash: new Uint8Array(32).fill(0x0d), hashType: "type", args: Uint8Array.of(1) },
                }),
                "udtScript is present: only CKB is paid",
            ],
            ["no payee key, signed by the payee all the same", withoutAttribute("payeePublicKey"), "payeePublicKey is missing"],
        ])("%s, as invoice_unpayable naming the field", (_, invoice, detail) => {
            const error = sdkRefusal(() => checkPayableInvoice(stringOf(invoice), "Fibt", NOW_MS));
            expect(error).toEqual(unpayable(detail));
            expect(error.code).toBe("invoice_unpayable");
            expect(error.cause).toBeUndefined();
        });

        it.each<[string, () => string, string]>([
            ["an empty string", () => "", "invoice must have a human-readable part before the last 1"],
            ["a string that is no invoice", () => "fibt1", "invoice must end with a six-character checksum"],
            [
                "the invoice with one character changed",
                () => {
                    const text = stringOf(INVOICE);
                    return `${text.slice(0, -1)}${text.endsWith("q") ? "p" : "q"}`;
                },
                "invoice must carry a valid bech32m checksum",
            ],
            [
                "the invoice in upper case, which fiber reads but writes otherwise",
                () => stringOf(INVOICE).toUpperCase(),
                "invoice must be lowercase",
            ],
            [
                "a signature by another key than the payee key it carries",
                () => stringOf(INVOICE, OTHER_SECRET_KEY),
                "signature must be by the payee key the invoice carries",
            ],
            ["an unsigned invoice", () => UNSIGNED_STRING, "flag must mark a signed invoice"],
        ])("%s, as invoice_unpayable over the decoder's refusal", (_, encodedInvoice, reason) => {
            const error = sdkRefusal(() => checkPayableInvoice(encodedInvoice(), "Fibt", NOW_MS));
            expect(error).toEqual(unpayable(`encodedInvoice does not decode: ${reason}`));
            expect(error.code).toBe("invoice_unpayable");
            expect(error.cause).toBeInstanceOf(InvoiceError);
            expect((error.cause as InvoiceError).message).toBe(reason);
        });
    });

    it("checks in order: an invoice wrong everywhere names each field as the ones before it are put right", () => {
        const faults: [string, (invoice: UnsignedInvoice) => UnsignedInvoice][] = [
            ["currency", (invoice) => ({ ...invoice, currency: "Fibb" })],
            ["amountShannons", (invoice) => ({ ...invoice, amountShannons: "0" })],
            [
                "udtScript",
                (invoice) =>
                    withAttribute(
                        {
                            type: "udtScript",
                            script: { codeHash: new Uint8Array(32).fill(0x0d), hashType: "type", args: Uint8Array.of(1) },
                        },
                        invoice,
                    ),
            ],
            ["payeePublicKey", (invoice) => withoutAttribute("payeePublicKey", invoice)],
            ["expiryTime", (invoice) => withAttribute({ type: "expiryTime", seconds: 0n }, invoice)],
        ];
        faults.forEach(([field], index) => {
            const invoice = faults.slice(index).reduce((faulty, [, fault]) => fault(faulty), INVOICE);
            const error = sdkRefusal(() => checkPayableInvoice(stringOf(invoice), "Fibt", NOW_MS));
            expect(error).toMatchObject({ code: "invoice_unpayable", message: expect.stringContaining(`paid: ${field} `) });
        });
    });
});
