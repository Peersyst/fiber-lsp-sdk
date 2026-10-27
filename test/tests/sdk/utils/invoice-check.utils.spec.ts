import { hexToBytes } from "@noble/hashes/utils.js";
import type { InvoiceAttribute, InvoiceAttributeType, UnsignedInvoice } from "../../../../src/invoice";
import { InvoiceError, encodeInvoice } from "../../../../src/invoice";
import type { SdkInvoiceRequest } from "../../../../src/sdk";
import { SdkError, checkTenantInvoice } from "../../../../src/sdk";
import { signInvoice } from "../../../utils/invoice-signing";
import { toUnsignedInvoice } from "../../../utils/invoice-typed";
import { loadInvoiceVectors } from "../../../utils/invoice-vectors";
import { sdkRefusal } from "../../../utils/refusal";

const vectors = loadInvoiceVectors();
const TENANT_CASE = vectors.invoices.find((kase) => kase.name === "tenant invoice as the hosted node shapes it");
if (TENANT_CASE === undefined) throw new Error("the invoice vectors carry no tenant invoice");
const TENANT_STRING = TENANT_CASE.string;
const TENANT_INVOICE: UnsignedInvoice = toUnsignedInvoice(TENANT_CASE.values);
const PAYEE_SECRET_KEY = hexToBytes(vectors.payee_secret_key);
// The vector's trampoline hint, the public key of the secret 0x22 repeated: the LSP's key here.
const LSP_PUBKEY = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";
// The secret 0x33 repeated, and its public key.
const OTHER_SECRET_KEY = hexToBytes("33".repeat(32));
const OTHER_PUBKEY = "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1";

// What the vector's invoice answers.
const REQUEST: SdkInvoiceRequest = {
    amountShannons: "250000000",
    currency: "Fibt",
    paymentHash: hexToBytes("03".repeat(32)),
    hashAlgorithm: "ckb-hash",
    expirySeconds: 3600n,
    finalExpiryDeltaMs: 9_600_000n,
    description: "coffee",
    lspPubkey: hexToBytes(LSP_PUBKEY),
};

const UNDESCRIBED_REQUEST: SdkInvoiceRequest = { ...REQUEST, description: undefined };

// The device's clock at the vector's timestamp, 2024-01-01T00:00:00Z.
const NOW_MS = 1_704_067_200_000;

function reissued(invoice: UnsignedInvoice, secretKey: Uint8Array = PAYEE_SECRET_KEY): string {
    return encodeInvoice(signInvoice(invoice, secretKey));
}

function withAttribute(attribute: InvoiceAttribute, invoice: UnsignedInvoice = TENANT_INVOICE): UnsignedInvoice {
    const at = invoice.attributes.findIndex((existing) => existing.type === attribute.type);
    const attributes =
        at === -1 ? [...invoice.attributes, attribute] : invoice.attributes.map((existing, i) => (i === at ? attribute : existing));
    return { ...invoice, attributes };
}

function withoutAttribute(type: InvoiceAttributeType, invoice: UnsignedInvoice = TENANT_INVOICE): UnsignedInvoice {
    return { ...invoice, attributes: invoice.attributes.filter((attribute) => attribute.type !== type) };
}

function invoiceRejected(detail: string): SdkError {
    return new SdkError("invoice_rejected", `the node's invoice is refused: ${detail}`);
}

describe("checkTenantInvoice", () => {
    it("accepts the vector's tenant invoice, as the hosted node shapes it, against what was asked", () => {
        expect(() => checkTenantInvoice(TENANT_STRING, REQUEST, NOW_MS)).not.toThrow();
    });

    it("re-signs the vector to its own string, so each refusal below differs from it only where it says", () => {
        expect(reissued(TENANT_INVOICE)).toBe(TENANT_STRING);
    });

    it("judges the attributes as a set: the vector's in reverse order pass", () => {
        const reversed = { ...TENANT_INVOICE, attributes: [...TENANT_INVOICE.attributes].reverse() };
        expect(() => checkTenantInvoice(reissued(reversed), REQUEST, NOW_MS)).not.toThrow();
    });

    it("accepts a past timestamp, which only shortens the invoice", () => {
        expect(() => checkTenantInvoice(reissued({ ...TENANT_INVOICE, timestampMs: 0n }), REQUEST, NOW_MS)).not.toThrow();
    });

    it("accepts a timestamp the tolerance past the device's clock, and refuses one a millisecond later", () => {
        const latest = reissued({ ...TENANT_INVOICE, timestampMs: 1_704_067_800_000n });
        expect(() => checkTenantInvoice(latest, REQUEST, NOW_MS)).not.toThrow();
        const later = reissued({ ...TENANT_INVOICE, timestampMs: 1_704_067_800_001n });
        const error = sdkRefusal(() => checkTenantInvoice(later, REQUEST, NOW_MS));
        expect(error).toEqual(invoiceRejected("timestampMs is 1704067800001, more than 600000 ms past the device's 1704067200000"));
        expect(error.code).toBe("invoice_rejected");
    });

    it("measures the tolerance from the clock it is handed", () => {
        const later = reissued({ ...TENANT_INVOICE, timestampMs: 1_704_067_800_001n });
        expect(() => checkTenantInvoice(later, REQUEST, NOW_MS + 1)).not.toThrow();
    });

    it("accepts any payee key the signature is by: the tenant's key is the node's", () => {
        const invoice = withAttribute({ type: "payeePublicKey", publicKey: hexToBytes(OTHER_PUBKEY) });
        expect(() => checkTenantInvoice(reissued(invoice, OTHER_SECRET_KEY), REQUEST, NOW_MS)).not.toThrow();
    });

    it("accepts no description when none was asked", () => {
        expect(() => checkTenantInvoice(reissued(withoutAttribute("description")), UNDESCRIBED_REQUEST, NOW_MS)).not.toThrow();
    });

    it("accepts an empty description when an empty one was asked, and refuses none for it", () => {
        const request = { ...REQUEST, description: "" };
        expect(() => checkTenantInvoice(reissued(withAttribute({ type: "description", text: "" })), request, NOW_MS)).not.toThrow();
        expect(sdkRefusal(() => checkTenantInvoice(reissued(withoutAttribute("description")), request, NOW_MS))).toEqual(
            invoiceRejected("description is missing"),
        );
    });

    describe("refuses", () => {
        it.each<[string, UnsignedInvoice, string]>([
            ["mainnet's currency", { ...TENANT_INVOICE, currency: "Fibb" }, "currency is Fibb, not the network's Fibt"],
            ["a development chain's currency", { ...TENANT_INVOICE, currency: "Fibd" }, "currency is Fibd, not the network's Fibt"],
            ["no amount", { ...TENANT_INVOICE, amountShannons: null }, "amountShannons is none, not the 250000000 asked"],
            [
                "one shannon more than asked",
                { ...TENANT_INVOICE, amountShannons: "250000001" },
                "amountShannons is 250000001, not the 250000000 asked",
            ],
            [
                "one shannon less than asked",
                { ...TENANT_INVOICE, amountShannons: "249999999" },
                "amountShannons is 249999999, not the 250000000 asked",
            ],
            [
                "another payment hash",
                { ...TENANT_INVOICE, paymentHash: hexToBytes(`${"03".repeat(31)}02`) },
                "paymentHash is not the hash the device derived",
            ],
            ["no hash algorithm", withoutAttribute("hashAlgorithm"), "hashAlgorithm is missing"],
            ["sha256", withAttribute({ type: "hashAlgorithm", algorithm: "sha256" }), "hashAlgorithm is sha256, not the ckb-hash asked"],
            ["no expiry", withoutAttribute("expiryTime"), "expiryTime is missing"],
            [
                "an expiry one second short",
                withAttribute({ type: "expiryTime", seconds: 3599n }),
                "expiryTime is 3599 s, not the 3600 s asked",
            ],
            [
                "an expiry one second long",
                withAttribute({ type: "expiryTime", seconds: 3601n }),
                "expiryTime is 3601 s, not the 3600 s asked",
            ],
            ["no final expiry delta", withoutAttribute("finalHtlcMinimumExpiryDelta"), "finalHtlcMinimumExpiryDelta is missing"],
            [
                "a final expiry delta one millisecond short",
                withAttribute({ type: "finalHtlcMinimumExpiryDelta", milliseconds: 9_599_999n }),
                "finalHtlcMinimumExpiryDelta is 9599999 ms, not the 9600000 ms asked",
            ],
            [
                "a final expiry delta one millisecond long",
                withAttribute({ type: "finalHtlcMinimumExpiryDelta", milliseconds: 9_600_001n }),
                "finalHtlcMinimumExpiryDelta is 9600001 ms, not the 9600000 ms asked",
            ],
            ["no description when one was asked", withoutAttribute("description"), "description is missing"],
            ["another description", withAttribute({ type: "description", text: "coffe" }), "description is not the one asked"],
            [
                "the description with a trailing space",
                withAttribute({ type: "description", text: "coffee " }),
                "description is not the one asked",
            ],
            ["no feature", withoutAttribute("feature"), "feature is missing"],
            [
                "no feature bit",
                withAttribute({ type: "feature", bits: new Uint8Array(0) }),
                "feature is not trampoline routing's optional bit alone",
            ],
            [
                "a zero feature byte",
                withAttribute({ type: "feature", bits: Uint8Array.of(0x00) }),
                "feature is not trampoline routing's optional bit alone",
            ],
            [
                "trampoline routing's required bit instead",
                withAttribute({ type: "feature", bits: Uint8Array.of(0x10) }),
                "feature is not trampoline routing's optional bit alone",
            ],
            [
                "MPP's optional bit besides",
                withAttribute({ type: "feature", bits: Uint8Array.of(0x28) }),
                "feature is not trampoline routing's optional bit alone",
            ],
            [
                "the bit followed by a zero byte",
                withAttribute({ type: "feature", bits: Uint8Array.of(0x20, 0x00) }),
                "feature is not trampoline routing's optional bit alone",
            ],
            ["no trampoline hint", withoutAttribute("trampolineRouteHint"), "trampolineRouteHint is missing"],
            [
                "a hint to another node",
                withAttribute({ type: "trampolineRouteHint", nodeId: hexToBytes(OTHER_PUBKEY) }),
                "trampolineRouteHint is not the LSP's key",
            ],
            ["no payee key", withoutAttribute("payeePublicKey"), "payeePublicKey is missing"],
            [
                "a fallback address",
                withAttribute({ type: "fallbackAddr", address: "ckt1qyqrdsefa43s6m882pcj53m4gdnj4k440axqswmu83" }),
                "fallbackAddr was not asked for",
            ],
            [
                "a UDT script",
                withAttribute({
                    type: "udtScript",
                    script: { codeHash: new Uint8Array(32).fill(0x0d), hashType: "type", args: Uint8Array.of(1) },
                }),
                "udtScript was not asked for",
            ],
            [
                "a payment secret",
                withAttribute({ type: "paymentSecret", secret: new Uint8Array(32).fill(0x5e) }),
                "paymentSecret was not asked for",
            ],
            [
                "the deprecated final HTLC timeout",
                withAttribute({ type: "finalHtlcTimeout", milliseconds: 9_600_000n }),
                "finalHtlcTimeout was not asked for",
            ],
        ])("%s, as invoice_rejected naming the field", (_, invoice, detail) => {
            const error = sdkRefusal(() => checkTenantInvoice(reissued(invoice), REQUEST, NOW_MS));
            expect(error).toEqual(invoiceRejected(detail));
            expect(error.code).toBe("invoice_rejected");
            expect(error.cause).toBeUndefined();
        });

        it("a description when none was asked", () => {
            expect(sdkRefusal(() => checkTenantInvoice(TENANT_STRING, UNDESCRIBED_REQUEST, NOW_MS))).toEqual(
                invoiceRejected("description was not asked for"),
            );
        });

        it.each<[string, () => string, string]>([
            ["a string that is no invoice", () => "fibt1", "invoice must end with a six-character checksum"],
            [
                "the vector with one character changed",
                () => `${TENANT_STRING.slice(0, -1)}${TENANT_STRING.endsWith("q") ? "p" : "q"}`,
                "invoice must carry a valid bech32m checksum",
            ],
            [
                "the vector in upper case, which fiber reads but writes otherwise",
                () => TENANT_STRING.toUpperCase(),
                "invoice must be lowercase",
            ],
            [
                "a signature by another key than the payee key it carries",
                () => reissued(TENANT_INVOICE, OTHER_SECRET_KEY),
                "signature must be by the payee key the invoice carries",
            ],
        ])("%s, as invoice_rejected over the decoder's refusal", (_, invoiceAddress, reason) => {
            const error = sdkRefusal(() => checkTenantInvoice(invoiceAddress(), REQUEST, NOW_MS));
            expect(error).toEqual(invoiceRejected(`invoiceAddress does not decode: ${reason}`));
            expect(error.code).toBe("invoice_rejected");
            expect(error.cause).toBeInstanceOf(InvoiceError);
            expect((error.cause as InvoiceError).message).toBe(reason);
        });
    });

    it("checks in order: an invoice wrong everywhere names each field as the ones before it are put right", () => {
        const faults: [string, (invoice: UnsignedInvoice) => UnsignedInvoice][] = [
            ["currency", (invoice) => ({ ...invoice, currency: "Fibb" })],
            ["amountShannons", (invoice) => ({ ...invoice, amountShannons: "1" })],
            ["timestampMs", (invoice) => ({ ...invoice, timestampMs: 1_704_067_800_001n })],
            ["paymentHash", (invoice) => ({ ...invoice, paymentHash: new Uint8Array(32) })],
            ["hashAlgorithm", (invoice) => withAttribute({ type: "hashAlgorithm", algorithm: "sha256" }, invoice)],
            ["expiryTime", (invoice) => withAttribute({ type: "expiryTime", seconds: 1n }, invoice)],
            ["finalHtlcMinimumExpiryDelta", (invoice) => withAttribute({ type: "finalHtlcMinimumExpiryDelta", milliseconds: 1n }, invoice)],
            ["description", (invoice) => withAttribute({ type: "description", text: "tea" }, invoice)],
            ["feature", (invoice) => withAttribute({ type: "feature", bits: Uint8Array.of(0x28) }, invoice)],
            ["trampolineRouteHint", (invoice) => withAttribute({ type: "trampolineRouteHint", nodeId: hexToBytes(OTHER_PUBKEY) }, invoice)],
            ["payeePublicKey", (invoice) => withoutAttribute("payeePublicKey", invoice)],
            ["paymentSecret", (invoice) => withAttribute({ type: "paymentSecret", secret: new Uint8Array(32).fill(0x5e) }, invoice)],
        ];
        faults.forEach(([field], index) => {
            const invoice = faults.slice(index).reduce((faulty, [, fault]) => fault(faulty), TENANT_INVOICE);
            const error = sdkRefusal(() => checkTenantInvoice(reissued(invoice), REQUEST, NOW_MS));
            expect(error).toMatchObject({ code: "invoice_rejected", message: expect.stringContaining(`refused: ${field} `) });
        });
    });
});
