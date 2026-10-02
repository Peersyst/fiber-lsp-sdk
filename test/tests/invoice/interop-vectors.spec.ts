import { writeFileSync } from "node:fs";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { SCRIPT_HASH_TYPES } from "../../../src/common";
import type { Invoice, InvoiceAttribute, InvoiceAttributeType, UnsignedInvoice } from "../../../src/invoice";
import {
    INVOICE_ATTRIBUTE_TYPES,
    INVOICE_CURRENCIES,
    InvoiceError,
    computeInvoiceDigest,
    decodeInvoice,
    encodeInvoice,
} from "../../../src/invoice";
import { arDecompress, arEncompress } from "../../../src/invoice/arithmetic-coder";
import { encodeInvoiceData } from "../../../src/invoice/invoice-data";
import { decodeInvoiceUtf8, encodeInvoiceUtf8 } from "../../../src/invoice/utils";
import { caseOf } from "../../utils/interop-vectors";
import { toInvoice, toInvoiceValuesVector, toUnsignedInvoice } from "../../utils/invoice-typed";
import { loadInvoiceVectors } from "../../utils/invoice-vectors";

const vectors = loadInvoiceVectors();
const PAYEE_SECRET_KEY = hexToBytes(vectors.payee_secret_key);

/**
 * Strings fiber reads and writes back unchanged that the SDK refuses on purpose, each with its refusal.
 */
const DELIBERATE_REFUSALS: Record<string, string> = {
    "recovery id flipped, with a payee key": "signature must be by the payee key the invoice carries",
    "duplicate expiry": "data.attributes[1] must not repeat an attribute type",
    "duplicate payee key, another key second": "data.attributes[1] must not repeat an attribute type",
    "udt script with hash type 9": "data.attributes[0].udtScript.value.hashType must be one of data, type, data1, data2",
};

function sign(invoice: UnsignedInvoice): Invoice {
    const recovered = secp256k1.sign(computeInvoiceDigest(invoice), PAYEE_SECRET_KEY, { prehash: false, format: "recovered" });
    return { ...invoice, signature: Uint8Array.from([...recovered.subarray(1), recovered[0] ?? 0]) };
}

function decodeOrRefusal(text: string): Invoice | InvoiceError {
    try {
        return decodeInvoice(text);
    } catch (error) {
        if (error instanceof InvoiceError) return error;
        throw error;
    }
}

// --- invoices the SDK writes that the vectors do not hold, for fiber's decoder to read ---

function xorshift(seed: number): () => number {
    let state = seed;
    return () => {
        state ^= state << 13;
        state ^= state >>> 17;
        state ^= state << 5;
        return state >>> 0;
    };
}

function generatedInvoices(count: number): UnsignedInvoice[] {
    const next = xorshift(0x5eed1e55);
    const below = (bound: number): number => next() % bound;
    const bytes = (length: number): Uint8Array => Uint8Array.from({ length }, () => below(256));
    const bigint = (bits: number): bigint => BigInt(`0x${bytesToHex(bytes(Math.ceil(bits / 8)))}`) & ((1n << BigInt(bits)) - 1n);
    // Every UTF-8 width, never a surrogate.
    const points = [0x61, 0x7a, 0x20, 0xe9, 0x7ff, 0x800, 0x20ac, 0xd7ff, 0xe000, 0xfffd, 0x10000, 0x1f600, 0x10ffff];
    const text = (): string => String.fromCodePoint(...Array.from({ length: below(40) }, () => points[below(points.length)] ?? 0x61));
    const attribute = (type: InvoiceAttributeType): InvoiceAttribute => {
        switch (type) {
            case "expiryTime":
                return { type, seconds: bigint(64) };
            case "description":
                return { type, text: text() };
            case "finalHtlcTimeout":
            case "finalHtlcMinimumExpiryDelta":
                return { type, milliseconds: bigint(64) };
            case "fallbackAddr":
                return { type, address: text() };
            case "feature":
                return { type, bits: bytes(below(5)) };
            case "udtScript":
                return { type, script: { codeHash: bytes(32), hashType: SCRIPT_HASH_TYPES[below(4)] ?? "type", args: bytes(below(40)) } };
            case "payeePublicKey":
                return { type, publicKey: secp256k1.getPublicKey(PAYEE_SECRET_KEY, true) };
            case "hashAlgorithm":
                return { type, algorithm: below(2) === 0 ? "ckb-hash" : "sha256" };
            case "paymentSecret":
                return { type, secret: bytes(32) };
        }
    };
    return Array.from({ length: count }, () => {
        const types = INVOICE_ATTRIBUTE_TYPES.filter(() => below(2) === 0);
        for (let index = types.length - 1; index > 0; index--) {
            const other = below(index + 1);
            [types[index], types[other]] = [types[other] as InvoiceAttributeType, types[index] as InvoiceAttributeType];
        }
        const amounts = [null, "0", bigint(64).toString(), bigint(128).toString()];
        return {
            currency: INVOICE_CURRENCIES[below(3)] ?? "Fibt",
            amountShannons: amounts[below(amounts.length)] ?? null,
            timestampMs: bigint(below(2) === 0 ? 48 : 128),
            paymentHash: bytes(32),
            attributes: types.map(attribute),
        };
    });
}

describe("invoice interop vectors", () => {
    it("declares the fiber release they were generated with, and the payee key of its secret", () => {
        expect(vectors.fiber_ref).toBe("b71a61c3");
        expect(bytesToHex(secp256k1.getPublicKey(PAYEE_SECRET_KEY, true))).toBe(vectors.payee_public_key);
    });

    describe("invoices fiber wrote", () => {
        it("cover every attribute alone, every currency, no amount, and both signed and unsigned", () => {
            const alone = vectors.invoices
                .filter((entry) => entry.values.attrs.length === 1)
                .map((entry) => toUnsignedInvoice(entry.values).attributes[0]?.type);
            expect(new Set(alone)).toEqual(new Set(INVOICE_ATTRIBUTE_TYPES));
            expect(new Set(vectors.invoices.map((entry) => entry.values.currency))).toEqual(new Set(INVOICE_CURRENCIES));
            expect(vectors.invoices.some((entry) => entry.values.amount === null)).toBe(true);
            expect(vectors.invoices.some((entry) => entry.signature === null)).toBe(true);
            expect(vectors.invoices.some((entry) => entry.signature !== null)).toBe(true);
        });

        it.each(vectors.invoices.map((entry) => [entry.name, entry] as const))("%s: every layer matches fiber's", (_, entry) => {
            const invoice = toUnsignedInvoice(entry.values);
            const molecule = encodeInvoiceData(invoice);
            expect(bytesToHex(molecule)).toBe(entry.molecule);
            expect(bytesToHex(arEncompress(molecule))).toBe(entry.compressed);
            expect(bytesToHex(arDecompress(hexToBytes(entry.compressed)))).toBe(entry.molecule);
            expect(bytesToHex(computeInvoiceDigest(invoice))).toBe(entry.digest);
        });

        it.each(vectors.invoices.filter((entry) => entry.signature !== null).map((entry) => [entry.name, entry] as const))(
            "%s: reads as its values and writes back as the same string",
            (_, entry) => {
                expect(decodeInvoice(entry.string)).toEqual(toInvoice(entry));
                expect(encodeInvoice(toInvoice(entry))).toBe(entry.string);
            },
        );

        it.each(vectors.invoices.filter((entry) => entry.signature !== null).map((entry) => [entry.name, entry] as const))(
            "%s: the SDK's signature over its own digest is fiber's",
            (_, entry) => {
                expect(bytesToHex(sign(toUnsignedInvoice(entry.values)).signature)).toBe(entry.signature);
            },
        );

        it.each(vectors.invoices.filter((entry) => entry.signature === null).map((entry) => [entry.name, entry] as const))(
            "%s: unsigned, refused at the flag",
            (_, entry) => {
                expect(decodeOrRefusal(entry.string)).toEqual(new InvoiceError("flag", "must mark a signed invoice"));
            },
        );
    });

    describe("the coder", () => {
        it.each(vectors.coder.compress.map((entry) => [entry.name, entry] as const))("%s: compresses as fiber does", (_, entry) => {
            expect(bytesToHex(arEncompress(hexToBytes(entry.data)))).toBe(entry.compressed);
        });

        it.each(vectors.coder.decompress.map((entry) => [entry.name, entry] as const))("%s: decompresses as fiber does", (_, entry) => {
            if (entry.data === null) {
                expect(() => arDecompress(hexToBytes(entry.compressed))).toThrow(InvoiceError);
            } else {
                expect(bytesToHex(arDecompress(hexToBytes(entry.compressed)))).toBe(entry.data);
            }
        });

        it("cover a stream fiber reads past what its coder wrote, ones it refuses, and its padding budget at both edges", () => {
            expect(caseOf(vectors.coder.decompress, "five trailing 0xff bytes").data).not.toBeNull();
            expect(caseOf(vectors.coder.decompress, "16385 zero bytes").data).toBeNull();
            expect(caseOf(vectors.coder.decompress, "empty").data).toBeNull();
            expect(caseOf(vectors.coder.decompress, "needs all 48 padding bits").data).not.toBeNull();
            expect(caseOf(vectors.coder.decompress, "needs 56 padding bits").data).toBeNull();
        });
    });

    describe("UTF-8", () => {
        it.each(vectors.utf8.map((entry) => [entry.name, entry] as const))("%s: read as Rust reads it", (_, entry) => {
            if (entry.text === null) {
                expect(() => decodeInvoiceUtf8(hexToBytes(entry.bytes), "text")).toThrow(new InvoiceError("text", "must be UTF-8"));
            } else {
                expect(decodeInvoiceUtf8(hexToBytes(entry.bytes), "text")).toBe(entry.text);
                expect(bytesToHex(encodeInvoiceUtf8("text", entry.text))).toBe(entry.bytes);
            }
        });
    });

    describe("variants of one invoice, with fiber's verdict", () => {
        it("cover every verdict fiber gives, the panic included", () => {
            expect(new Set(vectors.variants.map((entry) => entry.fiber))).toEqual(
                new Set(["accepted", "rewritten", "refused", "panicked"]),
            );
            expect(vectors.variants[0]).toMatchObject({ name: "canonical", fiber: "accepted" });
        });

        it("name every deliberate refusal after a variant fiber accepts as it is", () => {
            for (const name of Object.keys(DELIBERATE_REFUSALS)) expect(caseOf(vectors.variants, name).fiber).toBe("accepted");
        });

        it.each(vectors.variants.map((entry) => [entry.name, entry] as const))("%s", (name, entry) => {
            const outcome = decodeOrRefusal(entry.string);
            const deliberate = DELIBERATE_REFUSALS[name];
            if (deliberate !== undefined) {
                expect(outcome).toBeInstanceOf(InvoiceError);
                expect((outcome as InvoiceError).message).toBe(deliberate);
            } else if (entry.fiber === "accepted") {
                // One invoice is one string: what the SDK accepts it writes back unchanged.
                expect(outcome).not.toBeInstanceOf(InvoiceError);
                expect(encodeInvoice(outcome as Invoice)).toBe(entry.string);
            } else {
                // Fiber refuses it, panics on it, or reads it as an invoice it would write as another string.
                expect(outcome).toBeInstanceOf(InvoiceError);
            }
        });
    });

    describe("strings the SDK writes, for fiber's decoder", () => {
        const signed = vectors.invoices.filter((entry) => entry.signature !== null);
        const generated = generatedInvoices(64).map(sign);
        const written = [
            ...signed.map((entry) => ({ name: entry.name, invoice: toInvoice(entry) })),
            ...generated.map((invoice, index) => ({ name: `generated ${index}`, invoice })),
        ];

        it("read back as what they were written from", () => {
            for (const { invoice } of written) expect(decodeInvoice(encodeInvoice(invoice))).toEqual(invoice);
        });

        it("span every attribute type and every currency", () => {
            const types = new Set(generated.flatMap((invoice) => invoice.attributes.map((attribute) => attribute.type)));
            expect(types).toEqual(new Set(INVOICE_ATTRIBUTE_TYPES));
            expect(new Set(generated.map((invoice) => invoice.currency))).toEqual(new Set(INVOICE_CURRENCIES));
        });

        // Written only when asked, so `pnpm test` stays side-effect free; see interop/README.md.
        afterAll(() => {
            const outPath = process.env.INTEROP_INVOICE_OUT;
            if (!outPath) return;
            const cases = written.map(({ name, invoice }) => ({
                name,
                values: toInvoiceValuesVector(invoice),
                signature: bytesToHex(invoice.signature),
                string: encodeInvoice(invoice),
            }));
            writeFileSync(outPath, `${JSON.stringify({ cases }, null, 2)}\n`);
        });
    });
});
