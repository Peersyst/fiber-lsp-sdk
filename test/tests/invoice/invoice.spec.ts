import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { Invoice, UnsignedInvoice } from "../../../src/invoice";
import { InvoiceError, computeInvoiceDigest, decodeInvoice, encodeInvoice } from "../../../src/invoice";
import { arEncompress } from "../../../src/invoice/arithmetic-coder";
import { bytesToInvoiceGroups, decodeInvoiceBech32m, encodeInvoiceBech32m } from "../../../src/invoice/bech32m";
import { encodeInvoiceData } from "../../../src/invoice/invoice-data";
import { invoiceRefusal } from "../../utils/refusal";

const PAYEE_SECRET_KEY = new Uint8Array(32).fill(0x11);
const OTHER_SECRET_KEY = new Uint8Array(32).fill(0x22);
const PAYEE = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

// A hold invoice as fiber's `new_invoice` shapes it, its string and signature written by fiber.
const HOLD_STRING =
    "fibt2500000001phdztk3fx62gfw0pmm6vk9qxlq05dw76a7fh3qy3z9ud27n2l6ukehhkvu7ujkjee90rscgxrru4j5f07eq5kujq9pa07vsfywssvphrqwn5u338ygmn90y70f80luahy3xjgc65n3s83m23ntql5vf57q0vlulm069j0ae0zfxcx9jsjv2h835a70nr856rrq45y4d7tftqqdwnzsptaznsvs9ce8la6uf300yz4qjpqyvvfjsmddr5zrmcsahv89vv6je2dqewx60cm42mv7ctpzwqa5500uahfazlfqznjqhwq3lqpkqm3p3";
const HOLD_UNSIGNED: UnsignedInvoice = {
    currency: "Fibt",
    amountShannons: "250000000",
    timestampMs: 1704067200000n,
    paymentHash: hexToBytes("03".repeat(32)),
    attributes: [
        { type: "description", text: "coffee" },
        { type: "expiryTime", seconds: 3600n },
        { type: "finalHtlcMinimumExpiryDelta", milliseconds: 9600000n },
        { type: "hashAlgorithm", algorithm: "ckb-hash" },
        { type: "payeePublicKey", publicKey: hexToBytes(PAYEE) },
    ],
};
const HOLD_DIGEST = "95ec05874fc1034f48695759393012112e66c55931b642243c0f8b88df6ef1f8";
const HOLD: Invoice = {
    ...HOLD_UNSIGNED,
    signature: hexToBytes(
        "6ba628057d14e0c817193ffbae262f7905504820231899436d68e821ef10edd872b19a9654d065c6d3f1baab6cf61611381da51efe76e9e8be900a7205dc08fc01",
    ),
};

// The smallest signed invoice: no amount, no attributes; its 42-byte stream is padded with a zero byte in the digest.
const MIN_STRING =
    "fibd1pgw7y8090f2gfw0pmm6vkrwufvqqqqqqqp632ualle4w96ac4fujt2y5fzhc7a7m3u4ksfutp5v37h25hvtmy90apph8u9zzhyjz3yvasdt3zzpc9tzmce4us4y0a6v49e4wsxjsk7jqpprhj9vkhtuqczt7xez2ylzq4zz8mxsqqcfwk3n";
const MIN_UNSIGNED: UnsignedInvoice = {
    currency: "Fibd",
    amountShannons: null,
    timestampMs: 0n,
    paymentHash: hexToBytes("03".repeat(32)),
    attributes: [],
};
const MIN_DIGEST = "bb44d36f99325d6ab2d40257bacf0b2af1212af535406809249d2b10186ece9d";

function sign(invoice: UnsignedInvoice, key = PAYEE_SECRET_KEY): Invoice {
    const recovered = secp256k1.sign(computeInvoiceDigest(invoice), key, { prehash: false, format: "recovered" });
    return { ...invoice, signature: Uint8Array.from([...recovered.subarray(1), recovered[0] ?? 0]) };
}

// Writes a string from its parts as they are, so a test can break one part and keep the rest fiber's.
function stringOf(hrp: string, flag: number, stream: Uint8Array, signature: Uint8Array): string {
    return encodeInvoiceBech32m(hrp, [flag, ...bytesToInvoiceGroups(stream), ...bytesToInvoiceGroups(signature)]);
}

const HOLD_HRP = "fibt250000000";
const HOLD_STREAM = arEncompress(encodeInvoiceData(HOLD_UNSIGNED));

function withSignature(signature: Uint8Array): string {
    return stringOf(HOLD_HRP, 1, HOLD_STREAM, signature);
}

describe("computeInvoiceDigest", () => {
    it("hashes the human-readable part and the stream, as fiber does", () => {
        expect(bytesToHex(computeInvoiceDigest(HOLD_UNSIGNED))).toBe(HOLD_DIGEST);
    });

    it("pads a stream whose length is not a multiple of five with one zero byte", () => {
        expect(arEncompress(encodeInvoiceData(MIN_UNSIGNED))).toHaveLength(42);
        expect(bytesToHex(computeInvoiceDigest(MIN_UNSIGNED))).toBe(MIN_DIGEST);
    });

    it("covers the currency and the amount, which only the human-readable part carries", () => {
        expect(bytesToHex(computeInvoiceDigest({ ...HOLD_UNSIGNED, currency: "Fibb" }))).not.toBe(HOLD_DIGEST);
        expect(bytesToHex(computeInvoiceDigest({ ...HOLD_UNSIGNED, amountShannons: "250000001" }))).not.toBe(HOLD_DIGEST);
        expect(bytesToHex(computeInvoiceDigest({ ...HOLD_UNSIGNED, amountShannons: null }))).not.toBe(HOLD_DIGEST);
    });

    it("refuses a missing amount rather than hash the invoice without one", () => {
        expect(() => computeInvoiceDigest({ ...HOLD_UNSIGNED, amountShannons: undefined as never })).toThrow(
            new TypeError("amountShannons must be an amount in decimal shannons"),
        );
    });
});

describe("encodeInvoice", () => {
    it("writes the hold invoice as fiber does", () => {
        expect(encodeInvoice(HOLD)).toBe(HOLD_STRING);
    });

    it("writes an invoice without an amount with the currency alone", () => {
        expect(encodeInvoice(sign(MIN_UNSIGNED))).toBe(MIN_STRING);
    });

    it("writes the signature as given, without verifying it", () => {
        const other = sign(HOLD_UNSIGNED, OTHER_SECRET_KEY);
        expect(decodeInvoiceBech32m(encodeInvoice(other)).groups.slice(-104)).toEqual(bytesToInvoiceGroups(other.signature));
    });

    it.each<[string, Invoice, string]>([
        ["an unknown currency", { ...HOLD, currency: "Fibx" as never }, "currency must be one of Fibb, Fibt, Fibd"],
        [
            "an amount with a leading zero",
            { ...HOLD, amountShannons: "0250000000" },
            "amountShannons must be an amount in decimal shannons",
        ],
        ["a negative amount", { ...HOLD, amountShannons: "-1" }, "amountShannons must be an amount in decimal shannons"],
        // `null` is the invoice without an amount; a missing one must not read as it.
        ["a missing amount", { ...HOLD, amountShannons: undefined as never }, "amountShannons must be an amount in decimal shannons"],
        [
            "an amount past u128",
            { ...HOLD, amountShannons: "340282366920938463463374607431768211456" },
            "amountShannons must be an amount in decimal shannons",
        ],
        ["a signature of 64 bytes", { ...HOLD, signature: new Uint8Array(64) }, "signature must be 65 bytes, got 64"],
        ["a signature that is not bytes", { ...HOLD, signature: "00" as never }, "signature must be a Uint8Array"],
        ["data the decoder would refuse", { ...HOLD, paymentHash: new Uint8Array(31) }, "paymentHash must be 32 bytes"],
    ])("refuses %s", (_, invalid, message) => {
        expect(() => encodeInvoice(invalid)).toThrow(message);
    });
});

describe("decodeInvoice", () => {
    it("reads the hold invoice fiber wrote", () => {
        expect(decodeInvoice(HOLD_STRING)).toEqual(HOLD);
    });

    it.each([
        ["a number", 123],
        ["undefined", undefined],
        ["bytes", new Uint8Array(0)],
    ])("refuses %s as the caller's mistake, not as an invoice", (_, value) => {
        expect(() => decodeInvoice(value as never)).toThrow(new TypeError("invoice must be a string"));
    });

    it("reads an invoice without an amount", () => {
        expect(decodeInvoice(MIN_STRING)).toEqual(sign(MIN_UNSIGNED));
    });

    it("reads a zero amount and u128's largest", () => {
        for (const amountShannons of ["0", "340282366920938463463374607431768211455"]) {
            expect(decodeInvoice(encodeInvoice(sign({ ...HOLD_UNSIGNED, amountShannons }))).amountShannons).toBe(amountShannons);
        }
    });

    it("reads an invoice without a payee key whatever key its signature recovers to, as fiber does", () => {
        const unsigned: UnsignedInvoice = { ...MIN_UNSIGNED, attributes: [{ type: "expiryTime", seconds: 60n }] };
        const byOther = sign(unsigned, OTHER_SECRET_KEY);
        expect(decodeInvoice(encodeInvoice(byOther))).toEqual(byOther);
        const flipped = Uint8Array.from(byOther.signature);
        flipped[64] = (flipped[64] ?? 0) ^ 1;
        expect(decodeInvoice(encodeInvoice({ ...byOther, signature: flipped })).signature).toEqual(flipped);
    });

    describe("refuses, naming the layer", () => {
        const signature = HOLD.signature;
        const highS = (): Uint8Array => {
            const s = BigInt(`0x${bytesToHex(signature.subarray(32, 64))}`);
            const flipped = hexToBytes((ORDER - s).toString(16).padStart(64, "0"));
            return Uint8Array.from([...signature.subarray(0, 32), ...flipped, (signature[64] ?? 0) ^ 1]);
        };
        const withRecoveryId = (recoveryId: number): Uint8Array => Uint8Array.from([...signature.subarray(0, 64), recoveryId]);

        it.each<[string, () => string, InvoiceError]>([
            [
                "the string in upper case, which fiber reads",
                () => HOLD_STRING.toUpperCase(),
                new InvoiceError("invoice", "must be lowercase"),
            ],
            [
                "a character changed",
                () => `${HOLD_STRING.slice(0, -1)}q`,
                new InvoiceError("invoice", "must carry a valid bech32m checksum"),
            ],
            [
                "an unknown currency",
                () => stringOf("fibx250000000", 1, HOLD_STREAM, signature),
                new InvoiceError("currency", "must be one of fibb, fibt, fibd"),
            ],
            ["a currency in upper case only", () => `FIBT${HOLD_STRING.slice(4)}`, new InvoiceError("invoice", "must be lowercase")],
            [
                "a leading zero in the amount, which fiber reads",
                () => stringOf("fibt0250000000", 1, HOLD_STREAM, signature),
                new InvoiceError("amount", "must be decimal shannons within u128, without leading zeros"),
            ],
            [
                "an amount past u128",
                () => stringOf("fibt340282366920938463463374607431768211456", 1, HOLD_STREAM, signature),
                new InvoiceError("amount", "must be decimal shannons within u128, without leading zeros"),
            ],
            [
                "an SI multiplier after the amount",
                () => stringOf("fibt250m", 1, HOLD_STREAM, signature),
                new InvoiceError("amount", "must be decimal shannons within u128, without leading zeros"),
            ],
            [
                "the unsigned flag",
                () => stringOf(HOLD_HRP, 0, HOLD_STREAM, signature),
                new InvoiceError("flag", "must mark a signed invoice"),
            ],
            ["flag 2", () => stringOf(HOLD_HRP, 2, HOLD_STREAM, signature), new InvoiceError("flag", "must mark a signed invoice")],
            ["no data at all", () => encodeInvoiceBech32m(HOLD_HRP, []), new InvoiceError("flag", "must mark a signed invoice")],
            [
                "a signature and no stream, on which fiber panics",
                () => encodeInvoiceBech32m("fibd", [1, ...new Array<number>(103).fill(0)]),
                new InvoiceError("invoice", "must carry a compressed stream and a signature"),
            ],
            [
                "exactly a signature after the flag",
                () => encodeInvoiceBech32m("fibd", [1, ...bytesToInvoiceGroups(signature)]),
                new InvoiceError("invoice", "must carry a compressed stream and a signature"),
            ],
            [
                "padding bits that are not zero",
                () => {
                    const groups = bytesToInvoiceGroups(HOLD_STREAM);
                    groups[groups.length - 1] = (groups[groups.length - 1] ?? 0) | 1;
                    return encodeInvoiceBech32m(HOLD_HRP, [1, ...groups, ...bytesToInvoiceGroups(signature)]);
                },
                new InvoiceError("compressed", "must be whole bytes with zero padding"),
            ],
            [
                "bytes after the end marker, which fiber reads",
                () => stringOf(HOLD_HRP, 1, Uint8Array.from([...HOLD_STREAM, 0, 0, 0, 0, 0]), signature),
                new InvoiceError("compressed", "must be the stream fiber's coder writes"),
            ],
            [
                "bytes after the end marker without a payee key, which no signature check would catch",
                () => {
                    const unsigned: UnsignedInvoice = { ...MIN_UNSIGNED, attributes: [{ type: "expiryTime", seconds: 60n }] };
                    const stream = Uint8Array.from([...arEncompress(encodeInvoiceData(unsigned)), 0xff]);
                    const recovered = secp256k1.sign(
                        sha256(
                            Uint8Array.from([
                                ...new TextEncoder().encode("fibd"),
                                ...stream,
                                ...new Uint8Array(stream.length % 5 === 0 ? 0 : 1),
                            ]),
                        ),
                        PAYEE_SECRET_KEY,
                        { prehash: false, format: "recovered" },
                    );
                    return stringOf("fibd", 1, stream, Uint8Array.from([...recovered.subarray(1), recovered[0] ?? 0]));
                },
                new InvoiceError("compressed", "must be the stream fiber's coder writes"),
            ],
            [
                "a stream cut before its end marker",
                () => stringOf(HOLD_HRP, 1, HOLD_STREAM.subarray(0, 40), signature),
                new InvoiceError("compressed", "must reach the coder's end marker before its input runs out"),
            ],
            [
                "data molecule refuses",
                () => stringOf(HOLD_HRP, 1, arEncompress(Uint8Array.of(1, 2, 3)), signature),
                new InvoiceError("data", "must be exactly as long as its size says"),
            ],
            [
                "r of zero",
                () => withSignature(Uint8Array.from([...new Uint8Array(32), ...signature.subarray(32)])),
                new InvoiceError("signature", "must have r and s within the curve order"),
            ],
            [
                "s at the curve order",
                () => withSignature(Uint8Array.from([...signature.subarray(0, 32), ...hexToBytes(ORDER.toString(16)), 0])),
                new InvoiceError("signature", "must have r and s within the curve order"),
            ],
            [
                "recovery id 4",
                () => withSignature(withRecoveryId(4)),
                new InvoiceError("signature", "must have a recovery id of at most 3"),
            ],
            ["a high-S signature", () => withSignature(highS()), new InvoiceError("signature", "must be low-S")],
            [
                "recovery id 3, which recovers no key here",
                () => withSignature(withRecoveryId(3)),
                new InvoiceError("signature", "must recover a public key"),
            ],
            [
                "the recovery id flipped, which fiber reads",
                () => withSignature(withRecoveryId((signature[64] ?? 0) ^ 1)),
                new InvoiceError("signature", "must be by the payee key the invoice carries"),
            ],
            [
                "a signature by another key than the payee's",
                () => encodeInvoice(sign(HOLD_UNSIGNED, OTHER_SECRET_KEY)),
                new InvoiceError("signature", "must be by the payee key the invoice carries"),
            ],
            [
                "a signature over other data",
                () => stringOf(HOLD_HRP, 1, arEncompress(encodeInvoiceData({ ...HOLD_UNSIGNED, timestampMs: 1n })), signature),
                new InvoiceError("signature", "must be by the payee key the invoice carries"),
            ],
            [
                "a signature over another amount",
                () => stringOf("fibt250000001", 1, HOLD_STREAM, signature),
                new InvoiceError("signature", "must be by the payee key the invoice carries"),
            ],
        ])("%s", (_, text, refusal) => {
            expect(invoiceRefusal(() => decodeInvoice(text()))).toEqual(refusal);
        });
    });
});
