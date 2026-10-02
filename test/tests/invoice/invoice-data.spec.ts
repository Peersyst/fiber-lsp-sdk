import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { moleculeBytes, moleculeDynvec, moleculeTable, uint128Le, uint32Le, uint64Le } from "../../../src/common";
import type { InvoiceAttribute } from "../../../src/invoice";
import { InvoiceError, MAX_INVOICE_DATA_LENGTH } from "../../../src/invoice";
import type { InvoiceData } from "../../../src/invoice/invoice-data";
import { decodeInvoiceData, encodeInvoiceData } from "../../../src/invoice/invoice-data";
import { invoiceRefusal } from "../../utils/refusal";

const PAYEE = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
const PAYEE_UNCOMPRESSED =
    "044f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1";
const PAYMENT_HASH = "03".repeat(32);

// The data of a hold invoice as fiber's `new_invoice` shapes it, written by fiber.
const HOLD: InvoiceData = {
    timestampMs: 1704067200000n,
    paymentHash: hexToBytes(PAYMENT_HASH),
    attributes: [
        { type: "description", text: "coffee" },
        { type: "expiryTime", seconds: 3600n },
        { type: "finalHtlcMinimumExpiryDelta", milliseconds: 9600000n },
        { type: "hashAlgorithm", algorithm: "ckb-hash" },
        { type: "payeePublicKey", publicKey: hexToBytes(PAYEE) },
    ],
};
const HOLD_MOLECULE =
    "bc00000010000000200000004000000000f451c28c010000000000000000000003030303030303030303030303030303030303030303030303030303030303037c000000180000002e0000003a000000460000004b00000001000000120000000800000006000000636f6666656500000000100e00000000000003000000007c9200000000000800000000070000002d0000000800000021000000034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

const bytesTable = (data: Uint8Array): Uint8Array => moleculeTable([moleculeBytes(data)]);

// A `RawInvoiceData` around raw union items, so a test writes the one item it breaks byte by byte.
const withItems = (...items: Uint8Array[]): Uint8Array => moleculeTable([uint128Le(5n), hexToBytes(PAYMENT_HASH), moleculeDynvec(items)]);

const item = (id: number, body: Uint8Array): Uint8Array => new Uint8Array([...uint32Le(id), ...body]);

const data = (...attributes: InvoiceAttribute[]): InvoiceData => ({ timestampMs: 5n, paymentHash: hexToBytes(PAYMENT_HASH), attributes });

describe("encodeInvoiceData", () => {
    it("writes the hold invoice's data as fiber does", () => {
        expect(bytesToHex(encodeInvoiceData(HOLD))).toBe(HOLD_MOLECULE);
    });

    it("writes each attribute under its union id, in the order given", () => {
        const written = decodeInvoiceData(
            encodeInvoiceData(data({ type: "paymentSecret", secret: new Uint8Array(32).fill(9) }, { type: "expiryTime", seconds: 1n })),
        );
        expect(written.attributes.map((attribute) => attribute.type)).toEqual(["paymentSecret", "expiryTime"]);
        expect(bytesToHex(encodeInvoiceData(data({ type: "expiryTime", seconds: 1n })))).toBe(bytesToHex(withItems(item(0, uint64Le(1n)))));
        expect(bytesToHex(encodeInvoiceData(data({ type: "hashAlgorithm", algorithm: "sha256" })))).toBe(
            bytesToHex(withItems(item(8, Uint8Array.of(1)))),
        );
    });

    it.each<[string, InvoiceData, string]>([
        ["a timestamp past u128", { ...data(), timestampMs: 1n << 128n }, "timestampMs must be a bigint between 0 and"],
        ["a payment hash of 31 bytes", { ...data(), paymentHash: new Uint8Array(31) }, "paymentHash must be 32 bytes, got 31"],
        ["attributes that are not an array", { ...data(), attributes: {} as never }, "attributes must be an array"],
        ["an attribute that is not an object", data(null as never), "attributes[0] must be an object"],
        ["an unknown attribute type", data({ type: "routeHint" } as never), "attributes[0].type must be one of expiryTime"],
        [
            "a repeated attribute type",
            data({ type: "expiryTime", seconds: 1n }, { type: "expiryTime", seconds: 2n }),
            "attributes[1] must not repeat an attribute type",
        ],
        ["an expiry past u64", data({ type: "expiryTime", seconds: 1n << 64n }), "attributes[0].seconds must be a bigint between 0 and"],
        ["a negative expiry", data({ type: "expiryTime", seconds: -1n }), "attributes[0].seconds must be a bigint between 0 and"],
        [
            "a delta past u64",
            data({ type: "finalHtlcMinimumExpiryDelta", milliseconds: 1n << 64n }),
            "attributes[0].milliseconds must be a bigint between 0 and",
        ],
        [
            "a timeout past u64",
            data({ type: "finalHtlcTimeout", milliseconds: 1n << 64n }),
            "attributes[0].milliseconds must be a bigint between 0 and",
        ],
        [
            "a description with a lone surrogate",
            data({ type: "description", text: "\ud800" }),
            "attributes[0].text must be well-formed Unicode",
        ],
        ["a description that is not a string", data({ type: "description", text: 5 as never }), "attributes[0].text must be a string"],
        [
            "an address that is not a string",
            data({ type: "fallbackAddr", address: undefined as never }),
            "attributes[0].address must be a string",
        ],
        [
            "an address with a lone surrogate",
            data({ type: "fallbackAddr", address: "\udfff" }),
            "attributes[0].address must be well-formed Unicode",
        ],
        ["feature bits that are not bytes", data({ type: "feature", bits: "08" as never }), "attributes[0].bits must be a Uint8Array"],
        ["a missing script", data({ type: "udtScript" } as never), "attributes[0].script must be an object"],
        [
            "a script with a code hash of 31 bytes",
            data({ type: "udtScript", script: { codeHash: new Uint8Array(31), hashType: "type", args: new Uint8Array(0) } }),
            "attributes[0].script.codeHash must be 32 bytes, got 31",
        ],
        [
            "a script with an unknown hash type",
            data({ type: "udtScript", script: { codeHash: new Uint8Array(32), hashType: "data3" as never, args: new Uint8Array(0) } }),
            "attributes[0].script.hashType must be one of data, type, data1, data2",
        ],
        [
            "script args that are not bytes",
            data({ type: "udtScript", script: { codeHash: new Uint8Array(32), hashType: "type", args: "00" as never } }),
            "attributes[0].script.args must be a Uint8Array",
        ],
        [
            "an uncompressed payee key",
            data({ type: "payeePublicKey", publicKey: hexToBytes(PAYEE_UNCOMPRESSED) }),
            "attributes[0].publicKey must be a 33-byte compressed public key",
        ],
        [
            "a payee key off the curve",
            data({ type: "payeePublicKey", publicKey: hexToBytes(`02${"ff".repeat(32)}`) }),
            "attributes[0].publicKey must be a 33-byte compressed public key",
        ],
        [
            "a payee key that is not bytes",
            data({ type: "payeePublicKey", publicKey: PAYEE as never }),
            "attributes[0].publicKey must be a 33-byte compressed public key",
        ],
        [
            "an unknown hash algorithm",
            data({ type: "hashAlgorithm", algorithm: "blake3" as never }),
            "attributes[0].algorithm must be one of",
        ],
        [
            "a payment secret of 31 bytes",
            data({ type: "paymentSecret", secret: new Uint8Array(31) }),
            "attributes[0].secret must be 32 bytes",
        ],
    ])("refuses %s", (_, invalid, message) => {
        expect(() => encodeInvoiceData(invalid)).toThrow(message);
    });

    it("writes data of exactly the decoder's limit and refuses a byte more", () => {
        const text = (length: number): InvoiceData => data({ type: "description", text: "a".repeat(length) });
        expect(encodeInvoiceData(text(MAX_INVOICE_DATA_LENGTH - 88))).toHaveLength(MAX_INVOICE_DATA_LENGTH);
        expect(() => encodeInvoiceData(text(MAX_INVOICE_DATA_LENGTH - 87))).toThrow(
            new RangeError("the invoice data must be at most 16384 bytes"),
        );
    });
});

describe("decodeInvoiceData", () => {
    it("reads the hold invoice's data", () => {
        expect(decodeInvoiceData(hexToBytes(HOLD_MOLECULE))).toEqual(HOLD);
    });

    it("reads data without attributes", () => {
        expect(decodeInvoiceData(withItems())).toEqual(data());
    });

    it.each<[string, Uint8Array, InvoiceError]>([
        [
            "a fourth field",
            moleculeTable([uint128Le(5n), hexToBytes(PAYMENT_HASH), moleculeDynvec([]), Uint8Array.of(1)]),
            new InvoiceError("data", "must have exactly 3 fields"),
        ],
        ["a trailing byte", new Uint8Array([...withItems(), 0]), new InvoiceError("data", "must be exactly as long as its size says")],
        [
            "a timestamp of 8 bytes",
            moleculeTable([uint64Le(5n), hexToBytes(PAYMENT_HASH), moleculeDynvec([])]),
            new InvoiceError("data.timestamp", "must be exactly 16 bytes"),
        ],
        [
            "a payment hash of 31 bytes",
            moleculeTable([uint128Le(5n), new Uint8Array(31), moleculeDynvec([])]),
            new InvoiceError("data.paymentHash", "must be exactly 32 bytes"),
        ],
        [
            "an attribute id past the union",
            withItems(item(10, uint64Le(1n))),
            new InvoiceError("data.attributes[0]", "must have an item id below 10"),
        ],
        [
            "an expiry of 7 bytes",
            withItems(item(0, new Uint8Array(7))),
            new InvoiceError("data.attributes[0].expiryTime", "must be exactly 8 bytes"),
        ],
        [
            "a timeout of 9 bytes",
            withItems(item(2, new Uint8Array(9))),
            new InvoiceError("data.attributes[0].finalHtlcTimeout", "must be exactly 8 bytes"),
        ],
        [
            "a delta of 7 bytes",
            withItems(item(3, new Uint8Array(7))),
            new InvoiceError("data.attributes[0].finalHtlcMinimumExpiryDelta", "must be exactly 8 bytes"),
        ],
        [
            "a description that is not UTF-8",
            withItems(item(1, bytesTable(Uint8Array.of(0xff)))),
            new InvoiceError("data.attributes[0].description.value", "must be UTF-8"),
        ],
        [
            "a description table with a field more",
            withItems(item(1, moleculeTable([moleculeBytes(new Uint8Array(0)), new Uint8Array(0)]))),
            new InvoiceError("data.attributes[0].description", "must have exactly 1 field"),
        ],
        [
            "a description whose length is wrong",
            withItems(item(1, moleculeTable([Uint8Array.of(2, 0, 0, 0, 0x61)]))),
            new InvoiceError("data.attributes[0].description.value", "must be exactly as long as its length says"),
        ],
        [
            "an address that is not UTF-8",
            withItems(item(4, bytesTable(Uint8Array.of(0xc0, 0x80)))),
            new InvoiceError("data.attributes[0].fallbackAddr.value", "must be UTF-8"),
        ],
        [
            "feature bits whose length is wrong",
            withItems(item(5, moleculeTable([Uint8Array.of(9, 0, 0, 0)]))),
            new InvoiceError("data.attributes[0].feature.value", "must be exactly as long as its length says"),
        ],
        [
            "a script with hash type 3",
            withItems(item(6, moleculeTable([moleculeTable([new Uint8Array(32), Uint8Array.of(3), moleculeBytes(new Uint8Array(0))])]))),
            new InvoiceError("data.attributes[0].udtScript.value.hashType", "must be one of data, type, data1, data2"),
        ],
        [
            "a script table with two fields",
            withItems(item(6, moleculeTable([moleculeTable([new Uint8Array(32), Uint8Array.of(1)])]))),
            new InvoiceError("data.attributes[0].udtScript.value", "must have exactly 3 fields"),
        ],
        [
            "a payee key of 32 bytes",
            withItems(item(7, bytesTable(hexToBytes(PAYEE).subarray(1)))),
            new InvoiceError("data.attributes[0].payeePublicKey.value", "must be a 33-byte compressed public key"),
        ],
        [
            "an uncompressed payee key, which fiber reads and writes back compressed",
            withItems(item(7, bytesTable(hexToBytes(PAYEE_UNCOMPRESSED)))),
            new InvoiceError("data.attributes[0].payeePublicKey.value", "must be a 33-byte compressed public key"),
        ],
        [
            "a payee key off the curve",
            withItems(item(7, bytesTable(hexToBytes(`02${"ff".repeat(32)}`)))),
            new InvoiceError("data.attributes[0].payeePublicKey.value", "must be a 33-byte compressed public key"),
        ],
        [
            "hash algorithm byte 2, which fiber reads as ckb-hash and writes back as 0",
            withItems(item(8, Uint8Array.of(2))),
            new InvoiceError("data.attributes[0].hashAlgorithm", "must be 0 (ckb-hash) or 1 (sha256)"),
        ],
        [
            "a hash algorithm of two bytes",
            withItems(item(8, Uint8Array.of(0, 0))),
            new InvoiceError("data.attributes[0].hashAlgorithm", "must be exactly 1 byte"),
        ],
        [
            "a payment secret of 33 bytes",
            withItems(item(9, new Uint8Array(33))),
            new InvoiceError("data.attributes[0].paymentSecret", "must be exactly 32 bytes"),
        ],
        [
            "an attribute type twice, which fiber reads keeping the first",
            withItems(item(0, uint64Le(1n)), item(8, Uint8Array.of(0)), item(0, uint64Le(2n))),
            new InvoiceError("data.attributes[2]", "must not repeat an attribute type"),
        ],
    ])("refuses %s", (_, molecule, refusal) => {
        expect(invoiceRefusal(() => decodeInvoiceData(molecule))).toEqual(refusal);
    });

    it("reads every attribute at the edge of its range", () => {
        const edges: InvoiceAttribute[] = [
            { type: "expiryTime", seconds: (1n << 64n) - 1n },
            { type: "description", text: "" },
            { type: "finalHtlcTimeout", milliseconds: 0n },
            { type: "finalHtlcMinimumExpiryDelta", milliseconds: (1n << 64n) - 1n },
            { type: "fallbackAddr", address: "\u{10ffff}" },
            { type: "feature", bits: new Uint8Array(0) },
            { type: "udtScript", script: { codeHash: new Uint8Array(32).fill(0xff), hashType: "data2", args: new Uint8Array(0) } },
            { type: "payeePublicKey", publicKey: hexToBytes(PAYEE) },
            { type: "hashAlgorithm", algorithm: "sha256" },
            { type: "paymentSecret", secret: new Uint8Array(32) },
        ];
        const edge = { timestampMs: (1n << 128n) - 1n, paymentHash: new Uint8Array(32).fill(0xff), attributes: edges };
        expect(decodeInvoiceData(encodeInvoiceData(edge))).toEqual(edge);
    });
});
