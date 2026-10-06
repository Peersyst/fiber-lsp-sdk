import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { InvoiceError, MAX_INVOICE_DATA_LENGTH } from "../../../src/invoice";
import { arDecompress, arEncompress } from "../../../src/invoice/arithmetic-coder";
import { invoiceRefusal } from "../../utils/refusal";

// A `RawInvoiceData` with one expiry attribute, and the stream fiber's coder writes for it.
const MOLECULE =
    "54000000100000002000000040000000050000000000000000000000000000000303030303030303030303030303030303030303030303030303030303030303140000000800000000000000100e000000000000";
const STREAM = "53ac53acbf3a90973c3bde9962ca12fc0bff800000817e5ca06f4dfb4d49abdd22708d125ad1539abb51cb139746f9fd4d2a50";

const RUNS_OUT = new InvoiceError("compressed", "must reach the coder's end marker before its input runs out");

describe("arEncompress", () => {
    it.each([
        ["nothing", "", "ff40"],
        ["one zero byte", "00", "00fe80"],
        ["one 0xff byte", "ff", "ff0040"],
        ["a data table", MOLECULE, STREAM],
    ])("compresses %s as fiber does", (_, data, stream) => {
        expect(bytesToHex(arEncompress(hexToBytes(data)))).toBe(stream);
    });

    it("adapts: a run compresses to far fewer bytes than it has", () => {
        expect(arEncompress(new Uint8Array(4096).fill(0x61)).length).toBeLessThan(4096 / 16);
    });
});

describe("arDecompress", () => {
    it.each([
        ["nothing", "ff40", ""],
        ["one zero byte", "00fe80", "00"],
        ["a data table", STREAM, MOLECULE],
    ])("decompresses %s", (_, stream, data) => {
        expect(bytesToHex(arDecompress(hexToBytes(stream)))).toBe(data);
    });

    it("never reads past the end marker, so bytes after it change nothing", () => {
        expect(bytesToHex(arDecompress(hexToBytes(`${STREAM}0000000000`)))).toBe(MOLECULE);
        expect(bytesToHex(arDecompress(hexToBytes(`${STREAM}ffffffffff`)))).toBe(MOLECULE);
    });

    it("pads a short stream with zero bits, as the crate does, so a stream cut short can read as other data", () => {
        expect(bytesToHex(arDecompress(hexToBytes(STREAM.slice(0, -4))))).toBe(
            "54000000100000002000000040000000050000000000000000000000000000000303030303030303030303030303030303030303030303030303030303030303140000000800000000000000100d",
        );
    });

    it("pads with exactly 48 zero bits: a stream ending on the 48th reads, one needing 56 does not", () => {
        expect(bytesToHex(arDecompress(hexToBytes(`4e${"00".repeat(10)}`)))).toBe("4e4e4e4e4e4e4e4ee04fd2d8a5");
        expect(invoiceRefusal(() => arDecompress(hexToBytes(`4e${"00".repeat(9)}`)))).toEqual(RUNS_OUT);
    });

    it("refuses a stream that runs out of input and padding before the end marker", () => {
        expect(invoiceRefusal(() => arDecompress(new Uint8Array(0)))).toEqual(RUNS_OUT);
        expect(invoiceRefusal(() => arDecompress(hexToBytes(STREAM.slice(0, -2))))).toEqual(RUNS_OUT);
    });

    it("decompresses data of exactly the limit and refuses one byte more", () => {
        const atLimit = new Uint8Array(MAX_INVOICE_DATA_LENGTH);
        expect(arDecompress(arEncompress(atLimit))).toEqual(atLimit);
        expect(invoiceRefusal(() => arDecompress(arEncompress(new Uint8Array(MAX_INVOICE_DATA_LENGTH + 1))))).toEqual(
            new InvoiceError("compressed", "must decompress to at most 16384 bytes"),
        );
    });

    it("round-trips every byte value in either order", () => {
        const ascending = Uint8Array.from({ length: 256 }, (_, index) => index);
        const descending = ascending.slice().reverse();
        expect(arDecompress(arEncompress(ascending))).toEqual(ascending);
        expect(arDecompress(arEncompress(descending))).toEqual(descending);
    });
});
