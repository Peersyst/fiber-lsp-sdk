import { bytesToHex } from "@noble/hashes/utils.js";
import { ckbBlake2b } from "../../../src/common";
import { MAX_INVOICE_INDEX, deriveHoldInvoicePreimage } from "../../../src/derivation";
import { HoldInvoicePreimages } from "../../../src/signer/hold-invoice-preimages";

const MASTER_SEED = new Uint8Array(32).fill(0x24);
const OTHER_MASTER_SEED = new Uint8Array(32).fill(0x25);
// `deriveHoldInvoicePreimage(MASTER_SEED, 0)`, pinned in the device scheme's spec.
const PREIMAGE_0 = "a6b4115ac71b6ef546f367b8c787b0fd2b12ae68e28c6ba5226ba31d0c7a9fdb";
const PAYMENT_HASH_0 = "f5929b13558e3a2cdccea93a3a8c9bbf45fcc34f61ecb3388035a79b989fa35a";
const PAYMENT_HASH_MAX = "c51dcda364744dd8e4fce485bf4ea0b769c61241dbc0b6d5e4b1a29f46f79947";

describe("HoldInvoicePreimages", () => {
    const preimages = new HoldInvoicePreimages(MASTER_SEED);

    describe("preimage", () => {
        it("is the device scheme's preimage of the index", () => {
            expect(bytesToHex(preimages.preimage(0))).toBe(PREIMAGE_0);
            expect(bytesToHex(preimages.preimage(MAX_INVOICE_INDEX))).toBe(
                bytesToHex(deriveHoldInvoicePreimage(MASTER_SEED, MAX_INVOICE_INDEX)),
            );
        });

        it("returns a fresh copy every call", () => {
            const first = preimages.preimage(0);
            first.fill(0);
            expect(bytesToHex(preimages.preimage(0))).toBe(PREIMAGE_0);
        });

        it.each([-1, 1.5, MAX_INVOICE_INDEX + 1, NaN, undefined])("rejects the invoice index %p", (invoiceIndex) => {
            expect(() => preimages.preimage(invoiceIndex as number)).toThrow(
                new RangeError(`invoiceIndex must be an integer between 0 and ${MAX_INVOICE_INDEX}, got ${invoiceIndex}`),
            );
        });
    });

    describe("hashAlgorithm", () => {
        it("is ckb-hash, the hash paymentHash computes", () => {
            expect(preimages.hashAlgorithm).toBe("ckb-hash");
        });
    });

    describe("paymentHash", () => {
        it("is the preimage under fiber's ckb-hash", () => {
            expect(bytesToHex(preimages.paymentHash(0))).toBe(PAYMENT_HASH_0);
            expect(bytesToHex(ckbBlake2b(preimages.preimage(0)))).toBe(PAYMENT_HASH_0);
            expect(bytesToHex(preimages.paymentHash(MAX_INVOICE_INDEX))).toBe(PAYMENT_HASH_MAX);
        });

        it("returns a fresh copy every call", () => {
            const first = preimages.paymentHash(0);
            first.fill(0);
            expect(bytesToHex(preimages.paymentHash(0))).toBe(PAYMENT_HASH_0);
        });

        it.each([-1, 1.5, MAX_INVOICE_INDEX + 1, NaN, undefined])("rejects the invoice index %p", (invoiceIndex) => {
            expect(() => preimages.paymentHash(invoiceIndex as number)).toThrow(
                new RangeError(`invoiceIndex must be an integer between 0 and ${MAX_INVOICE_INDEX}, got ${invoiceIndex}`),
            );
        });
    });

    describe("construction", () => {
        it("is bound to the master seed", () => {
            expect(bytesToHex(new HoldInvoicePreimages(OTHER_MASTER_SEED).preimage(0))).not.toBe(PREIMAGE_0);
        });

        it("copies the master seed, so a later change to the host's array changes nothing", () => {
            const seed = Uint8Array.from(MASTER_SEED);
            const copied = new HoldInvoicePreimages(seed);
            seed.fill(0x25);
            expect(bytesToHex(copied.preimage(0))).toBe(PREIMAGE_0);
        });

        it.each([31, 33])("rejects a %i-byte master seed", (length) => {
            expect(() => new HoldInvoicePreimages(new Uint8Array(length))).toThrow(
                new TypeError(`masterSeed must be 32 bytes, got ${length}`),
            );
        });

        it("rejects an absent master seed", () => {
            expect(() => new HoldInvoicePreimages(undefined as unknown as Uint8Array)).toThrow(
                new TypeError("masterSeed must be a Uint8Array"),
            );
        });
    });
});
