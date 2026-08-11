import { bytesToHex } from "@noble/hashes/utils.js";
import { pubkeyOf } from "../../../../src/derivation/fiber-scheme";
import { aggregateXOnlyPubkey, subtractFee } from "../../../../src/digest/utils/digest.utils";

const KEY_A = pubkeyOf(new Uint8Array(32).fill(0x11));
const KEY_B = pubkeyOf(new Uint8Array(32).fill(0x22));

describe("aggregateXOnlyPubkey", () => {
    it("returns a deterministic 32-byte x-only key", () => {
        expect(aggregateXOnlyPubkey([KEY_A, KEY_B])).toHaveLength(32);
        expect(bytesToHex(aggregateXOnlyPubkey([KEY_A, KEY_B]))).toBe(bytesToHex(aggregateXOnlyPubkey([KEY_A, KEY_B])));
    });

    it("is order-sensitive, the property every lock args ordering rule exists for", () => {
        expect(bytesToHex(aggregateXOnlyPubkey([KEY_A, KEY_B]))).not.toBe(bytesToHex(aggregateXOnlyPubkey([KEY_B, KEY_A])));
    });
});

describe("subtractFee", () => {
    it("subtracts within bounds", () => {
        expect(subtractFee(1000n, 456n)).toBe(544n);
        expect(subtractFee(456n, 456n)).toBe(0n);
    });

    it("refuses a fee above the capacity", () => {
        expect(() => subtractFee(455n, 456n)).toThrow(RangeError);
    });

    it("refuses a total beyond u64, before subtracting", () => {
        expect(() => subtractFee(1n << 64n, 1n)).toThrow(RangeError);
    });
});
