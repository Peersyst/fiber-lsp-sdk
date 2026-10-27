import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { pubkeyOf } from "../../../../src/derivation/fiber-scheme";
import { aggregateXOnlyPubkey, commitmentCellValue, sortDistinctPubkeys, subtractTxFee } from "../../../../src/digest/utils/digest.utils";

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

describe("sortDistinctPubkeys", () => {
    // G, -G and 2G: G and -G differ in their first byte alone, G and 2G share it.
    const G = hexToBytes("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    const NEG_G = hexToBytes("0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    const TWO_G = hexToBytes("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");

    it("puts the lower key first, whichever order they come in", () => {
        expect(sortDistinctPubkeys("first", G, "second", NEG_G)).toEqual([G, NEG_G]);
        expect(sortDistinctPubkeys("first", NEG_G, "second", G)).toEqual([G, NEG_G]);
    });

    it("compares past the first byte", () => {
        expect(sortDistinctPubkeys("first", TWO_G, "second", G)).toEqual([G, TWO_G]);
        expect(sortDistinctPubkeys("first", G, "second", TWO_G)).toEqual([G, TWO_G]);
    });

    it.each([
        ["absent", undefined, new TypeError("first must be a Uint8Array")],
        ["of 32 bytes", KEY_A.subarray(1), new TypeError("first must be 33 bytes, got 32")],
        ["off the curve", Uint8Array.of(0x02, ...new Uint8Array(32)), new TypeError("first must be a compressed point on secp256k1")],
    ])("refuses the first key %s, naming it", (_, key, error) => {
        expect(() => sortDistinctPubkeys("first", key, "second", KEY_B)).toThrow(error);
    });

    it.each([
        ["absent", undefined, new TypeError("second must be a Uint8Array")],
        ["of 32 bytes", KEY_B.subarray(1), new TypeError("second must be 33 bytes, got 32")],
        ["off the curve", Uint8Array.of(0x02, ...new Uint8Array(32)), new TypeError("second must be a compressed point on secp256k1")],
    ])("refuses the second key %s, naming it", (_, key, error) => {
        expect(() => sortDistinctPubkeys("first", KEY_A, "second", key)).toThrow(error);
    });

    it("refuses the same key twice, naming both", () => {
        expect(() => sortDistinctPubkeys("first", KEY_A, "second", Uint8Array.from(KEY_A))).toThrow(
            new TypeError("first and second must be two distinct public keys"),
        );
    });
});

describe("subtractTxFee", () => {
    it("subtracts within bounds", () => {
        expect(subtractTxFee(1000n, 456n)).toBe(544n);
        expect(subtractTxFee(456n, 456n)).toBe(0n);
    });

    it("refuses a fee above the capacity", () => {
        expect(() => subtractTxFee(455n, 456n)).toThrow(RangeError);
    });

    it("refuses a total beyond u64, before subtracting", () => {
        expect(() => subtractTxFee(1n << 64n, 1n)).toThrow(RangeError);
    });
});

describe("commitmentCellValue", () => {
    const CKB = {
        udtTypeScript: null,
        liquidCapacityShannons: 80_500_000_000n,
        localReservedCkbShannons: 4_200_000_000n,
        remoteReservedCkbShannons: 6_300_000_000n,
    };
    const UDT = { ...CKB, udtTypeScript: { codeHash: new Uint8Array(32).fill(0xaa), hashType: "type" as const, args: new Uint8Array(0) } };

    it("holds the liquid capacity and both reserves as capacity on a CKB channel, less the fee, with no data", () => {
        const { capacityShannons, data } = commitmentCellValue(CKB, 456n);
        expect(capacityShannons).toBe(90_999_999_544n);
        expect(data).toEqual(new Uint8Array(0));
    });

    it("holds only the reserves as capacity on a UDT channel, the liquid capacity as its u128 data", () => {
        const { capacityShannons, data } = commitmentCellValue(UDT, 456n);
        expect(capacityShannons).toBe(10_499_999_544n);
        expect(bytesToHex(data)).toBe("00852cbe12000000" + "00".repeat(8));
    });

    it("refuses a fee the capacity cannot cover, the shannon past it", () => {
        expect(commitmentCellValue(UDT, 10_500_000_000n).capacityShannons).toBe(0n);
        expect(() => commitmentCellValue(UDT, 10_500_000_001n)).toThrow(
            new RangeError("capacity 10500000000 cannot cover the fee 10500000001"),
        );
    });

    it("holds a CKB cell whose liquid capacity and reserves add up to a u64, and refuses the shannon past it", () => {
        const max = (1n << 64n) - 1n;
        const liquid = max - CKB.localReservedCkbShannons - CKB.remoteReservedCkbShannons;
        expect(commitmentCellValue({ ...CKB, liquidCapacityShannons: liquid }, 0n).capacityShannons).toBe(max);
        expect(() => commitmentCellValue({ ...CKB, liquidCapacityShannons: liquid + 1n }, 0n)).toThrow(
            new RangeError(`total capacity must be a bigint between 0 and ${max}, got ${max + 1n}`),
        );
    });

    it("refuses a CKB cell beyond a u64", () => {
        expect(() => commitmentCellValue({ ...CKB, liquidCapacityShannons: 1n << 64n }, 0n)).toThrow(RangeError);
    });
});
