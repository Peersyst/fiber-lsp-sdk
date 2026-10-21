import { hexToBytes } from "@noble/hashes/utils.js";
import { assertTwoDistinctKeys, isAggregatedNonceHalf, nonceHalves } from "../../../../src/common/utils/musig.utils";

const G = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const G2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

describe("nonceHalves", () => {
    it("splits a 66-byte nonce at its 33rd byte", () => {
        const [first, second] = nonceHalves(hexToBytes(G + G2));
        expect(first).toEqual(hexToBytes(G));
        expect(second).toEqual(hexToBytes(G2));
    });
});

describe("isAggregatedNonceHalf", () => {
    it.each([
        ["a point on the curve", hexToBytes(G)],
        ["33 zero bytes, musig2's encoding of infinity", new Uint8Array(33)],
    ])("accepts %s", (_, half) => {
        expect(isAggregatedNonceHalf(half)).toBe(true);
    });

    it.each([
        ["an x off the curve", hexToBytes("03".repeat(33))],
        ["an uncompressed prefix", hexToBytes(`04${G.slice(2)}`)],
        ["a zero prefix that is not infinity", hexToBytes(`${"00".repeat(32)}01`)],
        ["32 zero bytes", new Uint8Array(32)],
        ["34 zero bytes", new Uint8Array(34)],
        ["the point with a byte appended", hexToBytes(`${G}00`)],
        ["zeros that are not bytes", new Array<number>(33).fill(0)],
        ["infinity in hex", "00".repeat(33)],
        ["null", null],
    ])("refuses %s", (_, half) => {
        expect(isAggregatedNonceHalf(half)).toBe(false);
    });
});

describe("assertTwoDistinctKeys", () => {
    const FIRST = hexToBytes(G);
    const SECOND = hexToBytes(G2);

    it("returns the two keys in the order of the list", () => {
        expect(assertTwoDistinctKeys("keys", [SECOND, FIRST])).toEqual([SECOND, FIRST]);
    });

    // The shape only: whether a key is on the curve is each caller's rule.
    it("accepts 33 bytes off the curve", () => {
        expect(() => assertTwoDistinctKeys("keys", [FIRST, new Uint8Array(33)])).not.toThrow();
    });

    it.each([
        ["not an array", FIRST],
        ["undefined", undefined],
        ["null", null],
        ["one key", [FIRST]],
        ["three keys", [FIRST, SECOND, hexToBytes("03".repeat(33))]],
    ])("refuses a key list that is %s", (_, keys) => {
        expect(() => assertTwoDistinctKeys("keys", keys)).toThrow(new TypeError("keys must be exactly 2 public keys"));
    });

    it.each([
        ["a 32-byte first key", [FIRST.subarray(1), SECOND], "keys[0] must be 33 bytes, got 32"],
        ["a 34-byte second key", [FIRST, Uint8Array.of(...SECOND, 0)], "keys[1] must be 33 bytes, got 34"],
        ["a first key that is not bytes", [G, SECOND], "keys[0] must be a Uint8Array"],
        ["a second key that is not bytes", [FIRST, G2], "keys[1] must be a Uint8Array"],
    ])("refuses %s", (_, keys, message) => {
        expect(() => assertTwoDistinctKeys("keys", keys)).toThrow(new TypeError(message));
    });

    it("refuses the same key twice, even as two arrays", () => {
        expect(() => assertTwoDistinctKeys("keys", [FIRST, hexToBytes(G)])).toThrow(new TypeError("keys must be two distinct public keys"));
    });
});
