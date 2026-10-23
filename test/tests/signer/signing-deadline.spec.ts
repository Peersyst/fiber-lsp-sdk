import { UINT64_MAX } from "../../../src/common";
import { pendingTlcSignatureDeadline, tlcExpiryDelay } from "../../../src/signer/signing-deadline";

// Fiber's `MILLI_SECONDS_PER_EPOCH` (`fiber-lib/src/fiber/config.rs:44-50`): 4 h in a release build, 2 s in a debug one.
const RELEASE = 14_400_000;
const DEBUG = 2_000;

// `EpochNumberWithFraction` full values: the length in bits 40-55, the index in 24-39, the number in 0-23.
const ONE_EPOCH = 0x10000000001n;

describe("tlcExpiryDelay", () => {
    // (1 + 0 / 1) * 14_400_000 * 2 / 3 = 9_600_000, exact in f64.
    it("takes two thirds of one epoch of a release build", () => {
        expect(tlcExpiryDelay(ONE_EPOCH, RELEASE)).toBe(9_600_000n);
    });

    // (1 + 0 / 1) * 2_000 * 2 / 3 = 1_333.33..., truncated as `as u64` truncates.
    it("takes two thirds of one epoch of a debug build, truncated", () => {
        expect(tlcExpiryDelay(ONE_EPOCH, DEBUG)).toBe(1_333n);
    });

    it.each([
        // 4 + 1/3 = 4.333333333333333; * 14_400_000 = 62_399_999.99999999; * 2 = 124_799_999.99999999; / 3 = 41_599_999.99999999.
        // Taking 14_400_000 * 2 / 3 first would give 41_600_000.
        ["4 + 1/3", 0x30001000004n, 41_599_999n],
        // 1 + 2/3 = 1.6666666666666665; * 14_400_000 = 23_999_999.999999996; * 2 = 47_999_999.99999999; / 3 = 15_999_999.999999998.
        // Taking (1 * 3 + 2) / 3 first would give 16_000_000.
        ["1 + 2/3", 0x30002000001n, 15_999_999n],
        // 0 + 1/3 = 0.3333333333333333; * 14_400_000 = 4_800_000, the error under half a unit; * 2 / 3 = 3_200_000.
        ["0 + 1/3", 0x30001000000n, 3_200_000n],
    ])("computes %s epochs in fiber's f64 arithmetic, in its order", (_, epoch, delay) => {
        expect(tlcExpiryDelay(epoch, RELEASE)).toBe(delay);
    });

    // CKB's `from_full_value` rewrites a zero length to the fraction 0/1.
    it.each([
        ["index 0", 0x1n],
        ["index 5", 0x5000001n],
    ])("reads a zero length with %s as the whole epoch number", (_, epoch) => {
        expect(tlcExpiryDelay(epoch, RELEASE)).toBe(9_600_000n);
    });

    // (0 + 5 / 2) * 14_400_000 * 2 / 3 = 24_000_000: CKB checks no well-formedness on the way.
    it("takes an index above the length as the fraction it states", () => {
        expect(tlcExpiryDelay(0x20005000000n, RELEASE)).toBe(24_000_000n);
    });

    // (0 + 1 / 2) * 14_400_000 * 2 / 3 = 4_800_000: flags in bits 56-63 belong to no field.
    it("reads each field under its own mask, the bits above the length ignored", () => {
        expect(tlcExpiryDelay(0xff00020001000000n, RELEASE)).toBe(4_800_000n);
    });

    // (8_388_608 + 32_768 / 32_768) * 2_000 * 2 / 3 = 11_184_812_000.
    it("reads the top bit of each field", () => {
        expect(tlcExpiryDelay(0x80008000800000n, DEBUG)).toBe(11_184_812_000n);
    });

    // (1 + 1 / 1) * 14_400_000 * 2 / 3 = 19_200_000: only a zero length is normalized.
    it("reads the index of a length-1 epoch", () => {
        expect(tlcExpiryDelay(0x10001000001n, RELEASE)).toBe(19_200_000n);
    });

    it("is zero for a zero delay", () => {
        expect(tlcExpiryDelay(0x10000000000n, RELEASE)).toBe(0n);
    });

    describe("the `as u64` cast", () => {
        // 6_144 * 2^52 * 2 / 3 = 2^64 exactly, the first value the cast saturates at.
        it("saturates at 2^64 to u64::MAX", () => {
            expect(tlcExpiryDelay(0x10000001800n, 2 ** 52)).toBe(UINT64_MAX);
        });

        // 6_143 * 2^53 / 3 = 18_443_741_673_957_971_285.33..., rounded to the f64 grid of 2_048 at that magnitude.
        it("keeps a value below 2^64 on the f64 grid", () => {
            expect(tlcExpiryDelay(0x100000017ffn, 2 ** 52)).toBe(18_443_741_673_957_971_968n);
        });

        // 3_072 * (2^53 - 1) rounds to (3 * 2^53 - 4) * 2^10, and * 2 / 3 to 2^64 - 2_048, the largest f64 below 2^64.
        it("keeps the largest f64 below 2^64", () => {
            expect(tlcExpiryDelay(0x10000000c00n, Number.MAX_SAFE_INTEGER)).toBe(18_446_744_073_709_549_568n);
        });

        // (16_777_215 + 65_535 / 1) * (2^53 - 1) * 2 / 3 = 1.01e23.
        it("saturates the widest delay over the widest epoch", () => {
            expect(tlcExpiryDelay(0x1ffffffffffn, Number.MAX_SAFE_INTEGER)).toBe(UINT64_MAX);
        });

        it("saturates an infinite product to u64::MAX", () => {
            expect(tlcExpiryDelay(ONE_EPOCH, Number.POSITIVE_INFINITY)).toBe(UINT64_MAX);
        });

        // Unreachable through the dispatch, which takes only a positive epoch: the cast is Rust's for every f64.
        it.each([
            ["NaN", Number.NaN],
            ["a negative product", -DEBUG],
        ])("casts %s to zero", (_, millisecondsPerEpoch) => {
            expect(tlcExpiryDelay(ONE_EPOCH, millisecondsPerEpoch)).toBe(0n);
        });
    });
});

describe("pendingTlcSignatureDeadline", () => {
    it("is null with no TLC", () => {
        expect(pendingTlcSignatureDeadline([], ONE_EPOCH, RELEASE)).toBeNull();
    });

    // 1_760_576_400_000 - 9_600_000.
    it("takes a TLC's expiry less two thirds of the delay", () => {
        expect(pendingTlcSignatureDeadline([{ expiryMs: 1_760_576_400_000n }], ONE_EPOCH, RELEASE)).toBe(1_760_566_800_000n);
    });

    // 1_760_576_400_000 - 1_333.
    it("reserves the delay under the build's epoch", () => {
        expect(pendingTlcSignatureDeadline([{ expiryMs: 1_760_576_400_000n }], ONE_EPOCH, DEBUG)).toBe(1_760_576_398_667n);
    });

    it("takes the earliest of several, neither the first nor the last", () => {
        const tlcs = [{ expiryMs: 1_760_580_000_000n }, { expiryMs: 1_760_576_400_000n }, { expiryMs: 1_760_583_600_000n }];
        expect(pendingTlcSignatureDeadline(tlcs, ONE_EPOCH, RELEASE)).toBe(1_760_566_800_000n);
    });

    // `saturating_sub`: an expiry the reserve reaches gives a deadline already past.
    it.each([
        [9_599_999n, 0n],
        [9_600_000n, 0n],
        [9_600_001n, 1n],
    ])("takes an expiry of %p less the 9_600_000 reserve as %p", (expiryMs, deadline) => {
        expect(pendingTlcSignatureDeadline([{ expiryMs }], ONE_EPOCH, RELEASE)).toBe(deadline);
    });

    it("takes a saturated expiry as the earliest", () => {
        const tlcs = [{ expiryMs: 1_760_576_400_000n }, { expiryMs: 9_599_999n }];
        expect(pendingTlcSignatureDeadline(tlcs, ONE_EPOCH, RELEASE)).toBe(0n);
    });

    it("takes even u64::MAX to zero under a saturated reserve", () => {
        expect(pendingTlcSignatureDeadline([{ expiryMs: UINT64_MAX }], 0x10000001800n, 2 ** 52)).toBe(0n);
    });
});
