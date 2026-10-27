import type { HoldInvoicePolicyRecord, HoldInvoiceReleaseChannel, HoldInvoiceReleaseReading, PolicyViewTlc } from "../../../src/policy";
import { HoldInvoiceError } from "../../../src/policy";
import { judgeHoldInvoiceRelease, listHoldInvoiceTlcs } from "../../../src/policy/hold-invoice-release";

const PAYMENT_HASH = "5b36757f3945408453a6282c4aba2c78bfaba94219e459932924b01f7fc09d1e";
const BOUND_PAYMENT_HASH = "5b36757f3945408453a6282c4aba2c78bfaba942";
// Shares the bound 20 bytes, so only the full-hash layout tells it apart.
const TWIN_PAYMENT_HASH = "5b36757f3945408453a6282c4aba2c78bfaba942000000000000000000000000";

const INVOICE: HoldInvoicePolicyRecord = {
    version: 1,
    paymentHash: PAYMENT_HASH,
    amountShannons: "2250000000",
    hashAlgorithm: "sha256",
    invoiceIndex: 1761475200000,
    released: false,
    channelIndexes: [3, 4],
};

// Expires at 1750000000000 ms.
const HELD: PolicyViewTlc = {
    direction: "received",
    hashAlgorithm: "sha256",
    boundPaymentHash: BOUND_PAYMENT_HASH,
    fullPaymentHash: null,
    amountShannons: "2250000000",
    expirySeconds: "1750000000",
};

const OFFERED: PolicyViewTlc = {
    direction: "offered",
    hashAlgorithm: "ckb-hash",
    boundPaymentHash: "6844f645bb03ff9d1c9c48ee5e9e971be09bf34a",
    fullPaymentHash: null,
    amountShannons: "1500000000",
    expirySeconds: "1723257890",
};

const DELAY = "1099511627777";

// One millisecond before the held TLC's expiry less the margin, the last instant a release passes.
const TIMING: HoldInvoiceReleaseReading = { nowMs: 1749999399999, releaseMarginMs: () => 600000n };

function errorOf(run: () => void): unknown {
    try {
        run();
    } catch (error) {
        return error;
    }
    throw new Error("expected the release to be refused");
}

describe("listHoldInvoiceTlcs", () => {
    it("lists the invoice's TLCs of a view, in its order, and nothing under another hash", () => {
        const half = { ...HELD, amountShannons: "1125000000" };
        expect(listHoldInvoiceTlcs({ tlcs: [half, OFFERED, HELD] }, INVOICE)).toEqual([half, HELD]);
    });

    it("lists a TLC binding the invoice's whole hash, and leaves out its twin", () => {
        const own = { ...HELD, fullPaymentHash: PAYMENT_HASH };
        const twin = { ...HELD, fullPaymentHash: TWIN_PAYMENT_HASH };
        expect(listHoldInvoiceTlcs({ tlcs: [twin, own] }, INVOICE)).toEqual([own]);
    });
});

describe("judgeHoldInvoiceRelease", () => {
    it("passes a channel holding the invoice's amount in both views", () => {
        const channels = new Map<number, HoldInvoiceReleaseChannel>([
            [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [HELD] }, local: { tlcs: [HELD] } } }],
        ]);
        expect(() => judgeHoldInvoiceRelease(INVOICE, channels, TIMING)).not.toThrow();
    });

    // Fiber takes a TLC of at least the invoice's amount.
    it("passes a TLC one shannon above the amount", () => {
        const over = { ...HELD, amountShannons: "2250000001" };
        const channels = new Map<number, HoldInvoiceReleaseChannel>([
            [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [over] }, local: { tlcs: [over] } } }],
        ]);
        expect(() => judgeHoldInvoiceRelease(INVOICE, channels, TIMING)).not.toThrow();
    });

    it("refuses a TLC one shannon short of the amount", () => {
        const short = { ...HELD, amountShannons: "2249999999" };
        const channels = new Map<number, HoldInvoiceReleaseChannel>([
            [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [short] }, local: { tlcs: [short] } } }],
        ]);
        const error = errorOf(() => judgeHoldInvoiceRelease(INVOICE, channels, TIMING));
        expect(error).toBeInstanceOf(HoldInvoiceError);
        expect(error).toMatchObject({
            code: "not_held",
            message: `the channels hold 2249999999 shannons under ${PAYMENT_HASH}, each at its view holding less, short of the invoice's 2250000000`,
        });
    });

    it.each([
        ["remote", { remote: { tlcs: [HELD] }, local: { tlcs: [] } }],
        ["local", { remote: { tlcs: [] }, local: { tlcs: [HELD] } }],
    ])("refuses the invoice held in the %s view alone", (_, views) => {
        const channels = new Map<number, HoldInvoiceReleaseChannel>([[3, { pins: { commitmentDelayEpoch: DELAY }, views }]]);
        expect(errorOf(() => judgeHoldInvoiceRelease(INVOICE, channels, TIMING))).toMatchObject({
            code: "not_held",
            message: `the channels hold 0 shannons under ${PAYMENT_HASH}, each at its view holding less, short of the invoice's 2250000000`,
        });
    });

    it("refuses an invoice whose channels list no TLC of it, or that lists no channel", () => {
        const channels = new Map<number, HoldInvoiceReleaseChannel>([
            [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [OFFERED] }, local: { tlcs: [] } } }],
        ]);
        expect(errorOf(() => judgeHoldInvoiceRelease(INVOICE, channels, TIMING))).toMatchObject({ code: "not_held" });
        expect(errorOf(() => judgeHoldInvoiceRelease(INVOICE, new Map(), TIMING))).toMatchObject({ code: "not_held" });
    });

    it("sums the channels it lists", () => {
        const part = { ...HELD, amountShannons: "1125000000" };
        const channels = new Map<number, HoldInvoiceReleaseChannel>([
            [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [part] }, local: { tlcs: [part] } } }],
            [4, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [part] }, local: { tlcs: [part] } } }],
        ]);
        expect(() => judgeHoldInvoiceRelease(INVOICE, channels, TIMING)).not.toThrow();
    });

    it("sums the TLCs of one view", () => {
        const part = { ...HELD, amountShannons: "1125000000" };
        const channels = new Map<number, HoldInvoiceReleaseChannel>([
            [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [part, part] }, local: { tlcs: [HELD] } } }],
        ]);
        expect(() => judgeHoldInvoiceRelease(INVOICE, channels, TIMING)).not.toThrow();
    });

    // The node may broadcast the remote commitment of one channel and the local one of the other.
    it("refuses two channels holding the invoice in crossed views", () => {
        const channels = new Map<number, HoldInvoiceReleaseChannel>([
            [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [HELD] }, local: { tlcs: [] } } }],
            [4, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [] }, local: { tlcs: [HELD] } } }],
        ]);
        expect(errorOf(() => judgeHoldInvoiceRelease(INVOICE, channels, TIMING))).toMatchObject({
            code: "not_held",
            message: `the channels hold 0 shannons under ${PAYMENT_HASH}, each at its view holding less, short of the invoice's 2250000000`,
        });
    });

    it.each([
        ["the remote view", "1250000000", "2250000000"],
        ["the local view", "2250000000", "1250000000"],
    ])("counts a channel at %s when it holds less there", (_, remote, local) => {
        const rest = (amountShannons: string) => ({ ...HELD, amountShannons });
        const passing = new Map<number, HoldInvoiceReleaseChannel>([
            [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [rest(remote)] }, local: { tlcs: [rest(local)] } } }],
            [
                4,
                {
                    pins: { commitmentDelayEpoch: DELAY },
                    views: { remote: { tlcs: [rest("1000000000")] }, local: { tlcs: [rest("1000000000")] } },
                },
            ],
        ]);
        expect(() => judgeHoldInvoiceRelease(INVOICE, passing, TIMING)).not.toThrow();

        const short = new Map<number, HoldInvoiceReleaseChannel>([
            [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [rest(remote)] }, local: { tlcs: [rest(local)] } } }],
            [
                4,
                {
                    pins: { commitmentDelayEpoch: DELAY },
                    views: { remote: { tlcs: [rest("999999999")] }, local: { tlcs: [rest("999999999")] } },
                },
            ],
        ]);
        expect(errorOf(() => judgeHoldInvoiceRelease(INVOICE, short, TIMING))).toMatchObject({
            code: "not_held",
            message: `the channels hold 2249999999 shannons under ${PAYMENT_HASH}, each at its view holding less, short of the invoice's 2250000000`,
        });
    });

    it("counts a TLC binding the invoice's whole hash, and not its twin", () => {
        const own = { ...HELD, fullPaymentHash: PAYMENT_HASH };
        const twin = { ...HELD, fullPaymentHash: TWIN_PAYMENT_HASH };
        const owned = new Map<number, HoldInvoiceReleaseChannel>([
            [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [own] }, local: { tlcs: [own] } } }],
        ]);
        expect(() => judgeHoldInvoiceRelease(INVOICE, owned, TIMING)).not.toThrow();
        const twinned = new Map<number, HoldInvoiceReleaseChannel>([
            [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [twin] }, local: { tlcs: [twin] } } }],
        ]);
        expect(errorOf(() => judgeHoldInvoiceRelease(INVOICE, twinned, TIMING))).toMatchObject({ code: "not_held" });
    });

    it("refuses a TLC of the invoice under another algorithm than the invoice's", () => {
        const other = { ...HELD, hashAlgorithm: "ckb-hash" as const };
        const channels = new Map<number, HoldInvoiceReleaseChannel>([
            [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [HELD] }, local: { tlcs: [HELD] } } }],
            [4, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [] }, local: { tlcs: [other] } } }],
        ]);
        const error = errorOf(() => judgeHoldInvoiceRelease(INVOICE, channels, TIMING));
        expect(error).toBeInstanceOf(HoldInvoiceError);
        expect(error).toMatchObject({
            code: "algorithm_mismatch",
            message: `channel index 4 lists a TLC under ${PAYMENT_HASH} locked with another algorithm than the invoice's`,
        });
    });

    it.each([
        ["remote", { remote: { tlcs: [HELD, OFFERED] }, local: { tlcs: [HELD] } }],
        ["local", { remote: { tlcs: [HELD] }, local: { tlcs: [OFFERED, HELD] } }],
    ])("refuses an offered TLC in the %s view of a channel holding the invoice", (_, views) => {
        const channels = new Map<number, HoldInvoiceReleaseChannel>([[3, { pins: { commitmentDelayEpoch: DELAY }, views }]]);
        const error = errorOf(() => judgeHoldInvoiceRelease(INVOICE, channels, TIMING));
        expect(error).toBeInstanceOf(HoldInvoiceError);
        expect(error).toMatchObject({
            code: "offered_in_flight",
            message: `channel index 3 lists an offered TLC, so the preimage of ${PAYMENT_HASH} is not released yet`,
        });
    });

    it("lets a channel listing no TLC of the invoice list offered TLCs", () => {
        const channels = new Map<number, HoldInvoiceReleaseChannel>([
            [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [OFFERED] }, local: { tlcs: [OFFERED] } } }],
            [4, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [HELD] }, local: { tlcs: [HELD] } } }],
        ]);
        expect(() => judgeHoldInvoiceRelease(INVOICE, channels, TIMING)).not.toThrow();
    });

    describe("the expiry", () => {
        // Fiber's own device SDK refuses an expiry at or before now plus the margin.
        it("refuses a TLC expiring exactly at the margin past now", () => {
            const channels = new Map<number, HoldInvoiceReleaseChannel>([
                [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [HELD] }, local: { tlcs: [HELD] } } }],
            ]);
            const error = errorOf(() => judgeHoldInvoiceRelease(INVOICE, channels, { ...TIMING, nowMs: 1749999400000 }));
            expect(error).toBeInstanceOf(HoldInvoiceError);
            expect(error).toMatchObject({
                code: "expiry_too_close",
                message: `channel index 3 holds a TLC under ${PAYMENT_HASH} expiring at 1750000000000, not after 1750000000000`,
            });
        });

        it.each([
            [
                "remote",
                { remote: { tlcs: [HELD, { ...HELD, amountShannons: "1", expirySeconds: "1749999400" }] }, local: { tlcs: [HELD] } },
            ],
            ["local", { remote: { tlcs: [HELD] }, local: { tlcs: [HELD, { ...HELD, amountShannons: "1", expirySeconds: "1749999400" }] } }],
        ])("checks every TLC of the invoice in the %s view, past the first", (_, views) => {
            const channels = new Map<number, HoldInvoiceReleaseChannel>([[3, { pins: { commitmentDelayEpoch: DELAY }, views }]]);
            expect(
                errorOf(() => judgeHoldInvoiceRelease(INVOICE, channels, { nowMs: 1749998800000, releaseMarginMs: () => 600000n })),
            ).toMatchObject({
                code: "expiry_too_close",
                message: `channel index 3 holds a TLC under ${PAYMENT_HASH} expiring at 1749999400000, not after 1749999400000`,
            });
        });

        it("reads each channel's margin from the delay it pinned", () => {
            const part = { ...HELD, amountShannons: "1125000000" };
            const releaseMarginMs = jest.fn((delay: bigint) => (delay === 1099511627777n ? 600000n : 600001n));
            const channels = new Map<number, HoldInvoiceReleaseChannel>([
                [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [part] }, local: { tlcs: [part] } } }],
                [4, { pins: { commitmentDelayEpoch: "1099511627778" }, views: { remote: { tlcs: [part] }, local: { tlcs: [part] } } }],
            ]);
            expect(errorOf(() => judgeHoldInvoiceRelease(INVOICE, channels, { ...TIMING, releaseMarginMs }))).toMatchObject({
                code: "expiry_too_close",
                message: `channel index 4 holds a TLC under ${PAYMENT_HASH} expiring at 1750000000000, not after 1750000000000`,
            });
            expect(releaseMarginMs.mock.calls).toEqual([[1099511627777n], [1099511627778n]]);
        });

        // A signed commitment pins its delay: only a broken record lists a TLC without one.
        it("throws a host error for a channel listing a TLC of the invoice with no delay pinned", () => {
            const channels = new Map<number, HoldInvoiceReleaseChannel>([
                [3, { pins: {}, views: { remote: { tlcs: [HELD] }, local: { tlcs: [HELD] } } }],
            ]);
            const error = errorOf(() => judgeHoldInvoiceRelease(INVOICE, channels, TIMING));
            expect(error).not.toBeInstanceOf(HoldInvoiceError);
            expect(error).toEqual(new TypeError("channel index 3 lists a TLC of a hold invoice but pins no commitment delay"));
        });

        it("asks no margin of a channel listing no TLC of the invoice, delay pinned or not", () => {
            const releaseMarginMs = jest.fn(() => 600000n);
            const channels = new Map<number, HoldInvoiceReleaseChannel>([
                [3, { pins: {}, views: { remote: { tlcs: [] }, local: { tlcs: [] } } }],
                [4, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [HELD] }, local: { tlcs: [HELD] } } }],
            ]);
            expect(() => judgeHoldInvoiceRelease(INVOICE, channels, { ...TIMING, releaseMarginMs })).not.toThrow();
            expect(releaseMarginMs.mock.calls).toEqual([[1099511627777n]]);
        });

        it.each([
            ["a negative margin", -1n],
            ["a margin past a u64", 18446744073709551616n],
            ["a margin in a number", 600000 as unknown as bigint],
        ])("throws on %s", (_, margin) => {
            const channels = new Map<number, HoldInvoiceReleaseChannel>([
                [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [HELD] }, local: { tlcs: [HELD] } } }],
            ]);
            expect(() => judgeHoldInvoiceRelease(INVOICE, channels, { ...TIMING, releaseMarginMs: () => margin })).toThrow(
                new RangeError(`the release margin must be a bigint between 0 and 18446744073709551615, got ${margin}`),
            );
        });

        it("takes a margin of a u64's top, which no TLC expiry clears", () => {
            const channels = new Map<number, HoldInvoiceReleaseChannel>([
                [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [HELD] }, local: { tlcs: [HELD] } } }],
            ]);
            const error = errorOf(() =>
                judgeHoldInvoiceRelease(INVOICE, channels, { ...TIMING, releaseMarginMs: () => 18446744073709551615n }),
            );
            expect(error).toBeInstanceOf(HoldInvoiceError);
            expect(error).toMatchObject({
                code: "expiry_too_close",
                message: `channel index 3 holds a TLC under ${PAYMENT_HASH} expiring at 1750000000000, not after 18446745823708951614`,
            });
        });

        it("takes a margin of zero, the TLC still unexpired", () => {
            const channels = new Map<number, HoldInvoiceReleaseChannel>([
                [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [HELD] }, local: { tlcs: [HELD] } } }],
            ]);
            expect(() => judgeHoldInvoiceRelease(INVOICE, channels, { nowMs: 1749999999999, releaseMarginMs: () => 0n })).not.toThrow();
            expect(
                errorOf(() => judgeHoldInvoiceRelease(INVOICE, channels, { nowMs: 1750000000000, releaseMarginMs: () => 0n })),
            ).toMatchObject({
                code: "expiry_too_close",
            });
        });
    });

    describe("the order of the refusals", () => {
        it("refuses another algorithm before an offered TLC beside it", () => {
            const other = { ...HELD, hashAlgorithm: "ckb-hash" as const };
            const channels = new Map<number, HoldInvoiceReleaseChannel>([
                [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [other, OFFERED] }, local: { tlcs: [] } } }],
            ]);
            expect(errorOf(() => judgeHoldInvoiceRelease(INVOICE, channels, TIMING))).toMatchObject({ code: "algorithm_mismatch" });
        });

        it("refuses an offered TLC before an amount short", () => {
            const channels = new Map<number, HoldInvoiceReleaseChannel>([
                [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [HELD, OFFERED] }, local: { tlcs: [] } } }],
            ]);
            expect(errorOf(() => judgeHoldInvoiceRelease(INVOICE, channels, TIMING))).toMatchObject({ code: "offered_in_flight" });
        });

        it("refuses a later channel's offered TLC before an amount the earlier one holds short", () => {
            const channels = new Map<number, HoldInvoiceReleaseChannel>([
                [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [HELD] }, local: { tlcs: [] } } }],
                [4, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [HELD, OFFERED] }, local: { tlcs: [HELD] } } }],
            ]);
            expect(errorOf(() => judgeHoldInvoiceRelease(INVOICE, channels, TIMING))).toMatchObject({
                code: "offered_in_flight",
                message: `channel index 4 lists an offered TLC, so the preimage of ${PAYMENT_HASH} is not released yet`,
            });
        });

        it("refuses an amount short before an expiry too close", () => {
            const short = { ...HELD, amountShannons: "2249999999" };
            const channels = new Map<number, HoldInvoiceReleaseChannel>([
                [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [short] }, local: { tlcs: [short] } } }],
            ]);
            expect(errorOf(() => judgeHoldInvoiceRelease(INVOICE, channels, { ...TIMING, nowMs: 1750000000000 }))).toMatchObject({
                code: "not_held",
            });
        });

        it("reads no margin before the amount is held", () => {
            const releaseMarginMs = jest.fn(() => 600000n);
            const channels = new Map<number, HoldInvoiceReleaseChannel>([
                [3, { pins: { commitmentDelayEpoch: DELAY }, views: { remote: { tlcs: [HELD] }, local: { tlcs: [] } } }],
            ]);
            expect(errorOf(() => judgeHoldInvoiceRelease(INVOICE, channels, { ...TIMING, releaseMarginMs }))).toMatchObject({
                code: "not_held",
            });
            expect(releaseMarginMs).not.toHaveBeenCalled();
        });
    });
});
