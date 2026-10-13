import { hexToBytes } from "@noble/hashes/utils.js";
import type { TlcHashAlgorithm } from "../../../src/common";
import type { BalanceRuleContext, PolicyView, PolicyViewSnapshot, PolicyViewTlc } from "../../../src/policy";
import { PolicyRefusalError } from "../../../src/policy";
import { judgeCommitment, judgeOpeningCommitment, judgeShutdown, toPolicyViewTlcs } from "../../../src/policy/balance-rule";

const HASH_A = "aa".repeat(20);
const HASH_B = "bb".repeat(20);
const HASH_R = "cc".repeat(20);
const FULL_HASH_A = HASH_A + "01".repeat(12);
const FULL_HASH_R = HASH_R + "01".repeat(12);

function off(boundPaymentHash: string, amountShannons: string, expirySeconds: string, hashAlgorithm: TlcHashAlgorithm): PolicyViewTlc {
    return { direction: "offered", hashAlgorithm, boundPaymentHash, amountShannons, expirySeconds };
}

function rec(boundPaymentHash: string, amountShannons: string, expirySeconds: string, hashAlgorithm: TlcHashAlgorithm): PolicyViewTlc {
    return { direction: "received", hashAlgorithm, boundPaymentHash, amountShannons, expirySeconds };
}

const NO_RECORDS: BalanceRuleContext = { intents: new Map(), invoices: new Map(), otherChannels: [] };

const UNUSED_VIEW: PolicyViewSnapshot = { exposureShannons: "0", tlcs: [], chargedShannons: {}, creditedShannons: {} };

const OPENING: PolicyViewSnapshot = { exposureShannons: "1000", tlcs: [], chargedShannons: {}, creditedShannons: {} };

function refusalOf(judge: () => unknown): PolicyRefusalError {
    try {
        judge();
    } catch (error) {
        if (error instanceof PolicyRefusalError) return error;
        throw error;
    }
    throw new Error("expected a policy refusal");
}

describe("toPolicyViewTlcs", () => {
    it("keeps what the witness binds: the direction, 20 bytes of the hash, the amount and the expiry in seconds", () => {
        const tlcs = toPolicyViewTlcs([
            {
                id: 7,
                direction: "offered",
                hashAlgorithm: "ckb-hash",
                amountShannons: 1500n,
                paymentHash: hexToBytes(FULL_HASH_A),
                expiryMs: 1723257890123n,
                createdAtRemoteCommitmentNumber: 3,
                remoteCommitmentPoint: new Uint8Array(33),
            },
        ]);
        expect(tlcs).toEqual([
            {
                direction: "offered",
                hashAlgorithm: "ckb-hash" as const,
                boundPaymentHash: HASH_A,
                amountShannons: "1500",
                expirySeconds: "1723257890",
            },
        ]);
    });

    it("reads two TLCs the witness cannot tell apart as the same entry, whatever their ids and unbound bytes", () => {
        const [first, second] = toPolicyViewTlcs([
            {
                id: 1,
                direction: "received",
                hashAlgorithm: "ckb-hash",
                amountShannons: 10n,
                paymentHash: hexToBytes(HASH_R + "01".repeat(12)),
                expiryMs: 5000n,
                createdAtRemoteCommitmentNumber: 1,
                remoteCommitmentPoint: new Uint8Array(33),
            },
            {
                id: 2,
                direction: "received",
                hashAlgorithm: "ckb-hash",
                amountShannons: 10n,
                paymentHash: hexToBytes(HASH_R + "02".repeat(12)),
                expiryMs: 5999n,
                createdAtRemoteCommitmentNumber: 2,
                remoteCommitmentPoint: new Uint8Array(33).fill(2),
            },
        ]);
        expect(first).toEqual(second);
    });

    // The witness binds the algorithm in its flag byte.
    it("reads two TLCs that differ in their hash algorithm alone as two entries", () => {
        const [first, second] = toPolicyViewTlcs([
            {
                id: 1,
                direction: "received",
                hashAlgorithm: "ckb-hash",
                amountShannons: 10n,
                paymentHash: hexToBytes(FULL_HASH_R),
                expiryMs: 5000n,
                createdAtRemoteCommitmentNumber: 1,
                remoteCommitmentPoint: new Uint8Array(33),
            },
            {
                id: 2,
                direction: "received",
                hashAlgorithm: "sha256",
                amountShannons: 10n,
                paymentHash: hexToBytes(FULL_HASH_R),
                expiryMs: 5000n,
                createdAtRemoteCommitmentNumber: 1,
                remoteCommitmentPoint: new Uint8Array(33),
            },
        ]);
        expect(first?.hashAlgorithm).toBe("ckb-hash");
        expect(second?.hashAlgorithm).toBe("sha256");
        expect(first).not.toEqual(second);
    });

    it("orders the entries by what they bind, not by the order the node sent them", () => {
        const tlcs = toPolicyViewTlcs([
            {
                id: 1,
                direction: "received",
                hashAlgorithm: "ckb-hash",
                amountShannons: 10n,
                paymentHash: hexToBytes(FULL_HASH_R),
                expiryMs: 5000n,
                createdAtRemoteCommitmentNumber: 1,
                remoteCommitmentPoint: new Uint8Array(33),
            },
            {
                id: 2,
                direction: "offered",
                hashAlgorithm: "ckb-hash",
                amountShannons: 20n,
                paymentHash: hexToBytes(FULL_HASH_A),
                expiryMs: 6000n,
                createdAtRemoteCommitmentNumber: 1,
                remoteCommitmentPoint: new Uint8Array(33),
            },
        ]);
        expect(tlcs.map((tlc) => tlc.direction)).toEqual(["offered", "received"]);
    });
});

describe("judgeCommitment", () => {
    describe("step 1: an offered amount may grow only against an open intent", () => {
        it("signs an offered TLC its intent covers, and records what the view now shows", () => {
            const next = judgeCommitment(
                "remote",
                { remote: OPENING, local: UNUSED_VIEW },
                {
                    exposureShannons: 900n,
                    tlcs: [
                        {
                            direction: "offered",
                            hashAlgorithm: "ckb-hash" as const,
                            boundPaymentHash: HASH_A,
                            amountShannons: "100",
                            expirySeconds: "50",
                        },
                    ],
                },
                {
                    intents: new Map([
                        [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "100", open: true, channelIndexes: [] }],
                    ]),
                    invoices: new Map(),
                    otherChannels: [],
                },
            );
            expect(next).toEqual<PolicyViewSnapshot>({
                exposureShannons: "900",
                tlcs: [
                    {
                        direction: "offered",
                        hashAlgorithm: "ckb-hash" as const,
                        boundPaymentHash: HASH_A,
                        amountShannons: "100",
                        expirySeconds: "50",
                    },
                ],
                chargedShannons: {},
                creditedShannons: {},
            });
        });

        it("refuses an offered TLC under a hash no intent names", () => {
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "remote",
                    { remote: OPENING, local: UNUSED_VIEW },
                    {
                        exposureShannons: 900n,
                        tlcs: [
                            {
                                direction: "offered",
                                hashAlgorithm: "ckb-hash" as const,
                                boundPaymentHash: HASH_A,
                                amountShannons: "100",
                                expirySeconds: "50",
                            },
                        ],
                    },
                    NO_RECORDS,
                ),
            );
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe(`the remote commitment offers a TLC under ${HASH_A}, which no debit intent covers`);
        });

        it("refuses an offered TLC that grows under a closed intent", () => {
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "local",
                    { local: OPENING, remote: UNUSED_VIEW },
                    {
                        exposureShannons: 900n,
                        tlcs: [
                            {
                                direction: "offered",
                                hashAlgorithm: "ckb-hash" as const,
                                boundPaymentHash: HASH_A,
                                amountShannons: "100",
                                expirySeconds: "50",
                            },
                        ],
                    },
                    {
                        intents: new Map([
                            [
                                HASH_A,
                                { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "100", open: false, channelIndexes: [] },
                            ],
                        ]),
                        invoices: new Map(),
                        otherChannels: [],
                    },
                ),
            );
            expect(refusal.message).toBe(`the local commitment draws more under ${HASH_A}, whose debit intent is closed`);
        });

        it("refuses an offered TLC above its intent by one shannon", () => {
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "remote",
                    { remote: OPENING, local: UNUSED_VIEW },
                    {
                        exposureShannons: 900n,
                        tlcs: [
                            {
                                direction: "offered",
                                hashAlgorithm: "ckb-hash" as const,
                                boundPaymentHash: HASH_A,
                                amountShannons: "100",
                                expirySeconds: "50",
                            },
                        ],
                    },
                    {
                        intents: new Map([
                            [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "99", open: true, channelIndexes: [] }],
                        ]),
                        invoices: new Map(),
                        otherChannels: [],
                    },
                ),
            );
            expect(refusal.message).toBe(`the remote view draws 100 shannons under ${HASH_A}, above its debit intent of 99`);
        });

        // An add reaches the peer's commitment first.
        it("lets a view catch up with what the channel's other view already showed, under a closed intent", () => {
            const views: Record<PolicyView, PolicyViewSnapshot> = {
                remote: { exposureShannons: "990", tlcs: [off(HASH_A, "10", "50", "ckb-hash")], chargedShannons: {}, creditedShannons: {} },
                local: { exposureShannons: "1000", tlcs: [], chargedShannons: {}, creditedShannons: {} },
            };
            const next = judgeCommitment(
                "local",
                views,
                { exposureShannons: 990n, tlcs: [off(HASH_A, "10", "50", "ckb-hash")] },
                {
                    intents: new Map([
                        [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "10", open: false, channelIndexes: [] }],
                    ]),
                    invoices: new Map(),
                    otherChannels: [],
                },
            );
            expect(next.tlcs).toEqual([off(HASH_A, "10", "50", "ckb-hash")]);
        });

        it("refuses a view drawing past what the channel's other view showed, under a closed intent", () => {
            const views: Record<PolicyView, PolicyViewSnapshot> = {
                remote: { exposureShannons: "990", tlcs: [off(HASH_A, "10", "50", "ckb-hash")], chargedShannons: {}, creditedShannons: {} },
                local: { exposureShannons: "1000", tlcs: [], chargedShannons: {}, creditedShannons: {} },
            };
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "local",
                    views,
                    { exposureShannons: 980n, tlcs: [off(HASH_A, "10", "50", "ckb-hash"), off(HASH_A, "10", "60", "ckb-hash")] },
                    {
                        intents: new Map([
                            [
                                HASH_A,
                                { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "100", open: false, channelIndexes: [] },
                            ],
                        ]),
                        invoices: new Map(),
                        otherChannels: [],
                    },
                ),
            );
            expect(refusal.message).toBe(`the local commitment draws more under ${HASH_A}, whose debit intent is closed`);
        });

        it("keeps signing a TLC already shown after its intent closes", () => {
            const shown: PolicyViewSnapshot = {
                exposureShannons: "900",
                tlcs: [
                    {
                        direction: "offered",
                        hashAlgorithm: "ckb-hash" as const,
                        boundPaymentHash: HASH_A,
                        amountShannons: "100",
                        expirySeconds: "50",
                    },
                ],
                chargedShannons: {},
                creditedShannons: {},
            };
            const next = judgeCommitment(
                "remote",
                { remote: shown, local: UNUSED_VIEW },
                {
                    exposureShannons: 900n,
                    tlcs: [
                        {
                            direction: "offered",
                            hashAlgorithm: "ckb-hash" as const,
                            boundPaymentHash: HASH_A,
                            amountShannons: "100",
                            expirySeconds: "50",
                        },
                    ],
                },
                {
                    intents: new Map([
                        [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "100", open: false, channelIndexes: [] }],
                    ]),
                    invoices: new Map(),
                    otherChannels: [],
                },
            );
            expect(next).toEqual(shown);
        });

        it("signs the parts of a multi-path payment up to the budget, and not a shannon past it", () => {
            const intents = new Map([
                [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "100", open: true, channelIndexes: [] }],
            ]);
            const parts = (second: string): PolicyViewSnapshot["tlcs"] => [
                {
                    direction: "offered",
                    hashAlgorithm: "ckb-hash" as const,
                    boundPaymentHash: HASH_A,
                    amountShannons: "60",
                    expirySeconds: "50",
                },
                {
                    direction: "offered",
                    hashAlgorithm: "ckb-hash" as const,
                    boundPaymentHash: HASH_A,
                    amountShannons: second,
                    expirySeconds: "51",
                },
            ];
            expect(() =>
                judgeCommitment(
                    "remote",
                    { remote: OPENING, local: UNUSED_VIEW },
                    { exposureShannons: 900n, tlcs: parts("40") },
                    { ...NO_RECORDS, intents },
                ),
            ).not.toThrow();
            expect(
                refusalOf(() =>
                    judgeCommitment(
                        "remote",
                        { remote: OPENING, local: UNUSED_VIEW },
                        { exposureShannons: 899n, tlcs: parts("41") },
                        { ...NO_RECORDS, intents },
                    ),
                ).code,
            ).toBe("policy_refusal");
        });

        it("counts what other channels show under the hash in the same view", () => {
            const other: PolicyViewSnapshot = {
                exposureShannons: "500",
                tlcs: [
                    {
                        direction: "offered",
                        hashAlgorithm: "ckb-hash" as const,
                        boundPaymentHash: HASH_A,
                        amountShannons: "60",
                        expirySeconds: "50",
                    },
                ],
                chargedShannons: {},
                creditedShannons: {},
            };
            const context = (max: string): BalanceRuleContext => ({
                intents: new Map([
                    [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: max, open: true, channelIndexes: [] }],
                ]),
                invoices: new Map(),
                otherChannels: [{ remote: other, local: other }],
            });
            const next = {
                exposureShannons: 950n,
                tlcs: [
                    {
                        direction: "offered" as const,
                        hashAlgorithm: "ckb-hash" as const,
                        boundPaymentHash: HASH_A,
                        amountShannons: "50",
                        expirySeconds: "50",
                    },
                ],
            };
            expect(
                refusalOf(() => judgeCommitment("remote", { remote: OPENING, local: UNUSED_VIEW }, next, context("109"))).message,
            ).toContain("draws 110 shannons");
            expect(() => judgeCommitment("remote", { remote: OPENING, local: UNUSED_VIEW }, next, context("110"))).not.toThrow();
        });

        // The node may broadcast a different view per channel.
        it("counts every other channel at its worst view, not at the view being judged", () => {
            const other: Record<PolicyView, PolicyViewSnapshot> = {
                remote: { exposureShannons: "500", tlcs: [off(HASH_A, "10", "50", "ckb-hash")], chargedShannons: {}, creditedShannons: {} },
                local: { exposureShannons: "510", tlcs: [], chargedShannons: {}, creditedShannons: {} },
            };
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "local",
                    { local: OPENING, remote: UNUSED_VIEW },
                    { exposureShannons: 990n, tlcs: [off(HASH_A, "10", "50", "ckb-hash")] },
                    {
                        intents: new Map([
                            [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "10", open: true, channelIndexes: [] }],
                        ]),
                        invoices: new Map(),
                        otherChannels: [other],
                    },
                ),
            );
            expect(refusal.message).toBe(`the local view draws 20 shannons under ${HASH_A}, above its debit intent of 10`);
        });

        it("counts this channel at the view that draws past its other one", () => {
            const views: Record<PolicyView, PolicyViewSnapshot> = {
                remote: OPENING,
                local: { exposureShannons: "990", tlcs: [off(HASH_A, "10", "50", "ckb-hash")], chargedShannons: {}, creditedShannons: {} },
            };
            const other: PolicyViewSnapshot = {
                exposureShannons: "500",
                tlcs: [off(HASH_A, "3", "50", "ckb-hash")],
                chargedShannons: {},
                creditedShannons: {},
            };
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "remote",
                    views,
                    { exposureShannons: 989n, tlcs: [off(HASH_A, "11", "50", "ckb-hash")] },
                    {
                        intents: new Map([
                            [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "13", open: true, channelIndexes: [] }],
                        ]),
                        invoices: new Map(),
                        otherChannels: [{ remote: other, local: other }],
                    },
                ),
            );
            expect(refusal.message).toBe(`the remote view draws 14 shannons under ${HASH_A}, above its debit intent of 13`);
        });

        it("counts what other channels have charged under the hash in the same view", () => {
            const other: PolicyViewSnapshot = {
                exposureShannons: "500",
                tlcs: [],
                chargedShannons: { [HASH_A]: "70" },
                creditedShannons: {},
            };
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "remote",
                    { remote: OPENING, local: UNUSED_VIEW },
                    {
                        exposureShannons: 950n,
                        tlcs: [
                            {
                                direction: "offered",
                                hashAlgorithm: "ckb-hash" as const,
                                boundPaymentHash: HASH_A,
                                amountShannons: "50",
                                expirySeconds: "50",
                            },
                        ],
                    },
                    {
                        intents: new Map([
                            [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "119", open: true, channelIndexes: [] }],
                        ]),
                        invoices: new Map(),
                        otherChannels: [{ remote: other, local: other }],
                    },
                ),
            );
            expect(refusal.message).toContain("draws 120 shannons");
        });

        it("counts what this view has already charged under the hash", () => {
            const charged: PolicyViewSnapshot = {
                exposureShannons: "1000",
                tlcs: [],
                chargedShannons: { [HASH_A]: "80" },
                creditedShannons: {},
            };
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "remote",
                    { remote: charged, local: UNUSED_VIEW },
                    {
                        exposureShannons: 970n,
                        tlcs: [
                            {
                                direction: "offered",
                                hashAlgorithm: "ckb-hash" as const,
                                boundPaymentHash: HASH_A,
                                amountShannons: "30",
                                expirySeconds: "50",
                            },
                        ],
                    },
                    {
                        intents: new Map([
                            [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "109", open: true, channelIndexes: [] }],
                        ]),
                        invoices: new Map(),
                        otherChannels: [],
                    },
                ),
            );
            expect(refusal.message).toContain("draws 110 shannons");
        });

        // A retry starts only once the failed TLC is gone, and a failure is charged nothing.
        it("lets a failed attempt's budget pay for the retry", () => {
            const intents = new Map([
                [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "100", open: true, channelIndexes: [] }],
            ]);
            const attempt = {
                direction: "offered" as const,
                hashAlgorithm: "ckb-hash" as const,
                boundPaymentHash: HASH_A,
                amountShannons: "100",
                expirySeconds: "50",
            };
            const shown = judgeCommitment(
                "remote",
                { remote: OPENING, local: UNUSED_VIEW },
                { exposureShannons: 900n, tlcs: [attempt] },
                { ...NO_RECORDS, intents },
            );
            const failed = judgeCommitment(
                "remote",
                { remote: shown, local: UNUSED_VIEW },
                { exposureShannons: 1000n, tlcs: [] },
                { ...NO_RECORDS, intents },
            );
            expect(failed.chargedShannons).toEqual({});
            const retried = judgeCommitment(
                "remote",
                { remote: failed, local: UNUSED_VIEW },
                { exposureShannons: 900n, tlcs: [{ ...attempt, expirySeconds: "60" }] },
                { ...NO_RECORDS, intents },
            );
            expect(retried.tlcs).toEqual([{ ...attempt, expirySeconds: "60" }]);
        });

        // Fiber never retries inside one commitment.
        it("draws again for a TLC that replaces one gone with the money in the same message", () => {
            const previous: PolicyViewSnapshot = {
                exposureShannons: "900",
                tlcs: [
                    {
                        direction: "offered",
                        hashAlgorithm: "ckb-hash" as const,
                        boundPaymentHash: HASH_A,
                        amountShannons: "100",
                        expirySeconds: "50",
                    },
                ],
                chargedShannons: {},
                creditedShannons: {},
            };
            const next = {
                exposureShannons: 800n,
                tlcs: [
                    {
                        direction: "offered" as const,
                        hashAlgorithm: "ckb-hash" as const,
                        boundPaymentHash: HASH_A,
                        amountShannons: "100",
                        expirySeconds: "60",
                    },
                ],
            };
            const context = (max: string, open = true): BalanceRuleContext => ({
                intents: new Map([[HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: max, open, channelIndexes: [] }]]),
                invoices: new Map(),
                otherChannels: [],
            });
            expect(
                refusalOf(() => judgeCommitment("remote", { remote: previous, local: UNUSED_VIEW }, next, context("199"))).message,
            ).toContain("draws 200 shannons");
            expect(
                refusalOf(() => judgeCommitment("remote", { remote: previous, local: UNUSED_VIEW }, next, context("200", false))).message,
            ).toContain("whose debit intent is closed");
            expect(judgeCommitment("remote", { remote: previous, local: UNUSED_VIEW }, next, context("200")).chargedShannons).toEqual({
                [HASH_A]: "100",
            });
        });

        it("lets a TLC leave with the money under a closed intent", () => {
            const previous: PolicyViewSnapshot = {
                exposureShannons: "900",
                tlcs: [
                    {
                        direction: "offered",
                        hashAlgorithm: "ckb-hash" as const,
                        boundPaymentHash: HASH_A,
                        amountShannons: "100",
                        expirySeconds: "50",
                    },
                ],
                chargedShannons: {},
                creditedShannons: {},
            };
            const next = judgeCommitment(
                "remote",
                { remote: previous, local: UNUSED_VIEW },
                { exposureShannons: 900n, tlcs: [] },
                {
                    intents: new Map([
                        [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "100", open: false, channelIndexes: [] }],
                    ]),
                    invoices: new Map(),
                    otherChannels: [],
                },
            );
            expect(next.chargedShannons).toEqual({ [HASH_A]: "100" });
        });

        it("asks nothing of a received TLC", () => {
            const next = judgeCommitment(
                "remote",
                { remote: OPENING, local: UNUSED_VIEW },
                {
                    exposureShannons: 1000n,
                    tlcs: [
                        {
                            direction: "received",
                            hashAlgorithm: "ckb-hash" as const,
                            boundPaymentHash: HASH_R,
                            amountShannons: "100",
                            expirySeconds: "50",
                        },
                    ],
                },
                NO_RECORDS,
            );
            expect(next.tlcs).toHaveLength(1);
        });
    });

    describe("step 2: holdings may fall only by what offered TLCs took with them", () => {
        const shown: PolicyViewSnapshot = {
            exposureShannons: "800",
            tlcs: [
                {
                    direction: "offered",
                    hashAlgorithm: "ckb-hash" as const,
                    boundPaymentHash: HASH_A,
                    amountShannons: "100",
                    expirySeconds: "50",
                },
                {
                    direction: "offered",
                    hashAlgorithm: "ckb-hash" as const,
                    boundPaymentHash: HASH_B,
                    amountShannons: "100",
                    expirySeconds: "50",
                },
            ],
            chargedShannons: {},
            creditedShannons: {},
        };

        it("charges a TLC that left with its amount to its hash", () => {
            const previous: PolicyViewSnapshot = {
                exposureShannons: "900",
                tlcs: [
                    {
                        direction: "offered",
                        hashAlgorithm: "ckb-hash" as const,
                        boundPaymentHash: HASH_A,
                        amountShannons: "100",
                        expirySeconds: "50",
                    },
                ],
                chargedShannons: { [HASH_A]: "5" },
                creditedShannons: {},
            };
            const next = judgeCommitment(
                "remote",
                { remote: previous, local: UNUSED_VIEW },
                { exposureShannons: 900n, tlcs: [] },
                NO_RECORDS,
            );
            expect(next).toEqual<PolicyViewSnapshot>({
                exposureShannons: "900",
                tlcs: [],
                chargedShannons: { [HASH_A]: "105" },
                creditedShannons: {},
            });
        });

        it("charges nothing when the TLC left and its amount came back", () => {
            const next = judgeCommitment(
                "remote",
                { remote: shown, local: UNUSED_VIEW },
                { exposureShannons: 1000n, tlcs: [] },
                NO_RECORDS,
            );
            expect(next.chargedShannons).toEqual({});
        });

        it("refuses a fall with no offered TLC leaving", () => {
            const refusal = refusalOf(() =>
                judgeCommitment("local", { local: OPENING, remote: UNUSED_VIEW }, { exposureShannons: 999n, tlcs: [] }, NO_RECORDS),
            );
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe("the local commitment lowers the holdings by 1 shannons, which no offered TLC took");
        });

        it("refuses a fall larger than every offered TLC that left", () => {
            const refusal = refusalOf(() =>
                judgeCommitment("remote", { remote: shown, local: UNUSED_VIEW }, { exposureShannons: 799n, tlcs: [] }, NO_RECORDS),
            );
            expect(refusal.message).toContain("lowers the holdings by 201 shannons, which no offered TLC took");
        });

        it("refuses a fall no set of the offered TLCs that left adds up to", () => {
            const refusal = refusalOf(() =>
                judgeCommitment("remote", { remote: shown, local: UNUSED_VIEW }, { exposureShannons: 950n, tlcs: [] }, NO_RECORDS),
            );
            expect(refusal.message).toBe(
                "the remote commitment lowers the holdings by 50 shannons, which no set of the offered TLCs that left accounts for",
            );
        });

        it("charges only the hash whose TLC accounts for the fall", () => {
            const previous: PolicyViewSnapshot = {
                exposureShannons: "830",
                tlcs: [
                    {
                        direction: "offered",
                        hashAlgorithm: "ckb-hash" as const,
                        boundPaymentHash: HASH_A,
                        amountShannons: "100",
                        expirySeconds: "50",
                    },
                    {
                        direction: "offered",
                        hashAlgorithm: "ckb-hash" as const,
                        boundPaymentHash: HASH_B,
                        amountShannons: "70",
                        expirySeconds: "50",
                    },
                ],
                chargedShannons: {},
                creditedShannons: {},
            };
            const next = judgeCommitment(
                "remote",
                { remote: previous, local: UNUSED_VIEW },
                { exposureShannons: 900n, tlcs: [] },
                NO_RECORDS,
            );
            expect(next.chargedShannons).toEqual({ [HASH_A]: "100" });
        });

        // The message does not say which of two equal TLCs was fulfilled.
        it("charges every hash that could account for the fall", () => {
            const next = judgeCommitment("remote", { remote: shown, local: UNUSED_VIEW }, { exposureShannons: 900n, tlcs: [] }, NO_RECORDS);
            expect(next.chargedShannons).toEqual({ [HASH_A]: "100", [HASH_B]: "100" });
        });

        it("charges both hashes when both took their amount", () => {
            const next = judgeCommitment("remote", { remote: shown, local: UNUSED_VIEW }, { exposureShannons: 800n, tlcs: [] }, NO_RECORDS);
            expect(next.chargedShannons).toEqual({ [HASH_A]: "100", [HASH_B]: "100" });
        });

        // Such as a keysend the node fulfils on its own.
        it("lets received TLCs that left widen what could account for the fall", () => {
            const previous: PolicyViewSnapshot = {
                exposureShannons: "900",
                tlcs: [
                    {
                        direction: "offered",
                        hashAlgorithm: "ckb-hash" as const,
                        boundPaymentHash: HASH_A,
                        amountShannons: "100",
                        expirySeconds: "50",
                    },
                    {
                        direction: "received",
                        hashAlgorithm: "ckb-hash" as const,
                        boundPaymentHash: HASH_R,
                        amountShannons: "30",
                        expirySeconds: "50",
                    },
                ],
                chargedShannons: {},
                creditedShannons: {},
            };
            const next = judgeCommitment(
                "remote",
                { remote: previous, local: UNUSED_VIEW },
                { exposureShannons: 930n, tlcs: [] },
                NO_RECORDS,
            );
            expect(next.chargedShannons).toEqual({ [HASH_A]: "100" });
            expect(
                refusalOf(() =>
                    judgeCommitment("remote", { remote: previous, local: UNUSED_VIEW }, { exposureShannons: 931n, tlcs: [] }, NO_RECORDS),
                ).code,
            ).toBe("policy_refusal");
        });

        // A paid offered TLC and a keysend the node fulfilled unasked leave the same exposure as both failing.
        it("charges an offered TLC a received one that left could have paid for, even with nothing fallen", () => {
            const intents = new Map([
                [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "10", open: true, channelIndexes: [] }],
            ]);
            const previous: PolicyViewSnapshot = {
                exposureShannons: "100",
                tlcs: [off(HASH_A, "10", "50", "ckb-hash"), rec(HASH_R, "10", "50", "ckb-hash")],
                chargedShannons: {},
                creditedShannons: {},
            };
            const settled = judgeCommitment(
                "remote",
                { remote: previous, local: UNUSED_VIEW },
                { exposureShannons: 110n, tlcs: [] },
                { ...NO_RECORDS, intents },
            );
            expect(settled.chargedShannons).toEqual({ [HASH_A]: "10" });
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "remote",
                    { remote: settled, local: UNUSED_VIEW },
                    { exposureShannons: 100n, tlcs: [off(HASH_A, "10", "60", "ckb-hash")] },
                    { ...NO_RECORDS, intents },
                ),
            );
            expect(refusal.message).toBe(`the remote view draws 20 shannons under ${HASH_A}, above its debit intent of 10`);
        });

        // Without the preimage, a held TLC that left can only have failed.
        it("lets no received TLC of an unreleased invoice widen what could have been paid", () => {
            const previous: PolicyViewSnapshot = {
                exposureShannons: "100",
                tlcs: [off(HASH_A, "10", "50", "ckb-hash"), rec(HASH_R, "10", "50", "ckb-hash")],
                chargedShannons: {},
                creditedShannons: {},
            };
            const next = judgeCommitment(
                "remote",
                { remote: previous, local: UNUSED_VIEW },
                { exposureShannons: 110n, tlcs: [] },
                {
                    intents: new Map([
                        [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "10", open: true, channelIndexes: [] }],
                    ]),
                    invoices: new Map([
                        [
                            HASH_R,
                            {
                                version: 1 as const,
                                paymentHash: FULL_HASH_R,
                                amountShannons: "10",
                                hashAlgorithm: "ckb-hash" as const,
                                released: false,
                                channelIndexes: [],
                            },
                        ],
                    ]),
                    otherChannels: [],
                },
            );
            expect(next.chargedShannons).toEqual({});
        });

        // Once released, the node can collect a part past what the invoice owes.
        it("lets a received TLC of a released invoice already paid in full widen what could have been paid", () => {
            const previous: PolicyViewSnapshot = {
                exposureShannons: "100",
                tlcs: [off(HASH_A, "10", "50", "ckb-hash"), rec(HASH_R, "10", "50", "ckb-hash")],
                chargedShannons: {},
                creditedShannons: { [HASH_R]: "10" },
            };
            const next = judgeCommitment(
                "remote",
                { remote: previous, local: UNUSED_VIEW },
                { exposureShannons: 110n, tlcs: [] },
                {
                    intents: new Map([
                        [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "10", open: true, channelIndexes: [] }],
                    ]),
                    invoices: new Map([
                        [
                            HASH_R,
                            {
                                version: 1 as const,
                                paymentHash: FULL_HASH_R,
                                amountShannons: "10",
                                hashAlgorithm: "ckb-hash" as const,
                                released: true,
                                channelIndexes: [],
                            },
                        ],
                    ]),
                    otherChannels: [],
                },
            );
            expect(next.chargedShannons).toEqual({ [HASH_A]: "10" });
        });

        it("charges nothing with nothing fallen when no received TLC that left could have paid for an offered one", () => {
            const previous: PolicyViewSnapshot = {
                exposureShannons: "100",
                tlcs: [off(HASH_A, "10", "50", "ckb-hash"), rec(HASH_R, "5", "50", "ckb-hash")],
                chargedShannons: {},
                creditedShannons: {},
            };
            const next = judgeCommitment(
                "remote",
                { remote: previous, local: UNUSED_VIEW },
                { exposureShannons: 110n, tlcs: [] },
                NO_RECORDS,
            );
            expect(next.chargedShannons).toEqual({});
        });

        it("searches exactly up to twelve departing TLCs with nothing fallen too, and charges them all past that", () => {
            const departing = (count: number): PolicyViewSnapshot => ({
                exposureShannons: "0",
                tlcs: [
                    ...Array.from({ length: count }, (_, index) => ({
                        direction: "offered" as const,
                        hashAlgorithm: "ckb-hash" as const,
                        boundPaymentHash: HASH_A,
                        amountShannons: "10",
                        expirySeconds: String(index),
                    })),
                    rec(HASH_R, "5", "50", "ckb-hash"),
                ],
                chargedShannons: {},
                creditedShannons: {},
            });
            const twelve = judgeCommitment(
                "remote",
                { remote: departing(12), local: UNUSED_VIEW },
                { exposureShannons: 120n, tlcs: [] },
                NO_RECORDS,
            );
            expect(twelve.chargedShannons).toEqual({});
            const thirteen = judgeCommitment(
                "remote",
                { remote: departing(13), local: UNUSED_VIEW },
                { exposureShannons: 130n, tlcs: [] },
                NO_RECORDS,
            );
            expect(thirteen.chargedShannons).toEqual({ [HASH_A]: "130" });
        });

        it("searches the sets exactly up to twelve departing TLCs, and charges them all past that", () => {
            const departing = (count: number): PolicyViewSnapshot => ({
                exposureShannons: "0",
                tlcs: Array.from({ length: count }, (_, index) => ({
                    direction: "offered" as const,
                    hashAlgorithm: "ckb-hash" as const,
                    boundPaymentHash: HASH_A,
                    amountShannons: "10",
                    expirySeconds: String(index),
                })),
                chargedShannons: {},
                creditedShannons: {},
            });
            expect(
                refusalOf(() =>
                    judgeCommitment(
                        "remote",
                        { remote: departing(12), local: UNUSED_VIEW },
                        { exposureShannons: 115n, tlcs: [] },
                        NO_RECORDS,
                    ),
                ).message,
            ).toContain("no set of the offered TLCs that left accounts for");
            const next = judgeCommitment(
                "remote",
                { remote: departing(13), local: UNUSED_VIEW },
                { exposureShannons: 125n, tlcs: [] },
                NO_RECORDS,
            );
            expect(next.chargedShannons).toEqual({ [HASH_A]: "130" });
        });
    });

    describe("step 3: a released preimage must be paid for", () => {
        const holding: PolicyViewSnapshot = {
            exposureShannons: "1000",
            tlcs: [
                {
                    direction: "received",
                    hashAlgorithm: "ckb-hash" as const,
                    boundPaymentHash: HASH_R,
                    amountShannons: "100",
                    expirySeconds: "50",
                },
            ],
            chargedShannons: {},
            creditedShannons: {},
        };
        const released = (otherChannels: BalanceRuleContext["otherChannels"] = []): BalanceRuleContext => ({
            intents: new Map(),
            invoices: new Map([
                [
                    HASH_R,
                    {
                        version: 1 as const,
                        paymentHash: FULL_HASH_R,
                        amountShannons: "100",
                        hashAlgorithm: "ckb-hash" as const,
                        released: true,
                        channelIndexes: [],
                    },
                ],
            ]),
            otherChannels,
        });

        it("refuses a commitment that drops a released TLC without paying for it", () => {
            const refusal = refusalOf(() =>
                judgeCommitment("remote", { remote: holding, local: UNUSED_VIEW }, { exposureShannons: 1000n, tlcs: [] }, released()),
            );
            expect(refusal.message).toBe("the remote commitment lowers the holdings by 100 shannons, which no offered TLC took");
        });

        it("signs one that pays for it, and records the credit", () => {
            const next = judgeCommitment(
                "remote",
                { remote: holding, local: UNUSED_VIEW },
                { exposureShannons: 1100n, tlcs: [] },
                released(),
            );
            expect(next).toEqual<PolicyViewSnapshot>({
                exposureShannons: "1100",
                tlcs: [],
                chargedShannons: {},
                creditedShannons: { [HASH_R]: "100" },
            });
        });

        it("asks nothing while the preimage is unreleased", () => {
            const next = judgeCommitment(
                "remote",
                { remote: holding, local: UNUSED_VIEW },
                { exposureShannons: 1000n, tlcs: [] },
                {
                    intents: new Map(),
                    invoices: new Map([
                        [
                            HASH_R,
                            {
                                version: 1 as const,
                                paymentHash: FULL_HASH_R,
                                amountShannons: "100",
                                hashAlgorithm: "ckb-hash" as const,
                                released: false,
                                channelIndexes: [],
                            },
                        ],
                    ]),
                    otherChannels: [],
                },
            );
            expect(next.creditedShannons).toEqual({});
        });

        it("asks nothing of a received TLC no invoice of this device names", () => {
            const next = judgeCommitment(
                "remote",
                { remote: holding, local: UNUSED_VIEW },
                { exposureShannons: 1000n, tlcs: [] },
                NO_RECORDS,
            );
            expect(next.creditedShannons).toEqual({});
        });

        it("asks a part of a multi-path payment for its own amount", () => {
            const part: PolicyViewSnapshot = {
                ...holding,
                tlcs: [
                    {
                        direction: "received",
                        hashAlgorithm: "ckb-hash" as const,
                        boundPaymentHash: HASH_R,
                        amountShannons: "60",
                        expirySeconds: "50",
                    },
                ],
            };
            const next = judgeCommitment("remote", { remote: part, local: UNUSED_VIEW }, { exposureShannons: 1060n, tlcs: [] }, released());
            expect(next.creditedShannons).toEqual({ [HASH_R]: "60" });
            expect(
                refusalOf(() =>
                    judgeCommitment("remote", { remote: part, local: UNUSED_VIEW }, { exposureShannons: 1059n, tlcs: [] }, released()),
                ).code,
            ).toBe("policy_refusal");
        });

        it("asks no more than what the invoice still owes across channels", () => {
            const other: PolicyViewSnapshot = {
                exposureShannons: "0",
                tlcs: [],
                chargedShannons: {},
                creditedShannons: { [HASH_R]: "60" },
            };
            const next = judgeCommitment(
                "remote",
                { remote: holding, local: UNUSED_VIEW },
                { exposureShannons: 1040n, tlcs: [] },
                released([{ remote: other, local: other }]),
            );
            expect(next.creditedShannons).toEqual({ [HASH_R]: "40" });
            expect(
                refusalOf(() =>
                    judgeCommitment(
                        "remote",
                        { remote: holding, local: UNUSED_VIEW },
                        { exposureShannons: 1039n, tlcs: [] },
                        released([{ remote: other, local: other }]),
                    ),
                ).code,
            ).toBe("policy_refusal");
        });

        // The node may broadcast the two commitments that never paid.
        it("counts another channel's credit at its less paid view", () => {
            const other: Record<PolicyView, PolicyViewSnapshot> = {
                remote: { exposureShannons: "0", tlcs: [], chargedShannons: {}, creditedShannons: { [HASH_R]: "100" } },
                local: { exposureShannons: "0", tlcs: [rec(HASH_R, "100", "50", "ckb-hash")], chargedShannons: {}, creditedShannons: {} },
            };
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "remote",
                    { remote: holding, local: UNUSED_VIEW },
                    { exposureShannons: 1000n, tlcs: [] },
                    released([other]),
                ),
            );
            expect(refusal.message).toBe("the remote commitment lowers the holdings by 100 shannons, which no offered TLC took");
        });

        it("asks nothing once this view has been paid the whole invoice", () => {
            const paid: PolicyViewSnapshot = { ...holding, creditedShannons: { [HASH_R]: "100" } };
            const next = judgeCommitment("remote", { remote: paid, local: UNUSED_VIEW }, { exposureShannons: 1000n, tlcs: [] }, released());
            expect(next.creditedShannons).toEqual({ [HASH_R]: "100" });
        });

        // Both paid and both failed leave the same exposure, so the offered hash pays for the doubt.
        it("charges an offered TLC that left beside a released one, the case the release sequence keeps from arising", () => {
            const previous: PolicyViewSnapshot = {
                ...holding,
                exposureShannons: "900",
                tlcs: [
                    ...holding.tlcs,
                    {
                        direction: "offered",
                        hashAlgorithm: "ckb-hash" as const,
                        boundPaymentHash: HASH_A,
                        amountShannons: "100",
                        expirySeconds: "50",
                    },
                ],
            };
            const next = judgeCommitment(
                "remote",
                { remote: previous, local: UNUSED_VIEW },
                { exposureShannons: 1000n, tlcs: [] },
                released(),
            );
            expect(next.chargedShannons).toEqual({ [HASH_A]: "100" });
            expect(next.creditedShannons).toEqual({ [HASH_R]: "100" });
            expect(
                refusalOf(() =>
                    judgeCommitment("remote", { remote: previous, local: UNUSED_VIEW }, { exposureShannons: 900n, tlcs: [] }, released()),
                ).code,
            ).toBe("policy_refusal");
        });

        it("refuses a commitment that would show an offered TLC beside a held TLC whose preimage was released", () => {
            const context: BalanceRuleContext = {
                intents: new Map([
                    [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "100", open: true, channelIndexes: [] }],
                ]),
                invoices: new Map([
                    [
                        HASH_R,
                        {
                            version: 1 as const,
                            paymentHash: FULL_HASH_R,
                            amountShannons: "100",
                            hashAlgorithm: "ckb-hash" as const,
                            released: true,
                            channelIndexes: [],
                        },
                    ],
                ]),
                otherChannels: [],
            };
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "remote",
                    { remote: holding, local: UNUSED_VIEW },
                    { exposureShannons: 900n, tlcs: [...holding.tlcs, off(HASH_A, "100", "50", "ckb-hash")] },
                    context,
                ),
            );
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe("the remote commitment would show an offered TLC beside a held TLC whose preimage was released");
        });

        it("refuses it when the released held TLC is listed in the channel's other view", () => {
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "local",
                    { local: OPENING, remote: holding },
                    { exposureShannons: 900n, tlcs: [off(HASH_A, "100", "50", "ckb-hash")] },
                    {
                        intents: new Map([
                            [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "100", open: true, channelIndexes: [] }],
                        ]),
                        invoices: new Map([
                            [
                                HASH_R,
                                {
                                    version: 1 as const,
                                    paymentHash: FULL_HASH_R,
                                    amountShannons: "100",
                                    hashAlgorithm: "ckb-hash" as const,
                                    released: true,
                                    channelIndexes: [],
                                },
                            ],
                        ]),
                        otherChannels: [],
                    },
                ),
            );
            expect(refusal.message).toBe("the local commitment would show an offered TLC beside a held TLC whose preimage was released");
        });

        it("refuses a released held TLC arriving beside an offered one", () => {
            const offering: PolicyViewSnapshot = {
                exposureShannons: "900",
                tlcs: [off(HASH_A, "100", "50", "ckb-hash")],
                chargedShannons: {},
                creditedShannons: {},
            };
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "remote",
                    { remote: offering, local: UNUSED_VIEW },
                    { exposureShannons: 900n, tlcs: [off(HASH_A, "100", "50", "ckb-hash"), rec(HASH_R, "100", "50", "ckb-hash")] },
                    released(),
                ),
            );
            expect(refusal.message).toBe("the remote commitment would show an offered TLC beside a held TLC whose preimage was released");
        });

        // Refusing every message there would leave the channel nothing to resolve the two with.
        it("keeps signing a mixed channel whose message adds nothing", () => {
            const both: PolicyViewSnapshot = {
                exposureShannons: "900",
                tlcs: [off(HASH_A, "100", "50", "ckb-hash"), rec(HASH_R, "100", "50", "ckb-hash")],
                chargedShannons: {},
                creditedShannons: {},
            };
            const next = judgeCommitment(
                "remote",
                { remote: both, local: UNUSED_VIEW },
                { exposureShannons: 900n, tlcs: [off(HASH_A, "100", "50", "ckb-hash"), rec(HASH_R, "100", "50", "ckb-hash")] },
                released(),
            );
            expect(next.tlcs).toHaveLength(2);
        });

        // A new offered TLC could cover for the released one again.
        it("refuses a new offered TLC on a channel that already shows one beside a released held TLC", () => {
            const both: PolicyViewSnapshot = {
                exposureShannons: "900",
                tlcs: [off(HASH_A, "100", "50", "ckb-hash"), rec(HASH_R, "100", "50", "ckb-hash")],
                chargedShannons: {},
                creditedShannons: {},
            };
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "remote",
                    { remote: both, local: UNUSED_VIEW },
                    {
                        exposureShannons: 800n,
                        tlcs: [
                            off(HASH_A, "100", "50", "ckb-hash"),
                            off(HASH_B, "100", "50", "ckb-hash"),
                            rec(HASH_R, "100", "50", "ckb-hash"),
                        ],
                    },
                    {
                        ...released(),
                        intents: new Map([
                            [
                                HASH_B,
                                {
                                    version: 1 as const,
                                    paymentHash: HASH_B + "01".repeat(12),
                                    maxShannons: "100",
                                    open: true,
                                    channelIndexes: [],
                                },
                            ],
                        ]),
                    },
                ),
            );
            expect(refusal.message).toBe("the remote commitment would show an offered TLC beside a held TLC whose preimage was released");
        });

        it("refuses a new released held TLC on a channel that already shows one beside an offered TLC", () => {
            const both: PolicyViewSnapshot = {
                exposureShannons: "900",
                tlcs: [off(HASH_A, "100", "50", "ckb-hash"), rec(HASH_R, "100", "50", "ckb-hash")],
                chargedShannons: {},
                creditedShannons: {},
            };
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "remote",
                    { remote: both, local: UNUSED_VIEW },
                    {
                        exposureShannons: 900n,
                        tlcs: [
                            off(HASH_A, "100", "50", "ckb-hash"),
                            rec(HASH_R, "100", "50", "ckb-hash"),
                            rec(HASH_R, "50", "60", "ckb-hash"),
                        ],
                    },
                    released(),
                ),
            );
            expect(refusal.message).toBe("the remote commitment would show an offered TLC beside a held TLC whose preimage was released");
        });

        it("keeps signing a channel mixed across its two views when the message only retires TLCs", () => {
            const offering: PolicyViewSnapshot = {
                exposureShannons: "800",
                tlcs: [off(HASH_A, "100", "50", "ckb-hash"), off(HASH_B, "100", "50", "ckb-hash")],
                chargedShannons: {},
                creditedShannons: {},
            };
            const next = judgeCommitment(
                "remote",
                { remote: offering, local: holding },
                { exposureShannons: 900n, tlcs: [off(HASH_A, "100", "50", "ckb-hash")] },
                released(),
            );
            expect(next.tlcs).toHaveLength(1);
        });

        it("keeps signing a mixed channel that only retires TLCs", () => {
            const mixed: PolicyViewSnapshot = {
                exposureShannons: "800",
                tlcs: [off(HASH_A, "100", "50", "ckb-hash"), off(HASH_B, "100", "50", "ckb-hash"), rec(HASH_R, "100", "50", "ckb-hash")],
                chargedShannons: {},
                creditedShannons: {},
            };
            const next = judgeCommitment(
                "remote",
                { remote: mixed, local: UNUSED_VIEW },
                { exposureShannons: 900n, tlcs: [off(HASH_A, "100", "50", "ckb-hash"), rec(HASH_R, "100", "50", "ckb-hash")] },
                released(),
            );
            expect(next.tlcs).toHaveLength(2);
        });

        it("refuses a TLC of a released invoice under another algorithm", () => {
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "remote",
                    { remote: holding, local: UNUSED_VIEW },
                    { exposureShannons: 1000n, tlcs: [...holding.tlcs, rec(HASH_R, "50", "60", "sha256")] },
                    released(),
                ),
            );
            expect(refusal.message).toBe(
                `the remote commitment adds a TLC under ${HASH_R} locked with another algorithm than its released invoice`,
            );
        });

        it("refuses a released TLC whose algorithm changes between two messages", () => {
            const refusal = refusalOf(() =>
                judgeCommitment(
                    "remote",
                    { remote: holding, local: UNUSED_VIEW },
                    { exposureShannons: 1100n, tlcs: [rec(HASH_R, "100", "50", "sha256")] },
                    released(),
                ),
            );
            expect(refusal.message).toBe(
                `the remote commitment adds a TLC under ${HASH_R} locked with another algorithm than its released invoice`,
            );
        });

        it("lets a TLC under another algorithm arrive while the invoice is not released", () => {
            const next = judgeCommitment(
                "remote",
                { remote: holding, local: UNUSED_VIEW },
                { exposureShannons: 1000n, tlcs: [...holding.tlcs, rec(HASH_R, "50", "60", "sha256")] },
                {
                    intents: new Map(),
                    invoices: new Map([
                        [
                            HASH_R,
                            {
                                version: 1 as const,
                                paymentHash: FULL_HASH_R,
                                amountShannons: "100",
                                hashAlgorithm: "ckb-hash" as const,
                                released: false,
                                channelIndexes: [],
                            },
                        ],
                    ]),
                    otherChannels: [],
                },
            );
            expect(next.tlcs).toHaveLength(2);
        });

        it("lets an offered TLC sit beside a held TLC whose preimage is not released", () => {
            const next = judgeCommitment(
                "remote",
                { remote: holding, local: UNUSED_VIEW },
                { exposureShannons: 900n, tlcs: [...holding.tlcs, off(HASH_A, "100", "50", "ckb-hash")] },
                {
                    intents: new Map([
                        [HASH_A, { version: 1 as const, paymentHash: FULL_HASH_A, maxShannons: "100", open: true, channelIndexes: [] }],
                    ]),
                    invoices: new Map([
                        [
                            HASH_R,
                            {
                                version: 1 as const,
                                paymentHash: FULL_HASH_R,
                                amountShannons: "100",
                                hashAlgorithm: "ckb-hash" as const,
                                released: false,
                                channelIndexes: [],
                            },
                        ],
                    ]),
                    otherChannels: [],
                },
            );
            expect(next.tlcs).toHaveLength(2);
        });
    });
});

describe("judgeOpeningCommitment", () => {
    it("signs a first commitment that lists nothing and pays exactly what was funded", () => {
        expect(() => judgeOpeningCommitment("1000", { exposureShannons: 1000n, tlcs: [] })).not.toThrow();
    });

    it.each([
        ["one shannon more", 1001n],
        ["one shannon less", 999n],
    ])("refuses a first commitment paying %s than was funded", (_, exposure) => {
        const refusal = refusalOf(() => judgeOpeningCommitment("1000", { exposureShannons: exposure, tlcs: [] }));
        expect(refusal.code).toBe("policy_refusal");
        expect(refusal.message).toBe(`the channel's first commitment pays the device ${exposure} shannons, not the 1000 it funded`);
    });

    it.each([
        ["an offered", off(HASH_A, "1", "1700000000", "ckb-hash")],
        ["a received", rec(HASH_R, "1", "1700000000", "ckb-hash")],
    ])("refuses a first commitment that lists %s TLC, whatever it pays", (_, tlc) => {
        const refusal = refusalOf(() => judgeOpeningCommitment("1000", { exposureShannons: 1000n, tlcs: [tlc] }));
        expect(refusal.message).toBe("the channel's first commitment lists TLCs");
    });
});

describe("judgeShutdown", () => {
    const settled = (exposureShannons: string): PolicyViewSnapshot => ({
        exposureShannons,
        tlcs: [],
        chargedShannons: {},
        creditedShannons: {},
    });

    it("signs a close that pays the device what both views last showed", () => {
        expect(() => judgeShutdown({ remote: settled("1000"), local: settled("990") }, 1000n)).not.toThrow();
    });

    it.each([
        ["remote", { remote: settled("1001"), local: settled("990") }],
        ["local", { remote: settled("990"), local: settled("1001") }],
    ])("refuses a close below what the %s view showed", (view, views) => {
        const refusal = refusalOf(() => judgeShutdown(views, 1000n));
        expect(refusal.code).toBe("policy_refusal");
        expect(refusal.message).toBe(`the close pays the device 1000 shannons, below the 1001 of the ${view} commitment`);
    });

    it("judges the two views alone when the record carries an unknown key beside them", () => {
        const views = { remote: settled("1000"), local: settled("990"), futureView: "x" } as unknown as Record<
            PolicyView,
            PolicyViewSnapshot
        >;
        expect(() => judgeShutdown(views, 1000n)).not.toThrow();
    });

    it.each(["remote", "local"] as const)("refuses a close while the %s view still lists a TLC", (view) => {
        const views = { remote: settled("0"), local: settled("0") };
        views[view] = {
            ...settled("0"),
            tlcs: [
                {
                    direction: "received",
                    hashAlgorithm: "ckb-hash" as const,
                    boundPaymentHash: HASH_R,
                    amountShannons: "1",
                    expirySeconds: "50",
                },
            ],
        };
        expect(refusalOf(() => judgeShutdown(views, 1000n)).message).toBe(
            `a cooperative close while the ${view} commitment still lists TLCs`,
        );
    });
});
