import type {
    ChannelPins,
    ChannelPolicyRecord,
    DebitIntentRecord,
    HoldInvoicePolicyRecord,
    PolicyViewSnapshot,
    SignedCommitmentRecord,
    WatchtowerSpendRecord,
} from "../../../../src/policy";
import { isChannelPolicyRecord, isDebitIntentRecord, isHoldInvoicePolicyRecord } from "../../../../src/policy/utils/validate.utils";

const MAX_COMMITMENT_NUMBER = 2 ** 48 - 1;

// The "ckb, no tlcs, for remote" commitment cell: molecule written by hand, its lock args committing the body below.
const COMMITMENT_ARGS = "7ff980b4d180ee128bbfc295ef936f8d73a5dea501000000000100a00000000000000000d192bbc331c35aebda34ea9953c40f79a54bab89";
const COMMITMENT_OUTPUT =
    "8600000010000000180000008600000038e5c483160000006e000000100000003000000031000000740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc" +
    `90b1a748438afcdf81d80139000000${COMMITMENT_ARGS}00`;
// The same cell flagged as a settlement unlock's remainder.
const REMAINDER_OUTPUT = COMMITMENT_OUTPUT.slice(0, -2) + "01";
const TYPED_OUTPUT =
    "cf00000010000000180000008600000038e5c483160000006e000000100000003000000031000000740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc" +
    `90b1a748438afcdf81d80139000000${COMMITMENT_ARGS}00` +
    "490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000b502c4a25f89b69ac44329eed55950843ab24495";
// Args of 20 bytes: a secp256k1 lock's, no commitment lock's.
const SHORT_ARGS_OUTPUT =
    "6100000010000000180000006100000038e5c4831600000049000000100000003000000031000000740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc" +
    "90b1a748438afcdf81d801140000007ff980b4d180ee128bbfc295ef936f8d73a5dea5";
const SETTLEMENT_WITNESS =
    "00e5b099614920970b0ec3c35f979f4d1a070336d600f831c60500000000000000000000006b5e8d9ad1828550472e07fe80b39585cc0837d600ef92bd10" +
    "0000000000000000000000";
// 85 bytes: an entry of the legacy layout the record pins.
const TLC_ENTRY = "cd".repeat(85);

describe("isChannelPolicyRecord", () => {
    function record(): ChannelPolicyRecord {
        return {
            version: 1,
            channelId: "0x1f".padEnd(66, "a"),
            lastSignedCommitmentNumbers: { "COMMITMENT:local": 5, "REVOKE:remote": 4 },
            signedSessions: { "COMMITMENT:5": "ab".repeat(32), "REVOKE:4": "cd".repeat(32) },
            nonceReuse: { "COMMITMENT:5": { sessionCommitment: "ef".repeat(32), message: "12".repeat(32) } },
            commitmentHashes: { remote: { commitmentNumber: 5, txHash: "34".repeat(32) } },
            revocations: [
                { version: 2, forRemote: true, signature: "56".repeat(64) },
                { version: 3, forRemote: true, signature: "78".repeat(64) },
            ],
            pins: pins(),
            views: { remote: snapshot(), local: snapshot() },
        };
    }

    function pins(): ChannelPins {
        return {
            fundedShannons: "71900000000",
            localCloseScript: "55000000100000003000000031000000" + "74".repeat(32) + "01" + "0400000000",
            localReservedCkbShannons: { legacy: "9900000000", fullPaymentHash: "10000000000" },
            udtTypeScript: null,
            fundingOutPoint: `${"6f".repeat(32)}:0`,
            fundingCapacityShannons: "96700000000",
            liquidCapacityShannons: "80500000000",
            remoteFundingPubkey: "02" + "63".repeat(32),
            remoteTlcBasePubkey: "03" + "25".repeat(32),
            commitmentDelayEpoch: "1099511627777",
            commitmentFeeRate: "1000",
            remoteReservedCkbShannons: "6300000000",
            remoteCloseScript: "55000000100000003000000031000000" + "01".repeat(32) + "02" + "20000000" + "06".repeat(32),
            lockLayout: "legacy",
        };
    }

    function withPins(override: Record<string, unknown>): Record<string, unknown> {
        return { ...record(), pins: { ...pins(), ...override } };
    }

    function snapshot(): PolicyViewSnapshot {
        return {
            exposureShannons: "5000000000",
            tlcs: [
                {
                    direction: "offered",
                    hashAlgorithm: "ckb-hash",
                    boundPaymentHash: "33".repeat(20),
                    fullPaymentHash: null,
                    amountShannons: "100",
                    expirySeconds: "1700000000",
                },
            ],
            chargedShannons: { ["44".repeat(20)]: "7" },
            creditedShannons: { ["55".repeat(20)]: "0" },
        };
    }

    function withRemote(override: Record<string, unknown>): Record<string, unknown> {
        return { ...record(), views: { remote: { ...snapshot(), ...override }, local: snapshot() } };
    }

    function withTlc(override: Record<string, unknown>): Record<string, unknown> {
        return withRemote({ tlcs: [{ ...snapshot().tlcs[0], ...override }] });
    }

    it("accepts a valid record", () => {
        expect(isChannelPolicyRecord(record())).toBe(true);
    });

    it("accepts the empty maps of a freshly registered channel", () => {
        expect(
            isChannelPolicyRecord({
                ...record(),
                lastSignedCommitmentNumbers: {},
                signedSessions: {},
                nonceReuse: {},
                commitmentHashes: {},
                revocations: [],
                pins: {
                    fundedShannons: "0",
                    localCloseScript: pins().localCloseScript,
                    localReservedCkbShannons: { legacy: "0", fullPaymentHash: "0" },
                    udtTypeScript: null,
                },
                views: {
                    remote: { exposureShannons: "0", tlcs: [], chargedShannons: {}, creditedShannons: {} },
                    local: { exposureShannons: "0", tlcs: [], chargedShannons: {}, creditedShannons: {} },
                },
            }),
        ).toBe(true);
    });

    it("accepts the boundary commitment number", () => {
        expect(
            isChannelPolicyRecord({
                ...record(),
                lastSignedCommitmentNumbers: { "COMMITMENT:local": MAX_COMMITMENT_NUMBER },
                signedSessions: { [`COMMITMENT:${MAX_COMMITMENT_NUMBER}`]: "ab".repeat(32) },
                nonceReuse: { [`COMMITMENT:${MAX_COMMITMENT_NUMBER}`]: { sessionCommitment: "ef".repeat(32), message: "12".repeat(32) } },
                commitmentHashes: { local: { commitmentNumber: MAX_COMMITMENT_NUMBER, txHash: "34".repeat(32) } },
                revocations: [{ version: MAX_COMMITMENT_NUMBER - 1, forRemote: true, signature: "56".repeat(64) }],
            }),
        ).toBe(true);
    });

    it("tolerates unknown extra fields", () => {
        expect(isChannelPolicyRecord({ ...record(), futureField: "x" })).toBe(true);
    });

    it.each(Object.keys(record()))("rejects a record missing %s", (field) => {
        const value = record() as unknown as Record<string, unknown>;
        delete value[field];
        expect(isChannelPolicyRecord(value)).toBe(false);
    });

    // JSON.parse creates __proto__ as an own property; it must neither pollute nor pass as a slot key.
    it("handles __proto__ keys without prototype pollution", () => {
        const withExtra = JSON.parse(`{"__proto__":{"polluted":true},${JSON.stringify(record()).slice(1)}`) as unknown;
        expect(isChannelPolicyRecord(withExtra)).toBe(true);
        expect(({} as Record<string, unknown>).polluted).toBeUndefined();

        const inDigests = { ...record(), signedSessions: JSON.parse('{"__proto__":"' + "ab".repeat(32) + '"}') as unknown };
        expect(isChannelPolicyRecord(inDigests)).toBe(false);
    });

    it.each([null, undefined, [], "record", 42])("rejects the non-object %p", (value) => {
        expect(isChannelPolicyRecord(value)).toBe(false);
    });

    it.each([
        ["a missing version", { version: undefined }],
        ["a future version", { version: 2 }],
        ["a string version", { version: "1" }],
        ["an empty channel id", { channelId: "" }],
        ["a numeric channel id", { channelId: 3 }],
        ["counters that are not an object", { lastSignedCommitmentNumbers: [] }],
        ["a counter for an unknown lane", { lastSignedCommitmentNumbers: { SETTLEMENT: 1 } }],
        // The form before the lanes: one counter per context.
        ["a counter keyed by its context alone", { lastSignedCommitmentNumbers: { COMMITMENT: 1 } }],
        ["a commitment counter on the remote lane", { lastSignedCommitmentNumbers: { "COMMITMENT:remote": 1 } }],
        ["a counter above the commitment cap", { lastSignedCommitmentNumbers: { "COMMITMENT:local": MAX_COMMITMENT_NUMBER + 1 } }],
        ["a negative counter", { lastSignedCommitmentNumbers: { "REVOKE:local": -1 } }],
        ["a fractional counter", { lastSignedCommitmentNumbers: { ANNOUNCEMENT: 0.5 } }],
        ["digests that are not an object", { signedSessions: [] }],
        ["a slot without a number", { signedSessions: { COMMITMENT: "ab".repeat(32) } }],
        ["a slot with an unknown context", { signedSessions: { "SETTLEMENT:1": "ab".repeat(32) } }],
        ["a slot with a non-canonical number", { signedSessions: { "COMMITMENT:01": "ab".repeat(32) } }],
        ["a slot above the commitment cap", { signedSessions: { [`COMMITMENT:${MAX_COMMITMENT_NUMBER + 1}`]: "ab".repeat(32) } }],
        ["a digest that is not 32 bytes", { signedSessions: { "COMMITMENT:5": "ab".repeat(31) } }],
        ["an uppercase digest", { signedSessions: { "COMMITMENT:5": "AB".repeat(32) } }],
        ["a slot of the retired close context", { signedSessions: { "CLOSE:5": "ab".repeat(32) } }],
        ["a reuse log that is not an object", { nonceReuse: [] }],
        ["a reuse entry that is not an object", { nonceReuse: { "COMMITMENT:5": "ef".repeat(32) } }],
        [
            "a reuse entry on a malformed slot",
            { nonceReuse: { "COMMITMENT:05": { sessionCommitment: "ef".repeat(32), message: "12".repeat(32) } } },
        ],
        // Only a served slot can serve a second session.
        [
            "a reuse entry on a slot that served nothing",
            { nonceReuse: { "COMMITMENT:6": { sessionCommitment: "ef".repeat(32), message: "12".repeat(32) } } },
        ],
        [
            "a reuse entry repeating the slot's first session",
            { nonceReuse: { "COMMITMENT:5": { sessionCommitment: "ab".repeat(32), message: "12".repeat(32) } } },
        ],
        ["a reuse entry without its session", { nonceReuse: { "COMMITMENT:5": { message: "12".repeat(32) } } }],
        ["a reuse entry without its message", { nonceReuse: { "COMMITMENT:5": { sessionCommitment: "ef".repeat(32) } } }],
        [
            "a reuse entry with a short session",
            { nonceReuse: { "COMMITMENT:5": { sessionCommitment: "ef".repeat(31), message: "12".repeat(32) } } },
        ],
        [
            "a reuse entry with an uppercase message",
            { nonceReuse: { "COMMITMENT:5": { sessionCommitment: "ef".repeat(32), message: "AB".repeat(32) } } },
        ],
        ["commitment hashes that are not an object", { commitmentHashes: [] }],
        ["a commitment hash under an unknown view", { commitmentHashes: { forRemote: { commitmentNumber: 5, txHash: "34".repeat(32) } } }],
        ["a commitment hash that is not an object", { commitmentHashes: { remote: "34".repeat(32) } }],
        ["a commitment hash without its number", { commitmentHashes: { remote: { txHash: "34".repeat(32) } } }],
        [
            "a commitment hash above the commitment cap",
            { commitmentHashes: { remote: { commitmentNumber: MAX_COMMITMENT_NUMBER + 1, txHash: "34".repeat(32) } } },
        ],
        ["a commitment hash with a negative number", { commitmentHashes: { local: { commitmentNumber: -1, txHash: "34".repeat(32) } } }],
        ["a commitment hash without its hash", { commitmentHashes: { remote: { commitmentNumber: 5 } } }],
        ["a commitment hash of 31 bytes", { commitmentHashes: { remote: { commitmentNumber: 5, txHash: "34".repeat(31) } } }],
        ["a commitment hash in uppercase", { commitmentHashes: { remote: { commitmentNumber: 5, txHash: "AB".repeat(32) } } }],
        ["revocations that are not an array", { revocations: {} }],
        ["a revocation that is not an object", { revocations: ["56".repeat(64)] }],
        ["a revocation without its version", { revocations: [{ forRemote: true, signature: "56".repeat(64) }] }],
        ["a revocation with a negative version", { revocations: [{ version: -1, forRemote: true, signature: "56".repeat(64) }] }],
        // Its revocation would claim the slot one above the chain's last number.
        [
            "a revocation of the chain's last commitment number",
            { revocations: [{ version: MAX_COMMITMENT_NUMBER, forRemote: true, signature: "56".repeat(64) }] },
        ],
        ["a revocation of the device's own commitment", { revocations: [{ version: 2, forRemote: false, signature: "56".repeat(64) }] }],
        ["a revocation without its direction", { revocations: [{ version: 2, signature: "56".repeat(64) }] }],
        ["a revocation with a partial signature", { revocations: [{ version: 2, forRemote: true, signature: "56".repeat(32) }] }],
        ["a revocation with an uppercase signature", { revocations: [{ version: 2, forRemote: true, signature: "AB".repeat(64) }] }],
        [
            "two revocations of one version",
            {
                revocations: [
                    { version: 2, forRemote: true, signature: "56".repeat(64) },
                    { version: 2, forRemote: true, signature: "78".repeat(64) },
                ],
            },
        ],
        [
            "revocations out of order",
            {
                revocations: [
                    { version: 3, forRemote: true, signature: "56".repeat(64) },
                    { version: 2, forRemote: true, signature: "78".repeat(64) },
                ],
            },
        ],
        ["views that are not an object", { views: [] }],
        ["one view only", { views: { remote: snapshot() } }],
        ["a view that is not an object", { views: { remote: snapshot(), local: "snapshot" } }],
    ])("rejects a record with %s", (_, override) => {
        expect(isChannelPolicyRecord({ ...record(), ...override })).toBe(false);
    });

    it.each(["fundedShannons", "localCloseScript", "localReservedCkbShannons", "udtTypeScript"])(
        "rejects pins missing %s, fixed at registration",
        (field) => {
            const value: Record<string, unknown> = pins();
            delete value[field];
            expect(isChannelPolicyRecord({ ...record(), pins: value })).toBe(false);
        },
    );

    it.each(Object.keys(pins()).slice(4))("accepts pins that have not seen %s yet", (field) => {
        const value: Record<string, unknown> = pins();
        delete value[field];
        expect(isChannelPolicyRecord({ ...record(), pins: value })).toBe(true);
    });

    it.each([["pins that are not an object", { pins: [] }]])("rejects a record with %s", (_, override) => {
        expect(isChannelPolicyRecord({ ...record(), ...override })).toBe(false);
    });

    it.each([
        ["a funded amount with a leading zero", { fundedShannons: "01" }],
        ["a numeric funded amount", { fundedShannons: 1 }],
        ["an empty close script", { localCloseScript: "" }],
        ["an uppercase close script", { localCloseScript: "AB" }],
        ["a close script of half a byte", { localCloseScript: "abc" }],
        ["a close script that is not hex", { localCloseScript: "zz" }],
        ["a close script that is not a string", { localCloseScript: 5 }],
        ["an empty peer close script", { remoteCloseScript: "" }],
        ["an uppercase peer close script", { remoteCloseScript: "AB" }],
        ["a peer close script of half a byte", { remoteCloseScript: "abc" }],
        ["a peer close script that is not hex", { remoteCloseScript: "zz" }],
        ["a peer close script that is not a string", { remoteCloseScript: 5 }],
        ["a null peer close script", { remoteCloseScript: null }],
        ["a UDT script", { udtTypeScript: "ab".repeat(53) }],
        ["an absent UDT script", { udtTypeScript: undefined }],
        ["an out point without an index", { fundingOutPoint: "6f".repeat(32) }],
        ["an out point under a short hash", { fundingOutPoint: `${"6f".repeat(31)}:0` }],
        ["an out point with a non-canonical index", { fundingOutPoint: `${"6f".repeat(32)}:01` }],
        ["an out point index above u32", { fundingOutPoint: `${"6f".repeat(32)}:4294967296` }],
        ["a numeric funding capacity", { fundingCapacityShannons: 96700000000 }],
        ["a funding capacity above u64", { fundingCapacityShannons: "18446744073709551616" }],
        ["a liquid capacity that is not decimal", { liquidCapacityShannons: "0x1" }],
        ["a peer funding key of 32 bytes", { remoteFundingPubkey: "63".repeat(32) }],
        ["an uppercase peer TLC base key", { remoteTlcBasePubkey: "03" + "AB".repeat(32) }],
        ["a delay above u64", { commitmentDelayEpoch: "18446744073709551616" }],
        ["a fee rate with a leading zero", { commitmentFeeRate: "01000" }],
        ["a local reserve as one string, the form before the layouts", { localReservedCkbShannons: "9900000000" }],
        ["a null local reserve", { localReservedCkbShannons: null }],
        ["a local reserve that is an array", { localReservedCkbShannons: ["9900000000", "10000000000"] }],
        ["a local reserve missing the legacy layout", { localReservedCkbShannons: { fullPaymentHash: "10000000000" } }],
        ["a local reserve missing the full-hash layout", { localReservedCkbShannons: { legacy: "9900000000" } }],
        [
            "a local reserve under a third layout",
            { localReservedCkbShannons: { legacy: "9900000000", fullPaymentHash: "10000000000", future: "10100000000" } },
        ],
        ["a negative local reserve", { localReservedCkbShannons: { legacy: "-1", fullPaymentHash: "10000000000" } }],
        ["a numeric local reserve", { localReservedCkbShannons: { legacy: "9900000000", fullPaymentHash: 10000000000 } }],
        ["a local reserve in hex", { localReservedCkbShannons: { legacy: "0x1", fullPaymentHash: "10000000000" } }],
        ["a local reserve with a leading zero", { localReservedCkbShannons: { legacy: "9900000000", fullPaymentHash: "010000000000" } }],
        ["a local reserve above u64", { localReservedCkbShannons: { legacy: "18446744073709551616", fullPaymentHash: "10000000000" } }],
        ["a remote reserve of more digits than u64 has", { remoteReservedCkbShannons: "1".repeat(21) }],
        ["a pin set to null", { commitmentFeeRate: null }],
        ["a lock layout fiber does not define", { lockLayout: "full_payment_hash" }],
        ["a capitalised lock layout", { lockLayout: "Legacy" }],
        ["an empty lock layout", { lockLayout: "" }],
        ["a null lock layout", { lockLayout: null }],
        ["a numeric lock layout", { lockLayout: 1 }],
    ])("rejects pins with %s", (_, override) => {
        expect(isChannelPolicyRecord(withPins(override))).toBe(false);
    });

    it.each(["legacy", "fullPaymentHash"])("accepts the %s lock layout", (lockLayout) => {
        expect(isChannelPolicyRecord(withPins({ lockLayout }))).toBe(true);
    });

    it("accepts the reserves at u64's maximum under both layouts", () => {
        expect(
            isChannelPolicyRecord(
                withPins({ localReservedCkbShannons: { legacy: "18446744073709551615", fullPaymentHash: "18446744073709551615" } }),
            ),
        ).toBe(true);
    });

    it("accepts the boundary out point index and u64 values", () => {
        expect(
            isChannelPolicyRecord(
                withPins({
                    fundingOutPoint: `${"6f".repeat(32)}:4294967295`,
                    commitmentDelayEpoch: "18446744073709551615",
                    remoteReservedCkbShannons: "18446744073709551615",
                }),
            ),
        ).toBe(true);
    });

    it("tolerates an unknown extra pin", () => {
        expect(isChannelPolicyRecord(withPins({ futurePin: "x" }))).toBe(true);
    });

    it("tolerates an unknown extra key beside the two views", () => {
        expect(isChannelPolicyRecord({ ...record(), views: { remote: snapshot(), local: snapshot(), futureView: "x" } })).toBe(true);
    });

    it.each(Object.keys(snapshot()))("rejects a view missing %s", (field) => {
        const view = snapshot() as unknown as Record<string, unknown>;
        delete view[field];
        expect(isChannelPolicyRecord({ ...record(), views: { remote: snapshot(), local: view } })).toBe(false);
    });

    it.each([
        ["an exposure with a leading zero", { exposureShannons: "01" }],
        ["a negative exposure", { exposureShannons: "-1" }],
        ["a numeric exposure", { exposureShannons: 100 }],
        ["an exposure above u128", { exposureShannons: "340282366920938463463374607431768211456" }],
        ["TLCs that are not an array", { tlcs: {} }],
        ["a TLC that is not an object", { tlcs: ["tlc"] }],
        ["charges that are not an object", { chargedShannons: [] }],
        ["a charge under a full 32-byte hash", { chargedShannons: { ["44".repeat(32)]: "7" } }],
        ["a charge under an uppercase hash", { chargedShannons: { ["AB".repeat(20)]: "7" } }],
        ["a charge that is not decimal", { chargedShannons: { ["44".repeat(20)]: "0x7" } }],
        ["credits that are not an object", { creditedShannons: "none" }],
        ["a credit under a short hash", { creditedShannons: { ["55".repeat(19)]: "0" } }],
        ["a credit that is negative", { creditedShannons: { ["55".repeat(20)]: "-1" } }],
    ])("rejects a view with %s", (_, override) => {
        expect(isChannelPolicyRecord(withRemote(override))).toBe(false);
    });

    it.each(["direction", "hashAlgorithm", "boundPaymentHash", "fullPaymentHash", "amountShannons", "expirySeconds"])(
        "rejects a TLC missing %s",
        (field) => {
            const tlc: Record<string, unknown> = { ...snapshot().tlcs[0] };
            delete tlc[field];
            expect(isChannelPolicyRecord(withRemote({ tlcs: [tlc] }))).toBe(false);
        },
    );

    it.each([
        ["an unknown direction", { direction: "forwarded" }],
        ["an algorithm fiber does not define", { hashAlgorithm: "ckb_hash" }],
        ["a full 32-byte hash", { boundPaymentHash: "33".repeat(32) }],
        ["an uppercase hash", { boundPaymentHash: "AB".repeat(20) }],
        ["an amount that is not decimal", { amountShannons: "1e3" }],
        ["a numeric expiry", { expirySeconds: 1700000000 }],
        ["an expiry with a leading zero", { expirySeconds: "01" }],
        ["a negative expiry", { expirySeconds: "-1" }],
        ["an expiry above u64", { expirySeconds: "18446744073709551616" }],
        ["an expiry of more digits than u64 has", { expirySeconds: "1".repeat(21) }],
        ["a full hash of 31 bytes", { fullPaymentHash: "33".repeat(31) }],
        ["a full hash of 33 bytes", { fullPaymentHash: "33".repeat(33) }],
        ["an uppercase full hash", { fullPaymentHash: "33".repeat(20) + "AB".repeat(12) }],
        ["a full hash the bound hash is not the prefix of", { fullPaymentHash: "34".repeat(32) }],
        [
            "a full hash that differs from the bound one in its last bound byte",
            { fullPaymentHash: "33".repeat(19) + "34" + "33".repeat(12) },
        ],
        ["a numeric full hash", { fullPaymentHash: 0 }],
        ["an undefined full hash", { fullPaymentHash: undefined }],
    ])("rejects a TLC with %s", (_, override) => {
        expect(isChannelPolicyRecord(withTlc(override))).toBe(false);
    });

    it("accepts a TLC expiring at the last second u64 can hold", () => {
        expect(isChannelPolicyRecord(withTlc({ expirySeconds: "18446744073709551615" }))).toBe(true);
    });

    it("accepts a TLC binding the whole hash its bound hash is the prefix of", () => {
        expect(isChannelPolicyRecord(withTlc({ fullPaymentHash: "33".repeat(20) + "ab".repeat(12) }))).toBe(true);
    });

    function commitment(): SignedCommitmentRecord {
        return {
            commitmentNumber: 0,
            txHash: "02".repeat(32),
            source: { output: COMMITMENT_OUTPUT, outputData: "" },
            settlementWitness: SETTLEMENT_WITNESS,
        };
    }

    function spend(): WatchtowerSpendRecord {
        return {
            requestId: "cc".repeat(32),
            purpose: { kind: "tlc", commitmentNumber: 6 },
            view: "remote",
            commitmentNumber: 5,
            tlcEntry: TLC_ENTRY,
            txHash: "5f".repeat(32),
            remainder: { output: REMAINDER_OUTPUT, outputData: "" },
            signature: "b4".repeat(65),
            applied: false,
        };
    }

    function withCommitment(override: Record<string, unknown>): Record<string, unknown> {
        return { ...record(), commitmentHashes: { remote: { ...commitment(), ...override } } };
    }

    function withSource(override: Record<string, unknown>): Record<string, unknown> {
        return withCommitment({ source: { ...commitment().source, ...override } });
    }

    function withSpend(override: Record<string, unknown>): Record<string, unknown> {
        return { ...record(), watchtowerSpends: [{ ...spend(), ...override }] };
    }

    function previous(): Record<string, unknown> {
        const { source, settlementWitness } = commitment();
        return { commitmentNumber: 4, source, settlementWitness };
    }

    function withPrevious(override: Record<string, unknown>): Record<string, unknown> {
        return { ...record(), previousRemoteCommitment: { ...previous(), ...override } };
    }

    it("accepts a commitment with its cell and settlement body, and one without, signed before the record kept them", () => {
        expect(
            isChannelPolicyRecord({
                ...record(),
                commitmentHashes: { remote: commitment(), local: { commitmentNumber: 5, txHash: "34".repeat(32) } },
            }),
        ).toBe(true);
    });

    it.each([
        ["a cell without its settlement body", { settlementWitness: undefined }],
        ["a settlement body without its cell", { source: undefined }],
        ["a cell that is not an object", { source: COMMITMENT_OUTPUT }],
        ["a settlement body that is not hex", { settlementWitness: "zz" }],
        ["an empty settlement body", { settlementWitness: "" }],
        ["a settlement body its layout does not read", { settlementWitness: SETTLEMENT_WITNESS.slice(0, -2) }],
        [
            "a settlement body its layout does not read, which the lock args commit",
            {
                source: {
                    output: COMMITMENT_OUTPUT.replace(
                        "d192bbc331c35aebda34ea9953c40f79a54bab89",
                        "555e6d27ea3c664b1aec27d6b30dbc42de99abbb",
                    ),
                    outputData: "",
                },
                settlementWitness: SETTLEMENT_WITNESS.slice(0, -2),
            },
        ],
        // A balance's amount moved by one: a body, but not the one the args commit.
        ["a settlement body the lock args do not commit", { settlementWitness: SETTLEMENT_WITNESS.replace("00ef92bd10", "01ef92bd10") }],
    ])("rejects a commitment with %s", (_, override) => {
        expect(isChannelPolicyRecord(withCommitment(override))).toBe(false);
    });

    it.each([
        ["no output", { output: undefined }],
        ["an empty output", { output: "" }],
        ["an output that is not hex", { output: "zz" }],
        ["an output no molecule reader takes", { output: COMMITMENT_OUTPUT.slice(0, -2) }],
        ["an output with a type", { output: TYPED_OUTPUT }],
        ["an output whose lock is no commitment lock's", { output: SHORT_ARGS_OUTPUT }],
        ["the output of a remainder", { output: REMAINDER_OUTPUT }],
        ["output data", { outputData: "00" }],
        ["no output data", { outputData: undefined }],
    ])("rejects a commitment cell with %s", (_, override) => {
        expect(isChannelPolicyRecord(withSource(override))).toBe(false);
    });

    it("accepts the remote commitment signed before the last remote one, one below it", () => {
        expect(isChannelPolicyRecord({ ...record(), previousRemoteCommitment: previous() })).toBe(true);
    });

    it.each([
        ["no remote commitment after it", { ...record(), commitmentHashes: {}, previousRemoteCommitment: previous() }],
        ["a previous remote commitment that is not an object", { ...record(), previousRemoteCommitment: "04" }],
        ["a previous remote commitment at the last one's version", withPrevious({ commitmentNumber: 5 })],
        ["a previous remote commitment two below the last one", withPrevious({ commitmentNumber: 3 })],
        ["a previous remote commitment without its version", withPrevious({ commitmentNumber: undefined })],
        [
            "a previous remote commitment at a negative version, below a last one at 0",
            {
                ...record(),
                commitmentHashes: { remote: { commitmentNumber: 0, txHash: "34".repeat(32) } },
                previousRemoteCommitment: { ...previous(), commitmentNumber: -1 },
            },
        ],
        ["a previous remote commitment above the chain's last number", withPrevious({ commitmentNumber: MAX_COMMITMENT_NUMBER + 1 })],
        ["a previous remote commitment without its cell", withPrevious({ source: undefined })],
        ["a previous remote commitment without its settlement body", withPrevious({ settlementWitness: undefined })],
        [
            "a previous remote commitment whose cell's lock args do not commit its settlement body",
            withPrevious({ settlementWitness: SETTLEMENT_WITNESS.replace("00ef92bd10", "01ef92bd10") }),
        ],
    ])("rejects %s", (_, value) => {
        expect(isChannelPolicyRecord(value)).toBe(false);
    });

    it("accepts the spends a watchtower was signed, with and without their remainder and signature", () => {
        const last = {
            ...spend(),
            requestId: "dd".repeat(32),
            purpose: { kind: "settlement" },
            tlcEntry: null,
            remainder: null,
            signature: null,
        };
        expect(isChannelPolicyRecord({ ...record(), watchtowerSpends: [spend(), last] })).toBe(true);
        expect(isChannelPolicyRecord({ ...record(), watchtowerSpends: [] })).toBe(true);
    });

    // One per TLC and one for the balance, in each of the three commitments a watchtower settles.
    it("accepts 768 spends, and no more", () => {
        const spends = (count: number) =>
            Array.from({ length: count }, (_, index) => ({
                ...spend(),
                requestId: index.toString(16).padStart(64, "0"),
                commitmentNumber: index,
            }));
        expect(isChannelPolicyRecord({ ...record(), watchtowerSpends: spends(768) })).toBe(true);
        expect(isChannelPolicyRecord({ ...record(), watchtowerSpends: spends(769) })).toBe(false);
    });

    it.each([
        ["another commitment's", { commitmentNumber: 4 }],
        ["another TLC's", { tlcEntry: "ce".repeat(85) }],
        ["the balance's", { purpose: { kind: "settlement" }, tlcEntry: null }],
    ])("accepts a second spend of %s unlock", (_, override) => {
        const second = { ...spend(), requestId: "dd".repeat(32), ...override };
        expect(isChannelPolicyRecord({ ...record(), watchtowerSpends: [spend(), second] })).toBe(true);
    });

    it("accepts a second spend of the same unlock in the other view's commitment", () => {
        const commitmentHashes = {
            remote: { commitmentNumber: 5, txHash: "34".repeat(32) },
            local: { commitmentNumber: 5, txHash: "35".repeat(32) },
        };
        const second = { ...spend(), requestId: "dd".repeat(32), view: "local" };
        expect(isChannelPolicyRecord({ ...record(), commitmentHashes, watchtowerSpends: [spend(), second] })).toBe(true);
    });

    it.each([
        ["spends that are not an array", { watchtowerSpends: {} }],
        ["a spend that is not an object", { watchtowerSpends: ["cc".repeat(32)] }],
        ["two spends of one request", { watchtowerSpends: [spend(), { ...spend(), commitmentNumber: 4 }] }],
        ["two spends of one commitment's unlock", { watchtowerSpends: [spend(), { ...spend(), requestId: "dd".repeat(32) }] }],
    ])("rejects a record with %s", (_, override) => {
        expect(isChannelPolicyRecord({ ...record(), ...override })).toBe(false);
    });

    it("rejects a spend of a view no commitment was signed in", () => {
        expect(isChannelPolicyRecord(withSpend({ view: "local" }))).toBe(false);
    });

    it.each(Object.keys(spend()))("rejects a spend missing %s", (field) => {
        const value = spend() as unknown as Record<string, unknown>;
        delete value[field];
        expect(isChannelPolicyRecord({ ...record(), watchtowerSpends: [value] })).toBe(false);
    });

    it.each([
        ["a request id of 31 bytes", { requestId: "cc".repeat(31) }],
        ["an uppercase request id", { requestId: "CC".repeat(32) }],
        ["a purpose that is not an object", { purpose: "settlement" }],
        ["a purpose of another kind", { purpose: { kind: "revocation" } }],
        ["a TLC purpose without its number", { purpose: { kind: "tlc" } }],
        ["a TLC purpose above the chain's last number", { purpose: { kind: "tlc", commitmentNumber: MAX_COMMITMENT_NUMBER + 1 } }],
        ["an unknown view", { view: "forRemote" }],
        ["a view the prototype names", { view: "toString" }],
        ["a numeric view", { view: 1 }],
        ["a commitment number above the chain's last", { commitmentNumber: MAX_COMMITMENT_NUMBER + 1 }],
        ["a fractional commitment number", { commitmentNumber: 4.5 }],
        ["an empty TLC entry", { tlcEntry: "" }],
        ["an uppercase TLC entry", { tlcEntry: "CD".repeat(85) }],
        ["a TLC entry a byte short of its layout's", { tlcEntry: "cd".repeat(84) }],
        ["a TLC entry a byte past its layout's", { tlcEntry: "cd".repeat(86) }],
        ["a TLC entry of the layout the record did not pin", { tlcEntry: "cd".repeat(97) }],
        ["a TLC entry of half a byte", { tlcEntry: "c" }],
        ["no TLC entry under a TLC key", { tlcEntry: null }],
        ["a TLC entry under the settlement key", { purpose: { kind: "settlement" } }],
        ["a tx hash of 31 bytes", { txHash: "5f".repeat(31) }],
        ["a remainder that is not an object", { remainder: REMAINDER_OUTPUT }],
        ["the commitment's own cell as its remainder", { remainder: { output: COMMITMENT_OUTPUT, outputData: "" } }],
        ["a remainder with a type", { remainder: { output: TYPED_OUTPUT, outputData: "" } }],
        ["a remainder with data", { remainder: { output: REMAINDER_OUTPUT, outputData: "00" } }],
        ["a remainder no molecule reader takes", { remainder: { output: REMAINDER_OUTPUT.slice(2), outputData: "" } }],
        ["a compact signature", { signature: "b4".repeat(64) }],
        ["an uppercase signature", { signature: "B4".repeat(65) }],
        ["an applied flag in a string", { applied: "true" }],
        ["a null applied flag", { applied: null }],
        ["an applied flag of 1", { applied: 1 }],
        ["no signature once applied", { applied: true, signature: null }],
    ])("rejects a spend with %s", (_, override) => {
        expect(isChannelPolicyRecord(withSpend(override))).toBe(false);
    });

    it("accepts a TLC entry of the full payment hash layout once the record pins it", () => {
        const value = withSpend({ tlcEntry: "cd".repeat(97) });
        expect(isChannelPolicyRecord({ ...value, pins: { ...pins(), lockLayout: "fullPaymentHash" } })).toBe(true);
        expect(
            isChannelPolicyRecord({ ...value, pins: { ...pins(), lockLayout: "fullPaymentHash" }, watchtowerSpends: [{ ...spend() }] }),
        ).toBe(false);
    });

    it.each([
        [85, true],
        [97, true],
        [96, false],
    ])("takes a TLC entry of %s bytes before the record pins a layout: %s", (length, accepted) => {
        expect(isChannelPolicyRecord({ ...withSpend({ tlcEntry: "cd".repeat(length) }), pins: { ...pins(), lockLayout: undefined } })).toBe(
            accepted,
        );
    });

    it("accepts a spend fiber applied, with its signature", () => {
        expect(isChannelPolicyRecord(withSpend({ applied: true }))).toBe(true);
    });

    it("accepts the settlement purpose and the chain's last TLC number and commitment number", () => {
        expect(isChannelPolicyRecord(withSpend({ purpose: { kind: "settlement" }, tlcEntry: null }))).toBe(true);
        expect(isChannelPolicyRecord(withSpend({ purpose: { kind: "tlc", commitmentNumber: MAX_COMMITMENT_NUMBER } }))).toBe(true);
        expect(isChannelPolicyRecord(withSpend({ commitmentNumber: MAX_COMMITMENT_NUMBER }))).toBe(true);
    });
});

describe("isDebitIntentRecord", () => {
    function intent(): DebitIntentRecord {
        return { version: 1, paymentHash: "11".repeat(32), maxShannons: "1500000000", open: true, channelIndexes: [3, 0] };
    }

    it("accepts a valid record, and one no channel has shown yet", () => {
        expect(isDebitIntentRecord(intent())).toBe(true);
        expect(isDebitIntentRecord({ ...intent(), channelIndexes: [] })).toBe(true);
    });

    it("tolerates unknown extra fields", () => {
        expect(isDebitIntentRecord({ ...intent(), futureField: "x" })).toBe(true);
    });

    it.each(Object.keys(intent()))("rejects a record missing %s", (field) => {
        const value = intent() as unknown as Record<string, unknown>;
        delete value[field];
        expect(isDebitIntentRecord(value)).toBe(false);
    });

    it.each([null, [], "intent"])("rejects the non-object %p", (value) => {
        expect(isDebitIntentRecord(value)).toBe(false);
    });

    it.each([
        ["a future version", { version: 2 }],
        ["a string version", { version: "1" }],
        ["a truncated hash", { paymentHash: "11".repeat(20) }],
        ["an uppercase hash", { paymentHash: "AB".repeat(32) }],
        ["a maximum that is not decimal", { maxShannons: "0x10" }],
        ["a string flag", { open: "true" }],
        ["channels that are not an array", { channelIndexes: 3 }],
        ["a negative channel index", { channelIndexes: [-1] }],
        ["a repeated channel index", { channelIndexes: [3, 3] }],
    ])("rejects a record with %s", (_, override) => {
        expect(isDebitIntentRecord({ ...intent(), ...override })).toBe(false);
    });
});

describe("isHoldInvoicePolicyRecord", () => {
    function invoice(): HoldInvoicePolicyRecord {
        return {
            version: 1,
            paymentHash: "11".repeat(32),
            amountShannons: "2250000000",
            hashAlgorithm: "ckb-hash",
            invoiceIndex: 1761475200000,
            released: false,
            channelIndexes: [7],
        };
    }

    it("accepts a valid record", () => {
        expect(isHoldInvoicePolicyRecord(invoice())).toBe(true);
    });

    it.each([0, Number.MAX_SAFE_INTEGER])("accepts the invoice index %p, at either end of the range", (invoiceIndex) => {
        expect(isHoldInvoicePolicyRecord({ ...invoice(), invoiceIndex })).toBe(true);
    });

    it("accepts the amount of one shannon, the least above zero", () => {
        expect(isHoldInvoicePolicyRecord({ ...invoice(), amountShannons: "1" })).toBe(true);
    });

    it("tolerates unknown extra fields", () => {
        expect(isHoldInvoicePolicyRecord({ ...invoice(), futureField: "x" })).toBe(true);
    });

    it.each(Object.keys(invoice()))("rejects a record missing %s", (field) => {
        const value = invoice() as unknown as Record<string, unknown>;
        delete value[field];
        expect(isHoldInvoicePolicyRecord(value)).toBe(false);
    });

    it.each([null, [], "invoice"])("rejects the non-object %p", (value) => {
        expect(isHoldInvoicePolicyRecord(value)).toBe(false);
    });

    it.each([
        ["a future version", { version: 2 }],
        ["a string version", { version: "1" }],
        ["a truncated hash", { paymentHash: "11".repeat(20) }],
        ["an amount that is not decimal", { amountShannons: "-5" }],
        ["an amount of zero", { amountShannons: "0" }],
        ["an algorithm fiber does not define", { hashAlgorithm: "ckb_hash" }],
        ["a fractional invoice index", { invoiceIndex: 1.5 }],
        ["a negative invoice index", { invoiceIndex: -1 }],
        ["an invoice index past the highest a preimage derives from", { invoiceIndex: 2 ** 53 }],
        ["an invoice index in a string", { invoiceIndex: "1761475200000" }],
        ["a numeric flag", { released: 0 }],
        ["a fractional channel index", { channelIndexes: [1.5] }],
        ["a repeated channel index", { channelIndexes: [7, 7] }],
    ])("rejects a record with %s", (_, override) => {
        expect(isHoldInvoicePolicyRecord({ ...invoice(), ...override })).toBe(false);
    });
});
