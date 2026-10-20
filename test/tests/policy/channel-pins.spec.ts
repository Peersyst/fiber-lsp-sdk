import { hexToBytes } from "@noble/hashes/utils.js";
import type { ChannelPins, StatedChannelPins } from "../../../src/policy";
import { CHANNEL_TERMS_PINS, FIRST_SIGHT_CHANNEL_PINS } from "../../../src/policy";
import {
    channelTermsPins,
    findChannelPinConflict,
    fundingCellPins,
    statedChannelPins,
    withChannelPins,
} from "../../../src/policy/channel-pins";
import { toChannelAnnouncementInput, toClosingTxInput, toCommitmentTxInput, toRevocationInput } from "../../utils/digest-inputs";
import { caseOf, loadInteropVectors } from "../../utils/interop-vectors";

const digest = loadInteropVectors().digest;

const FUNDING_TX_HASH = "6f4ea49726c322dbedceb12a09d013a0256ea697dc362cc8865f8bbcdd17684e";
const REMOTE_FUNDING_PUBKEY = "026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638";
const REMOTE_TLC_BASE_PUBKEY = "032559e1b167552782cab5be4294260d51edfc36aef4ca7cc165b3b21b15e98e21";
const LOCAL_CLOSE_SCRIPT_PIN =
    "4900000010000000300000003100000074d3f63a22681bdb6ff6512866db95264338cfaee12f71e28b9f23c414990c9c0114000000da694932ba803b4c07f6e3a9b6b2ea3f9c6c66c7";
const UDT_SCRIPT_PIN =
    "55000000100000003000000031000000912f64f976947ed5467ff5e7ba4c87bd37f240cdbdba0b38da619372056ef827" +
    "01200000008612706980baca14e3d03ea4d77d185e6f7338cd6e98a0ea0cd17a69918f2578";

const CKB_CAPACITY_PINS = {
    liquidCapacityShannons: "80500000000",
    fundingCapacityShannons: "96700000000",
    localReservedCkbShannons: "9900000000",
    remoteReservedCkbShannons: "6300000000",
};

// The full-hash cases: the device's reserve one byte larger, and the funding cell with it.
const CKB_FULL_HASH_CAPACITY_PINS = {
    liquidCapacityShannons: "80500000000",
    fundingCapacityShannons: "96800000000",
    localReservedCkbShannons: "10000000000",
    remoteReservedCkbShannons: "6300000000",
};

const PINS: ChannelPins = {
    fundedShannons: "71900000000",
    localCloseScript: LOCAL_CLOSE_SCRIPT_PIN,
    localReservedCkbShannons: { legacy: "9900000000", fullPaymentHash: "10000000000" },
    udtTypeScript: null,
    fundingOutPoint: `${FUNDING_TX_HASH}:0`,
    commitmentFeeRate: "1000",
};

describe("fundingCellPins", () => {
    it("writes the out point as its hash and index, and the capacity as given", () => {
        expect(fundingCellPins({ txHash: hexToBytes(FUNDING_TX_HASH), index: 4294967295 }, "96700000000")).toEqual<StatedChannelPins>({
            fundingOutPoint: `${FUNDING_TX_HASH}:4294967295`,
            fundingCapacityShannons: "96700000000",
        });
    });
});

describe("channelTermsPins", () => {
    it("writes the fee rate in decimal, and the amounts as given", () => {
        expect(
            channelTermsPins({
                commitmentFeeRate: 18446744073709551615n,
                remoteReservedCkbShannons: "0",
                liquidCapacityShannons: "80500000000",
            }),
        ).toEqual<StatedChannelPins>({
            liquidCapacityShannons: "80500000000",
            commitmentFeeRate: "18446744073709551615",
            remoteReservedCkbShannons: "0",
        });
    });
});

describe("statedChannelPins", () => {
    it("reads what a commitment states: the funding cell, the peer's keys, the delay, the rate, the reserves, the asset and the layout", () => {
        const input = toCommitmentTxInput(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote"), digest.remote);
        expect(statedChannelPins({ kind: "commitment_tx", input })).toEqual<StatedChannelPins>({
            ...CKB_CAPACITY_PINS,
            fundingOutPoint: `${FUNDING_TX_HASH}:0`,
            remoteFundingPubkey: REMOTE_FUNDING_PUBKEY,
            remoteTlcBasePubkey: REMOTE_TLC_BASE_PUBKEY,
            commitmentDelayEpoch: "1099511627777",
            commitmentFeeRate: "1000",
            udtTypeScript: null,
            lockLayout: "legacy",
        });
    });

    it("reads the full-hash layout a commitment is written under, with the reserve it states under it", () => {
        const input = toCommitmentTxInput(caseOf(digest.commitment_cases, "ckb, three tlcs, for remote, full payment hash"), digest.remote);
        expect(statedChannelPins({ kind: "commitment_tx", input })).toEqual<StatedChannelPins>({
            ...CKB_FULL_HASH_CAPACITY_PINS,
            fundingOutPoint: `${FUNDING_TX_HASH}:3`,
            remoteFundingPubkey: REMOTE_FUNDING_PUBKEY,
            remoteTlcBasePubkey: REMOTE_TLC_BASE_PUBKEY,
            commitmentDelayEpoch: "1099511627777",
            commitmentFeeRate: "1537",
            udtTypeScript: null,
            lockLayout: "fullPaymentHash",
        });
    });

    // A conflict names the first value that differs: the layout decides the reserve, so it is read right after the asset.
    it("states the asset first and the layout second", () => {
        const input = toCommitmentTxInput(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote"), digest.remote);
        expect(Object.keys(statedChannelPins({ kind: "commitment_tx", input })).slice(0, 2)).toEqual(["udtTypeScript", "lockLayout"]);
        const revocation = toRevocationInput(caseOf(digest.revocation_cases, "ckb, send side"), digest.remote);
        expect(Object.keys(statedChannelPins({ kind: "revocation", input: revocation })).slice(0, 2)).toEqual([
            "udtTypeScript",
            "lockLayout",
        ]);
    });

    it("reads the UDT script of a UDT commitment, and its funding cell's capacity in CKB beside its liquid amount", () => {
        const input = toCommitmentTxInput(caseOf(digest.commitment_cases, "udt, two tlcs, for remote"), digest.remote);
        expect(statedChannelPins({ kind: "commitment_tx", input })).toMatchObject<StatedChannelPins>({
            liquidCapacityShannons: "800000000000000000000",
            fundingCapacityShannons: "16200000000",
            udtTypeScript: UDT_SCRIPT_PIN,
        });
    });

    // Its outputs are what both fees left, so neither a capacity nor a reserve can be read off them.
    it("reads what a close states, the script it pays the device to included, and no capacity, reserve or layout", () => {
        const input = toClosingTxInput(caseOf(digest.shutdown_cases, "ckb"), digest.remote);
        expect(statedChannelPins({ kind: "closing_tx", input })).toEqual<StatedChannelPins>({
            fundingOutPoint: `${FUNDING_TX_HASH}:0`,
            remoteFundingPubkey: REMOTE_FUNDING_PUBKEY,
            localCloseScript: LOCAL_CLOSE_SCRIPT_PIN,
            udtTypeScript: null,
        });
        expect(Object.keys(statedChannelPins({ kind: "closing_tx", input }))[0]).toBe("udtTypeScript");
    });

    it("reads what a revocation the device sends states, its layout included, leaving its payout out: it is the peer's script", () => {
        const input = toRevocationInput(caseOf(digest.revocation_cases, "ckb, send side"), digest.remote);
        expect(statedChannelPins({ kind: "revocation", input })).toEqual<StatedChannelPins>({
            ...CKB_CAPACITY_PINS,
            remoteFundingPubkey: REMOTE_FUNDING_PUBKEY,
            commitmentDelayEpoch: "1099511627777",
            commitmentFeeRate: "1000",
            udtTypeScript: null,
            lockLayout: "legacy",
        });
    });

    it("reads the full-hash layout a revocation is sized under", () => {
        const input = toRevocationInput(caseOf(digest.revocation_cases, "ckb, send side, full payment hash"), digest.remote);
        expect(statedChannelPins({ kind: "revocation", input })).toEqual<StatedChannelPins>({
            ...CKB_FULL_HASH_CAPACITY_PINS,
            remoteFundingPubkey: REMOTE_FUNDING_PUBKEY,
            commitmentDelayEpoch: "1099511627777",
            commitmentFeeRate: "1000",
            udtTypeScript: null,
            lockLayout: "fullPaymentHash",
        });
    });

    it("reads the payout of a revocation the device receives as its own close script", () => {
        const input = toRevocationInput(caseOf(digest.revocation_cases, "udt, receive side"), digest.remote);
        expect(statedChannelPins({ kind: "revocation", input })).toEqual<StatedChannelPins>({
            liquidCapacityShannons: "800000000000000000000",
            fundingCapacityShannons: "16200000000",
            localReservedCkbShannons: "9900000000",
            remoteReservedCkbShannons: "6300000000",
            remoteFundingPubkey: REMOTE_FUNDING_PUBKEY,
            commitmentDelayEpoch: "1099511627777",
            commitmentFeeRate: "1000",
            udtTypeScript: UDT_SCRIPT_PIN,
            lockLayout: "legacy",
            localCloseScript: LOCAL_CLOSE_SCRIPT_PIN,
        });
    });

    it("reads what an announcement states, its capacity being the liquid one and no layout", () => {
        const input = toChannelAnnouncementInput(caseOf(digest.announcement_cases, "ckb"), digest.remote);
        expect(statedChannelPins({ kind: "channel_announcement", input })).toEqual<StatedChannelPins>({
            fundingOutPoint: `${FUNDING_TX_HASH}:0`,
            liquidCapacityShannons: "80500000000",
            remoteFundingPubkey: REMOTE_FUNDING_PUBKEY,
            udtTypeScript: null,
        });
    });
});

describe("findChannelPinConflict", () => {
    it("finds none when every stated value is pinned to itself or not pinned yet", () => {
        expect(
            findChannelPinConflict(PINS, { fundingOutPoint: `${FUNDING_TX_HASH}:0`, commitmentDelayEpoch: "1", udtTypeScript: null }),
        ).toBeNull();
    });

    it("finds none in an empty statement", () => {
        expect(findChannelPinConflict(PINS, {})).toBeNull();
    });

    it("names the first value that differs, with both forms", () => {
        expect(findChannelPinConflict(PINS, { commitmentDelayEpoch: "1", commitmentFeeRate: "1001", fundingOutPoint: "x" })).toEqual({
            field: "commitmentFeeRate",
            pinned: "1000",
            stated: "1001",
        });
    });

    it.each([
        ["a UDT script on a CKB channel", { udtTypeScript: UDT_SCRIPT_PIN }, "udtTypeScript", null, UDT_SCRIPT_PIN],
        ["another close script", { localCloseScript: "00" }, "localCloseScript", LOCAL_CLOSE_SCRIPT_PIN, "00"],
    ])("finds %s against what registration fixed", (_, stated, field, pinned, value) => {
        expect(findChannelPinConflict(PINS, stated)).toEqual({ field, pinned, stated: value });
    });

    it("skips a value a statement leaves undefined", () => {
        expect(findChannelPinConflict(PINS, { commitmentFeeRate: undefined })).toBeNull();
    });

    it("finds another layout than the one pinned", () => {
        expect(findChannelPinConflict({ ...PINS, lockLayout: "fullPaymentHash" }, { lockLayout: "legacy" })).toEqual({
            field: "lockLayout",
            pinned: "fullPaymentHash",
            stated: "legacy",
        });
    });

    describe("the device's reserve", () => {
        it.each([
            ["legacy", "9900000000"],
            ["fullPaymentHash", "10000000000"],
        ])("holds a statement declaring the %s layout to the reserve computed under it", (layout, reserved) => {
            expect(findChannelPinConflict(PINS, { lockLayout: layout, localReservedCkbShannons: reserved })).toBeNull();
        });

        it.each([
            ["legacy", "10000000000", "9900000000"],
            ["fullPaymentHash", "9900000000", "10000000000"],
        ])(
            "finds the other layout's reserve under a statement declaring %s, naming the value computed under it",
            (layout, stated, pinned) => {
                expect(findChannelPinConflict(PINS, { lockLayout: layout, localReservedCkbShannons: stated })).toEqual({
                    field: "localReservedCkbShannons",
                    pinned,
                    stated,
                });
            },
        );

        // The statement's layout decides, even against a pinned one: its own conflict is named first by the statement's order.
        it("reads the reserve under the layout the statement declares before the one pinned", () => {
            const pins = { ...PINS, lockLayout: "legacy" };
            expect(findChannelPinConflict(pins, { localReservedCkbShannons: "10000000000", lockLayout: "fullPaymentHash" })).toEqual({
                field: "lockLayout",
                pinned: "legacy",
                stated: "fullPaymentHash",
            });
            expect(findChannelPinConflict(pins, { lockLayout: "fullPaymentHash", localReservedCkbShannons: "9900000000" })).toEqual({
                field: "lockLayout",
                pinned: "legacy",
                stated: "fullPaymentHash",
            });
        });

        // Only a commitment and a revocation state the reserve, and both state the layout that sizes it.
        it.each([
            ["no pinned layout", PINS],
            ["a pinned layout", { ...PINS, lockLayout: "legacy" }],
        ])("throws on a reserve stated without its layout, under %s", (_, pins) => {
            expect(() => findChannelPinConflict(pins, { localReservedCkbShannons: "9900000000" })).toThrow(
                new TypeError("a reserve is stated without the lock layout that sizes it"),
            );
        });

        it("names the layout before the reserve when both differ", () => {
            expect(
                findChannelPinConflict({ ...PINS, lockLayout: "fullPaymentHash" }, { lockLayout: "legacy", localReservedCkbShannons: "0" }),
            ).toEqual({ field: "lockLayout", pinned: "fullPaymentHash", stated: "legacy" });
        });
    });
});

describe("withChannelPins", () => {
    it("pins what was not pinned yet and keeps what was", () => {
        expect(
            withChannelPins(PINS, { fundingOutPoint: "x", commitmentDelayEpoch: "1", remoteFundingPubkey: "02" }, FIRST_SIGHT_CHANNEL_PINS),
        ).toEqual<ChannelPins>({
            ...PINS,
            commitmentDelayEpoch: "1",
            remoteFundingPubkey: "02",
        });
    });

    it("pins the layout once, as any first-sight value", () => {
        const pinned = withChannelPins(PINS, { lockLayout: "fullPaymentHash" }, FIRST_SIGHT_CHANNEL_PINS);
        expect(pinned).toEqual<ChannelPins>({ ...PINS, lockLayout: "fullPaymentHash" });
        expect(withChannelPins(pinned, { lockLayout: "fullPaymentHash" }, FIRST_SIGHT_CHANNEL_PINS)).toBe(pinned);
        expect(withChannelPins(pinned, { lockLayout: "legacy" }, FIRST_SIGHT_CHANNEL_PINS)).toBe(pinned);
    });

    // A message is no evidence of a term: only the host's statement pins one.
    it("never pins a term at first sight", () => {
        const terms = { liquidCapacityShannons: "80500000000", remoteReservedCkbShannons: "6300000000", commitmentFeeRate: "1000" };
        const bare: ChannelPins = { ...PINS, commitmentFeeRate: undefined };
        expect(withChannelPins(bare, terms, FIRST_SIGHT_CHANNEL_PINS)).toBe(bare);
    });

    it("pins the terms the host states, and nothing a message would pin at first sight", () => {
        const bare: ChannelPins = { ...PINS, commitmentFeeRate: undefined };
        expect(
            withChannelPins(
                bare,
                { liquidCapacityShannons: "80500000000", commitmentFeeRate: "1001", commitmentDelayEpoch: "1", lockLayout: "legacy" },
                CHANNEL_TERMS_PINS,
            ),
        ).toEqual<ChannelPins>({ ...PINS, liquidCapacityShannons: "80500000000", commitmentFeeRate: "1001" });
    });

    it("never rewrites the reserves computed at registration, whatever a statement states", () => {
        expect(withChannelPins(PINS, { localReservedCkbShannons: "10000000000" }, FIRST_SIGHT_CHANNEL_PINS)).toBe(PINS);
        expect(
            withChannelPins(PINS, { localReservedCkbShannons: "1", lockLayout: "legacy" }, FIRST_SIGHT_CHANNEL_PINS),
        ).toEqual<ChannelPins>({
            ...PINS,
            lockLayout: "legacy",
        });
    });

    // Identity lets the engine skip the write.
    it("hands back the pins it was given when nothing is new", () => {
        expect(
            withChannelPins(PINS, { fundingOutPoint: "x", udtTypeScript: null, commitmentDelayEpoch: undefined }, FIRST_SIGHT_CHANNEL_PINS),
        ).toBe(PINS);
        expect(withChannelPins(PINS, { commitmentFeeRate: "1000" }, CHANNEL_TERMS_PINS)).toBe(PINS);
    });

    it("leaves the pins it was given untouched", () => {
        const before = { ...PINS };
        withChannelPins(PINS, { commitmentDelayEpoch: "1" }, FIRST_SIGHT_CHANNEL_PINS);
        expect(PINS).toEqual(before);
    });
});
