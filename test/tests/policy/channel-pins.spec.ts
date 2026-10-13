import { hexToBytes } from "@noble/hashes/utils.js";
import type { ChannelPins, StatedChannelPins } from "../../../src/policy";
import { findChannelPinConflict, fundingCellPins, statedChannelPins, withChannelPins } from "../../../src/policy/channel-pins";
import { toChannelAnnouncementInput, toCommitmentTxInput, toRevocationInput, toShutdownTxInput } from "../../utils/digest-inputs";
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

const PINS: ChannelPins = {
    fundedShannons: "71900000000",
    localCloseScript: LOCAL_CLOSE_SCRIPT_PIN,
    localReservedCkbShannons: "9900000000",
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

describe("statedChannelPins", () => {
    it("reads what a commitment states: the funding cell, the peer's keys, the delay, the rate, the reserves and the asset", () => {
        const input = toCommitmentTxInput(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote"), digest.remote);
        expect(statedChannelPins({ kind: "commitment_tx", input })).toEqual<StatedChannelPins>({
            ...CKB_CAPACITY_PINS,
            fundingOutPoint: `${FUNDING_TX_HASH}:0`,
            remoteFundingPubkey: REMOTE_FUNDING_PUBKEY,
            remoteTlcBasePubkey: REMOTE_TLC_BASE_PUBKEY,
            commitmentDelayEpoch: "1099511627777",
            commitmentFeeRate: "1000",
            udtTypeScript: null,
        });
    });

    it("reads the UDT script of a UDT commitment, and its funding cell's capacity in CKB beside its liquid amount", () => {
        const input = toCommitmentTxInput(caseOf(digest.commitment_cases, "udt, two tlcs, for remote"), digest.remote);
        expect(statedChannelPins({ kind: "commitment_tx", input })).toMatchObject<StatedChannelPins>({
            liquidCapacityShannons: "800000000000000000000",
            fundingCapacityShannons: "16200000000",
            udtTypeScript: UDT_SCRIPT_PIN,
        });
    });

    it("reads what a close states, the script it pays the device to included", () => {
        const input = toShutdownTxInput(caseOf(digest.shutdown_cases, "ckb"), digest.remote);
        expect(statedChannelPins({ kind: "shutdown_tx", input })).toEqual<StatedChannelPins>({
            ...CKB_CAPACITY_PINS,
            fundingOutPoint: `${FUNDING_TX_HASH}:0`,
            remoteFundingPubkey: REMOTE_FUNDING_PUBKEY,
            localCloseScript: LOCAL_CLOSE_SCRIPT_PIN,
            udtTypeScript: null,
        });
    });

    it("reads what a revocation the device sends states, leaving its payout out: it is the peer's script", () => {
        const input = toRevocationInput(caseOf(digest.revocation_cases, "ckb, send side"), digest.remote);
        expect(statedChannelPins({ kind: "revocation", input })).toEqual<StatedChannelPins>({
            ...CKB_CAPACITY_PINS,
            remoteFundingPubkey: REMOTE_FUNDING_PUBKEY,
            commitmentDelayEpoch: "1099511627777",
            commitmentFeeRate: "1000",
            udtTypeScript: null,
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
            localCloseScript: LOCAL_CLOSE_SCRIPT_PIN,
        });
    });

    it("reads what an announcement states, its capacity being the liquid one", () => {
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
});

describe("withChannelPins", () => {
    it("pins what was not pinned yet and keeps what was", () => {
        expect(
            withChannelPins(PINS, { commitmentFeeRate: "1000", commitmentDelayEpoch: "1", remoteFundingPubkey: "02" }),
        ).toEqual<ChannelPins>({
            ...PINS,
            commitmentDelayEpoch: "1",
            remoteFundingPubkey: "02",
        });
    });

    // Identity lets the engine skip the write.
    it("hands back the pins it was given when nothing is new", () => {
        expect(withChannelPins(PINS, { commitmentFeeRate: "1000", udtTypeScript: null, commitmentDelayEpoch: undefined })).toBe(PINS);
    });

    it("leaves the pins it was given untouched", () => {
        const before = { ...PINS };
        withChannelPins(PINS, { commitmentDelayEpoch: "1" });
        expect(PINS).toEqual(before);
    });
});
