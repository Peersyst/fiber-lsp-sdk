import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelSeed } from "../../../src/derivation/device-scheme";
import { deriveChannelKeys, deriveTlcKey, pubkeyOf } from "../../../src/derivation/fiber-scheme";
import { computeCommitmentTxDigest } from "../../../src/digest/commitment-tx";
import { COMMITMENT_LOCK_TESTNET } from "../../../src/digest/digest.constants";
import type {
    CommitmentSettlementTerms,
    CommitmentTxInput,
    SigningSettlement,
    SigningSettlementTlc,
} from "../../../src/digest/digest.types";
import { settlementToCommitmentInput } from "../../../src/digest/settlement-input";

const MASTER_SEED = new Uint8Array(32).fill(0x24);
const channelKeys = deriveChannelKeys(deriveChannelSeed(MASTER_SEED, 0));
const localTlcBasePubkey = pubkeyOf(channelKeys.tlcBaseKey);

const remoteFundingPubkey = pubkeyOf(new Uint8Array(32).fill(0x33));
const remoteTlcBasePubkey = pubkeyOf(new Uint8Array(32).fill(0x66));
const REMOTE_TLC_PUBKEY = pubkeyOf(new Uint8Array(32).fill(0x55));
const UDT_TYPE_SCRIPT = { codeHash: hexToBytes("aa".repeat(32)), hashType: "type" as const, args: hexToBytes("bb".repeat(32)) };

const OFFERED_TLC: SigningSettlementTlc = {
    tlcId: 1,
    direction: "offered",
    hashAlgorithm: "ckb-hash",
    amountShannons: 1_000_000_000n,
    paymentHash: new Uint8Array(32).fill(0xa1),
    expiryMs: 1_723_257_890_123n,
    localKeyCommitmentNumber: 2,
    localKeyPubkey: pubkeyOf(deriveTlcKey(channelKeys, 2)),
    remoteTlcPubkey: REMOTE_TLC_PUBKEY,
};

const RECEIVED_TLC: SigningSettlementTlc = {
    tlcId: 0,
    direction: "received",
    hashAlgorithm: "sha256",
    amountShannons: 2_250_000_000n,
    paymentHash: new Uint8Array(32).fill(0xb2),
    expiryMs: 1_750_000_000_000n,
    localKeyCommitmentNumber: 0,
    localKeyPubkey: pubkeyOf(deriveTlcKey(channelKeys, 0)),
    remoteTlcPubkey: pubkeyOf(new Uint8Array(32).fill(0x56)),
};

const TERMS: CommitmentSettlementTerms = {
    fundingOutPoint: { txHash: new Uint8Array(32).fill(0xf0), index: 0 },
    remoteFundingPubkey,
    commitmentDelayEpoch: (1n << 40n) | 1n,
    commitmentFeeRate: 1000n,
    cellDepsCount: 2,
    udtTypeScript: null,
    liquidCapacityShannons: 80_500_000_000n,
    localReservedCkbShannons: 4_200_000_000n,
    remoteReservedCkbShannons: 6_300_000_000n,
    commitmentLock: COMMITMENT_LOCK_TESTNET,
    lockLayout: "legacy",
};

// Fiber's witness amounts: 58_750_000_000 and 18_500_000_000 after the TLCs, each with its side's reserve added.
const SETTLEMENT: SigningSettlement = {
    localAmountShannons: 62_950_000_000n,
    remoteAmountShannons: 24_800_000_000n,
    localSettlementPubkey: localTlcBasePubkey,
    remoteSettlementPubkey: remoteTlcBasePubkey,
    forRemote: true,
    tlcs: [OFFERED_TLC, RECEIVED_TLC],
};

const EXPECTED: CommitmentTxInput = {
    forRemote: true,
    fundingOutPoint: { txHash: new Uint8Array(32).fill(0xf0), index: 0 },
    remoteFundingPubkey,
    remoteTlcBasePubkey,
    commitmentNumber: 11,
    commitmentDelayEpoch: (1n << 40n) | 1n,
    commitmentFeeRate: 1000n,
    cellDepsCount: 2,
    udtTypeScript: null,
    liquidCapacityShannons: 80_500_000_000n,
    settlementLocalShannons: 58_750_000_000n,
    settlementRemoteShannons: 18_500_000_000n,
    localReservedCkbShannons: 4_200_000_000n,
    remoteReservedCkbShannons: 6_300_000_000n,
    tlcs: [
        {
            id: 1,
            direction: "offered",
            hashAlgorithm: "ckb-hash",
            amountShannons: 1_000_000_000n,
            paymentHash: new Uint8Array(32).fill(0xa1),
            expiryMs: 1_723_257_890_123n,
            localKeyCommitmentNumber: 2,
            remoteTlcPubkey: REMOTE_TLC_PUBKEY,
        },
        {
            id: 0,
            direction: "received",
            hashAlgorithm: "sha256",
            amountShannons: 2_250_000_000n,
            paymentHash: new Uint8Array(32).fill(0xb2),
            expiryMs: 1_750_000_000_000n,
            localKeyCommitmentNumber: 0,
            remoteTlcPubkey: pubkeyOf(new Uint8Array(32).fill(0x56)),
        },
    ],
    commitmentLock: COMMITMENT_LOCK_TESTNET,
    lockLayout: "legacy",
};

function convert(settlement: Partial<SigningSettlement>, terms: Partial<CommitmentSettlementTerms> = {}): CommitmentTxInput {
    return settlementToCommitmentInput(channelKeys, { ...SETTLEMENT, ...settlement }, { ...TERMS, ...terms }, 11);
}

function convertWithTlc(tlc: Partial<SigningSettlementTlc>): CommitmentTxInput {
    return convert({ tlcs: [OFFERED_TLC, { ...RECEIVED_TLC, ...tlc }] });
}

describe("settlementToCommitmentInput", () => {
    it("rebuilds the commitment input, each side's reserve taken back out of its amount", () => {
        expect(convert({})).toEqual(EXPECTED);
        expect(bytesToHex(computeCommitmentTxDigest(channelKeys, convert({})))).toBe(
            bytesToHex(computeCommitmentTxDigest(channelKeys, EXPECTED)),
        );
    });

    it("takes the direction from the snapshot and the commitment number as given", () => {
        expect(convert({ forRemote: false }).forRemote).toBe(false);
        expect(settlementToCommitmentInput(channelKeys, SETTLEMENT, TERMS, 0).commitmentNumber).toBe(0);
        expect(settlementToCommitmentInput(channelKeys, SETTLEMENT, TERMS, 12).commitmentNumber).toBe(12);
    });

    it("keeps the TLCs in the order the node stated them, neither sorted nor filtered", () => {
        expect(convert({ tlcs: [RECEIVED_TLC, OFFERED_TLC] }).tlcs.map((tlc) => tlc.id)).toEqual([0, 1]);
        expect(convert({ tlcs: [] }).tlcs).toEqual([]);
    });

    it("keeps a UDT snapshot's amounts whole, the reserves being capacity there", () => {
        const input = convert(
            { localAmountShannons: 500_000_000_000_000_000_000n, remoteAmountShannons: 0n },
            { udtTypeScript: UDT_TYPE_SCRIPT, liquidCapacityShannons: 500_000_000_000_000_000_000n },
        );
        expect(input.settlementLocalShannons).toBe(500_000_000_000_000_000_000n);
        expect(input.settlementRemoteShannons).toBe(0n);
        expect(input.udtTypeScript).toEqual(UDT_TYPE_SCRIPT);
    });

    it("takes an amount down to its side's reserve and refuses the shannon below, on either side", () => {
        expect(convert({ localAmountShannons: 4_200_000_000n }).settlementLocalShannons).toBe(0n);
        expect(() => convert({ localAmountShannons: 4_199_999_999n })).toThrow(
            new RangeError("settlement.localAmountShannons 4199999999 is below the local reserve 4200000000 it includes"),
        );
        expect(convert({ remoteAmountShannons: 6_300_000_000n }).settlementRemoteShannons).toBe(0n);
        expect(() => convert({ remoteAmountShannons: 6_299_999_999n })).toThrow(
            new RangeError("settlement.remoteAmountShannons 6299999999 is below the remote reserve 6300000000 it includes"),
        );
    });

    it("refuses what is not a snapshot or terms", () => {
        expect(() => settlementToCommitmentInput(channelKeys, undefined as never, TERMS, 11)).toThrow(
            new TypeError("settlement must be an object"),
        );
        expect(() => settlementToCommitmentInput(channelKeys, SETTLEMENT, null as never, 11)).toThrow(
            new TypeError("terms must be an object"),
        );
    });

    it.each([undefined, null, "true", 1])("refuses the direction %p", (forRemote) => {
        expect(() => convert({ forRemote: forRemote as never })).toThrow(new TypeError("settlement.forRemote must be a boolean"));
    });

    describe("the local settlement key", () => {
        it.each<[string, unknown, TypeError]>([
            ["absent", undefined, new TypeError("settlement.localSettlementPubkey must be a Uint8Array")],
            ["32 bytes", new Uint8Array(32), new TypeError("settlement.localSettlementPubkey must be 33 bytes, got 32")],
            [
                "the device's funding key",
                pubkeyOf(channelKeys.fundingKey),
                new TypeError("settlement.localSettlementPubkey is not this device's TLC base key"),
            ],
            [
                "the peer's TLC base key",
                remoteTlcBasePubkey,
                new TypeError("settlement.localSettlementPubkey is not this device's TLC base key"),
            ],
        ])("refuses one %s", (_, localSettlementPubkey, error) => {
            expect(() => convert({ localSettlementPubkey: localSettlementPubkey as never })).toThrow(error);
        });
    });

    describe("the remote settlement key", () => {
        it.each<[string, unknown, TypeError]>([
            ["absent", undefined, new TypeError("settlement.remoteSettlementPubkey must be a Uint8Array")],
            ["34 bytes", new Uint8Array(34), new TypeError("settlement.remoteSettlementPubkey must be 33 bytes, got 34")],
        ])("refuses one %s", (_, remoteSettlementPubkey, error) => {
            expect(() => convert({ remoteSettlementPubkey: remoteSettlementPubkey as never })).toThrow(error);
        });

        // The device knows no remote key of its own: the policy pins the one the first signed commitment states.
        it("takes the peer's TLC base key as the snapshot states it", () => {
            const otherBase = pubkeyOf(new Uint8Array(32).fill(0x67));
            expect(convert({ remoteSettlementPubkey: otherBase }).remoteTlcBasePubkey).toEqual(otherBase);
        });
    });

    describe("the amounts", () => {
        it("takes each side's highest amount over its highest reserve", () => {
            const input = convert(
                { localAmountShannons: (1n << 128n) - 1n, remoteAmountShannons: (1n << 128n) - 1n },
                { localReservedCkbShannons: (1n << 64n) - 1n, remoteReservedCkbShannons: (1n << 64n) - 1n },
            );
            expect(input.settlementLocalShannons).toBe((1n << 128n) - (1n << 64n));
            expect(input.settlementRemoteShannons).toBe((1n << 128n) - (1n << 64n));
            expect(input.localReservedCkbShannons).toBe((1n << 64n) - 1n);
            expect(input.remoteReservedCkbShannons).toBe((1n << 64n) - 1n);
        });

        it("takes a UDT snapshot's highest amounts whole", () => {
            const input = convert(
                { localAmountShannons: (1n << 128n) - 1n, remoteAmountShannons: (1n << 128n) - 1n },
                { udtTypeScript: UDT_TYPE_SCRIPT },
            );
            expect(input.settlementLocalShannons).toBe((1n << 128n) - 1n);
            expect(input.settlementRemoteShannons).toBe((1n << 128n) - 1n);
        });

        // A UDT snapshot's amounts skip the reserve, never the range.
        it.each<[keyof SigningSettlement, unknown]>([
            ["localAmountShannons", undefined],
            ["localAmountShannons", -1n],
            ["localAmountShannons", 1n << 128n],
            ["remoteAmountShannons", undefined],
            ["remoteAmountShannons", -1n],
            ["remoteAmountShannons", 1n << 128n],
        ])("refuses a UDT snapshot's %s %p", (field, value) => {
            expect(() => convert({ [field]: value }, { udtTypeScript: UDT_TYPE_SCRIPT })).toThrow(
                new RangeError(`settlement.${field} must be a bigint between 0 and ${(1n << 128n) - 1n}, got ${value}`),
            );
        });

        it.each<[keyof SigningSettlement, unknown]>([
            ["localAmountShannons", undefined],
            ["localAmountShannons", -1n],
            ["localAmountShannons", 1n << 128n],
            ["remoteAmountShannons", undefined],
            ["remoteAmountShannons", -1n],
            ["remoteAmountShannons", 1n << 128n],
        ])("refuses %s %p", (field, value) => {
            expect(() => convert({ [field]: value })).toThrow(
                new RangeError(`settlement.${field} must be a bigint between 0 and ${(1n << 128n) - 1n}, got ${value}`),
            );
        });

        it.each<[keyof CommitmentSettlementTerms, unknown]>([
            ["localReservedCkbShannons", undefined],
            ["localReservedCkbShannons", -1n],
            ["localReservedCkbShannons", 1n << 64n],
            ["remoteReservedCkbShannons", undefined],
            ["remoteReservedCkbShannons", -1n],
            ["remoteReservedCkbShannons", 1n << 64n],
        ])("refuses the reserve %s %p", (field, value) => {
            expect(() => convert({}, { [field]: value })).toThrow(
                new RangeError(`terms.${field} must be a bigint between 0 and ${(1n << 64n) - 1n}, got ${value}`),
            );
        });
    });

    describe("the TLCs", () => {
        it("takes up to 255 and refuses the next", () => {
            expect(convert({ tlcs: Array.from({ length: 255 }, () => OFFERED_TLC) }).tlcs).toHaveLength(255);
            expect(() => convert({ tlcs: Array.from({ length: 256 }, () => OFFERED_TLC) })).toThrow(
                new TypeError("settlement.tlcs must be an array of at most 255 TLCs"),
            );
        });

        it.each([undefined, null, {}])("refuses the list %p", (tlcs) => {
            expect(() => convert({ tlcs: tlcs as never })).toThrow(new TypeError("settlement.tlcs must be an array of at most 255 TLCs"));
        });

        it("refuses a TLC that is not an object, naming it", () => {
            expect(() => convert({ tlcs: [OFFERED_TLC, null as never] })).toThrow(new TypeError("settlement.tlcs[1] must be an object"));
        });

        it("takes a key derived at the highest commitment number", () => {
            const localKeyPubkey = pubkeyOf(deriveTlcKey(channelKeys, 2 ** 48 - 1));
            expect(convertWithTlc({ localKeyCommitmentNumber: 2 ** 48 - 1, localKeyPubkey }).tlcs[1]?.localKeyCommitmentNumber).toBe(
                2 ** 48 - 1,
            );
        });

        it.each([undefined, -1, 1.5, 2 ** 48])("refuses the key number %p", (localKeyCommitmentNumber) => {
            expect(() => convertWithTlc({ localKeyCommitmentNumber: localKeyCommitmentNumber as never })).toThrow(
                new RangeError(
                    `settlement.tlcs[1].localKeyCommitmentNumber must be an integer between 0 and 281474976710655, got ${localKeyCommitmentNumber}`,
                ),
            );
        });

        it.each<[string, unknown, TypeError]>([
            ["absent", undefined, new TypeError("settlement.tlcs[1].localKeyPubkey must be a Uint8Array")],
            ["32 bytes", new Uint8Array(32), new TypeError("settlement.tlcs[1].localKeyPubkey must be 33 bytes, got 32")],
            [
                "derived at another number",
                pubkeyOf(deriveTlcKey(channelKeys, 1)),
                new TypeError("settlement.tlcs[1].localKeyPubkey is not this device's TLC key at commitment number 0"),
            ],
            [
                "the device's TLC base key",
                localTlcBasePubkey,
                new TypeError("settlement.tlcs[1].localKeyPubkey is not this device's TLC key at commitment number 0"),
            ],
            [
                "the peer's TLC key",
                REMOTE_TLC_PUBKEY,
                new TypeError("settlement.tlcs[1].localKeyPubkey is not this device's TLC key at commitment number 0"),
            ],
        ])("refuses a device key %s", (_, localKeyPubkey, error) => {
            expect(() => convertWithTlc({ localKeyPubkey: localKeyPubkey as never })).toThrow(error);
        });

        it("checks the key against the number the TLC states, not against its position", () => {
            const atSeven = { localKeyCommitmentNumber: 7, localKeyPubkey: pubkeyOf(deriveTlcKey(channelKeys, 7)) };
            expect(convertWithTlc(atSeven).tlcs[1]?.localKeyCommitmentNumber).toBe(7);
            expect(() => convertWithTlc({ localKeyCommitmentNumber: 7 })).toThrow(
                new TypeError("settlement.tlcs[1].localKeyPubkey is not this device's TLC key at commitment number 7"),
            );
        });
    });
});
