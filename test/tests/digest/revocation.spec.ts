import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelSeed } from "../../../src/derivation/device-scheme";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation/fiber-scheme";
import { COMMITMENT_LOCK_TESTNET } from "../../../src/digest/digest.constants";
import type { CellOutput, Script } from "../../../src/common";
import type { RevocationInput } from "../../../src/digest/digest.types";
import { calculateCommitmentTxFee } from "../../../src/digest/fee";
import { buildRevocationContent, computeRevocationDigest } from "../../../src/digest/revocation";
import { computeRevocationContentMessage } from "../../../src/digest/tx-message";
import { aggregateXOnlyPubkey } from "../../../src/digest/utils/digest.utils";
import { blake160 } from "../../../src/common/utils/ckb-hash.utils";

const MASTER_SEED = new Uint8Array(32).fill(0x24);
const channelKeys = deriveChannelKeys(deriveChannelSeed(MASTER_SEED, 0));

const remoteFundingPubkey = pubkeyOf(new Uint8Array(32).fill(0x33));

const PAYOUT_SCRIPT: Script = { codeHash: hexToBytes("ee".repeat(32)), hashType: "data1", args: hexToBytes("ff".repeat(32)) };

const BASE_INPUT: RevocationInput = {
    forRemote: false,
    revokedCommitmentNumber: 4,
    payoutScript: PAYOUT_SCRIPT,
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

const baseDigest = bytesToHex(computeRevocationDigest(channelKeys, BASE_INPUT));

function digestOf(overrides: Partial<RevocationInput>): string {
    return bytesToHex(computeRevocationDigest(channelKeys, { ...BASE_INPUT, ...overrides }));
}

// Fiber's revocation content for the send side.
const PUNISHMENT_OUTPUT: CellOutput = { capacityShannons: 80_500_000_000n + 10_500_000_000n - 456n, lock: PAYOUT_SCRIPT, type: null };
const REVOKED_ARGS = concatBytes(
    blake160(aggregateXOnlyPubkey([remoteFundingPubkey, pubkeyOf(channelKeys.fundingKey)])),
    hexToBytes("01000000000100a0"),
    hexToBytes("0000000000000004"),
);

describe("computeRevocationDigest", () => {
    it("returns a deterministic 32-byte digest", () => {
        expect(computeRevocationDigest(channelKeys, BASE_INPUT)).toHaveLength(32);
        expect(digestOf({})).toBe(baseDigest);
    });

    it("is the message of the revocation content fiber builds for it", () => {
        expect(digestOf({})).toBe(bytesToHex(computeRevocationContentMessage(PUNISHMENT_OUTPUT, hexToBytes("00000000"), REVOKED_ARGS)));
    });

    it("commits to the direction through the role-ordered key aggregation", () => {
        expect(digestOf({ forRemote: true })).not.toBe(baseDigest);
    });

    it.each<[keyof RevocationInput, Partial<RevocationInput>]>([
        ["revokedCommitmentNumber", { revokedCommitmentNumber: 5 }],
        ["payoutScript", { payoutScript: { ...PAYOUT_SCRIPT, hashType: "type" } }],
        ["remoteFundingPubkey", { remoteFundingPubkey: pubkeyOf(new Uint8Array(32).fill(0x34)) }],
        ["commitmentDelayEpoch", { commitmentDelayEpoch: (2n << 40n) | 1n }],
        ["commitmentFeeRate", { commitmentFeeRate: 2000n }],
        ["cellDepsCount", { cellDepsCount: 3 }],
        ["liquidCapacityShannons", { liquidCapacityShannons: 80_500_000_001n }],
        ["localReservedCkbShannons", { localReservedCkbShannons: 4_200_000_001n }],
        ["remoteReservedCkbShannons", { remoteReservedCkbShannons: 6_300_000_001n }],
        ["udtTypeScript", { udtTypeScript: { codeHash: hexToBytes("aa".repeat(32)), hashType: "type", args: new Uint8Array(0) } }],
        ["lockLayout", { lockLayout: "fullPaymentHash" }],
    ])("commits to %s", (_, overrides) => {
        expect(digestOf(overrides)).not.toBe(baseDigest);
    });

    // The revoked cell's 36-byte args carry no feature byte; only the fee mock, a byte larger under fullPaymentHash, sees the layout.
    it("commits to the layout only through the fee", () => {
        expect(calculateCommitmentTxFee(BASE_INPUT)).toBe(456n);
        expect(calculateCommitmentTxFee({ ...BASE_INPUT, lockLayout: "fullPaymentHash" })).toBe(457n);
        expect(digestOf({ lockLayout: "fullPaymentHash" })).not.toBe(baseDigest);
        expect(digestOf({ commitmentFeeRate: 0n, lockLayout: "fullPaymentHash" })).toBe(
            digestOf({ commitmentFeeRate: 0n, lockLayout: "legacy" }),
        );
    });

    // The commitment lock only sizes the fee mock, its args zeroed, so its code hash and hash type never reach the digest.
    it("does not commit to the commitment lock's content", () => {
        expect(digestOf({ commitmentLock: { ...COMMITMENT_LOCK_TESTNET, hashType: "data" } })).toBe(baseDigest);
        expect(digestOf({ commitmentLock: { ...COMMITMENT_LOCK_TESTNET, codeHash: new Uint8Array(32) } })).toBe(baseDigest);
    });

    // Only the message checks the scripts, when it serializes them.
    it("refuses a malformed payout script", () => {
        expect(() => digestOf({ payoutScript: { ...PAYOUT_SCRIPT, codeHash: new Uint8Array(31) } })).toThrow(
            new TypeError("output.lock.codeHash must be 32 bytes, got 31"),
        );
    });
});

const ENTRY_POINTS: [string, (overrides: Partial<RevocationInput>) => unknown][] = [
    ["the digest", digestOf],
    ["the builder", (overrides) => buildRevocationContent(channelKeys, { ...BASE_INPUT, ...overrides })],
];

describe("buildRevocationContent", () => {
    it("builds the payout output, its empty molecule data and the revoked cell's 36 bytes of args", () => {
        expect(buildRevocationContent(channelKeys, BASE_INPUT)).toEqual({
            output: PUNISHMENT_OUTPUT,
            outputData: hexToBytes("00000000"),
            commitmentLockArgs: REVOKED_ARGS,
        });
    });

    it("hashes the device's funding key first into the args of the peer's revoked commitment", () => {
        const { commitmentLockArgs } = buildRevocationContent(channelKeys, { ...BASE_INPUT, forRemote: true });
        const keyHash = blake160(aggregateXOnlyPubkey([pubkeyOf(channelKeys.fundingKey), remoteFundingPubkey]));
        expect(bytesToHex(commitmentLockArgs)).toBe(bytesToHex(concatBytes(keyHash, REVOKED_ARGS.subarray(20))));
    });

    // Only the reserves, less the 525-shannon fee; the data is the liquid amount's u128 behind a 4-byte length.
    it("types the output by the UDT and carries the liquid amount as its molecule data", () => {
        const udtTypeScript: Script = { codeHash: hexToBytes("aa".repeat(32)), hashType: "type", args: new Uint8Array(0) };
        expect(buildRevocationContent(channelKeys, { ...BASE_INPUT, udtTypeScript })).toEqual({
            output: { capacityShannons: 10_499_999_475n, lock: PAYOUT_SCRIPT, type: udtTypeScript },
            outputData: hexToBytes("1000000000852cbe120000000000000000000000"),
            commitmentLockArgs: REVOKED_ARGS,
        });
    });

    it.each(ENTRY_POINTS)("refuses through %s a fee the capacity cannot cover", (_, entry) => {
        expect(() => entry({ commitmentFeeRate: (1n << 63n) / 456n })).toThrow(RangeError);
    });

    it.each(ENTRY_POINTS)("refuses through %s malformed inputs, one field at a time", (_, entry) => {
        expect(() => entry({ remoteFundingPubkey: new Uint8Array(32) })).toThrow(TypeError);
        expect(() => entry({ revokedCommitmentNumber: 2 ** 48 })).toThrow(RangeError);
        expect(() => entry({ commitmentDelayEpoch: 1n << 56n })).toThrow(RangeError);
        expect(() => entry({ commitmentFeeRate: -1n })).toThrow(RangeError);
        expect(() => entry({ liquidCapacityShannons: undefined })).toThrow(RangeError);
        expect(() => entry({ liquidCapacityShannons: -1n })).toThrow(RangeError);
        expect(() => entry({ liquidCapacityShannons: 1n << 128n })).toThrow(RangeError);
        expect(() => entry({ localReservedCkbShannons: -1n })).toThrow(RangeError);
        expect(() => entry({ remoteReservedCkbShannons: undefined })).toThrow(
            new RangeError("remoteReservedCkbShannons must be a bigint between 0 and 18446744073709551615, got undefined"),
        );
        expect(() => entry({ remoteReservedCkbShannons: -1n })).toThrow(
            new RangeError("remoteReservedCkbShannons must be a bigint between 0 and 18446744073709551615, got -1"),
        );
        expect(() => entry({ remoteReservedCkbShannons: 1n << 64n })).toThrow(
            new RangeError("remoteReservedCkbShannons must be a bigint between 0 and 18446744073709551615, got 18446744073709551616"),
        );
        expect(() => entry({ lockLayout: undefined })).toThrow(new TypeError("lockLayout must be one of legacy, fullPaymentHash"));
        expect(() => entry({ lockLayout: null as never })).toThrow(new TypeError("lockLayout must be one of legacy, fullPaymentHash"));
        expect(() => entry({ lockLayout: "full_payment_hash" as never })).toThrow(
            new TypeError("lockLayout must be one of legacy, fullPaymentHash"),
        );
    });
});
