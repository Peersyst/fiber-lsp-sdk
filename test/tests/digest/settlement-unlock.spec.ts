import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { blake160 } from "../../../src/common/utils/ckb-hash.utils";
import { deriveChannelSeed } from "../../../src/derivation/device-scheme";
import { deriveChannelKeys, deriveTlcKey, pubkeyOf } from "../../../src/derivation/fiber-scheme";
import { readCommitmentLockSettled, readCommitmentLockSettlementHash } from "../../../src/digest/commitment-tx";
import type { CommitmentLockLayout, SettlementTlc, SettlementUnlock } from "../../../src/digest/digest.types";
import {
    buildRemainderLockArgs,
    deviceSettlementIndex,
    nextSettlementWitness,
    readSettlementBody,
    readSettlementTlcEntry,
    readSettlementUnlock,
    settlementTlcEntryLength,
} from "../../../src/digest/settlement-unlock";
import type { SettlementWitnessInput } from "../../../src/digest/settlement-witness";
import { buildSettlementWitness } from "../../../src/digest/settlement-witness";
import { ckbHash } from "../../utils/ckb-hash";

const PREFIX = "10000000".repeat(4);

// Legacy entries: the flag, the amount, the payment hash's first 20 bytes, the two key hashes, the since.
const TLC_A = "00" + "002f6859" + "00".repeat(12) + "a1".repeat(20) + "c1".repeat(20) + "c2".repeat(20) + "22d4b66600000040";
const TLC_B = "03" + "80461c86" + "00".repeat(12) + "b2".repeat(20) + "d1".repeat(20) + "d2".repeat(20) + "80e14e6800000040";
// The same entry as TLC_A under fullPaymentHash, binding the whole hash.
const TLC_FULL = "00" + "002f6859" + "00".repeat(12) + "a1".repeat(32) + "c1".repeat(20) + "c2".repeat(20) + "22d4b66600000040";

const FIRST_BALANCE = "e1".repeat(20) + "00c817a804" + "00".repeat(11);
const SECOND_BALANCE = "e2".repeat(20) + "005847f80d" + "00".repeat(11);
const SETTLED_BALANCE = "00".repeat(36);

const BODY = "02" + TLC_A + TLC_B + FIRST_BALANCE + SECOND_BALANCE;
const TLC_LESS_BODY = "00" + FIRST_BALANCE + SECOND_BALANCE;

const PLACEHOLDER = "00".repeat(65);
const PREIMAGE = "5e".repeat(32);

const FIRST = { pubkeyHash: hexToBytes("e1".repeat(20)), amountShannons: 20_000_000_000n };
const SECOND = { pubkeyHash: hexToBytes("e2".repeat(20)), amountShannons: 60_000_000_000n };

function witness(hex: string): Uint8Array {
    return hexToBytes(PREFIX + "01" + hex);
}

function blake160Of(hex: string): string {
    return bytesToHex(ckbHash(hexToBytes(hex)).slice(0, 20));
}

describe("readSettlementUnlock", () => {
    it("reads a TLC unlock carrying its preimage", () => {
        const unlock = readSettlementUnlock(witness(BODY + "01" + "01" + PLACEHOLDER + PREIMAGE), "legacy");
        expect(bytesToHex(unlock.body)).toBe(BODY);
        expect(unlock.tlcEntries.map((entry) => bytesToHex(entry))).toEqual([TLC_A, TLC_B]);
        expect(unlock.balances).toEqual([FIRST, SECOND]);
        expect(unlock.target).toEqual({ kind: "tlc", index: 1 });
        expect(bytesToHex(unlock.signature)).toBe(PLACEHOLDER);
        expect(unlock.preimage).toEqual(hexToBytes(PREIMAGE));
    });

    it("reads a TLC unlock without a preimage", () => {
        const unlock = readSettlementUnlock(witness(BODY + "00" + "00" + PLACEHOLDER), "legacy");
        expect(unlock.target).toEqual({ kind: "tlc", index: 0 });
        expect(unlock.preimage).toBeNull();
    });

    it.each<[string, SettlementUnlock["target"]]>([
        ["00", { kind: "tlc", index: 0 }],
        ["01", { kind: "tlc", index: 1 }],
        ["fe", { kind: "balance", index: 0 }],
        ["ff", { kind: "balance", index: 1 }],
    ])("reads the unlock type 0x%s as its target", (unlockType, target) => {
        expect(readSettlementUnlock(witness(BODY + unlockType + "00" + PLACEHOLDER), "legacy").target).toEqual(target);
    });

    it("reads a TLC-less body, which only a balance unlock spends", () => {
        const unlock = readSettlementUnlock(witness(TLC_LESS_BODY + "fe" + "00" + PLACEHOLDER), "legacy");
        expect(bytesToHex(unlock.body)).toBe(TLC_LESS_BODY);
        expect(unlock.tlcEntries).toEqual([]);
        expect(unlock.balances).toEqual([FIRST, SECOND]);
    });

    // The lock reads 0xfe and 0xff as balances first, so a 255th TLC can never be unlocked by its index.
    it("reads 0xfe as a balance even under 255 TLCs, and 0xfd as the last index it can name", () => {
        const body = "ff" + TLC_A.repeat(255) + FIRST_BALANCE + SECOND_BALANCE;
        expect(readSettlementUnlock(witness(body + "fe" + "00" + PLACEHOLDER), "legacy").target).toEqual({ kind: "balance", index: 0 });
        expect(readSettlementUnlock(witness(body + "fd" + "00" + PLACEHOLDER), "legacy").target).toEqual({ kind: "tlc", index: 253 });
    });

    it("reads the signature as the witness carries it", () => {
        const signature = "ab".repeat(64) + "01";
        expect(bytesToHex(readSettlementUnlock(witness(BODY + "ff" + "00" + signature), "legacy").signature)).toBe(signature);
    });

    it("sizes each entry by the layout", () => {
        const body = "01" + TLC_FULL + FIRST_BALANCE + SECOND_BALANCE;
        const unlock = readSettlementUnlock(witness(body + "00" + "00" + PLACEHOLDER), "fullPaymentHash");
        expect(unlock.tlcEntries.map((entry) => bytesToHex(entry))).toEqual([TLC_FULL]);
        expect(unlock.balances).toEqual([FIRST, SECOND]);
        // Read under the other layout, the body runs 24 bytes into the unlock.
        expect(() => readSettlementUnlock(witness(BODY + "00" + "00" + PLACEHOLDER), "fullPaymentHash")).toThrow(
            new TypeError("settlement unlock must be 67 or 99 bytes, got 43"),
        );
    });

    it("returns its own bytes, which a later change to the witness never reaches", () => {
        const bytes = witness(BODY + "01" + "01" + PLACEHOLDER + PREIMAGE);
        const unlock = readSettlementUnlock(bytes, "legacy");
        bytes.fill(0x77);
        expect(bytesToHex(unlock.body)).toBe(BODY);
        expect(unlock.tlcEntries.map((entry) => bytesToHex(entry))).toEqual([TLC_A, TLC_B]);
        expect(unlock.balances).toEqual([FIRST, SECOND]);
        expect(bytesToHex(unlock.signature)).toBe(PLACEHOLDER);
        expect(unlock.preimage).toEqual(hexToBytes(PREIMAGE));
    });

    it("refuses what is not a witness, or a layout fiber does not write", () => {
        expect(() => readSettlementUnlock("10000000" as never, "legacy")).toThrow(new TypeError("settlement witness must be a Uint8Array"));
        expect(() => readSettlementUnlock(witness(BODY + "ff" + "00" + PLACEHOLDER), "full" as never)).toThrow(
            new TypeError("layout must be one of legacy, fullPaymentHash"),
        );
    });

    it("refuses a witness without the XUDT-compatible prefix", () => {
        const refusal = new TypeError("settlement witness must start with the 16-byte XUDT-compatible prefix");
        expect(() => readSettlementUnlock(new Uint8Array(0), "legacy")).toThrow(refusal);
        expect(() => readSettlementUnlock(hexToBytes("10000000".repeat(3) + "100000"), "legacy")).toThrow(refusal);
        const unlock = "01" + BODY + "ff" + "00" + PLACEHOLDER;
        expect(() => readSettlementUnlock(hexToBytes("11000000" + "10000000".repeat(3) + unlock), "legacy")).toThrow(refusal);
        expect(() => readSettlementUnlock(hexToBytes("10000000".repeat(3) + "10000001" + unlock), "legacy")).toThrow(refusal);
    });

    it("refuses any unlock count but one", () => {
        const refusal = new TypeError("settlement witness must count exactly 1 unlock at byte 16");
        expect(() => readSettlementUnlock(hexToBytes(PREFIX), "legacy")).toThrow(refusal);
        expect(() => readSettlementUnlock(hexToBytes(PREFIX + "00" + BODY + "ff" + "00" + PLACEHOLDER), "legacy")).toThrow(refusal);
        expect(() => readSettlementUnlock(hexToBytes(PREFIX + "02" + BODY + "ff" + "00" + PLACEHOLDER), "legacy")).toThrow(refusal);
    });

    it("refuses a witness without a body, or with one shorter than its TLC count says", () => {
        expect(() => readSettlementUnlock(witness(""), "legacy")).toThrow(new TypeError("settlement body must start with its TLC count"));
        expect(() => readSettlementUnlock(witness(BODY.slice(0, -2)), "legacy")).toThrow(
            new TypeError("settlement body with a TLC count of 2 must be 243 bytes, got 242"),
        );
    });

    it("refuses an unlock that is neither 67 nor 99 bytes, trailing bytes included", () => {
        const refusal = (length: number): TypeError => new TypeError(`settlement unlock must be 67 or 99 bytes, got ${length}`);
        expect(() => readSettlementUnlock(witness(BODY), "legacy")).toThrow(refusal(0));
        expect(() => readSettlementUnlock(witness(BODY + "ff" + "00" + "00".repeat(64)), "legacy")).toThrow(refusal(66));
        expect(() => readSettlementUnlock(witness(BODY + "ff" + "00" + PLACEHOLDER + "00"), "legacy")).toThrow(refusal(68));
        expect(() => readSettlementUnlock(witness(BODY + "01" + "01" + PLACEHOLDER + "5e".repeat(31)), "legacy")).toThrow(refusal(98));
        expect(() => readSettlementUnlock(witness(BODY + "01" + "01" + PLACEHOLDER + PREIMAGE + "00"), "legacy")).toThrow(refusal(100));
    });

    it("refuses an unlock type that names no TLC and no balance", () => {
        expect(() => readSettlementUnlock(witness(BODY + "02" + "00" + PLACEHOLDER), "legacy")).toThrow(
            new TypeError("settlement unlock type must be 0xfe, 0xff or a TLC index below 2, got 0x02"),
        );
        expect(() => readSettlementUnlock(witness(BODY + "fd" + "00" + PLACEHOLDER), "legacy")).toThrow(
            new TypeError("settlement unlock type must be 0xfe, 0xff or a TLC index below 2, got 0xfd"),
        );
        expect(() => readSettlementUnlock(witness(TLC_LESS_BODY + "00" + "00" + PLACEHOLDER), "legacy")).toThrow(
            new TypeError("settlement unlock type must be 0xfe, 0xff or a TLC index below 0, got 0x00"),
        );
    });

    it("refuses a preimage flag that is neither 0 nor 1", () => {
        expect(() => readSettlementUnlock(witness(BODY + "01" + "02" + PLACEHOLDER), "legacy")).toThrow(
            new TypeError("settlement unlock preimage flag must be 0 or 1, got 2"),
        );
        expect(() => readSettlementUnlock(witness(BODY + "01" + "ff" + PLACEHOLDER + PREIMAGE), "legacy")).toThrow(
            new TypeError("settlement unlock preimage flag must be 0 or 1, got 255"),
        );
    });

    it("refuses a preimage flag the unlock's length contradicts", () => {
        expect(() => readSettlementUnlock(witness(BODY + "01" + "01" + PLACEHOLDER), "legacy")).toThrow(
            new TypeError("settlement unlock with the preimage flag 1 must be 99 bytes, got 67"),
        );
        // 32 trailing bytes after an unlock without a preimage.
        expect(() => readSettlementUnlock(witness(BODY + "01" + "00" + PLACEHOLDER + PREIMAGE), "legacy")).toThrow(
            new TypeError("settlement unlock with the preimage flag 0 must be 67 bytes, got 99"),
        );
    });

    it("refuses a balance unlock carrying a preimage", () => {
        expect(() => readSettlementUnlock(witness(BODY + "ff" + "01" + PLACEHOLDER + PREIMAGE), "legacy")).toThrow(
            new TypeError("settlement unlock of a balance must carry no preimage"),
        );
        expect(() => readSettlementUnlock(witness(BODY + "fe" + "01" + PLACEHOLDER + PREIMAGE), "legacy")).toThrow(
            new TypeError("settlement unlock of a balance must carry no preimage"),
        );
    });
});

describe("readSettlementBody", () => {
    it("splits a body into its entries and its two balances", () => {
        const body = readSettlementBody(hexToBytes(BODY), "legacy");
        expect(body.tlcEntries.map((entry) => bytesToHex(entry))).toEqual([TLC_A, TLC_B]);
        expect(body.balances).toEqual([FIRST, SECOND]);
    });

    it("reads the 73 bytes of a TLC-less body under either layout", () => {
        expect(readSettlementBody(hexToBytes(TLC_LESS_BODY), "legacy")).toEqual({ tlcEntries: [], balances: [FIRST, SECOND] });
        expect(readSettlementBody(hexToBytes(TLC_LESS_BODY), "fullPaymentHash")).toEqual({ tlcEntries: [], balances: [FIRST, SECOND] });
    });

    it("reads each amount as a little-endian u128", () => {
        const balance = "e1".repeat(20) + "ff".repeat(16);
        const body = readSettlementBody(hexToBytes("00" + balance + "e2".repeat(20) + "01" + "00".repeat(14) + "80"), "legacy");
        expect(body.balances[0].amountShannons).toBe((1n << 128n) - 1n);
        expect(body.balances[1].amountShannons).toBe((1n << 127n) | 1n);
    });

    it("refuses what is not a body, or a layout fiber does not write", () => {
        expect(() => readSettlementBody(BODY as never, "legacy")).toThrow(new TypeError("settlement body must be a Uint8Array"));
        expect(() => readSettlementBody(hexToBytes(BODY), undefined as never)).toThrow(
            new TypeError("layout must be one of legacy, fullPaymentHash"),
        );
    });

    it("refuses a body without its TLC count", () => {
        expect(() => readSettlementBody(new Uint8Array(0), "legacy")).toThrow(
            new TypeError("settlement body must start with its TLC count"),
        );
    });

    it("refuses a body one byte off the length its TLC count says", () => {
        expect(() => readSettlementBody(hexToBytes(BODY.slice(0, -2)), "legacy")).toThrow(
            new TypeError("settlement body with a TLC count of 2 must be 243 bytes, got 242"),
        );
        expect(() => readSettlementBody(hexToBytes(BODY + "00"), "legacy")).toThrow(
            new TypeError("settlement body with a TLC count of 2 must be 243 bytes, got 244"),
        );
        expect(() => readSettlementBody(hexToBytes(TLC_LESS_BODY.slice(0, -2)), "legacy")).toThrow(
            new TypeError("settlement body with a TLC count of 0 must be 73 bytes, got 72"),
        );
        expect(() => readSettlementBody(hexToBytes(BODY), "fullPaymentHash")).toThrow(
            new TypeError("settlement body with a TLC count of 2 must be 267 bytes, got 243"),
        );
    });
});

describe("readSettlementTlcEntry", () => {
    it.each<[string, string, boolean, string, bigint, string]>([
        ["TLC_A", TLC_A, true, "offered", 1_500_000_000n, "c2"],
        ["TLC_A", TLC_A, false, "received", 1_500_000_000n, "c1"],
        ["TLC_B", TLC_B, true, "received", 2_250_000_000n, "d2"],
        ["TLC_B", TLC_B, false, "offered", 2_250_000_000n, "d1"],
    ])("reads %s with forRemote %p", (_, entry, forRemote, direction, amountShannons, keyHash) => {
        expect(readSettlementTlcEntry(hexToBytes(entry), "legacy", forRemote)).toEqual({
            direction,
            amountShannons,
            localKeyHash: hexToBytes(keyHash.repeat(20)),
        });
    });

    it("finds the device's key hash after the whole payment hash under fullPaymentHash", () => {
        expect(readSettlementTlcEntry(hexToBytes(TLC_FULL), "fullPaymentHash", true).localKeyHash).toEqual(hexToBytes("c2".repeat(20)));
        expect(readSettlementTlcEntry(hexToBytes(TLC_FULL), "fullPaymentHash", false).localKeyHash).toEqual(hexToBytes("c1".repeat(20)));
    });

    it("refuses a layout fiber does not write", () => {
        expect(() => readSettlementTlcEntry(hexToBytes(TLC_A), "legacy " as never, true)).toThrow(
            new TypeError("layout must be one of legacy, fullPaymentHash"),
        );
    });

    it("refuses an entry of any length but its layout's", () => {
        expect(() => readSettlementTlcEntry(TLC_A as never, "legacy", true)).toThrow(
            new TypeError("settlement TLC entry must be a Uint8Array"),
        );
        expect(() => readSettlementTlcEntry(hexToBytes(TLC_A.slice(0, -2)), "legacy", true)).toThrow(
            new TypeError("settlement TLC entry must be 85 bytes, got 84"),
        );
        expect(() => readSettlementTlcEntry(hexToBytes(TLC_A + "00"), "legacy", true)).toThrow(
            new TypeError("settlement TLC entry must be 85 bytes, got 86"),
        );
        expect(() => readSettlementTlcEntry(hexToBytes(TLC_A), "fullPaymentHash", true)).toThrow(
            new TypeError("settlement TLC entry must be 97 bytes, got 85"),
        );
        expect(() => readSettlementTlcEntry(hexToBytes(TLC_FULL + "00"), "fullPaymentHash", true)).toThrow(
            new TypeError("settlement TLC entry must be 97 bytes, got 98"),
        );
    });

    it("refuses a view that is not a boolean", () => {
        expect(() => readSettlementTlcEntry(hexToBytes(TLC_A), "legacy", 1 as never)).toThrow(new TypeError("forRemote must be a boolean"));
    });

    it("refuses a flag above the hash algorithms fiber knows", () => {
        expect(readSettlementTlcEntry(hexToBytes("03" + TLC_A.slice(2)), "legacy", true).direction).toBe("received");
        expect(() => readSettlementTlcEntry(hexToBytes("04" + TLC_A.slice(2)), "legacy", true)).toThrow(
            new TypeError("settlement TLC entry flag must be at most 3, got 4"),
        );
        expect(() => readSettlementTlcEntry(hexToBytes("ff" + TLC_A.slice(2)), "legacy", true)).toThrow(
            new TypeError("settlement TLC entry flag must be at most 3, got 255"),
        );
    });
});

describe("settlementTlcEntryLength", () => {
    it.each<[CommitmentLockLayout, number]>([
        ["legacy", 85],
        ["fullPaymentHash", 97],
    ])("sizes a %s entry at %s bytes", (layout, length) => {
        expect(settlementTlcEntryLength(layout)).toBe(length);
    });
});

describe("deviceSettlementIndex", () => {
    it("places the device first in a local view and second in a remote one", () => {
        expect(deviceSettlementIndex(false)).toBe(0);
        expect(deviceSettlementIndex(true)).toBe(1);
    });

    it("refuses a view that is not a boolean", () => {
        expect(() => deviceSettlementIndex("true" as never)).toThrow(new TypeError("forRemote must be a boolean"));
        expect(() => deviceSettlementIndex(undefined as never)).toThrow(new TypeError("forRemote must be a boolean"));
    });
});

describe("nextSettlementWitness", () => {
    function unlockOf(body: string, unlockType: string): SettlementUnlock {
        return readSettlementUnlock(witness(body + unlockType + "00" + PLACEHOLDER), "legacy");
    }

    it.each([true, false])("drops the unlocked TLC and counts one fewer, in either view (forRemote %p)", (forRemote) => {
        expect(bytesToHex(nextSettlementWitness(unlockOf(BODY, "00"), forRemote))).toBe("01" + TLC_B + FIRST_BALANCE + SECOND_BALANCE);
        expect(bytesToHex(nextSettlementWitness(unlockOf(BODY, "01"), forRemote))).toBe("01" + TLC_A + FIRST_BALANCE + SECOND_BALANCE);
    });

    it("leaves a TLC-less body once the last TLC is unlocked", () => {
        const body = "01" + TLC_A + FIRST_BALANCE + SECOND_BALANCE;
        expect(bytesToHex(nextSettlementWitness(unlockOf(body, "00"), true))).toBe(TLC_LESS_BODY);
    });

    it("zeroes the device's balance, the second in a remote view and the first in a local one", () => {
        expect(bytesToHex(nextSettlementWitness(unlockOf(BODY, "ff"), true))).toBe("02" + TLC_A + TLC_B + FIRST_BALANCE + SETTLED_BALANCE);
        expect(bytesToHex(nextSettlementWitness(unlockOf(BODY, "fe"), false))).toBe(
            "02" + TLC_A + TLC_B + SETTLED_BALANCE + SECOND_BALANCE,
        );
    });

    it("leaves the unlock it reads as it was", () => {
        const unlock = unlockOf(BODY, "ff");
        nextSettlementWitness(unlock, true);
        nextSettlementWitness(unlockOf(BODY, "00"), true);
        expect(unlock.balances).toEqual([FIRST, SECOND]);
        expect(unlock.tlcEntries.map((entry) => bytesToHex(entry))).toEqual([TLC_A, TLC_B]);
    });

    it("refuses to settle the peer's balance", () => {
        expect(() => nextSettlementWitness(unlockOf(BODY, "fe"), true)).toThrow(
            new TypeError("settlement unlock 0xfe settles the peer's balance in a remote view"),
        );
        expect(() => nextSettlementWitness(unlockOf(BODY, "ff"), false)).toThrow(
            new TypeError("settlement unlock 0xff settles the peer's balance in a local view"),
        );
    });

    it("refuses a TLC index the body does not have", () => {
        const unlock = unlockOf(BODY, "01");
        expect(() => nextSettlementWitness({ ...unlock, target: { kind: "tlc", index: 2 } }, true)).toThrow(
            new RangeError("settlement unlock must spend a TLC index below 2, got 2"),
        );
        expect(() => nextSettlementWitness({ ...unlock, target: { kind: "tlc", index: -1 } }, true)).toThrow(
            new RangeError("settlement unlock must spend a TLC index below 2, got -1"),
        );
    });

    it("refuses a view that is not a boolean", () => {
        expect(() => nextSettlementWitness(unlockOf(BODY, "00"), null as never)).toThrow(new TypeError("forRemote must be a boolean"));
    });
});

describe("buildRemainderLockArgs", () => {
    const LEGACY_ARGS = "a0".repeat(20) + "b0".repeat(8) + "c0".repeat(8) + "d0".repeat(20) + "00";
    const NEXT_BODY = "01" + TLC_B + FIRST_BALANCE + SECOND_BALANCE;

    it("keeps the key hash, the delay and the version, commits the next body and flags the cell as settled", () => {
        expect(bytesToHex(buildRemainderLockArgs(hexToBytes(LEGACY_ARGS), hexToBytes(NEXT_BODY)))).toBe(
            "a0".repeat(20) + "b0".repeat(8) + "c0".repeat(8) + blake160Of(NEXT_BODY) + "01",
        );
    });

    it("keeps the feature byte under fullPaymentHash", () => {
        const args = LEGACY_ARGS + "01";
        expect(bytesToHex(buildRemainderLockArgs(hexToBytes(args), hexToBytes(TLC_LESS_BODY)))).toBe(
            "a0".repeat(20) + "b0".repeat(8) + "c0".repeat(8) + blake160Of(TLC_LESS_BODY) + "01" + "01",
        );
    });

    it("keeps the flag of a cell already settled from", () => {
        const args = LEGACY_ARGS.slice(0, -2) + "01";
        expect(bytesToHex(buildRemainderLockArgs(hexToBytes(args), hexToBytes(NEXT_BODY)))).toBe(
            "a0".repeat(20) + "b0".repeat(8) + "c0".repeat(8) + blake160Of(NEXT_BODY) + "01",
        );
    });

    it("writes args the lock-args readers read as a settled remainder committing the next body", () => {
        const args = buildRemainderLockArgs(hexToBytes(LEGACY_ARGS), hexToBytes(NEXT_BODY));
        expect(readCommitmentLockSettled(args)).toBe(true);
        expect(bytesToHex(readCommitmentLockSettlementHash(args))).toBe(blake160Of(NEXT_BODY));
    });

    it("refuses args no commitment lock carries", () => {
        expect(() => buildRemainderLockArgs(LEGACY_ARGS as never, hexToBytes(NEXT_BODY))).toThrow(
            new TypeError("commitment lock args must be a Uint8Array"),
        );
        expect(() => buildRemainderLockArgs(hexToBytes(LEGACY_ARGS.slice(0, -2)), hexToBytes(NEXT_BODY))).toThrow(
            new TypeError("commitment lock args must be 57 or 58 bytes, got 56"),
        );
        expect(() => buildRemainderLockArgs(hexToBytes(LEGACY_ARGS + "0100"), hexToBytes(NEXT_BODY))).toThrow(
            new TypeError("commitment lock args must be 57 or 58 bytes, got 59"),
        );
        expect(() => buildRemainderLockArgs(hexToBytes(LEGACY_ARGS + "00"), hexToBytes(NEXT_BODY))).toThrow(
            new TypeError("commitment lock args of 58 bytes must end in the feature byte 0x01, got 0x00"),
        );
    });

    it("refuses a next body the args' layout does not carry", () => {
        expect(() => buildRemainderLockArgs(hexToBytes(LEGACY_ARGS), NEXT_BODY as never)).toThrow(
            new TypeError("settlement body must be a Uint8Array"),
        );
        expect(() => buildRemainderLockArgs(hexToBytes(LEGACY_ARGS), hexToBytes(NEXT_BODY + "00"))).toThrow(
            new TypeError("settlement body with a TLC count of 1 must be 158 bytes, got 159"),
        );
        expect(() => buildRemainderLockArgs(hexToBytes(LEGACY_ARGS + "01"), hexToBytes(NEXT_BODY))).toThrow(
            new TypeError("settlement body with a TLC count of 1 must be 170 bytes, got 158"),
        );
    });
});

describe("against buildSettlementWitness", () => {
    const keys = deriveChannelKeys(deriveChannelSeed(new Uint8Array(32).fill(0x24), 0));
    const remoteTlcBasePubkey = pubkeyOf(new Uint8Array(32).fill(0x66));
    const remoteTlcPubkey = pubkeyOf(new Uint8Array(32).fill(0x55));

    const OFFERED_TLC: SettlementTlc = {
        id: 7,
        direction: "offered",
        hashAlgorithm: "ckb-hash",
        amountShannons: 1_500_000_000n,
        paymentHash: new Uint8Array(32).fill(0xa1),
        expiryMs: 1_723_257_890_123n,
        localKeyCommitmentNumber: 5,
        remoteTlcPubkey,
    };

    const RECEIVED_TLC: SettlementTlc = {
        id: 2,
        direction: "received",
        hashAlgorithm: "sha256",
        amountShannons: 2_250_000_000n,
        paymentHash: new Uint8Array(32).fill(0xb2),
        expiryMs: 1_750_000_000_000n,
        localKeyCommitmentNumber: 0,
        remoteTlcPubkey,
    };

    function inputOf(forRemote: boolean, lockLayout: CommitmentLockLayout, tlcs: SettlementTlc[]): SettlementWitnessInput {
        return {
            forRemote,
            remoteTlcBasePubkey,
            localAmountShannons: 60_000_000_000n,
            remoteAmountShannons: 20_000_000_000n,
            tlcs,
            lockLayout,
        };
    }

    const VIEWS = [
        [true, "legacy"],
        [false, "legacy"],
        [true, "fullPaymentHash"],
        [false, "fullPaymentHash"],
    ] as const;

    it.each(VIEWS)("reads back, with forRemote %p under %s, each balance on its side", (forRemote, layout) => {
        const body = readSettlementBody(buildSettlementWitness(keys, inputOf(forRemote, layout, [OFFERED_TLC, RECEIVED_TLC])), layout);
        const device = { pubkeyHash: blake160(pubkeyOf(keys.tlcBaseKey)), amountShannons: 60_000_000_000n };
        const peer = { pubkeyHash: blake160(remoteTlcBasePubkey), amountShannons: 20_000_000_000n };
        expect(body.balances[deviceSettlementIndex(forRemote)]).toEqual(device);
        expect(body.balances[1 - deviceSettlementIndex(forRemote)]).toEqual(peer);
    });

    it.each(VIEWS)("reads back, with forRemote %p under %s, each TLC as it was given", (forRemote, layout) => {
        const body = readSettlementBody(buildSettlementWitness(keys, inputOf(forRemote, layout, [OFFERED_TLC, RECEIVED_TLC])), layout);
        // The witness puts the received group first in a remote view, the offered group in a local one.
        const ordered = forRemote ? [RECEIVED_TLC, OFFERED_TLC] : [OFFERED_TLC, RECEIVED_TLC];
        expect(body.tlcEntries.map((entry) => readSettlementTlcEntry(entry, layout, forRemote))).toEqual(
            ordered.map((tlc) => ({
                direction: tlc.direction,
                amountShannons: tlc.amountShannons,
                localKeyHash: blake160(pubkeyOf(deriveTlcKey(keys, tlc.localKeyCommitmentNumber))),
            })),
        );
    });

    it.each(VIEWS)("drops, with forRemote %p under %s, a TLC as the witness without it", (forRemote, layout) => {
        const body = bytesToHex(buildSettlementWitness(keys, inputOf(forRemote, layout, [OFFERED_TLC, RECEIVED_TLC])));
        const ordered = forRemote ? [RECEIVED_TLC, OFFERED_TLC] : [OFFERED_TLC, RECEIVED_TLC];
        ordered.forEach((tlc, index) => {
            const unlock = readSettlementUnlock(witness(body + `0${index}` + "00" + PLACEHOLDER), layout);
            const rest = ordered.filter((other) => other !== tlc);
            expect(bytesToHex(nextSettlementWitness(unlock, forRemote))).toBe(
                bytesToHex(buildSettlementWitness(keys, inputOf(forRemote, layout, rest))),
            );
        });
    });
});
