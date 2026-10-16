import { bytesToHex } from "@noble/hashes/utils.js";
import { deriveChannelSeed } from "../../../src/derivation/device-scheme";
import { deriveChannelKeys, derivePublicKey, deriveTlcKey, pubkeyOf } from "../../../src/derivation/fiber-scheme";
import type { SettlementTlc } from "../../../src/digest/digest.types";
import type { SettlementWitnessInput } from "../../../src/digest/settlement-witness";
import { buildSettlementWitness } from "../../../src/digest/settlement-witness";
import { blake160 } from "../../../src/common/utils/ckb-hash.utils";

const MASTER_SEED = new Uint8Array(32).fill(0x24);
const channelKeys = deriveChannelKeys(deriveChannelSeed(MASTER_SEED, 0));
const localTlcBaseHash = blake160(pubkeyOf(channelKeys.tlcBaseKey));

const remoteTlcBasePubkey = pubkeyOf(new Uint8Array(32).fill(0x66));
const remoteTlcBaseHash = blake160(remoteTlcBasePubkey);

const REMOTE_COMMITMENT_POINT = pubkeyOf(new Uint8Array(32).fill(0x55));

const OFFERED_TLC: SettlementTlc = {
    id: 7,
    direction: "offered",
    hashAlgorithm: "ckb-hash",
    amountShannons: 1_500_000_000n,
    paymentHash: new Uint8Array(32).fill(0xa1),
    expiryMs: 1_723_257_890_123n,
    createdAtRemoteCommitmentNumber: 5,
    remoteCommitmentPoint: REMOTE_COMMITMENT_POINT,
};

const RECEIVED_TLC: SettlementTlc = {
    id: 2,
    direction: "received",
    hashAlgorithm: "sha256",
    amountShannons: 2_250_000_000n,
    paymentHash: new Uint8Array(32).fill(0xb2),
    expiryMs: 1_750_000_000_000n,
    createdAtRemoteCommitmentNumber: 0,
    remoteCommitmentPoint: REMOTE_COMMITMENT_POINT,
};

const BASE_INPUT: SettlementWitnessInput = {
    forRemote: true,
    remoteTlcBasePubkey,
    localAmountShannons: 60_000_000_000n,
    remoteAmountShannons: 20_000_000_000n,
    tlcs: [],
    lockLayout: "legacy",
};

// A record is 85 bytes under legacy and 97 under fullPaymentHash, the whole hash.
function record(witness: Uint8Array, at: number, length = 85): Uint8Array {
    return witness.slice(1 + at * length, 1 + (at + 1) * length);
}

describe("buildSettlementWitness", () => {
    it("lays out the TLC-less witness as count, then the two 36-byte side blocks", () => {
        const witness = buildSettlementWitness(channelKeys, BASE_INPUT);
        expect(witness).toHaveLength(73);
        expect(witness[0]).toBe(0);
        // for_remote puts the remote side first.
        expect(bytesToHex(witness.slice(1, 21))).toBe(bytesToHex(remoteTlcBaseHash));
        expect(bytesToHex(witness.slice(21, 37))).toBe("00c817a804000000" + "00".repeat(8));
        expect(bytesToHex(witness.slice(37, 57))).toBe(bytesToHex(localTlcBaseHash));
        expect(bytesToHex(witness.slice(57, 73))).toBe("005847f80d000000" + "00".repeat(8));
    });

    it("lays out the TLC-less witness identically under fullPaymentHash", () => {
        expect(bytesToHex(buildSettlementWitness(channelKeys, { ...BASE_INPUT, lockLayout: "fullPaymentHash" }))).toBe(
            bytesToHex(buildSettlementWitness(channelKeys, BASE_INPUT)),
        );
    });

    it("swaps the side blocks when building the local variant", () => {
        const witness = buildSettlementWitness(channelKeys, { ...BASE_INPUT, forRemote: false });
        expect(bytesToHex(witness.slice(1, 21))).toBe(bytesToHex(localTlcBaseHash));
        expect(bytesToHex(witness.slice(37, 57))).toBe(bytesToHex(remoteTlcBaseHash));
    });

    it("serializes one 85-byte record per TLC under legacy", () => {
        const witness = buildSettlementWitness(channelKeys, { ...BASE_INPUT, tlcs: [OFFERED_TLC, RECEIVED_TLC] });
        expect(witness).toHaveLength(73 + 2 * 85);
        expect(witness[0]).toBe(2);
    });

    it("serializes one 97-byte record per TLC under fullPaymentHash, the side blocks after them", () => {
        const witness = buildSettlementWitness(channelKeys, {
            ...BASE_INPUT,
            lockLayout: "fullPaymentHash",
            tlcs: [OFFERED_TLC, RECEIVED_TLC],
        });
        expect(witness).toHaveLength(73 + 2 * 97);
        expect(witness[0]).toBe(2);
        expect(bytesToHex(witness.slice(1 + 2 * 97, 21 + 2 * 97))).toBe(bytesToHex(remoteTlcBaseHash));
        expect(bytesToHex(witness.slice(21 + 2 * 97, 37 + 2 * 97))).toBe("00c817a804000000" + "00".repeat(8));
        expect(bytesToHex(witness.slice(37 + 2 * 97, 57 + 2 * 97))).toBe(bytesToHex(localTlcBaseHash));
        expect(bytesToHex(witness.slice(57 + 2 * 97, 73 + 2 * 97))).toBe("005847f80d000000" + "00".repeat(8));
    });

    it.each([
        [true, OFFERED_TLC, 0b00],
        [true, RECEIVED_TLC, 0b11],
        [false, OFFERED_TLC, 0b01],
        [false, RECEIVED_TLC, 0b10],
    ])("with forRemote %p flags the %o TLC as %i", (forRemote, tlc, flag) => {
        const witness = buildSettlementWitness(channelKeys, { ...BASE_INPUT, forRemote, tlcs: [tlc] });
        expect(record(witness, 0)[0]).toBe(flag);
    });

    it("orders received before offered for the remote variant, each group ascending by id", () => {
        const third: SettlementTlc = { ...OFFERED_TLC, id: 5, amountShannons: 750_000_000n };
        const witness = buildSettlementWitness(channelKeys, { ...BASE_INPUT, tlcs: [OFFERED_TLC, RECEIVED_TLC, third] });
        const amountOf = (at: number): bigint => new DataView(record(witness, at).slice(1, 17).buffer).getBigUint64(0, true);
        expect([amountOf(0), amountOf(1), amountOf(2)]).toEqual([2_250_000_000n, 750_000_000n, 1_500_000_000n]);
    });

    it("orders offered before received for the local variant", () => {
        const witness = buildSettlementWitness(channelKeys, { ...BASE_INPUT, forRemote: false, tlcs: [OFFERED_TLC, RECEIVED_TLC] });
        const amountOf = (at: number): bigint => new DataView(record(witness, at).slice(1, 17).buffer).getBigUint64(0, true);
        expect([amountOf(0), amountOf(1)]).toEqual([1_500_000_000n, 2_250_000_000n]);
    });

    it("binds the first 20 bytes of the payment hash under legacy, at offset 17 of the 85-byte record", () => {
        const witness = buildSettlementWitness(channelKeys, { ...BASE_INPUT, tlcs: [OFFERED_TLC] });
        const tlcRecord = record(witness, 0);
        expect(tlcRecord).toHaveLength(85);
        expect(tlcRecord[0]).toBe(0b00);
        expect(bytesToHex(tlcRecord.slice(1, 17))).toBe("002f6859" + "00".repeat(12));
        expect(bytesToHex(tlcRecord.slice(17, 37))).toBe("a1".repeat(20));
        const since = new DataView(tlcRecord.slice(77, 85).buffer).getBigUint64(0, true);
        expect(since).toBe(0x4000000000000000n | 1_723_257_890n);
    });

    it("binds the whole 32-byte payment hash under fullPaymentHash, at offset 17 of the 97-byte record", () => {
        const witness = buildSettlementWitness(channelKeys, { ...BASE_INPUT, lockLayout: "fullPaymentHash", tlcs: [OFFERED_TLC] });
        const tlcRecord = record(witness, 0, 97);
        expect(tlcRecord).toHaveLength(97);
        expect(tlcRecord[0]).toBe(0b00);
        expect(bytesToHex(tlcRecord.slice(1, 17))).toBe("002f6859" + "00".repeat(12));
        expect(bytesToHex(tlcRecord.slice(17, 49))).toBe("a1".repeat(32));
        const localHash = blake160(pubkeyOf(deriveTlcKey(channelKeys, OFFERED_TLC.createdAtRemoteCommitmentNumber)));
        const remoteHash = blake160(derivePublicKey(remoteTlcBasePubkey, REMOTE_COMMITMENT_POINT));
        expect(bytesToHex(tlcRecord.slice(49, 69))).toBe(bytesToHex(remoteHash));
        expect(bytesToHex(tlcRecord.slice(69, 89))).toBe(bytesToHex(localHash));
        const since = new DataView(tlcRecord.slice(89, 97).buffer).getBigUint64(0, true);
        expect(since).toBe(0x4000000000000000n | 1_723_257_890n);
        // Only the hash widens: the 17 bytes before it and the 48 after it are the legacy record's.
        const legacyRecord = record(buildSettlementWitness(channelKeys, { ...BASE_INPUT, tlcs: [OFFERED_TLC] }), 0);
        expect(bytesToHex(tlcRecord.slice(0, 17))).toBe(bytesToHex(legacyRecord.slice(0, 17)));
        expect(bytesToHex(tlcRecord.slice(49))).toBe(bytesToHex(legacyRecord.slice(37)));
    });

    it("derives the per-TLC key hashes, remote first for the remote variant", () => {
        const witness = buildSettlementWitness(channelKeys, { ...BASE_INPUT, tlcs: [OFFERED_TLC] });
        const tlcRecord = record(witness, 0);
        const localHash = blake160(pubkeyOf(deriveTlcKey(channelKeys, OFFERED_TLC.createdAtRemoteCommitmentNumber)));
        const remoteHash = blake160(derivePublicKey(remoteTlcBasePubkey, REMOTE_COMMITMENT_POINT));
        expect(bytesToHex(tlcRecord.slice(37, 57))).toBe(bytesToHex(remoteHash));
        expect(bytesToHex(tlcRecord.slice(57, 77))).toBe(bytesToHex(localHash));
    });

    it("swaps the per-TLC key hashes for the local variant", () => {
        const witness = buildSettlementWitness(channelKeys, { ...BASE_INPUT, forRemote: false, tlcs: [OFFERED_TLC] });
        const tlcRecord = record(witness, 0);
        const localHash = blake160(pubkeyOf(deriveTlcKey(channelKeys, OFFERED_TLC.createdAtRemoteCommitmentNumber)));
        expect(bytesToHex(tlcRecord.slice(37, 57))).toBe(bytesToHex(localHash));
    });

    it("refuses more TLCs than the one-byte count can hold", () => {
        const tlcs = Array.from({ length: 256 }, () => OFFERED_TLC);
        expect(() => buildSettlementWitness(channelKeys, { ...BASE_INPUT, tlcs })).toThrow(TypeError);
    });

    it("refuses a malformed side input, one field at a time", () => {
        expect(() => buildSettlementWitness(channelKeys, { ...BASE_INPUT, remoteTlcBasePubkey: new Uint8Array(32) })).toThrow(TypeError);
        expect(() => buildSettlementWitness(channelKeys, { ...BASE_INPUT, localAmountShannons: -1n })).toThrow(RangeError);
        expect(() => buildSettlementWitness(channelKeys, { ...BASE_INPUT, remoteAmountShannons: 1n << 128n })).toThrow(RangeError);
    });

    it.each([undefined, null, "full_payment_hash", "Legacy", "constructor"])("refuses the layout %p", (lockLayout) => {
        expect(() => buildSettlementWitness(channelKeys, { ...BASE_INPUT, lockLayout: lockLayout as never })).toThrow(
            new TypeError("lockLayout must be one of legacy, fullPaymentHash"),
        );
    });

    it("refuses a malformed TLC, one field at a time", () => {
        const witnessWith = (tlc: SettlementTlc) => () => buildSettlementWitness(channelKeys, { ...BASE_INPUT, tlcs: [tlc] });
        expect(witnessWith({ ...OFFERED_TLC, id: -1 })).toThrow(RangeError);
        expect(witnessWith({ ...OFFERED_TLC, direction: "inbound" as never })).toThrow(TypeError);
        expect(witnessWith({ ...OFFERED_TLC, hashAlgorithm: "sha512" as never })).toThrow(
            new TypeError("tlc.hashAlgorithm must be one of ckb-hash, sha256"),
        );
        // An inherited key of a plain object is no algorithm either.
        expect(witnessWith({ ...OFFERED_TLC, hashAlgorithm: "constructor" as never })).toThrow(
            new TypeError("tlc.hashAlgorithm must be one of ckb-hash, sha256"),
        );
        expect(witnessWith({ ...OFFERED_TLC, amountShannons: 1n << 128n })).toThrow(RangeError);
        expect(witnessWith({ ...OFFERED_TLC, paymentHash: new Uint8Array(31) })).toThrow(TypeError);
        expect(witnessWith({ ...OFFERED_TLC, expiryMs: -1n })).toThrow(RangeError);
        expect(witnessWith({ ...OFFERED_TLC, createdAtRemoteCommitmentNumber: 2 ** 48 })).toThrow(RangeError);
        expect(witnessWith({ ...OFFERED_TLC, remoteCommitmentPoint: new Uint8Array(32) })).toThrow(TypeError);
    });

    it("refuses a 31-byte payment hash under fullPaymentHash too", () => {
        const tlc: SettlementTlc = { ...OFFERED_TLC, paymentHash: new Uint8Array(31).fill(0xa1) };
        expect(() => buildSettlementWitness(channelKeys, { ...BASE_INPUT, lockLayout: "fullPaymentHash", tlcs: [tlc] })).toThrow(
            new TypeError("tlc.paymentHash must be 32 bytes, got 31"),
        );
    });
});
