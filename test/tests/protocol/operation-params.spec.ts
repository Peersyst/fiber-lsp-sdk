import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation";
import {
    COMMITMENT_LOCK_MAINNET,
    COMMITMENT_LOCK_TESTNET,
    computeChannelAnnouncementDigest,
    computeCommitmentTxDigest,
    computeRevocationDigest,
    computeShutdownTxDigest,
} from "../../../src/digest";
import {
    decodeChannelAnnouncement,
    decodeCommitmentTx,
    decodeRevocation,
    decodeShutdownTx,
    decodeSignSession,
} from "../../../src/protocol/operation-params";
import type { ChannelAnnouncementInput, CommitmentTxInput, RevocationInput, ShutdownTxInput } from "../../../src/digest";
import type { Field } from "../../../src/wire";
import { toChannelAnnouncementInput, toCommitmentTxInput, toRevocationInput, toShutdownTxInput } from "../../utils/digest-inputs";
import { caseOf, loadInteropVectors } from "../../utils/interop-vectors";
import { refusal } from "../../utils/refusal";
import { withField } from "../../utils/with-field";
import {
    toChannelAnnouncementWire,
    toCommitmentTxWire,
    toRevocationWire,
    toScriptWire,
    toShutdownTxWire,
    toSignSessionWire,
} from "../../utils/wire-requests";

const vectors = loadInteropVectors();
const digest = vectors.digest;
const REMOTE = digest.remote;
const KEYS = deriveChannelKeys(hexToBytes(vectors.sdk_scheme.channel.seed));
const LOCAL_FUNDING_PUBKEY_HEX = bytesToHex(pubkeyOf(KEYS.fundingKey));

const THREE_TLCS = caseOf(digest.commitment_cases, "ckb, three tlcs, for remote");
const CKB_SHUTDOWN = caseOf(digest.shutdown_cases, "ckb");
const SEND_SIDE_REVOCATION = caseOf(digest.revocation_cases, "ckb, send side");
const CKB_ANNOUNCEMENT = caseOf(digest.announcement_cases, "ckb");

const U32_MAX_HEX = "0xffffffff";
const U48_MAX_HEX = "0xffffffffffff";
const MAX_SAFE_INTEGER_HEX = "0x1fffffffffffff";
const U64_MAX_HEX = `0x${"f".repeat(16)}`;
const U128_MAX_HEX = `0x${"f".repeat(32)}`;
const ABOVE_U64 = `0x1${"0".repeat(16)}`;
const U64_MAX = 2n ** 64n - 1n;
const U128_MAX = 2n ** 128n - 1n;

type BoundCase<Input> = [string, string, (input: Input) => number | bigint | undefined, number | bigint];

function field(value: unknown, path: string): Field {
    return { value, path };
}

describe("decodeSignSession", () => {
    const wire = toSignSessionWire([LOCAL_FUNDING_PUBKEY_HEX, REMOTE.funding_pubkey], vectors.musig.remote_pubnonce, vectors.musig.message);

    it("reads the key list in the node's order, the aggregate nonce and the message", () => {
        expect(decodeSignSession(field(wire, "session"))).toEqual({
            orderedPublicKeys: [hexToBytes(LOCAL_FUNDING_PUBKEY_HEX), hexToBytes(REMOTE.funding_pubkey)],
            aggregatedNonce: hexToBytes(vectors.musig.remote_pubnonce),
            message: hexToBytes(vectors.musig.message),
        });
        const reversed = toSignSessionWire(
            [REMOTE.funding_pubkey, LOCAL_FUNDING_PUBKEY_HEX],
            vectors.musig.remote_pubnonce,
            vectors.musig.message,
        );
        expect(decodeSignSession(field(reversed, "session")).orderedPublicKeys).toEqual([
            hexToBytes(REMOTE.funding_pubkey),
            hexToBytes(LOCAL_FUNDING_PUBKEY_HEX),
        ]);
    });

    it.each([
        ["ordered_pubkeys", [wire.ordered_pubkeys[0]]],
        ["ordered_pubkeys", [...wire.ordered_pubkeys, wire.ordered_pubkeys[0]]],
        ["ordered_pubkeys", wire.ordered_pubkeys[0]],
        ["ordered_pubkeys", undefined],
        ["ordered_pubkeys[1]", `0x${"02".repeat(32)}`],
        ["ordered_pubkeys[0]", "02".repeat(33)],
        ["aggregated_nonce", `0x${"02".repeat(65)}`],
        ["aggregated_nonce", undefined],
        ["message", `0x${"ab".repeat(31)}`],
        ["message", hexToBytes(vectors.musig.message)],
    ])("refuses %s = %p", (path, value) => {
        expect(refusal(() => decodeSignSession(field(withField(wire, path, value), "session"))).path).toBe(`session.${path}`);
    });
});

describe("decodeCommitmentTx", () => {
    for (const kase of digest.commitment_cases) {
        it(`reads the "${kase.name}" case into the typed input, and back to fiber's digest`, () => {
            const decoded = decodeCommitmentTx(field(toCommitmentTxWire(kase, REMOTE), "commitment_tx"), COMMITMENT_LOCK_TESTNET);
            expect(decoded).toEqual(toCommitmentTxInput(kase, REMOTE));
            expect(bytesToHex(computeCommitmentTxDigest(KEYS, decoded))).toBe(kase.digest);
        });
    }

    it("takes the commitment lock from the device, never from the wire", () => {
        const wire = { ...toCommitmentTxWire(THREE_TLCS, REMOTE), commitment_lock: toScriptWire(digest.commitment_lock) };
        expect(decodeCommitmentTx(field(wire, "commitment_tx"), COMMITMENT_LOCK_MAINNET).commitmentLock).toBe(COMMITMENT_LOCK_MAINNET);
    });

    it("reads up to 255 TLCs and refuses the 256th", () => {
        const wire = toCommitmentTxWire(THREE_TLCS, REMOTE);
        const tlc = wire.tlcs[0];
        const full = { ...wire, tlcs: Array.from({ length: 255 }, () => tlc) };
        expect(decodeCommitmentTx(field(full, "commitment_tx"), COMMITMENT_LOCK_TESTNET).tlcs).toHaveLength(255);
        const overfull = { ...wire, tlcs: Array.from({ length: 256 }, () => tlc) };
        expect(refusal(() => decodeCommitmentTx(field(overfull, "commitment_tx"), COMMITMENT_LOCK_TESTNET)).message).toBe(
            "commitment_tx.tlcs must have at most 255 items",
        );
    });

    it.each<BoundCase<CommitmentTxInput>>([
        ["funding_out_point.index", U32_MAX_HEX, (input) => input.fundingOutPoint.index, 2 ** 32 - 1],
        ["commitment_number", U48_MAX_HEX, (input) => input.commitmentNumber, 2 ** 48 - 1],
        ["commitment_delay_epoch", U64_MAX_HEX, (input) => input.commitmentDelayEpoch, U64_MAX],
        ["commitment_fee_rate", U64_MAX_HEX, (input) => input.commitmentFeeRate, U64_MAX],
        ["cell_deps_count", "0xff", (input) => input.cellDepsCount, 255],
        ["to_local", U128_MAX_HEX, (input) => input.toLocalShannons, U128_MAX],
        ["to_remote", U128_MAX_HEX, (input) => input.toRemoteShannons, U128_MAX],
        ["settlement_local", U128_MAX_HEX, (input) => input.settlementLocalShannons, U128_MAX],
        ["settlement_remote", U128_MAX_HEX, (input) => input.settlementRemoteShannons, U128_MAX],
        ["local_reserved", U64_MAX_HEX, (input) => input.localReservedCkbShannons, U64_MAX],
        ["remote_reserved", U64_MAX_HEX, (input) => input.remoteReservedCkbShannons, U64_MAX],
        ["tlcs[0].id", MAX_SAFE_INTEGER_HEX, (input) => input.tlcs[0]?.id, Number.MAX_SAFE_INTEGER],
        ["tlcs[0].amount", U128_MAX_HEX, (input) => input.tlcs[0]?.amountShannons, U128_MAX],
        ["tlcs[0].expiry_ms", U64_MAX_HEX, (input) => input.tlcs[0]?.expiryMs, U64_MAX],
        [
            "tlcs[0].created_at_remote_commitment_number",
            U48_MAX_HEX,
            (input) => input.tlcs[0]?.createdAtRemoteCommitmentNumber,
            2 ** 48 - 1,
        ],
    ])("reads %s at its exact bound", (path, value, read, bound) => {
        const wire = withField(toCommitmentTxWire(THREE_TLCS, REMOTE), path, value);
        expect(read(decodeCommitmentTx(field(wire, "commitment_tx"), COMMITMENT_LOCK_TESTNET))).toBe(bound);
    });

    it.each([
        ["for_remote", "true"],
        ["for_remote", 1],
        ["for_remote", undefined],
        ["funding_out_point", null],
        ["funding_out_point.tx_hash", `0x${"ab".repeat(31)}`],
        ["funding_out_point.index", "0x100000000"],
        ["funding_out_point.index", 0],
        ["remote_funding_pubkey", `0x${"02".repeat(32)}`],
        ["remote_funding_pubkey", `0x${"02".repeat(34)}`],
        ["remote_funding_pubkey", undefined],
        ["remote_tlc_base_pubkey", "02".repeat(33)],
        ["commitment_number", "0x1000000000000"],
        ["commitment_number", "0x01"],
        ["commitment_number", 5],
        ["commitment_number", undefined],
        ["commitment_delay_epoch", `0x1${"0".repeat(16)}`],
        ["commitment_delay_epoch", undefined],
        ["commitment_fee_rate", "0x"],
        ["commitment_fee_rate", "1000"],
        ["commitment_fee_rate", ABOVE_U64],
        ["cell_deps_count", "0x100"],
        ["cell_deps_count", "0x02"],
        ["cell_deps_count", 2],
        ["udt_type_script", undefined],
        ["udt_type_script", "null"],
        ["udt_type_script", []],
        ["to_local", `0x1${"0".repeat(32)}`],
        ["to_local", undefined],
        ["to_remote", "0xFF"],
        ["settlement_local", ""],
        ["settlement_remote", "-1"],
        ["local_reserved", `0x1${"0".repeat(16)}`],
        ["remote_reserved", -1],
        ["remote_reserved", ABOVE_U64],
        ["tlcs", {}],
        ["tlcs", undefined],
        ["tlcs", "[]"],
        ["tlcs[0]", null],
        ["tlcs[0]", "tlc"],
        ["tlcs[0].id", "0x20000000000000"],
        ["tlcs[0].id", 7],
        ["tlcs[0].direction", "sent"],
        ["tlcs[0].direction", undefined],
        ["tlcs[0].hash_algorithm", "ckb-hash"],
        ["tlcs[0].hash_algorithm", "CkbHash"],
        ["tlcs[0].amount", "0x0f"],
        ["tlcs[0].amount", `0x1${"0".repeat(32)}`],
        ["tlcs[0].payment_hash", `0x${"ab".repeat(31)}`],
        ["tlcs[0].expiry_ms", `0x1${"0".repeat(16)}`],
        ["tlcs[0].created_at_remote_commitment_number", "0x1000000000000"],
        ["tlcs[0].remote_commitment_point", `0x${"02".repeat(32)}`],
        ["tlcs[1]", null],
    ])("refuses %s = %p", (path, value) => {
        const wire = withField(toCommitmentTxWire(THREE_TLCS, REMOTE), path, value);
        const error = refusal(() => decodeCommitmentTx(field(wire, "commitment_tx"), COMMITMENT_LOCK_TESTNET));
        expect(error.path).toBe(`commitment_tx.${path}`);
    });

    it("refuses what is not an object", () => {
        expect(refusal(() => decodeCommitmentTx(field(undefined, "commitment_tx"), COMMITMENT_LOCK_TESTNET)).message).toBe(
            "commitment_tx must be an object",
        );
    });
});

describe("decodeShutdownTx", () => {
    for (const kase of digest.shutdown_cases) {
        it(`reads the "${kase.name}" case into the typed input, and back to fiber's digest`, () => {
            const decoded = decodeShutdownTx(field(toShutdownTxWire(kase, REMOTE), "shutdown_tx"));
            expect(decoded).toEqual(toShutdownTxInput(kase, REMOTE));
            expect(bytesToHex(computeShutdownTxDigest(KEYS, decoded))).toBe(kase.digest);
        });
    }

    it.each<BoundCase<ShutdownTxInput>>([
        ["funding_out_point.index", U32_MAX_HEX, (input) => input.fundingOutPoint.index, 2 ** 32 - 1],
        ["local_fee_rate", U64_MAX_HEX, (input) => input.localFeeRate, U64_MAX],
        ["remote_fee_rate", U64_MAX_HEX, (input) => input.remoteFeeRate, U64_MAX],
        ["cell_deps_count", "0xff", (input) => input.cellDepsCount, 255],
        ["to_local", U128_MAX_HEX, (input) => input.toLocalShannons, U128_MAX],
        ["to_remote", U128_MAX_HEX, (input) => input.toRemoteShannons, U128_MAX],
        ["local_reserved", U64_MAX_HEX, (input) => input.localReservedCkbShannons, U64_MAX],
        ["remote_reserved", U64_MAX_HEX, (input) => input.remoteReservedCkbShannons, U64_MAX],
    ])("reads %s at its exact bound", (path, value, read, bound) => {
        const wire = withField(toShutdownTxWire(CKB_SHUTDOWN, REMOTE), path, value);
        expect(read(decodeShutdownTx(field(wire, "shutdown_tx")))).toBe(bound);
    });

    it.each([
        ["funding_out_point.tx_hash", `0x${"ab".repeat(31)}`],
        ["remote_funding_pubkey", `0x${"02".repeat(32)}`],
        ["local_close_script", null],
        ["local_close_script.code_hash", `0x${"ab".repeat(31)}`],
        ["remote_close_script.hash_type", "data3"],
        ["remote_close_script.args", "0xb"],
        ["local_fee_rate", "0x01"],
        ["local_fee_rate", ABOVE_U64],
        ["remote_fee_rate", 2143],
        ["remote_fee_rate", ABOVE_U64],
        ["cell_deps_count", "0x100"],
        ["udt_type_script", undefined],
        ["to_local", `0x1${"0".repeat(32)}`],
        ["to_remote", "0xFF"],
        ["local_reserved", `0x1${"0".repeat(16)}`],
        ["remote_reserved", undefined],
        ["remote_reserved", ABOVE_U64],
    ])("refuses %s = %p", (path, value) => {
        const wire = withField(toShutdownTxWire(CKB_SHUTDOWN, REMOTE), path, value);
        expect(refusal(() => decodeShutdownTx(field(wire, "shutdown_tx"))).path).toBe(`shutdown_tx.${path}`);
    });
});

describe("decodeRevocation", () => {
    for (const kase of digest.revocation_cases) {
        it(`reads the "${kase.name}" case into the typed input, and back to fiber's digest`, () => {
            const decoded = decodeRevocation(field(toRevocationWire(kase, REMOTE), "revocation"), COMMITMENT_LOCK_TESTNET);
            expect(decoded).toEqual(toRevocationInput(kase, REMOTE));
            expect(bytesToHex(computeRevocationDigest(KEYS, decoded))).toBe(kase.digest);
        });
    }

    it("takes the commitment lock from the device, never from the wire", () => {
        const wire = { ...toRevocationWire(SEND_SIDE_REVOCATION, REMOTE), commitment_lock: toScriptWire(digest.commitment_lock) };
        expect(decodeRevocation(field(wire, "revocation"), COMMITMENT_LOCK_MAINNET).commitmentLock).toBe(COMMITMENT_LOCK_MAINNET);
    });

    it.each<BoundCase<RevocationInput>>([
        ["revoked_commitment_number", U48_MAX_HEX, (input) => input.revokedCommitmentNumber, 2 ** 48 - 1],
        ["commitment_delay_epoch", U64_MAX_HEX, (input) => input.commitmentDelayEpoch, U64_MAX],
        ["commitment_fee_rate", U64_MAX_HEX, (input) => input.commitmentFeeRate, U64_MAX],
        ["cell_deps_count", "0xff", (input) => input.cellDepsCount, 255],
        ["to_local", U128_MAX_HEX, (input) => input.toLocalShannons, U128_MAX],
        ["to_remote", U128_MAX_HEX, (input) => input.toRemoteShannons, U128_MAX],
        ["local_reserved", U64_MAX_HEX, (input) => input.localReservedCkbShannons, U64_MAX],
        ["remote_reserved", U64_MAX_HEX, (input) => input.remoteReservedCkbShannons, U64_MAX],
    ])("reads %s at its exact bound", (path, value, read, bound) => {
        const wire = withField(toRevocationWire(SEND_SIDE_REVOCATION, REMOTE), path, value);
        expect(read(decodeRevocation(field(wire, "revocation"), COMMITMENT_LOCK_TESTNET))).toBe(bound);
    });

    it.each([
        ["for_remote", "false"],
        ["revoked_commitment_number", "0x1000000000000"],
        ["revoked_commitment_number", 4],
        ["payout_script", null],
        ["payout_script.args", "0xb"],
        ["remote_funding_pubkey", `0x${"02".repeat(34)}`],
        ["commitment_delay_epoch", `0x1${"0".repeat(16)}`],
        ["commitment_fee_rate", "0x"],
        ["commitment_fee_rate", ABOVE_U64],
        ["cell_deps_count", "0x100"],
        ["udt_type_script", undefined],
        ["to_local", `0x1${"0".repeat(32)}`],
        ["to_remote", "0x00"],
        ["local_reserved", "4200000000"],
        ["local_reserved", ABOVE_U64],
        ["remote_reserved", `0x1${"0".repeat(16)}`],
    ])("refuses %s = %p", (path, value) => {
        const wire = withField(toRevocationWire(SEND_SIDE_REVOCATION, REMOTE), path, value);
        expect(refusal(() => decodeRevocation(field(wire, "revocation"), COMMITMENT_LOCK_TESTNET)).path).toBe(`revocation.${path}`);
    });
});

describe("decodeChannelAnnouncement", () => {
    for (const kase of digest.announcement_cases) {
        it(`reads the "${kase.name}" case into the typed input, and back to fiber's digest`, () => {
            const decoded = decodeChannelAnnouncement(field(toChannelAnnouncementWire(kase, REMOTE), "channel_announcement"));
            expect(decoded).toEqual(toChannelAnnouncementInput(kase, REMOTE));
            expect(bytesToHex(computeChannelAnnouncementDigest(KEYS, decoded))).toBe(kase.digest);
        });
    }

    it.each<BoundCase<ChannelAnnouncementInput>>([
        ["funding_out_point.index", U32_MAX_HEX, (input) => input.fundingOutPoint.index, 2 ** 32 - 1],
        ["capacity", U128_MAX_HEX, (input) => input.capacityShannons, U128_MAX],
    ])("reads %s at its exact bound", (path, value, read, bound) => {
        const wire = withField(toChannelAnnouncementWire(CKB_ANNOUNCEMENT, REMOTE), path, value);
        expect(read(decodeChannelAnnouncement(field(wire, "channel_announcement")))).toBe(bound);
    });

    it.each([
        ["chain_hash", `0x${"ab".repeat(31)}`],
        ["chain_hash", undefined],
        ["funding_out_point.index", "0x100000000"],
        ["node_ids", [`0x${"02".repeat(33)}`]],
        ["node_ids", [`0x${"02".repeat(33)}`, `0x${"03".repeat(33)}`, `0x${"02".repeat(33)}`]],
        ["node_ids", `0x${"02".repeat(33)}`],
        ["node_ids", undefined],
        ["node_ids[0]", undefined],
        ["node_ids[1]", `0x${"02".repeat(32)}`],
        ["remote_funding_pubkey", `0x${"02".repeat(32)}`],
        ["capacity", `0x1${"0".repeat(32)}`],
        ["capacity", "80500000000"],
        ["udt_type_script", undefined],
    ])("refuses %s = %p", (path, value) => {
        const wire = withField(toChannelAnnouncementWire(CKB_ANNOUNCEMENT, REMOTE), path, value);
        expect(refusal(() => decodeChannelAnnouncement(field(wire, "channel_announcement"))).path).toBe(`channel_announcement.${path}`);
    });
});

describe("refusals", () => {
    it("name the field and what it had to be, never the value", () => {
        const markers = ["5ECRE7", "BADCAFE", "SENTINEL"];
        const wires = [
            withField(toCommitmentTxWire(THREE_TLCS, REMOTE), "remote_funding_pubkey", `0x${"5ECRE7".repeat(11)}`),
            withField(toCommitmentTxWire(THREE_TLCS, REMOTE), "to_local", "0xBADCAFE"),
            withField(toCommitmentTxWire(THREE_TLCS, REMOTE), "tlcs[0].direction", "SENTINEL"),
            withField(toCommitmentTxWire(THREE_TLCS, REMOTE), "tlcs[0].hash_algorithm", "SENTINEL"),
            withField(toCommitmentTxWire(THREE_TLCS, REMOTE), "udt_type_script", {
                code_hash: "BADCAFE",
                hash_type: "SENTINEL",
                args: "5ECRE7",
            }),
        ];
        for (const wire of wires) {
            const error = refusal(() => decodeCommitmentTx(field(wire, "commitment_tx"), COMMITMENT_LOCK_TESTNET));
            for (const marker of markers) expect(error.message).not.toContain(marker);
        }
    });
});
