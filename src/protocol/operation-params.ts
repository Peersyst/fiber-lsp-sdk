import type { ScriptTemplate } from "../common";
import {
    COMPRESSED_POINT_LENGTH,
    HASH256_LENGTH,
    MESSAGE_DIGEST_LENGTH,
    MUSIG_PARTICIPANTS,
    PAYMENT_HASH_LENGTH,
    PUBLIC_NONCE_LENGTH,
    TLC_DIRECTIONS,
    UINT64_MAX,
    UINT128_MAX,
} from "../common";
import { MAX_COMMITMENT_NUMBER } from "../derivation";
import type { ChannelAnnouncementInput, CommitmentTxInput, RevocationInput, SettlementTlc, ShutdownTxInput } from "../digest";
import { MAX_CELL_DEPS_COUNT, MAX_SETTLEMENT_TLCS } from "../digest";
import type { SignSession } from "../policy";
import type { Field } from "../wire";
import {
    TLC_HASH_ALGORITHMS,
    decodeBoolean,
    decodeEnum,
    decodeHexBytes,
    decodeMapped,
    decodeOutPoint,
    decodeScript,
    decodeScriptOrNull,
    decodeUintHex,
    decodeUintHexNumber,
    malformed,
    readArray,
    readObject,
    readPair,
} from "../wire";
import type {
    ChannelAnnouncementWire,
    CommitmentTxWire,
    RevocationWire,
    SettlementTlcWire,
    ShutdownTxWire,
    SignSessionWire,
} from "./protocol.types";

/**
 * Reads a field as the musig2 session of a signing request.
 * @param field Field to read.
 * @returns The session, shape-checked; whether it aggregates this channel's key is the policy gate's question.
 */
export function decodeSignSession(field: Field): SignSession {
    const at = readObject<SignSessionWire>(field);
    return {
        orderedPublicKeys: readArray(at("ordered_pubkeys"), MUSIG_PARTICIPANTS).map((key) => decodeHexBytes(key, COMPRESSED_POINT_LENGTH)),
        aggregatedNonce: decodeHexBytes(at("aggregated_nonce"), PUBLIC_NONCE_LENGTH),
        message: decodeHexBytes(at("message"), MESSAGE_DIGEST_LENGTH),
    };
}

/**
 * Reads a field as the inputs of a commitment tx digest, with the commitment lock supplied by the device rather than the wire.
 * @param field Field to read.
 * @param commitmentLock The network's commitment lock template, never read from the node.
 * @returns The typed input the digest module rebuilds the message from.
 */
export function decodeCommitmentTx(field: Field, commitmentLock: ScriptTemplate): CommitmentTxInput {
    const at = readObject<CommitmentTxWire>(field);
    const tlcsField = at("tlcs");
    const tlcs = readArray(tlcsField);
    if (tlcs.length > MAX_SETTLEMENT_TLCS) malformed(tlcsField, `must have at most ${MAX_SETTLEMENT_TLCS} items`);
    return {
        forRemote: decodeBoolean(at("for_remote")),
        fundingOutPoint: decodeOutPoint(at("funding_out_point")),
        remoteFundingPubkey: decodeHexBytes(at("remote_funding_pubkey"), COMPRESSED_POINT_LENGTH),
        remoteTlcBasePubkey: decodeHexBytes(at("remote_tlc_base_pubkey"), COMPRESSED_POINT_LENGTH),
        commitmentNumber: decodeUintHexNumber(at("commitment_number"), MAX_COMMITMENT_NUMBER),
        commitmentDelayEpoch: decodeUintHex(at("commitment_delay_epoch"), UINT64_MAX),
        commitmentFeeRate: decodeUintHex(at("commitment_fee_rate"), UINT64_MAX),
        cellDepsCount: decodeUintHexNumber(at("cell_deps_count"), MAX_CELL_DEPS_COUNT),
        udtTypeScript: decodeScriptOrNull(at("udt_type_script")),
        toLocalShannons: decodeUintHex(at("to_local"), UINT128_MAX),
        toRemoteShannons: decodeUintHex(at("to_remote"), UINT128_MAX),
        settlementLocalShannons: decodeUintHex(at("settlement_local"), UINT128_MAX),
        settlementRemoteShannons: decodeUintHex(at("settlement_remote"), UINT128_MAX),
        localReservedCkbShannons: decodeUintHex(at("local_reserved"), UINT64_MAX),
        remoteReservedCkbShannons: decodeUintHex(at("remote_reserved"), UINT64_MAX),
        tlcs: tlcs.map(decodeSettlementTlc),
        commitmentLock,
    };
}

/**
 * Reads a field as the inputs of a cooperative-close (shutdown) tx digest.
 * @param field Field to read.
 * @returns The typed input the digest module rebuilds the message from.
 */
export function decodeShutdownTx(field: Field): ShutdownTxInput {
    const at = readObject<ShutdownTxWire>(field);
    return {
        fundingOutPoint: decodeOutPoint(at("funding_out_point")),
        remoteFundingPubkey: decodeHexBytes(at("remote_funding_pubkey"), COMPRESSED_POINT_LENGTH),
        localCloseScript: decodeScript(at("local_close_script")),
        remoteCloseScript: decodeScript(at("remote_close_script")),
        localFeeRate: decodeUintHex(at("local_fee_rate"), UINT64_MAX),
        remoteFeeRate: decodeUintHex(at("remote_fee_rate"), UINT64_MAX),
        cellDepsCount: decodeUintHexNumber(at("cell_deps_count"), MAX_CELL_DEPS_COUNT),
        udtTypeScript: decodeScriptOrNull(at("udt_type_script")),
        toLocalShannons: decodeUintHex(at("to_local"), UINT128_MAX),
        toRemoteShannons: decodeUintHex(at("to_remote"), UINT128_MAX),
        localReservedCkbShannons: decodeUintHex(at("local_reserved"), UINT64_MAX),
        remoteReservedCkbShannons: decodeUintHex(at("remote_reserved"), UINT64_MAX),
    };
}

/**
 * Reads a field as the inputs of a revocation digest, with the commitment lock supplied by the device rather than the wire.
 * @param field Field to read.
 * @param commitmentLock The network's commitment lock template, never read from the node.
 * @returns The typed input the digest module rebuilds the message from.
 */
export function decodeRevocation(field: Field, commitmentLock: ScriptTemplate): RevocationInput {
    const at = readObject<RevocationWire>(field);
    return {
        forRemote: decodeBoolean(at("for_remote")),
        revokedCommitmentNumber: decodeUintHexNumber(at("revoked_commitment_number"), MAX_COMMITMENT_NUMBER),
        payoutScript: decodeScript(at("payout_script")),
        remoteFundingPubkey: decodeHexBytes(at("remote_funding_pubkey"), COMPRESSED_POINT_LENGTH),
        commitmentDelayEpoch: decodeUintHex(at("commitment_delay_epoch"), UINT64_MAX),
        commitmentFeeRate: decodeUintHex(at("commitment_fee_rate"), UINT64_MAX),
        cellDepsCount: decodeUintHexNumber(at("cell_deps_count"), MAX_CELL_DEPS_COUNT),
        udtTypeScript: decodeScriptOrNull(at("udt_type_script")),
        toLocalShannons: decodeUintHex(at("to_local"), UINT128_MAX),
        toRemoteShannons: decodeUintHex(at("to_remote"), UINT128_MAX),
        localReservedCkbShannons: decodeUintHex(at("local_reserved"), UINT64_MAX),
        remoteReservedCkbShannons: decodeUintHex(at("remote_reserved"), UINT64_MAX),
        commitmentLock,
    };
}

/**
 * Reads a field as the inputs of a channel announcement digest.
 * @param field Field to read.
 * @returns The typed input the digest module rebuilds the message from.
 */
export function decodeChannelAnnouncement(field: Field): ChannelAnnouncementInput {
    const at = readObject<ChannelAnnouncementWire>(field);
    const [firstNode, secondNode] = readPair(at("node_ids"));
    return {
        chainHash: decodeHexBytes(at("chain_hash"), HASH256_LENGTH),
        fundingOutPoint: decodeOutPoint(at("funding_out_point")),
        nodeIds: [decodeHexBytes(firstNode, COMPRESSED_POINT_LENGTH), decodeHexBytes(secondNode, COMPRESSED_POINT_LENGTH)],
        remoteFundingPubkey: decodeHexBytes(at("remote_funding_pubkey"), COMPRESSED_POINT_LENGTH),
        capacityShannons: decodeUintHex(at("capacity"), UINT128_MAX),
        udtTypeScript: decodeScriptOrNull(at("udt_type_script")),
    };
}

/**
 * Reads a field as one TLC of the settlement witness.
 * @param field Field to read.
 * @returns The TLC.
 */
function decodeSettlementTlc(field: Field): SettlementTlc {
    const at = readObject<SettlementTlcWire>(field);
    return {
        id: decodeUintHexNumber(at("id"), Number.MAX_SAFE_INTEGER),
        direction: decodeEnum(at("direction"), TLC_DIRECTIONS),
        hashAlgorithm: decodeMapped(at("hash_algorithm"), TLC_HASH_ALGORITHMS),
        amountShannons: decodeUintHex(at("amount"), UINT128_MAX),
        paymentHash: decodeHexBytes(at("payment_hash"), PAYMENT_HASH_LENGTH),
        expiryMs: decodeUintHex(at("expiry_ms"), UINT64_MAX),
        createdAtRemoteCommitmentNumber: decodeUintHexNumber(at("created_at_remote_commitment_number"), MAX_COMMITMENT_NUMBER),
        remoteCommitmentPoint: decodeHexBytes(at("remote_commitment_point"), COMPRESSED_POINT_LENGTH),
    };
}
