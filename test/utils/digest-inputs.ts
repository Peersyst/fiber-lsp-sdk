import { hexToBytes } from "@noble/hashes/utils.js";
import type { OutPoint, Script, ScriptHashType, TlcDirection, TlcHashAlgorithm } from "../../src/common";
import type { ChannelAnnouncementInput, CommitmentTxInput, RevocationInput, SettlementTlc, ShutdownTxInput } from "../../src/digest";
import { COMMITMENT_LOCK_TESTNET } from "../../src/digest";
import type {
    AnnouncementCaseVector,
    CommitmentCaseVector,
    OutPointVector,
    RevocationCaseVector,
    ScriptVector,
    ShutdownCaseVector,
    TlcVector,
} from "./interop-vectors";

export type RemotePubkeys = { funding_pubkey: string; tlc_base_pubkey: string };

export function toScript(vector: ScriptVector): Script {
    return { codeHash: hexToBytes(vector.code_hash), hashType: vector.hash_type as ScriptHashType, args: hexToBytes(vector.args) };
}

export function toScriptOrNull(vector: ScriptVector | null): Script | null {
    return vector === null ? null : toScript(vector);
}

export function toOutPoint(vector: OutPointVector): OutPoint {
    return { txHash: hexToBytes(vector.tx_hash), index: vector.index };
}

export function toTlc(vector: TlcVector): SettlementTlc {
    return {
        id: vector.id,
        direction: vector.direction as TlcDirection,
        hashAlgorithm: vector.hash_algorithm as TlcHashAlgorithm,
        amountShannons: BigInt(vector.amount),
        paymentHash: hexToBytes(vector.payment_hash),
        expiryMs: BigInt(vector.expiry_ms),
        createdAtRemoteCommitmentNumber: vector.created_at_remote_commitment_number,
        remoteCommitmentPoint: hexToBytes(vector.remote_commitment_point),
    };
}

export function toCommitmentTxInput(kase: CommitmentCaseVector, remote: RemotePubkeys): CommitmentTxInput {
    return {
        forRemote: kase.for_remote,
        fundingOutPoint: toOutPoint(kase.funding_out_point),
        remoteFundingPubkey: hexToBytes(remote.funding_pubkey),
        remoteTlcBasePubkey: hexToBytes(remote.tlc_base_pubkey),
        commitmentNumber: kase.commitment_number,
        commitmentDelayEpoch: BigInt(kase.delay_epoch),
        commitmentFeeRate: BigInt(kase.fee_rate),
        cellDepsCount: kase.cell_deps_count,
        udtTypeScript: toScriptOrNull(kase.udt_type_script),
        toLocalShannons: BigInt(kase.to_local),
        toRemoteShannons: BigInt(kase.to_remote),
        settlementLocalShannons: BigInt(kase.settlement_local),
        settlementRemoteShannons: BigInt(kase.settlement_remote),
        localReservedCkbShannons: BigInt(kase.local_reserved),
        remoteReservedCkbShannons: BigInt(kase.remote_reserved),
        tlcs: kase.tlcs.map(toTlc),
        commitmentLock: COMMITMENT_LOCK_TESTNET,
    };
}

export function toShutdownTxInput(kase: ShutdownCaseVector, remote: RemotePubkeys): ShutdownTxInput {
    return {
        fundingOutPoint: toOutPoint(kase.funding_out_point),
        remoteFundingPubkey: hexToBytes(remote.funding_pubkey),
        localCloseScript: toScript(kase.local_close_script),
        remoteCloseScript: toScript(kase.remote_close_script),
        localFeeRate: BigInt(kase.local_fee_rate),
        remoteFeeRate: BigInt(kase.remote_fee_rate),
        cellDepsCount: kase.cell_deps_count,
        udtTypeScript: toScriptOrNull(kase.udt_type_script),
        toLocalShannons: BigInt(kase.to_local),
        toRemoteShannons: BigInt(kase.to_remote),
        localReservedCkbShannons: BigInt(kase.local_reserved),
        remoteReservedCkbShannons: BigInt(kase.remote_reserved),
    };
}

export function toRevocationInput(kase: RevocationCaseVector, remote: RemotePubkeys): RevocationInput {
    return {
        forRemote: kase.for_remote,
        revokedCommitmentNumber: kase.revoked_commitment_number,
        payoutScript: toScript(kase.payout_script),
        remoteFundingPubkey: hexToBytes(remote.funding_pubkey),
        commitmentDelayEpoch: BigInt(kase.delay_epoch),
        commitmentFeeRate: BigInt(kase.fee_rate),
        cellDepsCount: kase.cell_deps_count,
        udtTypeScript: toScriptOrNull(kase.udt_type_script),
        toLocalShannons: BigInt(kase.to_local),
        toRemoteShannons: BigInt(kase.to_remote),
        localReservedCkbShannons: BigInt(kase.local_reserved),
        remoteReservedCkbShannons: BigInt(kase.remote_reserved),
        commitmentLock: COMMITMENT_LOCK_TESTNET,
    };
}

export function toChannelAnnouncementInput(kase: AnnouncementCaseVector, remote: RemotePubkeys): ChannelAnnouncementInput {
    return {
        chainHash: hexToBytes(kase.chain_hash),
        fundingOutPoint: toOutPoint(kase.funding_out_point),
        nodeIds: [hexToBytes(kase.node_ids[0]), hexToBytes(kase.node_ids[1])],
        remoteFundingPubkey: hexToBytes(remote.funding_pubkey),
        capacityShannons: BigInt(kase.capacity),
        udtTypeScript: toScriptOrNull(kase.udt_type_script),
    };
}
