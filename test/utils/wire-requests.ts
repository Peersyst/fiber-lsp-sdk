import type { ScriptHashType, TlcDirection } from "../../src/common";
import type {
    ChannelAnnouncementWire,
    CommitmentTxWire,
    RevocationWire,
    SettlementTlcWire,
    ShutdownTxWire,
    SignSessionWire,
} from "../../src/protocol";
import type { OutPointWire, ScriptWire, TlcHashAlgorithmWire } from "../../src/wire";
import type { RemotePubkeys } from "./digest-inputs";
import type {
    AnnouncementCaseVector,
    CommitmentCaseVector,
    OutPointVector,
    RevocationCaseVector,
    ScriptVector,
    ShutdownCaseVector,
    TlcVector,
} from "./interop-vectors";

function wireHex(hex: string): string {
    return `0x${hex}`;
}

export function wireUint(value: string | number | bigint): string {
    return `0x${BigInt(value).toString(16)}`;
}

const HASH_ALGORITHM_WIRE: Record<string, TlcHashAlgorithmWire> = { "ckb-hash": "ckb_hash", sha256: "sha256" };

export function toScriptWire(vector: ScriptVector): ScriptWire {
    return { code_hash: wireHex(vector.code_hash), hash_type: vector.hash_type as ScriptHashType, args: wireHex(vector.args) };
}

function toScriptWireOrNull(vector: ScriptVector | null): ScriptWire | null {
    return vector === null ? null : toScriptWire(vector);
}

function toOutPointWire(vector: OutPointVector): OutPointWire {
    return { tx_hash: wireHex(vector.tx_hash), index: wireUint(vector.index) };
}

function toTlcWire(vector: TlcVector): SettlementTlcWire {
    const hashAlgorithm = HASH_ALGORITHM_WIRE[vector.hash_algorithm];
    if (hashAlgorithm === undefined) throw new Error(`the vectors carry an unknown hash algorithm: ${vector.hash_algorithm}`);
    return {
        id: wireUint(vector.id),
        direction: vector.direction as TlcDirection,
        hash_algorithm: hashAlgorithm,
        amount: wireUint(vector.amount),
        payment_hash: wireHex(vector.payment_hash),
        expiry_ms: wireUint(vector.expiry_ms),
        created_at_remote_commitment_number: wireUint(vector.created_at_remote_commitment_number),
        remote_commitment_point: wireHex(vector.remote_commitment_point),
    };
}

export function toCommitmentTxWire(kase: CommitmentCaseVector, remote: RemotePubkeys): CommitmentTxWire {
    return {
        for_remote: kase.for_remote,
        funding_out_point: toOutPointWire(kase.funding_out_point),
        remote_funding_pubkey: wireHex(remote.funding_pubkey),
        remote_tlc_base_pubkey: wireHex(remote.tlc_base_pubkey),
        commitment_number: wireUint(kase.commitment_number),
        commitment_delay_epoch: wireUint(kase.delay_epoch),
        commitment_fee_rate: wireUint(kase.fee_rate),
        cell_deps_count: wireUint(kase.cell_deps_count),
        udt_type_script: toScriptWireOrNull(kase.udt_type_script),
        to_local: wireUint(kase.to_local),
        to_remote: wireUint(kase.to_remote),
        settlement_local: wireUint(kase.settlement_local),
        settlement_remote: wireUint(kase.settlement_remote),
        local_reserved: wireUint(kase.local_reserved),
        remote_reserved: wireUint(kase.remote_reserved),
        tlcs: kase.tlcs.map(toTlcWire),
    };
}

export function toShutdownTxWire(kase: ShutdownCaseVector, remote: RemotePubkeys): ShutdownTxWire {
    return {
        funding_out_point: toOutPointWire(kase.funding_out_point),
        remote_funding_pubkey: wireHex(remote.funding_pubkey),
        local_close_script: toScriptWire(kase.local_close_script),
        remote_close_script: toScriptWire(kase.remote_close_script),
        local_fee_rate: wireUint(kase.local_fee_rate),
        remote_fee_rate: wireUint(kase.remote_fee_rate),
        cell_deps_count: wireUint(kase.cell_deps_count),
        udt_type_script: toScriptWireOrNull(kase.udt_type_script),
        to_local: wireUint(kase.to_local),
        to_remote: wireUint(kase.to_remote),
        local_reserved: wireUint(kase.local_reserved),
        remote_reserved: wireUint(kase.remote_reserved),
    };
}

export function toRevocationWire(kase: RevocationCaseVector, remote: RemotePubkeys): RevocationWire {
    return {
        for_remote: kase.for_remote,
        revoked_commitment_number: wireUint(kase.revoked_commitment_number),
        payout_script: toScriptWire(kase.payout_script),
        remote_funding_pubkey: wireHex(remote.funding_pubkey),
        commitment_delay_epoch: wireUint(kase.delay_epoch),
        commitment_fee_rate: wireUint(kase.fee_rate),
        cell_deps_count: wireUint(kase.cell_deps_count),
        udt_type_script: toScriptWireOrNull(kase.udt_type_script),
        to_local: wireUint(kase.to_local),
        to_remote: wireUint(kase.to_remote),
        local_reserved: wireUint(kase.local_reserved),
        remote_reserved: wireUint(kase.remote_reserved),
    };
}

export function toChannelAnnouncementWire(kase: AnnouncementCaseVector, remote: RemotePubkeys): ChannelAnnouncementWire {
    return {
        chain_hash: wireHex(kase.chain_hash),
        funding_out_point: toOutPointWire(kase.funding_out_point),
        node_ids: [wireHex(kase.node_ids[0]), wireHex(kase.node_ids[1])],
        remote_funding_pubkey: wireHex(remote.funding_pubkey),
        capacity: wireUint(kase.capacity),
        udt_type_script: toScriptWireOrNull(kase.udt_type_script),
    };
}

export function toSignSessionWire(orderedPubkeys: [string, string], aggregatedNonce: string, message: string): SignSessionWire {
    return {
        ordered_pubkeys: [wireHex(orderedPubkeys[0]), wireHex(orderedPubkeys[1])],
        aggregated_nonce: wireHex(aggregatedNonce),
        message: wireHex(message),
    };
}
