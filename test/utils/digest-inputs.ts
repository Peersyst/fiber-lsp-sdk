import { hexToBytes } from "@noble/hashes/utils.js";
import { equalBytes } from "@noble/curves/utils.js";
import type { CellOutput, OutPoint, Script, ScriptHashType, TlcDirection, TlcHashAlgorithm, Transaction } from "../../src/common";
import type {
    ChannelAnnouncementInput,
    ClosingTxInput,
    CommitmentLockLayout,
    CommitmentSettlementTerms,
    CommitmentTxInput,
    RevocationInput,
    SettlementTlc,
    ShutdownTxInput,
} from "../../src/digest";
import { COMMITMENT_LOCK_TESTNET } from "../../src/digest";
import { decodeTransaction } from "../../src/wire";
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

export function toLockLayout(vector: string): CommitmentLockLayout {
    if (vector === "legacy") return "legacy";
    if (vector === "full_payment_hash") return "fullPaymentHash";
    throw new Error(`the vectors carry an unknown lock layout: ${vector}`);
}

export function toTlc(vector: TlcVector): SettlementTlc {
    return {
        id: vector.id,
        direction: vector.direction as TlcDirection,
        hashAlgorithm: vector.hash_algorithm as TlcHashAlgorithm,
        amountShannons: BigInt(vector.amount),
        paymentHash: hexToBytes(vector.payment_hash),
        expiryMs: BigInt(vector.expiry_ms),
        localKeyCommitmentNumber: vector.local_key_commitment_number,
        remoteTlcPubkey: hexToBytes(vector.remote_tlc_pubkey),
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
        liquidCapacityShannons: BigInt(kase.to_local) + BigInt(kase.to_remote),
        settlementLocalShannons: BigInt(kase.settlement_local),
        settlementRemoteShannons: BigInt(kase.settlement_remote),
        localReservedCkbShannons: BigInt(kase.local_reserved),
        remoteReservedCkbShannons: BigInt(kase.remote_reserved),
        tlcs: kase.tlcs.map(toTlc),
        commitmentLock: COMMITMENT_LOCK_TESTNET,
        lockLayout: toLockLayout(kase.lock_layout),
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

export function toCommitmentSettlementTerms(kase: CommitmentCaseVector, remote: RemotePubkeys): CommitmentSettlementTerms {
    return {
        fundingOutPoint: toOutPoint(kase.funding_out_point),
        remoteFundingPubkey: hexToBytes(remote.funding_pubkey),
        commitmentDelayEpoch: BigInt(kase.delay_epoch),
        commitmentFeeRate: BigInt(kase.fee_rate),
        cellDepsCount: kase.cell_deps_count,
        udtTypeScript: toScriptOrNull(kase.udt_type_script),
        liquidCapacityShannons: BigInt(kase.to_local) + BigInt(kase.to_remote),
        localReservedCkbShannons: BigInt(kase.local_reserved),
        remoteReservedCkbShannons: BigInt(kase.remote_reserved),
        commitmentLock: COMMITMENT_LOCK_TESTNET,
        lockLayout: toLockLayout(kase.lock_layout),
    };
}

// The unsigned tx a case carries, read the way a signing request's is.
export function toTransaction(vector: Record<string, unknown>): Transaction {
    return decodeTransaction({ value: vector, path: "transaction" });
}

// The close as its tx states it: each side's output found by its close script, not by its position.
export function toClosingTxInput(kase: ShutdownCaseVector, remote: RemotePubkeys): ClosingTxInput {
    if (kase.udt_type_script !== null) throw new Error(`the closing input is CKB only, and "${kase.name}" is a UDT case`);
    const localCloseScript = toScript(kase.local_close_script);
    const remoteCloseScript = toScript(kase.remote_close_script);
    const tx = toTransaction(kase.transaction);
    return {
        fundingOutPoint: toOutPoint(kase.funding_out_point),
        remoteFundingPubkey: hexToBytes(remote.funding_pubkey),
        localCloseScript,
        remoteCloseScript,
        localCapacityShannons: outputLockedBy(tx, localCloseScript, kase.name).capacityShannons,
        remoteCapacityShannons: outputLockedBy(tx, remoteCloseScript, kase.name).capacityShannons,
    };
}

function outputLockedBy(tx: Transaction, lock: Script, name: string): CellOutput {
    const found = tx.outputs.filter(
        (output) =>
            equalBytes(output.lock.codeHash, lock.codeHash) &&
            output.lock.hashType === lock.hashType &&
            equalBytes(output.lock.args, lock.args),
    );
    if (found.length !== 1 || found[0] === undefined)
        throw new Error(`the "${name}" close does not lock exactly one output with that script`);
    return found[0];
}

// The punishment output of a revocation case, rebuilt from its fields: the content carries its molecule bytes.
export function toRevocationOutput(kase: RevocationCaseVector): CellOutput {
    const reserved = BigInt(kase.local_reserved) + BigInt(kase.remote_reserved);
    const liquid = BigInt(kase.to_local) + BigInt(kase.to_remote);
    return {
        capacityShannons: (kase.udt_type_script === null ? liquid + reserved : reserved) - BigInt(kase.fee),
        lock: toScript(kase.payout_script),
        type: toScriptOrNull(kase.udt_type_script),
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
        liquidCapacityShannons: BigInt(kase.to_local) + BigInt(kase.to_remote),
        localReservedCkbShannons: BigInt(kase.local_reserved),
        remoteReservedCkbShannons: BigInt(kase.remote_reserved),
        commitmentLock: COMMITMENT_LOCK_TESTNET,
        lockLayout: toLockLayout(kase.lock_layout),
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
