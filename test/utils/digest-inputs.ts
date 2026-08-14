import { hexToBytes } from "@noble/hashes/utils.js";
import type { OutPoint, Script, ScriptHashType, SettlementTlc, TlcDirection, TlcHashAlgorithm } from "../../src/digest";
import type { OutPointVector, ScriptVector, TlcVector } from "./interop-vectors";

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
