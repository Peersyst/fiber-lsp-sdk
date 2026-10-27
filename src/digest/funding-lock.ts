import { bytesToHex } from "@noble/hashes/utils.js";
import { blake160, ckbBlake2b } from "../common";
import { aggregateXOnlyPubkey, sortDistinctPubkeys } from "./utils";

/**
 * Port of the args of fiber's `get_funding_lock_script`: the blake160 of the x-only aggregate of the funding keys, sorted.
 * @param fundingPubkeyA One party's compressed funding pubkey, either side.
 * @param fundingPubkeyB The other party's compressed funding pubkey.
 * @returns The 20-byte args of the channel's funding lock.
 */
export function fundingLockArgs(fundingPubkeyA: Uint8Array, fundingPubkeyB: Uint8Array): Uint8Array {
    return blake160(aggregateXOnlyPubkey(sortDistinctPubkeys("fundingPubkeyA", fundingPubkeyA, "fundingPubkeyB", fundingPubkeyB)));
}

/**
 * Port of fiber's `derive_channel_id_from_tlc_keys`: the CKB blake2b-256 of the two TLC base keys, sorted and concatenated.
 * @param localTlcBasePubkey The device's TLC base pubkey.
 * @param remoteSettlementKey The peer's TLC base pubkey, the opening context's `remote_settlement_key`.
 * @returns The channel id as fiber's JSON writes it, `0x`-prefixed lowercase hex.
 */
export function tenantChannelId(localTlcBasePubkey: Uint8Array, remoteSettlementKey: Uint8Array): string {
    const sortedKeys = sortDistinctPubkeys("localTlcBasePubkey", localTlcBasePubkey, "remoteSettlementKey", remoteSettlementKey);
    return `0x${bytesToHex(ckbBlake2b(...sortedKeys))}`;
}
