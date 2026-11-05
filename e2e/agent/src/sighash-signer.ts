import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { BYTES32_HEX_PATTERN } from "./agent.constants";
import type { AgentNodeFetch, ScriptJson } from "./agent.types";
import { readJsonObject } from "./agent.utils";
import { ckbBlake2b } from "./ckb-hash";
import { ckbTxHash, moleculeUint64, moleculeWitnessArgs, readWitnessArgs } from "./ckb-tx";
import type { CkbOutPointJson } from "./ckb-json";
import type { CkbTxJson, CkbWitnessArgs } from "./ckb-tx";
import { jsonRpcCall, NO_BEARER_TOKEN } from "./json-rpc";
import { readScriptJson, sameScriptJson } from "./open-params";

/**
 * The type hash of secp256k1-blake160 sighash-all, the default lock on every chain of CKB's standard genesis, the devnet's included.
 */
export const SIGHASH_ALL_LOCK_CODE_HASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";

export type CkbLockResolver = (outPoint: CkbOutPointJson) => Promise<ScriptJson>;

const BLAKE160_BYTES = 20;

const SIGNATURE_BYTES = 65;

/**
 * Reads a secp256k1 secret key from 0x hex.
 * @param hex The key.
 * @returns Its 32 bytes.
 */
function readPrivateKey(hex: string): Uint8Array {
    if (!BYTES32_HEX_PATTERN.test(hex)) throw new Error("the private key must be 32 bytes of 0x hex");
    const key = hexToBytes(hex.slice(2));
    if (!secp256k1.utils.isValidSecretKey(key)) throw new Error("the private key is not a valid secp256k1 secret key");
    return key;
}

/**
 * Builds the default lock a key owns: its compressed public key's blake160 as the args.
 * @param privateKey The key, as 0x hex.
 * @returns The lock.
 */
export function sighashAllLock(privateKey: string): ScriptJson {
    const args = ckbBlake2b(secp256k1.getPublicKey(readPrivateKey(privateKey), true)).subarray(0, BLAKE160_BYTES);
    return { code_hash: SIGHASH_ALL_LOCK_CODE_HASH, hash_type: "type", args: `0x${bytesToHex(args)}` };
}

/**
 * Reads a witness's bytes, an absent one as empty.
 * @param tx The transaction.
 * @param index The witness's index.
 * @returns Its bytes.
 */
function witnessBytes(tx: CkbTxJson, index: number): Uint8Array {
    const witness = tx.witnesses[index];
    return witness === undefined ? new Uint8Array() : hexToBytes(witness.slice(2));
}

/**
 * Reads the `WitnessArgs` at an index, an empty witness as one with no field set.
 * @param tx The transaction.
 * @param index The witness's index.
 * @returns Its fields.
 */
function witnessArgsAt(tx: CkbTxJson, index: number): CkbWitnessArgs {
    const bytes = witnessBytes(tx, index);
    return bytes.length === 0 ? { lock: null, inputType: null, outputType: null } : readWitnessArgs(bytes, `witnesses[${index}]`);
}

/**
 * Builds the message the default lock checks for a group of inputs, the first one's witness with its lock zeroed.
 * @param tx The transaction.
 * @param group The indices of the group's inputs, in order.
 * @returns The 32-byte message.
 */
export function sighashAllMessage(tx: CkbTxJson, group: readonly number[]): Uint8Array {
    const [first, ...rest] = group;
    if (first === undefined) throw new Error("a sighash group holds one input at least");
    const zeroed = moleculeWitnessArgs({ ...witnessArgsAt(tx, first), lock: new Uint8Array(SIGNATURE_BYTES) });
    const parts = [ckbTxHash(tx), moleculeUint64(zeroed.length), zeroed];
    const extra = Array.from({ length: Math.max(0, tx.witnesses.length - tx.inputs.length) }, (_, offset) => tx.inputs.length + offset);
    // The lock stops at the first group input with no witness, and every later one has none either.
    for (const index of [...rest.filter((input) => input < tx.witnesses.length), ...extra]) {
        const witness = witnessBytes(tx, index);
        parts.push(moleculeUint64(witness.length), witness);
    }
    return ckbBlake2b(concatBytes(...parts));
}

/**
 * Signs the inputs a key's default lock holds, as CKB's sighash-all wants: one signature in the group's first witness.
 * @param tx The transaction, its inputs unsigned.
 * @param privateKey The key, as 0x hex.
 * @param resolveLock Finds the lock of the cell an input spends.
 * @returns The transaction with the signed witness.
 */
export async function signSighashAllInputs(tx: CkbTxJson, privateKey: string, resolveLock: CkbLockResolver): Promise<CkbTxJson> {
    const key = readPrivateKey(privateKey);
    const lock = sighashAllLock(privateKey);
    const group: number[] = [];
    for (const [index, input] of tx.inputs.entries()) {
        if (sameScriptJson(await resolveLock(input.previous_output), lock)) group.push(index);
    }
    const [first] = group;
    const last = group.at(-1);
    if (first === undefined || last === undefined) throw new Error(`no input of the transaction is locked by ${lock.args}'s default lock`);
    // Every input of the group gets a witness, empty but the first's, so the message covers what the tx carries.
    const padded = {
        ...tx,
        witnesses: Array.from({ length: Math.max(tx.witnesses.length, last + 1) }, (_, index) => tx.witnesses[index] ?? "0x"),
    };
    // As rust-secp256k1's `sign_ecdsa_recoverable`: no prehash, RFC 6979 without extra entropy, low-S.
    const recovered = secp256k1.sign(sighashAllMessage(padded, group), key, {
        prehash: false,
        lowS: true,
        extraEntropy: false,
        format: "recovered",
    });
    // Noble writes the recovery id first; CKB's lock reads it after `r` and `s`.
    const signature = concatBytes(recovered.subarray(1), recovered.subarray(0, 1));
    const witnesses = [...padded.witnesses];
    witnesses[first] = `0x${bytesToHex(moleculeWitnessArgs({ ...witnessArgsAt(padded, first), lock: signature }))}`;
    return { ...padded, witnesses };
}

/**
 * Finds the lock of a live cell through CKB's `get_live_cell`, refusing a cell that is not live.
 * @param ckbRpcUrl The CKB RPC.
 * @param fetch The fetch.
 * @returns The resolver.
 */
export function liveCellLockResolver(ckbRpcUrl: string, fetch: AgentNodeFetch): CkbLockResolver {
    return async (outPoint) => {
        const where = `get_live_cell ${outPoint.tx_hash}:${outPoint.index}`;
        const result = readJsonObject(await jsonRpcCall(ckbRpcUrl, fetch, "get_live_cell", [outPoint, false], NO_BEARER_TOKEN), where);
        if (result.status !== "live") throw new Error(`${where} is ${JSON.stringify(result.status)}, not live`);
        const cell = readJsonObject(result.cell, `${where}.cell`);
        return readScriptJson(readJsonObject(cell.output, `${where}.cell.output`).lock, `${where}.cell.output.lock`);
    };
}
