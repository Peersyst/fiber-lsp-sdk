import { hexToBytes } from "@noble/hashes/utils.js";
import type { CellDep, Script } from "@peersyst/fiber-lsp-sdk";
import { SCRIPT_HASH_TYPES, UINT64_MAX } from "./agent.constants";
import { AgentRequestError } from "./agent.error";
import type { OpenChannelRequest, ScriptJson } from "./agent.types";
import { bareLowerHex, readExactJsonObject, readJsonList, readJsonObject } from "./agent.utils";
import { readCkbBytes, readCkbCellDep, readCkbHash, readCkbQuantity } from "./ckb-json";

const U128_MAX = (1n << 128n) - 1n;

// What `prepareChannelOpen` sends: a driver asking for other terms would get a channel it did not ask for.
const COMMITMENT_FEE_RATE = 0x3e8n;
const COMMITMENT_DELAY_EPOCH = 0x10000000001n;

const REFUSED_OPTIONALS = [
    "funding_udt_type_script",
    "funding_fee_rate",
    "tlc_expiry_delta",
    "tlc_min_value",
    "tlc_fee_proportional_millionths",
    "max_tlc_value_in_flight",
    "max_tlc_number_in_flight",
];

/**
 * Reads a CKB script in fiber's JSON, refusing unknown keys and hash types.
 * @param value The value read.
 * @param field Where it sits, for the refusal.
 * @returns The script, as sent.
 */
export function readScriptJson(value: unknown, field: string): ScriptJson {
    const script = readExactJsonObject(value, ["code_hash", "hash_type", "args"], field);
    const codeHash = readCkbHash(script.code_hash, `${field}.code_hash`);
    const { hash_type: hashType } = script;
    if (typeof hashType !== "string" || !SCRIPT_HASH_TYPES.some((known) => known === hashType)) {
        throw new AgentRequestError(`${field}.hash_type must be one of ${SCRIPT_HASH_TYPES.join(", ")}`);
    }
    return { code_hash: codeHash, hash_type: hashType, args: readCkbBytes(script.args, `${field}.args`) };
}

/**
 * Turns a script already read by `readScriptJson` into the SDK's.
 * @param json The script in fiber's JSON.
 * @returns The SDK's script.
 */
export function scriptFromJson(json: ScriptJson): Script {
    const hashType = SCRIPT_HASH_TYPES.find((known) => known === json.hash_type);
    if (hashType === undefined) throw new AgentRequestError(`hash_type ${json.hash_type} is not one the SDK signs for`);
    return { codeHash: hexToBytes(json.code_hash.slice(2)), hashType, args: hexToBytes(json.args.slice(2)) };
}

/**
 * Reads a uint in fiber's hex, bounded.
 * @param value The value read.
 * @param max The largest value the field holds.
 * @param field Where it sits, for the refusal.
 * @returns The value.
 */
function readUintHex(value: unknown, max: bigint, field: string): bigint {
    return BigInt(readCkbQuantity(value, max, field));
}

/**
 * Reads the cell deps of the funding lock, in CKB's JSON.
 * @param value The value read.
 * @param field Where it sits, for the refusal.
 * @returns The SDK's cell deps.
 */
function readCellDeps(value: unknown, field: string): CellDep[] {
    return readJsonList(value, field, readCkbCellDep).map(({ out_point: outPoint, dep_type: depType }) => ({
        outPoint: { txHash: hexToBytes(outPoint.tx_hash.slice(2)), index: Number(BigInt(outPoint.index)) },
        depType,
    }));
}

/**
 * Says whether two scripts read by `readScriptJson` are the same script, whatever the case of their hex.
 * @param a One script.
 * @param b The other.
 * @returns Whether they are equal.
 */
export function sameScriptJson(a: ScriptJson, b: ScriptJson): boolean {
    return (
        a.code_hash.toLowerCase() === b.code_hash.toLowerCase() &&
        a.hash_type === b.hash_type &&
        a.args.toLowerCase() === b.args.toLowerCase()
    );
}

/**
 * Reads a `POST /open-channel` body into `prepareChannelOpen`'s arguments, refusing what the SDK would not open as asked.
 * @param body The parsed body, `{ params }` in fiber's JSON.
 * @param lspPubkeyHex The LSP's node id, the only peer the SDK opens to.
 * @returns The amount, the lock and its cell deps.
 */
export function readOpenChannelRequest(body: unknown, lspPubkeyHex: string): OpenChannelRequest {
    const params = readJsonObject(readJsonObject(body, "body").params, "params");
    const { pubkey } = params;
    if (typeof pubkey !== "string" || bareLowerHex(pubkey) !== bareLowerHex(lspPubkeyHex)) {
        throw new AgentRequestError("params.pubkey must be the LSP's node id");
    }
    if (isPresent(params, "public") && params.public !== false) {
        throw new AgentRequestError("params.public must be false: the SDK opens private channels");
    }
    const amount = readUintHex(params.funding_amount, U128_MAX, "params.funding_amount");
    const shutdownScript = readScriptJson(params.shutdown_script, "params.shutdown_script");
    const userLockJson = readScriptJson(params.funding_lock_script, "params.funding_lock_script");
    if (!sameScriptJson(shutdownScript, userLockJson)) {
        throw new AgentRequestError("params.shutdown_script must be params.funding_lock_script: the SDK closes to the lock that funded");
    }
    assertOpenTerm(params, "commitment_fee_rate", COMMITMENT_FEE_RATE, "rate");
    assertOpenTerm(params, "commitment_delay_epoch", COMMITMENT_DELAY_EPOCH, "delay");
    for (const key of REFUSED_OPTIONALS) {
        if (isPresent(params, key)) throw new AgentRequestError(`params.${key} is not a term the SDK opens with`);
    }
    return {
        amountShannons: amount.toString(),
        userLock: scriptFromJson(userLockJson),
        userLockCellDeps: isPresent(params, "funding_lock_script_cell_deps")
            ? readCellDeps(params.funding_lock_script_cell_deps, "params.funding_lock_script_cell_deps")
            : undefined,
        userLockJson,
    };
}

/**
 * Refuses an optional u64 param present with another value than the one `prepareChannelOpen` sends.
 * @param params The params.
 * @param key The param.
 * @param expected The value the SDK sends.
 * @param noun What the param is, for the refusal.
 */
function assertOpenTerm(params: Record<string, unknown>, key: string, expected: bigint, noun: string): void {
    if (isPresent(params, key) && readUintHex(params[key], UINT64_MAX, `params.${key}`) !== expected) {
        throw new AgentRequestError(`params.${key} must be 0x${expected.toString(16)}, the ${noun} the SDK opens with`);
    }
}

/**
 * Says whether an optional param is present, reading null as absent as serde does.
 * @param params The params.
 * @param key The param.
 * @returns Whether it holds a value.
 */
function isPresent(params: Record<string, unknown>, key: string): boolean {
    return params[key] !== undefined && params[key] !== null;
}
