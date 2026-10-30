import { hexToBytes } from "@noble/hashes/utils.js";
import type { CellDep, DepType, Script } from "@peersyst/fiber-lsp-sdk";
import { SCRIPT_ARGS_PATTERN, SCRIPT_CODE_HASH_PATTERN, SCRIPT_HASH_TYPES } from "./agent.constants";
import { AgentRequestError } from "./agent.error";
import type { OpenChannelRequest, ScriptJson } from "./agent.types";
import { bareLowerHex, readJsonObject } from "./agent.utils";

const DEP_TYPES: readonly DepType[] = ["code", "dep_group"];

const UINT_HEX = /^0x(0|[1-9a-fA-F][0-9a-fA-F]*)$/;
const U128_MAX = (1n << 128n) - 1n;
const U64_MAX = (1n << 64n) - 1n;
const U32_MAX = 0xffffffffn;

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
 * Reads a CKB script in fiber's JSON, refusing a hash type the SDK cannot sign for and any key CKB's JSON does not have.
 * @param value The value read.
 * @param field Where it sits, for the refusal.
 * @returns The script, as sent.
 */
export function readScriptJson(value: unknown, field: string): ScriptJson {
    const script = readJsonObject(value, field);
    for (const key of Object.keys(script)) {
        if (key !== "code_hash" && key !== "hash_type" && key !== "args")
            throw new AgentRequestError(`${field}.${key} is not a script field`);
    }
    const { code_hash: codeHash, hash_type: hashType, args } = script;
    if (typeof codeHash !== "string" || !SCRIPT_CODE_HASH_PATTERN.test(codeHash)) {
        throw new AgentRequestError(`${field}.code_hash must be 32 bytes of 0x hex`);
    }
    if (typeof hashType !== "string" || !SCRIPT_HASH_TYPES.some((known) => known === hashType)) {
        throw new AgentRequestError(`${field}.hash_type must be one of ${SCRIPT_HASH_TYPES.join(", ")}`);
    }
    if (typeof args !== "string" || !SCRIPT_ARGS_PATTERN.test(args)) throw new AgentRequestError(`${field}.args must be 0x hex bytes`);
    return { code_hash: codeHash, hash_type: hashType, args };
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
    if (typeof value !== "string" || !UINT_HEX.test(value) || BigInt(value) > max) {
        throw new AgentRequestError(`${field} must be a 0x hex uint up to 0x${max.toString(16)}`);
    }
    return BigInt(value);
}

/**
 * Reads the cell deps of the funding lock, in CKB's JSON.
 * @param value The value read.
 * @param field Where it sits, for the refusal.
 * @returns The SDK's cell deps.
 */
function readCellDeps(value: unknown, field: string): CellDep[] {
    if (!Array.isArray(value)) throw new AgentRequestError(`${field} must be an array`);
    return value.map((entry: unknown, position): CellDep => {
        const at = `${field}[${position}]`;
        const dep = readJsonObject(entry, at);
        for (const key of Object.keys(dep)) {
            if (key !== "out_point" && key !== "dep_type") throw new AgentRequestError(`${at}.${key} is not a cell dep field`);
        }
        const outPoint = readJsonObject(dep.out_point, `${at}.out_point`);
        for (const key of Object.keys(outPoint)) {
            if (key !== "tx_hash" && key !== "index") throw new AgentRequestError(`${at}.out_point.${key} is not an out point field`);
        }
        const { tx_hash: txHash } = outPoint;
        if (typeof txHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
            throw new AgentRequestError(`${at}.out_point.tx_hash must be 32 bytes of 0x hex`);
        }
        const index = Number(readUintHex(outPoint.index, U32_MAX, `${at}.out_point.index`));
        const depType = DEP_TYPES.find((known) => known === dep.dep_type);
        if (depType === undefined) throw new AgentRequestError(`${at}.dep_type must be one of ${DEP_TYPES.join(", ")}`);
        return { outPoint: { txHash: hexToBytes(txHash.slice(2)), index }, depType };
    });
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
    if (isPresent(params, key) && readUintHex(params[key], U64_MAX, `params.${key}`) !== expected) {
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
