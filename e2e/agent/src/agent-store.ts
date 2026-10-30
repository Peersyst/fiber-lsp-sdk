import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type {
    AgentChannel,
    AgentState,
    CloseAuthorization,
    InvoiceAuthorization,
    ScriptJson,
    WatchtowerAuthorization,
} from "./agent.types";
import { writeFileAtomically } from "./file-storage";
import { HASH_ALGORITHMS, SCRIPT_ARGS_PATTERN, SCRIPT_CODE_HASH_PATTERN, SCRIPT_HASH_TYPES } from "./agent.constants";

export const MASTER_SEED_FILE = "master-seed";

export const AGENT_STATE_FILE = "agent.json";

const MASTER_SEED_LENGTH = 32;

const HASH256_PATTERN = /^0x[0-9a-f]{64}$/;

const NODE_ID_PATTERN = /^[0-9a-f]{66}$/;

// The fee rates and the fee cap, written as `readAuthorization` reads them.
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/;

type FieldReader = (key: string) => unknown;

/**
 * Builds the refusal of a malformed `agent.json` field.
 * @param path Where the field sits, from the root.
 * @param problem What is wrong with it.
 * @returns The error to throw.
 */
function malformed(path: string, problem: string): Error {
    return new Error(`${AGENT_STATE_FILE}: ${path} ${problem}`);
}

/**
 * Reads a value as an object holding exactly the given keys.
 * @param value The value.
 * @param path Where it sits, from the root.
 * @param keys The keys it must hold, and no others.
 * @returns A reader of its fields.
 */
function readExactObject(value: unknown, path: string, keys: readonly string[]): FieldReader {
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw malformed(path, "must be an object");
    const record = value as Record<string, unknown>;
    for (const key of Object.keys(record)) if (!keys.includes(key)) throw malformed(`${path}.${key}`, "is not a known field");
    for (const key of keys) if (!Object.hasOwn(record, key)) throw malformed(`${path}.${key}`, "is missing");
    return (key) => record[key];
}

/**
 * Reads a value as a string matching a pattern.
 * @param value The value.
 * @param path Where it sits, from the root.
 * @param pattern The pattern it must match.
 * @param shape What the pattern means, for the refusal.
 * @returns The string.
 */
function readPattern(value: unknown, path: string, pattern: RegExp, shape: string): string {
    if (typeof value !== "string" || !pattern.test(value)) throw malformed(path, `must be ${shape}`);
    return value;
}

/**
 * Reads a value as a 32-byte id in `0x`-prefixed lowercase hex.
 * @param value The value.
 * @param path Where it sits, from the root.
 * @returns The id.
 */
function readHash256(value: unknown, path: string): string {
    return readPattern(value, path, HASH256_PATTERN, "32 bytes of 0x-prefixed lowercase hex");
}

/**
 * Reads a value as one of a list of literals.
 * @param value The value.
 * @param path Where it sits, from the root.
 * @param literals The values it may take.
 * @returns The literal.
 */
function readLiteral<T extends string>(value: unknown, path: string, literals: readonly T[]): T {
    const match = literals.find((literal) => literal === value);
    if (match === undefined) throw malformed(path, `must be one of ${literals.map((literal) => JSON.stringify(literal)).join(", ")}`);
    return match;
}

/**
 * Reads a value as a CKB script in fiber's JSON.
 * @param value The value.
 * @param path Where it sits, from the root.
 * @returns The script.
 */
function readScript(value: unknown, path: string): ScriptJson {
    const at = readExactObject(value, path, ["code_hash", "hash_type", "args"]);
    return {
        code_hash: readPattern(at("code_hash"), `${path}.code_hash`, SCRIPT_CODE_HASH_PATTERN, "32 bytes of 0x-prefixed hex"),
        hash_type: readLiteral(at("hash_type"), `${path}.hash_type`, SCRIPT_HASH_TYPES),
        args: readPattern(at("args"), `${path}.args`, SCRIPT_ARGS_PATTERN, "whole bytes of 0x-prefixed hex"),
    };
}

/**
 * Reads a value as an object keyed by 32-byte ids, each entry read by a reader.
 * @param value The value.
 * @param path Where it sits, from the root.
 * @param readEntry The reader of one entry, given its key.
 * @returns The record.
 */
function readIdRecord<T>(value: unknown, path: string, readEntry: (entry: unknown, path: string, key: string) => T): Record<string, T> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw malformed(path, "must be an object");
    const record: Record<string, T> = {};
    for (const [key, entry] of Object.entries(value)) {
        const entryPath = `${path}[${JSON.stringify(key)}]`;
        if (!HASH256_PATTERN.test(key)) throw malformed(entryPath, "must be keyed by 32 bytes of 0x-prefixed lowercase hex");
        record[key] = readEntry(entry, entryPath, key);
    }
    return record;
}

/**
 * Reads a value as a channel the agent opened.
 * @param value The value.
 * @param path Where it sits, from the root.
 * @returns The channel.
 */
function readChannel(value: unknown, path: string): AgentChannel {
    const at = readExactObject(value, path, ["localScript", "remoteScript"]);
    return {
        localScript: readScript(at("localScript"), `${path}.localScript`),
        remoteScript: readScript(at("remoteScript"), `${path}.remoteScript`),
    };
}

/**
 * Reads a value as an invoice authorization, filed under its payment hash.
 * @param value The value.
 * @param path Where it sits, from the root.
 * @param key The payment hash it is filed under.
 * @returns The authorization.
 */
function readInvoice(value: unknown, path: string, key: string): InvoiceAuthorization {
    const at = readExactObject(value, path, ["type", "channelId", "preimage", "paymentHash", "hashAlgorithm"]);
    const invoice: InvoiceAuthorization = {
        type: readLiteral(at("type"), `${path}.type`, ["Invoice"]),
        channelId: readHash256(at("channelId"), `${path}.channelId`),
        preimage: readHash256(at("preimage"), `${path}.preimage`),
        paymentHash: readHash256(at("paymentHash"), `${path}.paymentHash`),
        hashAlgorithm: readLiteral(at("hashAlgorithm"), `${path}.hashAlgorithm`, HASH_ALGORITHMS),
    };
    if (invoice.paymentHash !== key) throw malformed(`${path}.paymentHash`, "must be the key it is filed under");
    return invoice;
}

/**
 * Reads a value as a close authorization, filed under its channel.
 * @param value The value.
 * @param path Where it sits, from the root.
 * @param key The channel id it is filed under.
 * @returns The authorization.
 */
function readClose(value: unknown, path: string, key: string): CloseAuthorization {
    const at = readExactObject(value, path, ["type", "channelId", "localScript", "remoteScript", "localFeeRate", "remoteFeeRate"]);
    const close: CloseAuthorization = {
        type: readLiteral(at("type"), `${path}.type`, ["Close"]),
        channelId: readHash256(at("channelId"), `${path}.channelId`),
        localScript: readScript(at("localScript"), `${path}.localScript`),
        remoteScript: readScript(at("remoteScript"), `${path}.remoteScript`),
        localFeeRate: readPattern(at("localFeeRate"), `${path}.localFeeRate`, DECIMAL_PATTERN, "a decimal integer string"),
        remoteFeeRate: readPattern(at("remoteFeeRate"), `${path}.remoteFeeRate`, DECIMAL_PATTERN, "a decimal integer string"),
    };
    if (close.channelId !== key) throw malformed(`${path}.channelId`, "must be the key it is filed under");
    return close;
}

/**
 * Reads a value as the watchtower approval, or its absence.
 * @param value The value.
 * @param path Where it sits, from the root.
 * @returns The approval, or `null`.
 */
function readWatchtower(value: unknown, path: string): WatchtowerAuthorization | null {
    if (value === null) return null;
    const at = readExactObject(value, path, ["type", "channelId", "destination", "maxFeeShannons"]);
    return {
        type: readLiteral(at("type"), `${path}.type`, ["Watchtower"]),
        channelId: readHash256(at("channelId"), `${path}.channelId`),
        destination: readScript(at("destination"), `${path}.destination`),
        maxFeeShannons: readPattern(at("maxFeeShannons"), `${path}.maxFeeShannons`, DECIMAL_PATTERN, "a decimal integer string"),
    };
}

/**
 * Reads a value as a non-empty string, or `null`.
 * @param value The value.
 * @param path Where it sits, from the root.
 * @returns The string, or `null`.
 */
function readTokenOrNull(value: unknown, path: string): string | null {
    if (value === null) return null;
    if (typeof value !== "string" || value === "") throw malformed(path, "must be a non-empty string or null");
    return value;
}

/**
 * Reads the device's master seed from the store, creating a random one, owner-readable only, on first run.
 * @param storeDir The agent's store, created when absent.
 * @returns The 32-byte seed.
 */
export function loadOrCreateMasterSeed(storeDir: string): Uint8Array {
    mkdirSync(storeDir, { recursive: true });
    const path = join(storeDir, MASTER_SEED_FILE);
    if (!existsSync(path)) writeFileAtomically(path, randomBytes(MASTER_SEED_LENGTH));
    const seed = readFileSync(path);
    if (seed.length !== MASTER_SEED_LENGTH) throw new Error(`${path} must hold ${MASTER_SEED_LENGTH} bytes, found ${seed.length}`);
    return new Uint8Array(seed);
}

/**
 * Reads what the agent persists beside the SDK's store, refusing a malformed file field by field.
 * @param storeDir The agent's store.
 * @returns The state, empty when the file does not exist yet.
 */
export function readAgentState(storeDir: string): AgentState {
    const path = join(storeDir, AGENT_STATE_FILE);
    if (!existsSync(path)) return { tenantToken: null, lspPubkey: null, channels: {}, invoices: {}, closes: {}, watchtower: null };
    let parsed: unknown;
    try {
        parsed = JSON.parse(readFileSync(path, "utf8"));
    } catch {
        throw new Error(`${AGENT_STATE_FILE} is not JSON`);
    }
    const at = readExactObject(parsed, "state", ["tenantToken", "lspPubkey", "channels", "invoices", "closes", "watchtower"]);
    const lspPubkey = at("lspPubkey");
    return {
        tenantToken: readTokenOrNull(at("tenantToken"), "state.tenantToken"),
        lspPubkey:
            lspPubkey === null
                ? null
                : readPattern(lspPubkey, "state.lspPubkey", NODE_ID_PATTERN, "33 bytes of lowercase hex without 0x, or null"),
        channels: readIdRecord(at("channels"), "state.channels", readChannel),
        invoices: readIdRecord(at("invoices"), "state.invoices", readInvoice),
        closes: readIdRecord(at("closes"), "state.closes", readClose),
        watchtower: readWatchtower(at("watchtower"), "state.watchtower"),
    };
}

/**
 * Replaces what the agent persists beside the SDK's store, in one step.
 * @param storeDir The agent's store, created when absent.
 * @param state The state to keep.
 */
export function writeAgentState(storeDir: string, state: AgentState): void {
    mkdirSync(storeDir, { recursive: true });
    writeFileAtomically(join(storeDir, AGENT_STATE_FILE), `${JSON.stringify(state, null, 4)}\n`);
}
