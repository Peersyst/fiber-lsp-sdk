import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { NONCE_CONTEXTS } from "../../src/derivation/derivation.constants.js";
import type { NonceContext } from "../../src/derivation/derivation.types.js";

export const CHANNEL_KEY_FIELDS = [
    "funding_key",
    "tlc_base_key",
    "musig2_base_nonce",
    "commitment_seed",
    "funding_pubkey",
    "tlc_base_pubkey",
] as const;

export const COMMITMENT_FIELDS = ["secret", "point", "tlc_privkey", "tlc_pubkey", "musig2_nonce_seckey"] as const;

export type ChannelKeysVector = Record<(typeof CHANNEL_KEY_FIELDS)[number], string>;

export type CommitmentVector = Record<(typeof COMMITMENT_FIELDS)[number], string> & { n: number };

export type HashVector = { label: string; chunks: string[]; digest: string };

export type NonceSeedVector = { commitment_number: number; context: NonceContext; seed: string };

export type Vectors = {
    scheme_version: number;
    fiber_ref: string;
    hashes: HashVector[];
    fiber_scheme: { channel_seed: string; channel_keys: ChannelKeysVector; commitments: CommitmentVector[] };
    sdk_scheme: {
        master_seed: string;
        wallet_identity_key: string;
        channel_seeds: { channel_index: number; seed: string }[];
        channel: { channel_index: number; seed: string; channel_keys: ChannelKeysVector; nonce_seeds: NonceSeedVector[] };
    };
};

function asRecord(value: unknown, path: string): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${path} must be an object`);
    return value as Record<string, unknown>;
}

function asString(value: unknown, path: string): string {
    if (typeof value !== "string") throw new Error(`${path} must be a string`);
    return value;
}

function asNumber(value: unknown, path: string): number {
    if (typeof value !== "number") throw new Error(`${path} must be a number`);
    return value;
}

function asArray(value: unknown, path: string): unknown[] {
    if (!Array.isArray(value)) throw new Error(`${path} must be an array`);
    return value;
}

function asStringFields<Field extends string>(value: unknown, path: string, fields: readonly Field[]): Record<Field, string> {
    const record = asRecord(value, path);
    const parsed = {} as Record<Field, string>;
    for (const field of fields) parsed[field] = asString(record[field], `${path}.${field}`);
    return parsed;
}

function asNonceContext(value: unknown, path: string): NonceContext {
    const raw = asString(value, path);
    const context = NONCE_CONTEXTS.find((known) => known === raw);
    if (context === undefined) throw new Error(`${path} is not a known nonce context: ${raw}`);
    return context;
}

/**
 * Validates parsed JSON against the shape the suite expects.
 * @param value The raw parsed JSON.
 * @returns The typed vectors.
 */
export function parseVectors(value: unknown): Vectors {
    const root = asRecord(value, "vectors");
    const fiberScheme = asRecord(root.fiber_scheme, "fiber_scheme");
    const sdkScheme = asRecord(root.sdk_scheme, "sdk_scheme");
    const sdkChannel = asRecord(sdkScheme.channel, "sdk_scheme.channel");

    return {
        scheme_version: asNumber(root.scheme_version, "scheme_version"),
        fiber_ref: asString(root.fiber_ref, "fiber_ref"),
        hashes: asArray(root.hashes, "hashes").map((entry, index) => {
            const path = `hashes[${index}]`;
            const record = asRecord(entry, path);
            return {
                label: asString(record.label, `${path}.label`),
                chunks: asArray(record.chunks, `${path}.chunks`).map((chunk, at) => asString(chunk, `${path}.chunks[${at}]`)),
                digest: asString(record.digest, `${path}.digest`),
            };
        }),
        fiber_scheme: {
            channel_seed: asString(fiberScheme.channel_seed, "fiber_scheme.channel_seed"),
            channel_keys: asStringFields(fiberScheme.channel_keys, "fiber_scheme.channel_keys", CHANNEL_KEY_FIELDS),
            commitments: asArray(fiberScheme.commitments, "fiber_scheme.commitments").map((entry, index) => {
                const path = `fiber_scheme.commitments[${index}]`;
                return { n: asNumber(asRecord(entry, path).n, `${path}.n`), ...asStringFields(entry, path, COMMITMENT_FIELDS) };
            }),
        },
        sdk_scheme: {
            master_seed: asString(sdkScheme.master_seed, "sdk_scheme.master_seed"),
            wallet_identity_key: asString(sdkScheme.wallet_identity_key, "sdk_scheme.wallet_identity_key"),
            channel_seeds: asArray(sdkScheme.channel_seeds, "sdk_scheme.channel_seeds").map((entry, index) => {
                const path = `sdk_scheme.channel_seeds[${index}]`;
                const record = asRecord(entry, path);
                return {
                    channel_index: asNumber(record.channel_index, `${path}.channel_index`),
                    seed: asString(record.seed, `${path}.seed`),
                };
            }),
            channel: {
                channel_index: asNumber(sdkChannel.channel_index, "sdk_scheme.channel.channel_index"),
                seed: asString(sdkChannel.seed, "sdk_scheme.channel.seed"),
                channel_keys: asStringFields(sdkChannel.channel_keys, "sdk_scheme.channel.channel_keys", CHANNEL_KEY_FIELDS),
                nonce_seeds: asArray(sdkChannel.nonce_seeds, "sdk_scheme.channel.nonce_seeds").map((entry, index) => {
                    const path = `sdk_scheme.channel.nonce_seeds[${index}]`;
                    const record = asRecord(entry, path);
                    return {
                        commitment_number: asNumber(record.commitment_number, `${path}.commitment_number`),
                        context: asNonceContext(record.context, `${path}.context`),
                        seed: asString(record.seed, `${path}.seed`),
                    };
                }),
            },
        },
    };
}

/**
 * Reads and validates the committed vector file.
 * @returns The typed vectors.
 */
export function loadInteropVectors(): Vectors {
    const path = fileURLToPath(new URL("../../interop/vectors/vectors.json", import.meta.url));
    const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
    return parseVectors(raw);
}
