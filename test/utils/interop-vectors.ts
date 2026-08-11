import { readFileSync } from "node:fs";
import { join } from "node:path";
import { NONCE_CONTEXTS } from "../../src/derivation/derivation.constants";
import type { NonceContext } from "../../src/derivation/derivation.types";

export const CHANNEL_KEY_FIELDS = [
    "funding_key",
    "tlc_base_key",
    "musig2_base_nonce",
    "commitment_seed",
    "funding_pubkey",
    "tlc_base_pubkey",
] as const;

export const COMMITMENT_FIELDS = ["secret", "point", "tlc_privkey", "tlc_pubkey", "musig2_nonce_seckey"] as const;

export const MUSIG_FIELDS = ["remote_seckey", "remote_pubkey", "remote_pubnonce", "message"] as const;

export type ChannelKeysVector = Record<(typeof CHANNEL_KEY_FIELDS)[number], string>;

export type CommitmentVector = Record<(typeof COMMITMENT_FIELDS)[number], string> & { n: number };

export type MusigVector = Record<(typeof MUSIG_FIELDS)[number], string>;

export type HashVector = { label: string; chunks: string[]; digest: string };

export type NonceSeedVector = { commitment_number: number; context: NonceContext; seed: string };

export type MasterSeedVector = { account_index: number; path: string; master_seed: string };

export type ScriptVector = { code_hash: string; hash_type: string; args: string };

export type OutPointVector = { tx_hash: string; index: number };

export type TlcVector = {
    id: number;
    direction: string;
    hash_algorithm: string;
    amount: string;
    payment_hash: string;
    expiry_ms: string;
    created_at_remote_commitment_number: number;
    remote_commitment_point: string;
};

export type CommitmentCaseVector = {
    name: string;
    for_remote: boolean;
    funding_out_point: OutPointVector;
    commitment_number: number;
    delay_epoch: string;
    fee_rate: string;
    cell_deps_count: number;
    udt_type_script: ScriptVector | null;
    to_local: string;
    to_remote: string;
    settlement_local: string;
    settlement_remote: string;
    local_reserved: string;
    remote_reserved: string;
    tlcs: TlcVector[];
    settlement_witness: string;
    lock_args: string;
    tx_size: number;
    fee: string;
    digest: string;
};

export type ShutdownCaseVector = {
    name: string;
    funding_out_point: OutPointVector;
    local_close_script: ScriptVector;
    remote_close_script: ScriptVector;
    local_fee_rate: string;
    remote_fee_rate: string;
    cell_deps_count: number;
    udt_type_script: ScriptVector | null;
    to_local: string;
    to_remote: string;
    local_reserved: string;
    remote_reserved: string;
    tx_size: number;
    local_fee: string;
    remote_fee: string;
    digest: string;
};

export type RevocationCaseVector = {
    name: string;
    for_remote: boolean;
    revoked_commitment_number: number;
    payout_script: ScriptVector;
    delay_epoch: string;
    fee_rate: string;
    cell_deps_count: number;
    udt_type_script: ScriptVector | null;
    to_local: string;
    to_remote: string;
    local_reserved: string;
    remote_reserved: string;
    fee: string;
    digest: string;
};

export type AnnouncementCaseVector = {
    name: string;
    chain_hash: string;
    funding_out_point: OutPointVector;
    node_ids: [string, string];
    capacity: string;
    udt_type_script: ScriptVector | null;
    digest: string;
};

export type DigestVectors = {
    commitment_lock: ScriptVector;
    remote: { seed: string; funding_pubkey: string; tlc_base_pubkey: string };
    commitment_cases: CommitmentCaseVector[];
    shutdown_cases: ShutdownCaseVector[];
    revocation_cases: RevocationCaseVector[];
    announcement_cases: AnnouncementCaseVector[];
};

export type Vectors = {
    scheme_version: number;
    fiber_ref: string;
    hashes: HashVector[];
    fiber_scheme: { channel_seed: string; channel_keys: ChannelKeysVector; commitments: CommitmentVector[] };
    sdk_scheme: {
        bip39_seed: string;
        master_seeds: MasterSeedVector[];
        master_seed: string;
        wallet_identity_key: string;
        channel_seeds: { channel_index: number; seed: string }[];
        channel: { channel_index: number; seed: string; channel_keys: ChannelKeysVector; nonce_seeds: NonceSeedVector[] };
    };
    musig: MusigVector;
    digest: DigestVectors;
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

function asBoolean(value: unknown, path: string): boolean {
    if (typeof value !== "boolean") throw new Error(`${path} must be a boolean`);
    return value;
}

function asScript(value: unknown, path: string): ScriptVector {
    return asStringFields(value, path, ["code_hash", "hash_type", "args"] as const);
}

function asScriptOrNull(value: unknown, path: string): ScriptVector | null {
    return value === null || value === undefined ? null : asScript(value, path);
}

function asOutPoint(value: unknown, path: string): OutPointVector {
    const record = asRecord(value, path);
    return { tx_hash: asString(record.tx_hash, `${path}.tx_hash`), index: asNumber(record.index, `${path}.index`) };
}

function asTlc(value: unknown, path: string): TlcVector {
    const record = asRecord(value, path);
    return {
        id: asNumber(record.id, `${path}.id`),
        created_at_remote_commitment_number: asNumber(
            record.created_at_remote_commitment_number,
            `${path}.created_at_remote_commitment_number`,
        ),
        ...asStringFields(record, path, [
            "direction",
            "hash_algorithm",
            "amount",
            "payment_hash",
            "expiry_ms",
            "remote_commitment_point",
        ] as const),
    };
}

function asDigestVectors(value: unknown): DigestVectors {
    const root = asRecord(value, "digest");
    return {
        commitment_lock: asScript(root.commitment_lock, "digest.commitment_lock"),
        remote: asStringFields(root.remote, "digest.remote", ["seed", "funding_pubkey", "tlc_base_pubkey"] as const),
        commitment_cases: asArray(root.commitment_cases, "digest.commitment_cases").map((entry, index) => {
            const path = `digest.commitment_cases[${index}]`;
            const record = asRecord(entry, path);
            return {
                for_remote: asBoolean(record.for_remote, `${path}.for_remote`),
                funding_out_point: asOutPoint(record.funding_out_point, `${path}.funding_out_point`),
                commitment_number: asNumber(record.commitment_number, `${path}.commitment_number`),
                cell_deps_count: asNumber(record.cell_deps_count, `${path}.cell_deps_count`),
                udt_type_script: asScriptOrNull(record.udt_type_script, `${path}.udt_type_script`),
                tlcs: asArray(record.tlcs, `${path}.tlcs`).map((tlc, at) => asTlc(tlc, `${path}.tlcs[${at}]`)),
                tx_size: asNumber(record.tx_size, `${path}.tx_size`),
                ...asStringFields(record, path, [
                    "name",
                    "delay_epoch",
                    "fee_rate",
                    "to_local",
                    "to_remote",
                    "settlement_local",
                    "settlement_remote",
                    "local_reserved",
                    "remote_reserved",
                    "settlement_witness",
                    "lock_args",
                    "fee",
                    "digest",
                ] as const),
            };
        }),
        shutdown_cases: asArray(root.shutdown_cases, "digest.shutdown_cases").map((entry, index) => {
            const path = `digest.shutdown_cases[${index}]`;
            const record = asRecord(entry, path);
            return {
                funding_out_point: asOutPoint(record.funding_out_point, `${path}.funding_out_point`),
                local_close_script: asScript(record.local_close_script, `${path}.local_close_script`),
                remote_close_script: asScript(record.remote_close_script, `${path}.remote_close_script`),
                cell_deps_count: asNumber(record.cell_deps_count, `${path}.cell_deps_count`),
                udt_type_script: asScriptOrNull(record.udt_type_script, `${path}.udt_type_script`),
                tx_size: asNumber(record.tx_size, `${path}.tx_size`),
                ...asStringFields(record, path, [
                    "name",
                    "local_fee_rate",
                    "remote_fee_rate",
                    "to_local",
                    "to_remote",
                    "local_reserved",
                    "remote_reserved",
                    "local_fee",
                    "remote_fee",
                    "digest",
                ] as const),
            };
        }),
        revocation_cases: asArray(root.revocation_cases, "digest.revocation_cases").map((entry, index) => {
            const path = `digest.revocation_cases[${index}]`;
            const record = asRecord(entry, path);
            return {
                for_remote: asBoolean(record.for_remote, `${path}.for_remote`),
                revoked_commitment_number: asNumber(record.revoked_commitment_number, `${path}.revoked_commitment_number`),
                payout_script: asScript(record.payout_script, `${path}.payout_script`),
                cell_deps_count: asNumber(record.cell_deps_count, `${path}.cell_deps_count`),
                udt_type_script: asScriptOrNull(record.udt_type_script, `${path}.udt_type_script`),
                ...asStringFields(record, path, [
                    "name",
                    "delay_epoch",
                    "fee_rate",
                    "to_local",
                    "to_remote",
                    "local_reserved",
                    "remote_reserved",
                    "fee",
                    "digest",
                ] as const),
            };
        }),
        announcement_cases: asArray(root.announcement_cases, "digest.announcement_cases").map((entry, index) => {
            const path = `digest.announcement_cases[${index}]`;
            const record = asRecord(entry, path);
            const nodeIds = asArray(record.node_ids, `${path}.node_ids`).map((id, at) => asString(id, `${path}.node_ids[${at}]`));
            if (nodeIds.length !== 2) throw new Error(`${path}.node_ids must have exactly two entries`);
            return {
                funding_out_point: asOutPoint(record.funding_out_point, `${path}.funding_out_point`),
                node_ids: [nodeIds[0] as string, nodeIds[1] as string],
                udt_type_script: asScriptOrNull(record.udt_type_script, `${path}.udt_type_script`),
                ...asStringFields(record, path, ["name", "chain_hash", "capacity", "digest"] as const),
            };
        }),
    };
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
            bip39_seed: asString(sdkScheme.bip39_seed, "sdk_scheme.bip39_seed"),
            master_seeds: asArray(sdkScheme.master_seeds, "sdk_scheme.master_seeds").map((entry, index) => {
                const path = `sdk_scheme.master_seeds[${index}]`;
                const record = asRecord(entry, path);
                return {
                    account_index: asNumber(record.account_index, `${path}.account_index`),
                    path: asString(record.path, `${path}.path`),
                    master_seed: asString(record.master_seed, `${path}.master_seed`),
                };
            }),
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
        musig: asStringFields(root.musig, "musig", MUSIG_FIELDS),
        digest: asDigestVectors(root.digest),
    };
}

/**
 * Reads and validates the committed vector file.
 * @returns The typed vectors.
 */
export function loadInteropVectors(): Vectors {
    const path = join(__dirname, "../../interop/vectors/vectors.json");
    const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
    return parseVectors(raw);
}
