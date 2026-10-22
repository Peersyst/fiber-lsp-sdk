import { readFileSync } from "node:fs";
import { join } from "node:path";
import { hexToBytes } from "@noble/hashes/utils.js";
import { NONCE_CONTEXTS } from "../../src/derivation/derivation.constants";
import type { NonceContext } from "../../src/derivation/derivation.types";
import type { SigningSettlement } from "../../src/digest/digest.types";
import { asArray, asBoolean, asNullable, asNumber, asRecord, asString, asStringFields } from "./json-shape";

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

export const TENANT_REGISTRY_FIELDS = [
    "root_signer_secret_from",
    "lsp_node_secret",
    "lsp_node_id",
    "root_signer_pubkey",
    "nonce",
    "payload",
    "digest",
    "signature",
    "tenant_id",
] as const;

export type ChannelKeysVector = Record<(typeof CHANNEL_KEY_FIELDS)[number], string>;

export type CommitmentVector = Record<(typeof COMMITMENT_FIELDS)[number], string> & { n: number };

export type MusigVector = Record<(typeof MUSIG_FIELDS)[number], string>;

export type TenantRegistryVector = Record<(typeof TENANT_REGISTRY_FIELDS)[number], string>;

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
    local_key_commitment_number: number;
    remote_tlc_pubkey: string;
};

export type CommitmentCaseVector = {
    name: string;
    for_remote: boolean;
    lock_layout: string;
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
    transaction: Record<string, unknown>;
    settlement: SettlementVector;
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
    transaction: Record<string, unknown>;
    digest: string;
};

export type RevocationCaseVector = {
    name: string;
    for_remote: boolean;
    lock_layout: string;
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
    output: string;
    output_data: string;
    commitment_lock_script_args: string;
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

export type ReserveCaseVector = {
    name: string;
    shutdown_script: ScriptVector;
    reserved: { legacy: string; full_payment_hash: string };
};

export type DigestVectors = {
    commitment_lock: ScriptVector;
    remote: { seed: string; funding_pubkey: string; tlc_base_pubkey: string };
    commitment_cases: CommitmentCaseVector[];
    shutdown_cases: ShutdownCaseVector[];
    revocation_cases: RevocationCaseVector[];
    announcement_cases: AnnouncementCaseVector[];
    reserve_cases: ReserveCaseVector[];
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
    tenant_registry: TenantRegistryVector;
};

// fiber's `SigningSettlementTlc` as its JSON writes it: hex integers, a 0x-prefixed hash, bare-hex pubkeys.
export type SettlementTlcVector = {
    tlc_id: string;
    local_key_commitment_number: string;
    inbound: boolean;
    payment_hash: string;
    payment_amount: string;
    hash_algorithm: string;
    expiry: string;
    local_key_pubkey: string;
    remote_key: string;
};

export type SettlementVector = {
    local_amount: string;
    remote_amount: string;
    local_settlement_pubkey: string;
    remote_settlement_pubkey: string;
    for_remote: boolean;
    tlcs: SettlementTlcVector[];
};

export function asScript(value: unknown, path: string): ScriptVector {
    return asStringFields(value, path, ["code_hash", "hash_type", "args"] as const);
}

export function asOutPoint(value: unknown, path: string): OutPointVector {
    const record = asRecord(value, path);
    return { tx_hash: asString(record.tx_hash, `${path}.tx_hash`), index: asNumber(record.index, `${path}.index`) };
}

export function asTlc(value: unknown, path: string): TlcVector {
    const record = asRecord(value, path);
    return {
        id: asNumber(record.id, `${path}.id`),
        local_key_commitment_number: asNumber(record.local_key_commitment_number, `${path}.local_key_commitment_number`),
        ...asStringFields(record, path, [
            "direction",
            "hash_algorithm",
            "amount",
            "payment_hash",
            "expiry_ms",
            "remote_tlc_pubkey",
        ] as const),
    };
}

function asSettlement(value: unknown, path: string): SettlementVector {
    const record = asRecord(value, path);
    return {
        for_remote: asBoolean(record.for_remote, `${path}.for_remote`),
        tlcs: asArray(record.tlcs, `${path}.tlcs`).map((entry, index) => {
            const at = `${path}.tlcs[${index}]`;
            return {
                inbound: asBoolean(asRecord(entry, at).inbound, `${at}.inbound`),
                ...asStringFields(entry, at, [
                    "tlc_id",
                    "local_key_commitment_number",
                    "payment_hash",
                    "payment_amount",
                    "hash_algorithm",
                    "expiry",
                    "local_key_pubkey",
                    "remote_key",
                ] as const),
            };
        }),
        ...asStringFields(record, path, ["local_amount", "remote_amount", "local_settlement_pubkey", "remote_settlement_pubkey"] as const),
    };
}

// fiber's JSON names the hash algorithms in snake case, the SDK in its own spelling.
const SETTLEMENT_HASH_ALGORITHMS = { ckb_hash: "ckb-hash", sha256: "sha256" } as const;

// The snapshot fiber's `to_rpc_signing_settlement` wrote for a commitment case, every field read from the vector.
export function toVectorSettlement(vector: SettlementVector): SigningSettlement {
    return {
        localAmountShannons: BigInt(vector.local_amount),
        remoteAmountShannons: BigInt(vector.remote_amount),
        localSettlementPubkey: hexToBytes(vector.local_settlement_pubkey),
        remoteSettlementPubkey: hexToBytes(vector.remote_settlement_pubkey),
        forRemote: vector.for_remote,
        tlcs: vector.tlcs.map((tlc) => {
            const hashAlgorithm = Object.entries(SETTLEMENT_HASH_ALGORITHMS).find(([wire]) => wire === tlc.hash_algorithm)?.[1];
            if (hashAlgorithm === undefined) throw new Error(`unknown settlement hash algorithm: ${tlc.hash_algorithm}`);
            return {
                tlcId: Number(BigInt(tlc.tlc_id)),
                direction: tlc.inbound ? "received" : "offered",
                hashAlgorithm,
                amountShannons: BigInt(tlc.payment_amount),
                paymentHash: hexToBytes(tlc.payment_hash.replace(/^0x/, "")),
                expiryMs: BigInt(tlc.expiry),
                localKeyCommitmentNumber: Number(BigInt(tlc.local_key_commitment_number)),
                localKeyPubkey: hexToBytes(tlc.local_key_pubkey),
                remoteTlcPubkey: hexToBytes(tlc.remote_key),
            };
        }),
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
                udt_type_script: asNullable(record.udt_type_script, `${path}.udt_type_script`, asScript),
                tlcs: asArray(record.tlcs, `${path}.tlcs`).map((tlc, at) => asTlc(tlc, `${path}.tlcs[${at}]`)),
                tx_size: asNumber(record.tx_size, `${path}.tx_size`),
                transaction: asRecord(record.transaction, `${path}.transaction`),
                settlement: asSettlement(record.settlement, `${path}.settlement`),
                ...asStringFields(record, path, [
                    "name",
                    "lock_layout",
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
                udt_type_script: asNullable(record.udt_type_script, `${path}.udt_type_script`, asScript),
                tx_size: asNumber(record.tx_size, `${path}.tx_size`),
                transaction: asRecord(record.transaction, `${path}.transaction`),
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
                udt_type_script: asNullable(record.udt_type_script, `${path}.udt_type_script`, asScript),
                ...asStringFields(record, path, [
                    "name",
                    "lock_layout",
                    "delay_epoch",
                    "fee_rate",
                    "to_local",
                    "to_remote",
                    "local_reserved",
                    "remote_reserved",
                    "fee",
                    "output",
                    "output_data",
                    "commitment_lock_script_args",
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
                udt_type_script: asNullable(record.udt_type_script, `${path}.udt_type_script`, asScript),
                ...asStringFields(record, path, ["name", "chain_hash", "capacity", "digest"] as const),
            };
        }),
        reserve_cases: asArray(root.reserve_cases, "digest.reserve_cases").map((entry, index) => {
            const path = `digest.reserve_cases[${index}]`;
            const record = asRecord(entry, path);
            return {
                shutdown_script: asScript(record.shutdown_script, `${path}.shutdown_script`),
                reserved: asStringFields(record.reserved, `${path}.reserved`, ["legacy", "full_payment_hash"] as const),
                ...asStringFields(record, path, ["name"] as const),
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
        tenant_registry: asStringFields(root.tenant_registry, "tenant_registry", TENANT_REGISTRY_FIELDS),
    };
}

export function loadInteropVectors(): Vectors {
    const path = join(__dirname, "../../interop/vectors/vectors.json");
    const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
    return parseVectors(raw);
}

export function caseOf<Vector extends { name: string }>(cases: Vector[], name: string): Vector {
    const found = cases.find((entry) => entry.name === name);
    if (found === undefined) throw new Error(`the vectors carry no case named "${name}"`);
    return found;
}
