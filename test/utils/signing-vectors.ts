import { readFileSync } from "node:fs";
import { join } from "node:path";
import { bytesToHex } from "@noble/hashes/utils.js";
import {
    DEP_TYPES,
    SCRIPT_HASH_TYPES,
    type CellDep,
    type CellOutput,
    type DepType,
    type Script,
    type ScriptHashType,
} from "../../src/common";
import { moleculeCellOutput, readCommitmentLockVersion } from "../../src/digest";
import type { SignedCommitmentRecord, WatchtowerApproval, WatchtowerKeyPurpose } from "../../src/policy";
import { CHANNEL_SIGNING_TRANSITIONS, type ChannelSigningTransition } from "../../src/protocol";
import type { WireField } from "../../src/wire";
import { decodeCellDep, decodeScript } from "../../src/wire";
import { toTransaction } from "./digest-inputs";
import { asOutPoint, asScript, asTlc, caseOf, type OutPointVector, type ScriptVector, type TlcVector } from "./interop-vectors";
import { asBoolean, asList, asNullable, asNumber, asRecord, asString, asStringFields } from "./json-shape";

// The path the rpc client hands a status on with: the `status` member of the response's `result`.
const STATUS_PATH = "response.result.status";

const KEY_ROLES = ["device", "peer"] as const;

export type SigningKeyRole = (typeof KEY_ROLES)[number];

export type SigningDeviceVector = { master_seed: string; channel_index: number; funding_pubkey: string; tlc_base_pubkey: string };

export type SigningPeerVector = { seed: string; funding_pubkey: string; tlc_base_pubkey: string };

export type SigningChannelVector = {
    channel_id: string;
    funding_out_point: OutPointVector;
    lock_layout: string;
    commitment_lock: ScriptVector;
    funding_lock_cell_deps_count: number;
    delay_epoch: string;
    commitment_fee_rate: string;
    udt_type_script: ScriptVector | null;
    to_local: string;
    to_remote: string;
    local_reserved: string;
    remote_reserved: string;
    local_close_script: ScriptVector;
    remote_close_script: ScriptVector;
    local_shutdown_fee_rate: string;
    remote_shutdown_fee_rate: string;
    tlcs: TlcVector[];
};

export type SigningResultVector = { channel_id: string; status: Record<string, unknown> };

export type SigningNextMaterialVector = { next_commitment_point: string; next_commitment_nonce: string; next_revocation_nonce: string };

export type SigningExpectedVector = {
    key_order: [SigningKeyRole, SigningKeyRole];
    message: string;
    public_nonce: string;
    partial_signature: string;
    next_material: SigningNextMaterialVector | null;
    signature: string | null;
};

export type SigningCaseVector = {
    name: string;
    transition: ChannelSigningTransition;
    result: SigningResultVector;
    expected: SigningExpectedVector;
};

export type SigningVariantVector = {
    name: string;
    case: string;
    result: SigningResultVector;
    verdict: { accepted: boolean; message: string | null };
};

// CKB's JSON forms, `0x` hex, as fiber writes a transaction.
export type CkbOutPointJson = { tx_hash: string; index: string };

export type CkbScriptJson = { code_hash: string; hash_type: ScriptHashType; args: string };

export type CkbCellDepJson = { out_point: CkbOutPointJson; dep_type: DepType };

export type CkbCellInputJson = { since: string; previous_output: CkbOutPointJson };

export type CkbCellOutputJson = { capacity: string; lock: CkbScriptJson; type: CkbScriptJson | null };

export type CkbTransactionJson = {
    version: string;
    cell_deps: CkbCellDepJson[];
    header_deps: string[];
    inputs: CkbCellInputJson[];
    outputs: CkbCellOutputJson[];
    outputs_data: string[];
    witnesses: string[];
};

export type OnchainKeyPurposeJson = { type: "Settlement" } | { type: "Tlc"; commitment_number: string };

export type SigningWatchtowerCommitmentVector = {
    transaction: CkbTransactionJson;
    onchain_tx_hash: string;
    message: string;
    settlement_witness: string;
};

export type SigningWatchtowerSpendVector = {
    name: string;
    key_purpose: OnchainKeyPurposeJson;
    transaction: CkbTransactionJson;
    request_id: string;
    message: string;
    tx_hash: string;
    released_shannons: string;
    signer_pubkey: string;
    signature: string;
};

// A spend of the peer's own, with no signature of the device's: the history the device's later spends start from.
export type SigningWatchtowerPeerSpendVector = { name: string; transaction: CkbTransactionJson; tx_hash: string };

export type SigningWatchtowerViewVector = {
    for_remote: boolean;
    commitment: SigningWatchtowerCommitmentVector;
    spends: SigningWatchtowerSpendVector[];
    peer_spends: SigningWatchtowerPeerSpendVector[];
};

export type SigningWatchtowerVariantVector = {
    name: string;
    view_for_remote: boolean;
    spend: string;
    transaction: CkbTransactionJson;
    key_purpose: OnchainKeyPurposeJson;
    request_id: string;
    fiber_error: string;
};

export type SigningWatchtowerVector = {
    funding_cell_deps: CkbCellDepJson[];
    settlement_cell_deps: CkbCellDepJson[];
    destination: CkbScriptJson;
    max_fee: string;
    tlcs: TlcVector[];
    views: SigningWatchtowerViewVector[];
    variants: SigningWatchtowerVariantVector[];
};

export type SigningVectors = {
    fiber_ref: string;
    device: SigningDeviceVector;
    peer: SigningPeerVector;
    channel: SigningChannelVector;
    cases: SigningCaseVector[];
    variants: SigningVariantVector[];
    watchtower: SigningWatchtowerVector;
};

function asOneOf<Value extends string>(value: unknown, path: string, values: readonly Value[]): Value {
    const raw = asString(value, path);
    const found = values.find((known) => known === raw);
    if (found === undefined) throw new Error(`${path} is not one of ${values.join(", ")}: ${raw}`);
    return found;
}

function asResult(value: unknown, path: string): SigningResultVector {
    const record = asRecord(value, path);
    return { channel_id: asString(record.channel_id, `${path}.channel_id`), status: asRecord(record.status, `${path}.status`) };
}

function asChannel(value: unknown, path: string): SigningChannelVector {
    const record = asRecord(value, path);
    return {
        funding_out_point: asOutPoint(record.funding_out_point, `${path}.funding_out_point`),
        commitment_lock: asScript(record.commitment_lock, `${path}.commitment_lock`),
        funding_lock_cell_deps_count: asNumber(record.funding_lock_cell_deps_count, `${path}.funding_lock_cell_deps_count`),
        udt_type_script: asNullable(record.udt_type_script, `${path}.udt_type_script`, asScript),
        local_close_script: asScript(record.local_close_script, `${path}.local_close_script`),
        remote_close_script: asScript(record.remote_close_script, `${path}.remote_close_script`),
        tlcs: asList(record.tlcs, `${path}.tlcs`, asTlc),
        ...asStringFields(record, path, [
            "channel_id",
            "lock_layout",
            "delay_epoch",
            "commitment_fee_rate",
            "to_local",
            "to_remote",
            "local_reserved",
            "remote_reserved",
            "local_shutdown_fee_rate",
            "remote_shutdown_fee_rate",
        ] as const),
    };
}

function asExpected(value: unknown, path: string): SigningExpectedVector {
    const record = asRecord(value, path);
    const keyOrder = asList(record.key_order, `${path}.key_order`, (role, at) => asOneOf(role, at, KEY_ROLES));
    const [first, second] = keyOrder;
    if (keyOrder.length !== 2 || first === undefined || second === undefined || first === second) {
        throw new Error(`${path}.key_order must name the device and the peer once each`);
    }
    return {
        key_order: [first, second],
        next_material: asNullable(record.next_material, `${path}.next_material`, (material, at) =>
            asStringFields(material, at, ["next_commitment_point", "next_commitment_nonce", "next_revocation_nonce"] as const),
        ),
        signature: asNullable(record.signature, `${path}.signature`, asString),
        ...asStringFields(record, path, ["message", "public_nonce", "partial_signature"] as const),
    };
}

function asCkbOutPoint(value: unknown, path: string): CkbOutPointJson {
    return asStringFields(value, path, ["tx_hash", "index"] as const);
}

function asCkbScript(value: unknown, path: string): CkbScriptJson {
    const record = asRecord(value, path);
    return {
        hash_type: asOneOf(record.hash_type, `${path}.hash_type`, SCRIPT_HASH_TYPES),
        ...asStringFields(record, path, ["code_hash", "args"] as const),
    };
}

function asCkbCellDep(value: unknown, path: string): CkbCellDepJson {
    const record = asRecord(value, path);
    return {
        out_point: asCkbOutPoint(record.out_point, `${path}.out_point`),
        dep_type: asOneOf(record.dep_type, `${path}.dep_type`, DEP_TYPES),
    };
}

function asCkbTransaction(value: unknown, path: string): CkbTransactionJson {
    const record = asRecord(value, path);
    return {
        version: asString(record.version, `${path}.version`),
        cell_deps: asList(record.cell_deps, `${path}.cell_deps`, asCkbCellDep),
        header_deps: asList(record.header_deps, `${path}.header_deps`, asString),
        inputs: asList(record.inputs, `${path}.inputs`, (input, at) => {
            const fields = asRecord(input, at);
            return {
                since: asString(fields.since, `${at}.since`),
                previous_output: asCkbOutPoint(fields.previous_output, `${at}.previous_output`),
            };
        }),
        outputs: asList(record.outputs, `${path}.outputs`, (output, at) => {
            const fields = asRecord(output, at);
            return {
                capacity: asString(fields.capacity, `${at}.capacity`),
                lock: asCkbScript(fields.lock, `${at}.lock`),
                type: asNullable(fields.type, `${at}.type`, asCkbScript),
            };
        }),
        outputs_data: asList(record.outputs_data, `${path}.outputs_data`, asString),
        witnesses: asList(record.witnesses, `${path}.witnesses`, asString),
    };
}

function asOnchainKeyPurpose(value: unknown, path: string): OnchainKeyPurposeJson {
    const record = asRecord(value, path);
    const type = asOneOf(record.type, `${path}.type`, ["Settlement", "Tlc"] as const);
    if (type === "Settlement") {
        if (record.commitment_number !== undefined) throw new Error(`${path}.commitment_number is not a field of Settlement`);
        return { type };
    }
    return { type, commitment_number: asString(record.commitment_number, `${path}.commitment_number`) };
}

function asWatchtower(value: unknown, path: string): SigningWatchtowerVector {
    const record = asRecord(value, path);
    return {
        funding_cell_deps: asList(record.funding_cell_deps, `${path}.funding_cell_deps`, asCkbCellDep),
        settlement_cell_deps: asList(record.settlement_cell_deps, `${path}.settlement_cell_deps`, asCkbCellDep),
        destination: asCkbScript(record.destination, `${path}.destination`),
        max_fee: asString(record.max_fee, `${path}.max_fee`),
        tlcs: asList(record.tlcs, `${path}.tlcs`, asTlc),
        views: asList(record.views, `${path}.views`, (view, at) => {
            const fields = asRecord(view, at);
            const commitment = asRecord(fields.commitment, `${at}.commitment`);
            return {
                for_remote: asBoolean(fields.for_remote, `${at}.for_remote`),
                commitment: {
                    transaction: asCkbTransaction(commitment.transaction, `${at}.commitment.transaction`),
                    ...asStringFields(commitment, `${at}.commitment`, ["onchain_tx_hash", "message", "settlement_witness"] as const),
                },
                spends: asList(fields.spends, `${at}.spends`, (spend, spendPath) => {
                    const spendFields = asRecord(spend, spendPath);
                    return {
                        key_purpose: asOnchainKeyPurpose(spendFields.key_purpose, `${spendPath}.key_purpose`),
                        transaction: asCkbTransaction(spendFields.transaction, `${spendPath}.transaction`),
                        ...asStringFields(spendFields, spendPath, [
                            "name",
                            "request_id",
                            "message",
                            "tx_hash",
                            "released_shannons",
                            "signer_pubkey",
                            "signature",
                        ] as const),
                    };
                }),
                peer_spends: asList(fields.peer_spends, `${at}.peer_spends`, (spend, spendPath) => {
                    const spendFields = asRecord(spend, spendPath);
                    return {
                        transaction: asCkbTransaction(spendFields.transaction, `${spendPath}.transaction`),
                        ...asStringFields(spendFields, spendPath, ["name", "tx_hash"] as const),
                    };
                }),
            };
        }),
        variants: asList(record.variants, `${path}.variants`, (variant, at) => {
            const fields = asRecord(variant, at);
            return {
                view_for_remote: asBoolean(fields.view_for_remote, `${at}.view_for_remote`),
                transaction: asCkbTransaction(fields.transaction, `${at}.transaction`),
                key_purpose: asOnchainKeyPurpose(fields.key_purpose, `${at}.key_purpose`),
                ...asStringFields(fields, at, ["name", "spend", "request_id", "fiber_error"] as const),
            };
        }),
    };
}

export function parseSigningVectors(value: unknown): SigningVectors {
    const root = asRecord(value, "signing");
    const device = asRecord(root.device, "device");
    return {
        fiber_ref: asString(root.fiber_ref, "fiber_ref"),
        device: {
            channel_index: asNumber(device.channel_index, "device.channel_index"),
            ...asStringFields(device, "device", ["master_seed", "funding_pubkey", "tlc_base_pubkey"] as const),
        },
        peer: asStringFields(root.peer, "peer", ["seed", "funding_pubkey", "tlc_base_pubkey"] as const),
        channel: asChannel(root.channel, "channel"),
        cases: asList(root.cases, "cases", (entry, path) => {
            const record = asRecord(entry, path);
            return {
                name: asString(record.name, `${path}.name`),
                transition: asOneOf(record.transition, `${path}.transition`, CHANNEL_SIGNING_TRANSITIONS),
                result: asResult(record.result, `${path}.result`),
                expected: asExpected(record.expected, `${path}.expected`),
            };
        }),
        variants: asList(root.variants, "variants", (entry, path) => {
            const record = asRecord(entry, path);
            const verdict = asRecord(record.verdict, `${path}.verdict`);
            return {
                name: asString(record.name, `${path}.name`),
                case: asString(record.case, `${path}.case`),
                result: asResult(record.result, `${path}.result`),
                verdict: {
                    accepted: asBoolean(verdict.accepted, `${path}.verdict.accepted`),
                    message: asNullable(verdict.message, `${path}.verdict.message`, asString),
                },
            };
        }),
        watchtower: asWatchtower(root.watchtower, "watchtower"),
    };
}

export function loadSigningVectors(): SigningVectors {
    const raw: unknown = JSON.parse(readFileSync(join(__dirname, "../../interop/vectors/signing.json"), "utf8"));
    return parseSigningVectors(raw);
}

export function signingCaseOf(vectors: SigningVectors, transition: ChannelSigningTransition): SigningCaseVector {
    const found = vectors.cases.filter((entry) => entry.transition === transition);
    if (found.length !== 1 || found[0] === undefined) throw new Error(`the vectors carry ${found.length} cases of ${transition}`);
    return found[0];
}

export function signingVariantOf(vectors: SigningVectors, name: string): SigningVariantVector {
    return caseOf(vectors.variants, name);
}

// A fresh copy, so a spec's mutation stays its own.
export function signingStatusField(entry: { result: SigningResultVector }): WireField {
    return { value: structuredClone(entry.result.status), path: STATUS_PATH };
}

export function watchtowerViewOf(vectors: SigningVectors, forRemote: boolean): SigningWatchtowerViewVector {
    const found = vectors.watchtower.views.filter((view) => view.for_remote === forRemote);
    if (found.length !== 1 || found[0] === undefined)
        throw new Error(`the vectors carry ${found.length} watchtower views of for_remote ${forRemote}`);
    return found[0];
}

export function watchtowerSpendOf(vectors: SigningVectors, name: string): SigningWatchtowerSpendVector {
    return caseOf(
        vectors.watchtower.views.flatMap((view) => view.spends),
        name,
    );
}

export function watchtowerVariantOf(vectors: SigningVectors, name: string): SigningWatchtowerVariantVector {
    return caseOf(vectors.watchtower.variants, name);
}

// A fresh copy, at the rpc client's path.
export function watchtowerStatusField(entry: {
    request_id: string;
    key_purpose: OnchainKeyPurposeJson;
    transaction: CkbTransactionJson;
}): WireField {
    const status = {
        type: "SignatureRequired",
        request_id: entry.request_id,
        content: { key_purpose: entry.key_purpose, transaction: entry.transaction },
    };
    return { value: structuredClone(status), path: STATUS_PATH };
}

export function toCkbScript(json: CkbScriptJson): Script {
    return decodeScript({ value: json, path: "script" });
}

export function toCkbCellDep(json: CkbCellDepJson): CellDep {
    return decodeCellDep({ value: json, path: "cellDep" });
}

export function watchtowerApprovalOf(vectors: SigningVectors): WatchtowerApproval {
    const { watchtower } = vectors;
    return { destination: toCkbScript(watchtower.destination), maxFeeShannons: watchtower.max_fee };
}

export function toWatchtowerKeyPurpose(json: OnchainKeyPurposeJson): WatchtowerKeyPurpose {
    return json.type === "Settlement" ? { kind: "settlement" } : { kind: "tlc", commitmentNumber: Number(json.commitment_number) };
}

export function watchtowerSignedCommitmentOf(vectors: SigningVectors, forRemote: boolean): SignedCommitmentRecord {
    const { commitment } = watchtowerViewOf(vectors, forRemote);
    const tx = toTransaction(commitment.transaction);
    const [cell] = tx.outputs as [CellOutput];
    const [outputData] = tx.outputsData as [Uint8Array];
    return {
        commitmentNumber: readCommitmentLockVersion(cell.lock.args),
        txHash: commitment.message.slice(2),
        source: {
            output: bytesToHex(moleculeCellOutput(cell.capacityShannons, cell.lock, cell.type)),
            outputData: bytesToHex(outputData),
        },
        settlementWitness: commitment.settlement_witness.slice(2),
    };
}
