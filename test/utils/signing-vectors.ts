import { readFileSync } from "node:fs";
import { join } from "node:path";
import { CHANNEL_SIGNING_TRANSITIONS, type ChannelSigningTransition } from "../../src/protocol";
import type { WireField } from "../../src/wire";
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

export type SigningVectors = {
    fiber_ref: string;
    device: SigningDeviceVector;
    peer: SigningPeerVector;
    channel: SigningChannelVector;
    cases: SigningCaseVector[];
    variants: SigningVariantVector[];
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
