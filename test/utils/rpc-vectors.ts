import { readFileSync } from "node:fs";
import { join } from "node:path";
import { RPC_METHODS, type RpcMethod } from "../../src/rpc";
import { asOutPoint, asScript, type OutPointVector, type ScriptVector } from "./interop-vectors";
import { asBoolean, asList, asNullable, asNumber, asPresent, asRecord, asString, asStringFields } from "./json-shape";

export type CellDepVector = { out_point: OutPointVector; dep_type: string };

export type CellInputVector = { since: string; previous_output: OutPointVector };

export type CellOutputVector = { capacity: string; lock: ScriptVector; type: ScriptVector | null };

export type TransactionVector = {
    version: number;
    cell_deps: CellDepVector[];
    header_deps: string[];
    inputs: CellInputVector[];
    outputs: CellOutputVector[];
    outputs_data: string[];
    witnesses: string[];
};

export type ChannelStateVector = { name: string; flags: string[] };

export type HtlcVector = {
    id: string;
    amount: string;
    payment_hash: string;
    expiry: string;
    forwarding_channel_id: string | null;
    forwarding_tlc_id: string | null;
    status: { direction: string; status: string };
};

export type ChannelVector = {
    channel_id: string;
    is_public: boolean;
    is_acceptor: boolean;
    is_one_way: boolean;
    channel_outpoint: OutPointVector | null;
    pubkey: string;
    funding_udt_type_script: ScriptVector | null;
    state: ChannelStateVector;
    local_balance: string;
    offered_tlc_balance: string;
    remote_balance: string;
    received_tlc_balance: string;
    pending_tlcs: HtlcVector[];
    latest_commitment_transaction_hash: string | null;
    created_at: string;
    enabled: boolean;
    tlc_expiry_delta: string;
    tlc_fee_proportional_millionths: string;
    shutdown_transaction_hash: string | null;
    failure_detail: string | null;
};

export type InvoiceAttributeVector = { name: string; value: unknown };

export type InvoiceVector = {
    currency: string;
    amount: string | null;
    signature: string | null;
    data: { timestamp: string; payment_hash: string; attrs: InvoiceAttributeVector[] };
};

export type PaymentVector = {
    payment_hash: string;
    status: string;
    created_at: string;
    last_updated_at: string;
    failed_error: string | null;
    fee: string;
    custom_records: { key: number; data: string }[] | null;
};

export type OpenChannelParamsVector = {
    pubkey: string;
    funding_amount: string;
    public: boolean;
    shutdown_script: ScriptVector;
    funding_lock_script: ScriptVector;
    funding_lock_script_cell_deps: CellDepVector[] | null;
};

export type SubmitSignedFundingTxParamsVector = { channel_id: string; signed_funding_tx: TransactionVector };

export type ChannelIdParamsVector = { channel_id: string };

export type ListChannelsParamsVector = { include_closed: boolean | null; only_pending: boolean | null };

export type NewInvoiceParamsVector = {
    amount: string;
    currency: string;
    payment_hash: string;
    hash_algorithm: string;
    expiry: string;
    description: string | null;
};

export type PaymentHashParamsVector = { payment_hash: string };

export type SettleInvoiceParamsVector = { payment_hash: string; payment_preimage: string };

export type SendPaymentParamsVector = { invoice: string; max_fee_amount: string; dry_run: boolean };

export type OpenChannelResultVector = { channel_id: string; unsigned_funding_tx: TransactionVector };

export type SubmitSignedFundingTxResultVector = { channel_id: string; funding_tx_hash: string };

export type ListChannelsResultVector = { channels: ChannelVector[] };

export type InvoiceResultVector = { invoice_address: string; invoice: InvoiceVector };

export type GetInvoiceResultVector = InvoiceResultVector & { status: string };

export type ChannelOpenSignerMaterialVector = {
    funding_pubkey: string;
    tlc_base_key: string;
    first_commitment_point: string;
    second_commitment_point: string;
    commitment_nonce: string;
    next_commitment_nonce: string;
    revocation_nonce: string;
    channel_announcement_nonce: string | null;
};

export type OpenTenantChannelParamsVector = {
    pubkey: string;
    funding_amount: string;
    shutdown_script: ScriptVector;
    funding_lock_script: ScriptVector;
    funding_lock_script_cell_deps: CellDepVector[] | null;
    commitment_delay_epoch: string | null;
    commitment_fee_rate: string | null;
    external_channel_signer: ChannelOpenSignerMaterialVector;
};

export type TenantChannelOpeningContextVector = {
    remote_funding_key: string;
    remote_settlement_key: string;
    remote_shutdown_script: ScriptVector;
    commitment_delay_epoch: string;
    commitment_fee_rate: string;
    local_amount: string;
    remote_amount: string;
    local_reserved_ckb_amount: string;
    remote_reserved_ckb_amount: string;
};

export type OpenTenantChannelResultVector = OpenChannelResultVector & { opening_context: TenantChannelOpeningContextVector };

export type ShutdownChannelParamsVector = {
    channel_id: string;
    close_script: ScriptVector | null;
    fee_rate: string | null;
    force: boolean | null;
};

export type SigningStatusResultVector = { channel_id: string; status: string };

export type WatchtowerKeyPurposeVector = { name: "Settlement"; commitment_number: null } | { name: "Tlc"; commitment_number: string };

export type WatchtowerSignatureRequiredVector = {
    channel_id: string;
    status: "SignatureRequired";
    request_id: string;
    key_purpose: WatchtowerKeyPurposeVector;
    transaction: TransactionVector;
};

export type WatchtowerSigningStatusResultVector = { channel_id: string; status: "NoSignatureRequired" } | WatchtowerSignatureRequiredVector;

export type NextChannelSignerMaterialVector = {
    next_commitment_point: string;
    next_commitment_nonce: string;
    next_revocation_nonce: string;
};

export type SubmitChannelSignatureParamsVector = {
    channel_id: string;
    request_id: string;
    partial_signature: string;
    next_material: NextChannelSignerMaterialVector | null;
};

export type SubmissionResultVector = { outcome: string };

export type SubmitWatchtowerSignatureParamsVector = { channel_id: string; request_id: string; signature: string };

export type TenantRegistryNonceParamsVector = { root_signer_pubkey: string };

export type TenantRegistryNonceResultVector = { lsp_node_id: string; root_signer_pubkey: string; nonce: string };

export type RegisterTenantParamsVector = { root_signer_pubkey: string; nonce: string; signature: string };

export type LspTenantStatusVector = {
    tenant_id: string;
    root_signer_pubkey: string | null;
    invoice_pubkey: string;
    private_channel_id: string | null;
    created_at: string;
    runtime_status: string;
    channel_online: boolean;
};

export type RegisterTenantResultVector = { tenant: LspTenantStatusVector; access_token: string };

export type RpcVectorShapes = {
    open_channel_with_external_funding: { params: OpenChannelParamsVector; result: OpenChannelResultVector };
    submit_signed_funding_tx: { params: SubmitSignedFundingTxParamsVector; result: SubmitSignedFundingTxResultVector };
    abandon_channel: { params: ChannelIdParamsVector; result: null };
    list_channels: { params: ListChannelsParamsVector; result: ListChannelsResultVector };
    new_invoice: { params: NewInvoiceParamsVector; result: InvoiceResultVector };
    get_invoice: { params: PaymentHashParamsVector; result: GetInvoiceResultVector };
    settle_invoice: { params: SettleInvoiceParamsVector; result: Record<string, never> };
    cancel_invoice: { params: PaymentHashParamsVector; result: GetInvoiceResultVector };
    send_payment: { params: SendPaymentParamsVector; result: PaymentVector };
    get_payment: { params: PaymentHashParamsVector; result: PaymentVector };
    open_tenant_channel: { params: OpenTenantChannelParamsVector; result: OpenTenantChannelResultVector };
    shutdown_channel: { params: ShutdownChannelParamsVector; result: null };
    get_channel_signing_status: { params: ChannelIdParamsVector; result: SigningStatusResultVector };
    submit_channel_signature: { params: SubmitChannelSignatureParamsVector; result: SubmissionResultVector };
    get_watchtower_signing_status: { params: ChannelIdParamsVector; result: WatchtowerSigningStatusResultVector };
    submit_watchtower_signature: { params: SubmitWatchtowerSignatureParamsVector; result: SubmissionResultVector };
    lsp_get_tenant_registry_nonce: { params: TenantRegistryNonceParamsVector; result: TenantRegistryNonceResultVector };
    lsp_register_tenant: { params: RegisterTenantParamsVector; result: RegisterTenantResultVector };
};

export type RpcCaseVector<Values> = { name: string; values: Values; json: unknown };

export type RpcMethodVectors<Method extends RpcMethod> = {
    params: RpcCaseVector<RpcVectorShapes[Method]["params"]>[];
    results: RpcCaseVector<RpcVectorShapes[Method]["result"]>[];
};

export type RequestEnvelopeVector = { id: number; method: string; params: unknown; text: string };

export type ResultEnvelopeVector = { name: string; id: number; result: unknown; text: string };

export type ErrorEnvelopeVector = { name: string; id: number | null; code: number; message: string; data: unknown; text: string };

export type RpcVectors = {
    fiber_ref: string;
    jsonrpsee_version: string;
    channel_state_flags: Record<string, string[]>;
    envelopes: { request: RequestEnvelopeVector; results: ResultEnvelopeVector[]; errors: ErrorEnvelopeVector[] };
    methods: { [Method in RpcMethod]: RpcMethodVectors<Method> };
};

type Parser<Value> = (value: unknown, path: string) => Value;

function asCellDep(value: unknown, path: string): CellDepVector {
    const entry = asRecord(value, path);
    return { out_point: asOutPoint(entry.out_point, `${path}.out_point`), dep_type: asString(entry.dep_type, `${path}.dep_type`) };
}

function asCellDeps(value: unknown, path: string): CellDepVector[] {
    return asList(value, path, asCellDep);
}

function asTransaction(value: unknown, path: string): TransactionVector {
    const record = asRecord(value, path);
    return {
        version: asNumber(record.version, `${path}.version`),
        cell_deps: asCellDeps(record.cell_deps, `${path}.cell_deps`),
        header_deps: asList(record.header_deps, `${path}.header_deps`, asString),
        inputs: asList(record.inputs, `${path}.inputs`, (input, at) => {
            const entry = asRecord(input, at);
            return {
                since: asString(entry.since, `${at}.since`),
                previous_output: asOutPoint(entry.previous_output, `${at}.previous_output`),
            };
        }),
        outputs: asList(record.outputs, `${path}.outputs`, (output, at) => {
            const entry = asRecord(output, at);
            return {
                capacity: asString(entry.capacity, `${at}.capacity`),
                lock: asScript(entry.lock, `${at}.lock`),
                type: asNullable(entry.type, `${at}.type`, asScript),
            };
        }),
        outputs_data: asList(record.outputs_data, `${path}.outputs_data`, asString),
        witnesses: asList(record.witnesses, `${path}.witnesses`, asString),
    };
}

function asChannel(value: unknown, path: string): ChannelVector {
    const record = asRecord(value, path);
    const state = asRecord(record.state, `${path}.state`);
    return {
        is_public: asBoolean(record.is_public, `${path}.is_public`),
        is_acceptor: asBoolean(record.is_acceptor, `${path}.is_acceptor`),
        is_one_way: asBoolean(record.is_one_way, `${path}.is_one_way`),
        channel_outpoint: asNullable(record.channel_outpoint, `${path}.channel_outpoint`, asOutPoint),
        funding_udt_type_script: asNullable(record.funding_udt_type_script, `${path}.funding_udt_type_script`, asScript),
        state: { name: asString(state.name, `${path}.state.name`), flags: asList(state.flags, `${path}.state.flags`, asString) },
        pending_tlcs: asList(record.pending_tlcs, `${path}.pending_tlcs`, (tlc, at) => {
            const entry = asRecord(tlc, at);
            const status = asRecord(entry.status, `${at}.status`);
            return {
                forwarding_channel_id: asNullable(entry.forwarding_channel_id, `${at}.forwarding_channel_id`, asString),
                forwarding_tlc_id: asNullable(entry.forwarding_tlc_id, `${at}.forwarding_tlc_id`, asString),
                status: asStringFields(status, `${at}.status`, ["direction", "status"] as const),
                ...asStringFields(entry, at, ["id", "amount", "payment_hash", "expiry"] as const),
            };
        }),
        latest_commitment_transaction_hash: asNullable(
            record.latest_commitment_transaction_hash,
            `${path}.latest_commitment_transaction_hash`,
            asString,
        ),
        enabled: asBoolean(record.enabled, `${path}.enabled`),
        shutdown_transaction_hash: asNullable(record.shutdown_transaction_hash, `${path}.shutdown_transaction_hash`, asString),
        failure_detail: asNullable(record.failure_detail, `${path}.failure_detail`, asString),
        ...asStringFields(record, path, [
            "channel_id",
            "pubkey",
            "local_balance",
            "offered_tlc_balance",
            "remote_balance",
            "received_tlc_balance",
            "created_at",
            "tlc_expiry_delta",
            "tlc_fee_proportional_millionths",
        ] as const),
    };
}

function asInvoice(value: unknown, path: string): InvoiceVector {
    const record = asRecord(value, path);
    const data = asRecord(record.data, `${path}.data`);
    return {
        currency: asString(record.currency, `${path}.currency`),
        amount: asNullable(record.amount, `${path}.amount`, asString),
        signature: asNullable(record.signature, `${path}.signature`, asString),
        data: {
            timestamp: asString(data.timestamp, `${path}.data.timestamp`),
            payment_hash: asString(data.payment_hash, `${path}.data.payment_hash`),
            attrs: asList(data.attrs, `${path}.data.attrs`, (attr, at) => {
                const entry = asRecord(attr, at);
                return { name: asString(entry.name, `${at}.name`), value: asPresent(entry.value, `${at}.value`) };
            }),
        },
    };
}

function asPayment(value: unknown, path: string): PaymentVector {
    const record = asRecord(value, path);
    return {
        failed_error: asNullable(record.failed_error, `${path}.failed_error`, asString),
        custom_records: asNullable(record.custom_records, `${path}.custom_records`, (records, at) =>
            asList(records, at, (entry, entryAt) => {
                const item = asRecord(entry, entryAt);
                return { key: asNumber(item.key, `${entryAt}.key`), data: asString(item.data, `${entryAt}.data`) };
            }),
        ),
        ...asStringFields(record, path, ["payment_hash", "status", "created_at", "last_updated_at", "fee"] as const),
    };
}

function asInvoiceResult(value: unknown, path: string): InvoiceResultVector {
    const record = asRecord(value, path);
    return {
        invoice_address: asString(record.invoice_address, `${path}.invoice_address`),
        invoice: asInvoice(record.invoice, `${path}.invoice`),
    };
}

function asGetInvoiceResult(value: unknown, path: string): GetInvoiceResultVector {
    return { ...asInvoiceResult(value, path), status: asString(asRecord(value, path).status, `${path}.status`) };
}

function asPaymentHashParams(value: unknown, path: string): PaymentHashParamsVector {
    return asStringFields(value, path, ["payment_hash"] as const);
}

function asChannelIdParams(value: unknown, path: string): ChannelIdParamsVector {
    return asStringFields(value, path, ["channel_id"] as const);
}

function asOpenResult(value: unknown, path: string): OpenChannelResultVector {
    const record = asRecord(value, path);
    return {
        channel_id: asString(record.channel_id, `${path}.channel_id`),
        unsigned_funding_tx: asTransaction(record.unsigned_funding_tx, `${path}.unsigned_funding_tx`),
    };
}

function asSignerMaterial(value: unknown, path: string): ChannelOpenSignerMaterialVector {
    const record = asRecord(value, path);
    return {
        channel_announcement_nonce: asNullable(record.channel_announcement_nonce, `${path}.channel_announcement_nonce`, asString),
        ...asStringFields(record, path, [
            "funding_pubkey",
            "tlc_base_key",
            "first_commitment_point",
            "second_commitment_point",
            "commitment_nonce",
            "next_commitment_nonce",
            "revocation_nonce",
        ] as const),
    };
}

function asOpeningContext(value: unknown, path: string): TenantChannelOpeningContextVector {
    const record = asRecord(value, path);
    return {
        remote_shutdown_script: asScript(record.remote_shutdown_script, `${path}.remote_shutdown_script`),
        ...asStringFields(record, path, [
            "remote_funding_key",
            "remote_settlement_key",
            "commitment_delay_epoch",
            "commitment_fee_rate",
            "local_amount",
            "remote_amount",
            "local_reserved_ckb_amount",
            "remote_reserved_ckb_amount",
        ] as const),
    };
}

function asSigningStatusResult(value: unknown, path: string): SigningStatusResultVector {
    return asStringFields(value, path, ["channel_id", "status"] as const);
}

function asWatchtowerKeyPurpose(value: unknown, path: string): WatchtowerKeyPurposeVector {
    const record = asRecord(value, path);
    const name = asString(record.name, `${path}.name`);
    if (name === "Settlement") return { name, commitment_number: asNull(record.commitment_number, `${path}.commitment_number`) };
    if (name === "Tlc") return { name, commitment_number: asString(record.commitment_number, `${path}.commitment_number`) };
    throw new Error(`${path}.name is not a key purpose: ${name}`);
}

function asWatchtowerSigningStatusResult(value: unknown, path: string): WatchtowerSigningStatusResultVector {
    const record = asRecord(value, path);
    const channel_id = asString(record.channel_id, `${path}.channel_id`);
    const status = asString(record.status, `${path}.status`);
    if (status === "NoSignatureRequired") return { channel_id, status };
    if (status !== "SignatureRequired") throw new Error(`${path}.status is not a watchtower signing status: ${status}`);
    return {
        channel_id,
        status,
        request_id: asString(record.request_id, `${path}.request_id`),
        key_purpose: asWatchtowerKeyPurpose(record.key_purpose, `${path}.key_purpose`),
        transaction: asTransaction(record.transaction, `${path}.transaction`),
    };
}

function asSubmissionResult(value: unknown, path: string): SubmissionResultVector {
    return asStringFields(value, path, ["outcome"] as const);
}

function asTenantStatus(value: unknown, path: string): LspTenantStatusVector {
    const record = asRecord(value, path);
    return {
        root_signer_pubkey: asNullable(record.root_signer_pubkey, `${path}.root_signer_pubkey`, asString),
        private_channel_id: asNullable(record.private_channel_id, `${path}.private_channel_id`, asString),
        channel_online: asBoolean(record.channel_online, `${path}.channel_online`),
        ...asStringFields(record, path, ["tenant_id", "invoice_pubkey", "created_at", "runtime_status"] as const),
    };
}

function asNull(value: unknown, path: string): null {
    if (value !== null) throw new Error(`${path} must be null`);
    return null;
}

function asEmptyRecord(value: unknown, path: string): Record<string, never> {
    if (Object.keys(asRecord(value, path)).length !== 0) throw new Error(`${path} must be an empty object`);
    return {};
}

const METHOD_PARSERS: {
    [Method in RpcMethod]: { params: Parser<RpcVectorShapes[Method]["params"]>; result: Parser<RpcVectorShapes[Method]["result"]> };
} = {
    open_channel_with_external_funding: {
        params: (value, path) => {
            const record = asRecord(value, path);
            return {
                public: asBoolean(record.public, `${path}.public`),
                shutdown_script: asScript(record.shutdown_script, `${path}.shutdown_script`),
                funding_lock_script: asScript(record.funding_lock_script, `${path}.funding_lock_script`),
                funding_lock_script_cell_deps: asNullable(
                    record.funding_lock_script_cell_deps,
                    `${path}.funding_lock_script_cell_deps`,
                    asCellDeps,
                ),
                ...asStringFields(record, path, ["pubkey", "funding_amount"] as const),
            };
        },
        result: asOpenResult,
    },
    submit_signed_funding_tx: {
        params: (value, path) => {
            const record = asRecord(value, path);
            return {
                channel_id: asString(record.channel_id, `${path}.channel_id`),
                signed_funding_tx: asTransaction(record.signed_funding_tx, `${path}.signed_funding_tx`),
            };
        },
        result: (value, path) => asStringFields(value, path, ["channel_id", "funding_tx_hash"] as const),
    },
    abandon_channel: { params: asChannelIdParams, result: asNull },
    list_channels: {
        params: (value, path) => {
            const record = asRecord(value, path);
            return {
                include_closed: asNullable(record.include_closed, `${path}.include_closed`, asBoolean),
                only_pending: asNullable(record.only_pending, `${path}.only_pending`, asBoolean),
            };
        },
        result: (value, path) => ({ channels: asList(asRecord(value, path).channels, `${path}.channels`, asChannel) }),
    },
    new_invoice: {
        params: (value, path) => {
            const record = asRecord(value, path);
            return {
                description: asNullable(record.description, `${path}.description`, asString),
                ...asStringFields(record, path, ["amount", "currency", "payment_hash", "hash_algorithm", "expiry"] as const),
            };
        },
        result: asInvoiceResult,
    },
    get_invoice: { params: asPaymentHashParams, result: asGetInvoiceResult },
    settle_invoice: {
        params: (value, path) => asStringFields(value, path, ["payment_hash", "payment_preimage"] as const),
        result: asEmptyRecord,
    },
    cancel_invoice: { params: asPaymentHashParams, result: asGetInvoiceResult },
    send_payment: {
        params: (value, path) => {
            const record = asRecord(value, path);
            return {
                dry_run: asBoolean(record.dry_run, `${path}.dry_run`),
                ...asStringFields(record, path, ["invoice", "max_fee_amount"] as const),
            };
        },
        result: asPayment,
    },
    get_payment: { params: asPaymentHashParams, result: asPayment },
    open_tenant_channel: {
        params: (value, path) => {
            const record = asRecord(value, path);
            return {
                shutdown_script: asScript(record.shutdown_script, `${path}.shutdown_script`),
                funding_lock_script: asScript(record.funding_lock_script, `${path}.funding_lock_script`),
                funding_lock_script_cell_deps: asNullable(
                    record.funding_lock_script_cell_deps,
                    `${path}.funding_lock_script_cell_deps`,
                    asCellDeps,
                ),
                commitment_delay_epoch: asNullable(record.commitment_delay_epoch, `${path}.commitment_delay_epoch`, asString),
                commitment_fee_rate: asNullable(record.commitment_fee_rate, `${path}.commitment_fee_rate`, asString),
                external_channel_signer: asSignerMaterial(record.external_channel_signer, `${path}.external_channel_signer`),
                ...asStringFields(record, path, ["pubkey", "funding_amount"] as const),
            };
        },
        result: (value, path) => ({
            ...asOpenResult(value, path),
            opening_context: asOpeningContext(asRecord(value, path).opening_context, `${path}.opening_context`),
        }),
    },
    shutdown_channel: {
        params: (value, path) => {
            const record = asRecord(value, path);
            return {
                channel_id: asString(record.channel_id, `${path}.channel_id`),
                close_script: asNullable(record.close_script, `${path}.close_script`, asScript),
                fee_rate: asNullable(record.fee_rate, `${path}.fee_rate`, asString),
                force: asNullable(record.force, `${path}.force`, asBoolean),
            };
        },
        result: asNull,
    },
    get_channel_signing_status: { params: asChannelIdParams, result: asSigningStatusResult },
    submit_channel_signature: {
        params: (value, path) => {
            const record = asRecord(value, path);
            return {
                next_material: asNullable(record.next_material, `${path}.next_material`, (material, at) =>
                    asStringFields(material, at, ["next_commitment_point", "next_commitment_nonce", "next_revocation_nonce"] as const),
                ),
                ...asStringFields(record, path, ["channel_id", "request_id", "partial_signature"] as const),
            };
        },
        result: asSubmissionResult,
    },
    get_watchtower_signing_status: { params: asChannelIdParams, result: asWatchtowerSigningStatusResult },
    submit_watchtower_signature: {
        params: (value, path) => asStringFields(value, path, ["channel_id", "request_id", "signature"] as const),
        result: asSubmissionResult,
    },
    lsp_get_tenant_registry_nonce: {
        params: (value, path) => asStringFields(value, path, ["root_signer_pubkey"] as const),
        result: (value, path) => asStringFields(value, path, ["lsp_node_id", "root_signer_pubkey", "nonce"] as const),
    },
    lsp_register_tenant: {
        params: (value, path) => asStringFields(value, path, ["root_signer_pubkey", "nonce", "signature"] as const),
        result: (value, path) => {
            const record = asRecord(value, path);
            return {
                tenant: asTenantStatus(record.tenant, `${path}.tenant`),
                access_token: asString(record.access_token, `${path}.access_token`),
            };
        },
    },
};

function asCases<Values>(value: unknown, path: string, parse: Parser<Values>): RpcCaseVector<Values>[] {
    return asList(value, path, (entry, at) => {
        const record = asRecord(entry, at);
        return {
            name: asString(record.name, `${at}.name`),
            values: parse(record.values, `${at}.values`),
            json: asPresent(record.json, `${at}.json`),
        };
    });
}

function asMethodVectors<Method extends RpcMethod>(value: unknown, method: Method): RpcMethodVectors<Method> {
    const record = asRecord(value, `methods.${method}`);
    const parsers = METHOD_PARSERS[method];
    return {
        params: asCases(record.params, `methods.${method}.params`, parsers.params),
        results: asCases(record.results, `methods.${method}.results`, parsers.result),
    };
}

export function parseRpcVectors(value: unknown): RpcVectors {
    const root = asRecord(value, "rpc vectors");
    const envelopes = asRecord(root.envelopes, "envelopes");
    const request = asRecord(envelopes.request, "envelopes.request");
    const stateFlags = asRecord(root.channel_state_flags, "channel_state_flags");
    const methods = asRecord(root.methods, "methods");
    const unknownMethod = Object.keys(methods).find((method) => !(RPC_METHODS as readonly string[]).includes(method));
    if (unknownMethod !== undefined) throw new Error(`methods.${unknownMethod} is not a method of the client`);
    const parsedMethods = {} as RpcVectors["methods"];
    for (const method of RPC_METHODS) {
        (parsedMethods as Record<RpcMethod, RpcMethodVectors<RpcMethod>>)[method] = asMethodVectors(methods[method], method);
    }
    return {
        fiber_ref: asString(root.fiber_ref, "fiber_ref"),
        jsonrpsee_version: asString(root.jsonrpsee_version, "jsonrpsee_version"),
        channel_state_flags: Object.fromEntries(
            Object.entries(stateFlags).map(([state, flags]) => [state, asList(flags, `channel_state_flags.${state}`, asString)]),
        ),
        envelopes: {
            request: {
                id: asNumber(request.id, "envelopes.request.id"),
                method: asString(request.method, "envelopes.request.method"),
                params: asPresent(request.params, "envelopes.request.params"),
                text: asString(request.text, "envelopes.request.text"),
            },
            results: asList(envelopes.results, "envelopes.results", (entry, at) => {
                const record = asRecord(entry, at);
                return {
                    name: asString(record.name, `${at}.name`),
                    id: asNumber(record.id, `${at}.id`),
                    result: asPresent(record.result, `${at}.result`),
                    text: asString(record.text, `${at}.text`),
                };
            }),
            errors: asList(envelopes.errors, "envelopes.errors", (entry, at) => {
                const record = asRecord(entry, at);
                return {
                    id: asNullable(record.id, `${at}.id`, asNumber),
                    code: asNumber(record.code, `${at}.code`),
                    data: asPresent(record.data, `${at}.data`),
                    ...asStringFields(record, at, ["name", "message", "text"] as const),
                };
            }),
        },
        methods: parsedMethods,
    };
}

export function loadRpcVectors(): RpcVectors {
    const path = join(__dirname, "../../interop/vectors/rpc.json");
    const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
    return parseRpcVectors(raw);
}
