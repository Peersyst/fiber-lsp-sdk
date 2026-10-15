import { hexToBytes } from "@noble/hashes/utils.js";
import type { DepType, TlcHashAlgorithm, Transaction } from "../../src/common";
import type { InvoiceCurrency } from "../../src/invoice";
import type {
    GetTenantRegistryNonceParams,
    GetTenantRegistryNonceResult,
    ListChannelsParams,
    LspTenantStatus,
    NewInvoiceParams,
    NewInvoiceResult,
    OpenChannelWithExternalFundingParams,
    OpenChannelWithExternalFundingResult,
    OpenTenantChannelParams,
    OpenTenantChannelResult,
    RegisterTenantParams,
    RegisterTenantResult,
    RpcChannel,
    RpcChannelIdParams,
    RpcChannelState,
    RpcInvoice,
    RpcInvoiceStatus,
    RpcMethod,
    RpcParamsWire,
    RpcPayment,
    RpcPaymentHashParams,
    RpcPaymentStatus,
    RpcSigningStatusResult,
    RpcSubmissionResult,
    RpcTenantRuntimeStatus,
    SendPaymentParams,
    SettleInvoiceParams,
    ShutdownChannelParams,
    SubmitChannelSignatureParams,
    SubmitSignedFundingTxParams,
    SubmitSignedFundingTxResult,
    SubmitWatchtowerSignatureParams,
    TenantChannelOpeningContext,
} from "../../src/rpc";
import {
    encodeGetTenantRegistryNonceParams,
    encodeListChannelsParams,
    encodeNewInvoiceParams,
    encodeOpenChannelWithExternalFundingParams,
    encodeOpenTenantChannelParams,
    encodeRegisterTenantParams,
    encodeRpcChannelIdParams,
    encodeRpcPaymentHashParams,
    encodeSendPaymentParams,
    encodeSettleInvoiceParams,
    encodeShutdownChannelParams,
    encodeSubmitChannelSignatureParams,
    encodeSubmitSignedFundingTxParams,
    encodeSubmitWatchtowerSignatureParams,
} from "../../src/rpc";
import { toOutPoint, toScript, toScriptOrNull } from "./digest-inputs";
import { RPC_RESULT_PATH } from "./rpc-answers";
import type {
    ChannelIdParamsVector,
    ChannelStateVector,
    ChannelVector,
    GetInvoiceResultVector,
    InvoiceResultVector,
    ListChannelsParamsVector,
    LspTenantStatusVector,
    NewInvoiceParamsVector,
    OpenChannelParamsVector,
    OpenChannelResultVector,
    OpenTenantChannelParamsVector,
    OpenTenantChannelResultVector,
    PaymentHashParamsVector,
    PaymentVector,
    RegisterTenantParamsVector,
    RegisterTenantResultVector,
    RpcVectorShapes,
    SendPaymentParamsVector,
    SettleInvoiceParamsVector,
    ShutdownChannelParamsVector,
    SigningStatusResultVector,
    SubmissionResultVector,
    SubmitChannelSignatureParamsVector,
    SubmitSignedFundingTxParamsVector,
    SubmitSignedFundingTxResultVector,
    SubmitWatchtowerSignatureParamsVector,
    TenantChannelOpeningContextVector,
    TenantRegistryNonceParamsVector,
    TenantRegistryNonceResultVector,
    TransactionVector,
} from "./rpc-vectors";
import { HASH_ALGORITHM_WIRE, wireHex } from "./wire-requests";

const HASH_ALGORITHMS = Object.fromEntries(Object.entries(HASH_ALGORITHM_WIRE).map(([sdk, wire]) => [wire, sdk])) as Record<
    string,
    TlcHashAlgorithm
>;

export function toTransaction(vector: TransactionVector): Transaction {
    return {
        version: vector.version,
        cellDeps: vector.cell_deps.map((dep) => ({ outPoint: toOutPoint(dep.out_point), depType: dep.dep_type as DepType })),
        headerDeps: vector.header_deps.map((dep) => hexToBytes(dep)),
        inputs: vector.inputs.map((input) => ({ since: BigInt(input.since), previousOutput: toOutPoint(input.previous_output) })),
        outputs: vector.outputs.map((output) => ({
            capacityShannons: BigInt(output.capacity),
            lock: toScript(output.lock),
            type: toScriptOrNull(output.type),
        })),
        outputsData: vector.outputs_data.map((data) => hexToBytes(data)),
        witnesses: vector.witnesses.map((witness) => hexToBytes(witness)),
    };
}

export function toOpenChannelWithExternalFundingParams(vector: OpenChannelParamsVector): OpenChannelWithExternalFundingParams {
    return {
        peerPubkey: hexToBytes(vector.pubkey),
        fundingAmountShannons: vector.funding_amount,
        public: vector.public,
        shutdownScript: toScript(vector.shutdown_script),
        fundingLockScript: toScript(vector.funding_lock_script),
    };
}

export function toOpenChannelWithExternalFundingResult(vector: OpenChannelResultVector): OpenChannelWithExternalFundingResult {
    return { channelId: wireHex(vector.channel_id), unsignedFundingTx: toTransaction(vector.unsigned_funding_tx) };
}

export function toSubmitSignedFundingTxParams(vector: SubmitSignedFundingTxParamsVector): SubmitSignedFundingTxParams {
    return { channelId: wireHex(vector.channel_id), signedFundingTx: toTransaction(vector.signed_funding_tx) };
}

export function toSubmitSignedFundingTxResult(vector: SubmitSignedFundingTxResultVector): SubmitSignedFundingTxResult {
    return { channelId: wireHex(vector.channel_id), fundingTxHash: hexToBytes(vector.funding_tx_hash) };
}

export function toRpcChannelIdParams(vector: ChannelIdParamsVector): RpcChannelIdParams {
    return { channelId: wireHex(vector.channel_id) };
}

export function toOpenTenantChannelParams(vector: OpenTenantChannelParamsVector): OpenTenantChannelParams {
    const material = vector.external_channel_signer;
    const params: OpenTenantChannelParams = {
        peerPubkey: hexToBytes(vector.pubkey),
        fundingAmountShannons: vector.funding_amount,
        shutdownScript: toScript(vector.shutdown_script),
        fundingLockScript: toScript(vector.funding_lock_script),
        signerMaterial: {
            fundingPubkey: hexToBytes(material.funding_pubkey),
            tlcBaseKey: hexToBytes(material.tlc_base_key),
            firstCommitmentPoint: hexToBytes(material.first_commitment_point),
            secondCommitmentPoint: hexToBytes(material.second_commitment_point),
            commitmentNonce: hexToBytes(material.commitment_nonce),
            nextCommitmentNonce: hexToBytes(material.next_commitment_nonce),
            revocationNonce: hexToBytes(material.revocation_nonce),
            channelAnnouncementNonce: material.channel_announcement_nonce === null ? null : hexToBytes(material.channel_announcement_nonce),
        },
    };
    if (vector.commitment_delay_epoch !== null) params.commitmentDelayEpoch = BigInt(vector.commitment_delay_epoch);
    if (vector.commitment_fee_rate !== null) params.commitmentFeeRate = BigInt(vector.commitment_fee_rate);
    return params;
}

export function toTenantChannelOpeningContext(vector: TenantChannelOpeningContextVector): TenantChannelOpeningContext {
    return {
        remoteFundingKey: hexToBytes(vector.remote_funding_key),
        remoteSettlementKey: hexToBytes(vector.remote_settlement_key),
        remoteShutdownScript: toScript(vector.remote_shutdown_script),
        commitmentDelayEpoch: BigInt(vector.commitment_delay_epoch),
        commitmentFeeRate: BigInt(vector.commitment_fee_rate),
        localAmountShannons: vector.local_amount,
        remoteAmountShannons: vector.remote_amount,
        localReservedCkbShannons: vector.local_reserved_ckb_amount,
        remoteReservedCkbShannons: vector.remote_reserved_ckb_amount,
    };
}

export function toOpenTenantChannelResult(vector: OpenTenantChannelResultVector): OpenTenantChannelResult {
    return { ...toOpenChannelWithExternalFundingResult(vector), openingContext: toTenantChannelOpeningContext(vector.opening_context) };
}

export function toShutdownChannelParams(vector: ShutdownChannelParamsVector): ShutdownChannelParams {
    const params: ShutdownChannelParams = { channelId: wireHex(vector.channel_id) };
    if (vector.close_script !== null) params.closeScript = toScript(vector.close_script);
    if (vector.fee_rate !== null) params.feeRate = BigInt(vector.fee_rate);
    if (vector.force !== null) params.force = vector.force;
    return params;
}

// Fiber writes a unit variant as its tag alone, positioned where the decoder leaves it.
export function toRpcSigningStatusResult(vector: SigningStatusResultVector): RpcSigningStatusResult {
    return { channelId: wireHex(vector.channel_id), status: { value: { type: vector.status }, path: `${RPC_RESULT_PATH}.status` } };
}

export function toSubmitChannelSignatureParams(vector: SubmitChannelSignatureParamsVector): SubmitChannelSignatureParams {
    const material = vector.next_material;
    return {
        channelId: wireHex(vector.channel_id),
        requestId: hexToBytes(vector.request_id),
        partialSignature: hexToBytes(vector.partial_signature),
        nextMaterial:
            material === null
                ? null
                : {
                      nextCommitmentPoint: hexToBytes(material.next_commitment_point),
                      nextCommitmentNonce: hexToBytes(material.next_commitment_nonce),
                      nextRevocationNonce: hexToBytes(material.next_revocation_nonce),
                  },
    };
}

export function toSubmitWatchtowerSignatureParams(vector: SubmitWatchtowerSignatureParamsVector): SubmitWatchtowerSignatureParams {
    return { channelId: wireHex(vector.channel_id), requestId: hexToBytes(vector.request_id), signature: hexToBytes(vector.signature) };
}

export function toRpcSubmissionResult(vector: SubmissionResultVector): RpcSubmissionResult {
    return vector.outcome as RpcSubmissionResult;
}

export function toGetTenantRegistryNonceParams(vector: TenantRegistryNonceParamsVector): GetTenantRegistryNonceParams {
    return { rootSignerPubkey: hexToBytes(vector.root_signer_pubkey) };
}

export function toGetTenantRegistryNonceResult(vector: TenantRegistryNonceResultVector): GetTenantRegistryNonceResult {
    return {
        lspNodeId: hexToBytes(vector.lsp_node_id),
        rootSignerPubkey: hexToBytes(vector.root_signer_pubkey),
        nonce: hexToBytes(vector.nonce),
    };
}

export function toRegisterTenantParams(vector: RegisterTenantParamsVector): RegisterTenantParams {
    return {
        rootSignerPubkey: hexToBytes(vector.root_signer_pubkey),
        nonce: hexToBytes(vector.nonce),
        signature: hexToBytes(vector.signature),
    };
}

export function toLspTenantStatus(vector: LspTenantStatusVector): LspTenantStatus {
    return {
        tenantId: vector.tenant_id,
        rootSignerPubkey: vector.root_signer_pubkey === null ? null : hexToBytes(vector.root_signer_pubkey),
        invoicePubkey: hexToBytes(vector.invoice_pubkey),
        privateChannelId: vector.private_channel_id === null ? null : wireHex(vector.private_channel_id),
        createdAtMs: BigInt(vector.created_at),
        runtimeStatus: vector.runtime_status as RpcTenantRuntimeStatus,
        channelOnline: vector.channel_online,
    };
}

export function toRegisterTenantResult(vector: RegisterTenantResultVector): RegisterTenantResult {
    return { tenant: toLspTenantStatus(vector.tenant), accessToken: vector.access_token };
}

export function toListChannelsParams(vector: ListChannelsParamsVector): ListChannelsParams {
    if (vector.include_closed && vector.only_pending) throw new Error("fiber refuses both filters at once");
    if (vector.include_closed) return { filter: "include_closed" };
    if (vector.only_pending) return { filter: "only_pending" };
    return {};
}

export function toChannelState(vector: ChannelStateVector): RpcChannelState {
    return { name: vector.name, flags: vector.flags } as RpcChannelState;
}

export function toChannel(vector: ChannelVector): RpcChannel {
    return {
        channelId: wireHex(vector.channel_id),
        peerPubkey: hexToBytes(vector.pubkey),
        fundingUdtTypeScript: toScriptOrNull(vector.funding_udt_type_script),
        state: toChannelState(vector.state),
        localBalanceShannons: vector.local_balance,
        remoteBalanceShannons: vector.remote_balance,
        offeredTlcBalanceShannons: vector.offered_tlc_balance,
        receivedTlcBalanceShannons: vector.received_tlc_balance,
        createdAtMs: BigInt(vector.created_at),
        shutdownTransactionHash: vector.shutdown_transaction_hash === null ? null : hexToBytes(vector.shutdown_transaction_hash),
        failureDetail: vector.failure_detail,
    };
}

export function toNewInvoiceParams(vector: NewInvoiceParamsVector): NewInvoiceParams {
    const hashAlgorithm = HASH_ALGORITHMS[vector.hash_algorithm];
    if (hashAlgorithm === undefined) throw new Error(`the vectors carry an unknown hash algorithm: ${vector.hash_algorithm}`);
    const params: NewInvoiceParams = {
        amountShannons: vector.amount,
        currency: vector.currency as InvoiceCurrency,
        paymentHash: hexToBytes(vector.payment_hash),
        hashAlgorithm,
        expirySeconds: BigInt(vector.expiry),
    };
    if (vector.description !== null) params.description = vector.description;
    return params;
}

export function toNewInvoiceResult(vector: InvoiceResultVector): NewInvoiceResult {
    return { invoiceAddress: vector.invoice_address };
}

export function toRpcInvoice(vector: GetInvoiceResultVector): RpcInvoice {
    return { invoiceAddress: vector.invoice_address, status: vector.status as RpcInvoiceStatus };
}

export function toRpcPaymentHashParams(vector: PaymentHashParamsVector): RpcPaymentHashParams {
    return { paymentHash: hexToBytes(vector.payment_hash) };
}

export function toSettleInvoiceParams(vector: SettleInvoiceParamsVector): SettleInvoiceParams {
    return { paymentHash: hexToBytes(vector.payment_hash), paymentPreimage: hexToBytes(vector.payment_preimage) };
}

export function toSendPaymentParams(vector: SendPaymentParamsVector): SendPaymentParams {
    return { invoice: vector.invoice, maxFeeAmountShannons: vector.max_fee_amount, dryRun: vector.dry_run };
}

export function toRpcPayment(vector: PaymentVector): RpcPayment {
    return {
        paymentHash: hexToBytes(vector.payment_hash),
        status: vector.status as RpcPaymentStatus,
        createdAtMs: BigInt(vector.created_at),
        lastUpdatedAtMs: BigInt(vector.last_updated_at),
        failedError: vector.failed_error,
        feeShannons: vector.fee,
    };
}

// Total by type: a method without an encoder does not compile.
export const RPC_PARAMS_ENCODERS: { [Method in RpcMethod]: (values: RpcVectorShapes[Method]["params"]) => RpcParamsWire } = {
    open_channel_with_external_funding: (values) =>
        encodeOpenChannelWithExternalFundingParams(toOpenChannelWithExternalFundingParams(values)),
    submit_signed_funding_tx: (values) => encodeSubmitSignedFundingTxParams(toSubmitSignedFundingTxParams(values)),
    abandon_channel: (values) => encodeRpcChannelIdParams(toRpcChannelIdParams(values)),
    list_channels: (values) => encodeListChannelsParams(toListChannelsParams(values)),
    new_invoice: (values) => encodeNewInvoiceParams(toNewInvoiceParams(values)),
    get_invoice: (values) => encodeRpcPaymentHashParams(toRpcPaymentHashParams(values)),
    settle_invoice: (values) => encodeSettleInvoiceParams(toSettleInvoiceParams(values)),
    cancel_invoice: (values) => encodeRpcPaymentHashParams(toRpcPaymentHashParams(values)),
    send_payment: (values) => encodeSendPaymentParams(toSendPaymentParams(values)),
    get_payment: (values) => encodeRpcPaymentHashParams(toRpcPaymentHashParams(values)),
    open_tenant_channel: (values) => encodeOpenTenantChannelParams(toOpenTenantChannelParams(values)),
    shutdown_channel: (values) => encodeShutdownChannelParams(toShutdownChannelParams(values)),
    get_channel_signing_status: (values) => encodeRpcChannelIdParams(toRpcChannelIdParams(values)),
    submit_channel_signature: (values) => encodeSubmitChannelSignatureParams(toSubmitChannelSignatureParams(values)),
    get_watchtower_signing_status: (values) => encodeRpcChannelIdParams(toRpcChannelIdParams(values)),
    submit_watchtower_signature: (values) => encodeSubmitWatchtowerSignatureParams(toSubmitWatchtowerSignatureParams(values)),
    lsp_get_tenant_registry_nonce: (values) => encodeGetTenantRegistryNonceParams(toGetTenantRegistryNonceParams(values)),
    lsp_register_tenant: (values) => encodeRegisterTenantParams(toRegisterTenantParams(values)),
};

// Mirror of the harness's `without_nulls`: fiber reads an absent option and a `null` as one.
export function withoutNulls(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(withoutNulls);
    if (typeof value === "object" && value !== null) {
        return Object.fromEntries(
            Object.entries(value)
                .filter(([, member]) => member !== null)
                .map(([key, member]) => [key, withoutNulls(member)]),
        );
    }
    return value;
}
