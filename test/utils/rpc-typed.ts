import { hexToBytes } from "@noble/hashes/utils.js";
import type { DepType, TlcHashAlgorithm, Transaction } from "../../src/common";
import type {
    AbandonChannelParams,
    ListChannelsParams,
    NewInvoiceParams,
    NewInvoiceResult,
    OpenChannelWithExternalFundingParams,
    OpenChannelWithExternalFundingResult,
    RpcChannel,
    RpcChannelState,
    RpcInvoice,
    RpcInvoiceCurrency,
    RpcInvoiceStatus,
    RpcMethod,
    RpcParamsWire,
    RpcPayment,
    RpcPaymentHashParams,
    RpcPaymentStatus,
    SendPaymentParams,
    SettleInvoiceParams,
    SubmitSignedFundingTxParams,
    SubmitSignedFundingTxResult,
} from "../../src/rpc";
import {
    encodeAbandonChannelParams,
    encodeListChannelsParams,
    encodeNewInvoiceParams,
    encodeOpenChannelWithExternalFundingParams,
    encodeRpcPaymentHashParams,
    encodeSendPaymentParams,
    encodeSettleInvoiceParams,
    encodeSubmitSignedFundingTxParams,
} from "../../src/rpc";
import { toOutPoint, toScript, toScriptOrNull } from "./digest-inputs";
import { HASH_ALGORITHM_WIRE, wireHex } from "./wire-requests";
import type {
    ChannelIdParamsVector,
    ChannelStateVector,
    ChannelVector,
    GetInvoiceResultVector,
    InvoiceResultVector,
    ListChannelsParamsVector,
    NewInvoiceParamsVector,
    OpenChannelParamsVector,
    OpenChannelResultVector,
    PaymentHashParamsVector,
    PaymentVector,
    RpcVectorShapes,
    SendPaymentParamsVector,
    SettleInvoiceParamsVector,
    SubmitSignedFundingTxParamsVector,
    SubmitSignedFundingTxResultVector,
    TransactionVector,
} from "./rpc-vectors";

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

export function toAbandonChannelParams(vector: ChannelIdParamsVector): AbandonChannelParams {
    return { channelId: wireHex(vector.channel_id) };
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
        currency: vector.currency as RpcInvoiceCurrency,
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
    abandon_channel: (values) => encodeAbandonChannelParams(toAbandonChannelParams(values)),
    list_channels: (values) => encodeListChannelsParams(toListChannelsParams(values)),
    new_invoice: (values) => encodeNewInvoiceParams(toNewInvoiceParams(values)),
    get_invoice: (values) => encodeRpcPaymentHashParams(toRpcPaymentHashParams(values)),
    settle_invoice: (values) => encodeSettleInvoiceParams(toSettleInvoiceParams(values)),
    cancel_invoice: (values) => encodeRpcPaymentHashParams(toRpcPaymentHashParams(values)),
    send_payment: (values) => encodeSendPaymentParams(toSendPaymentParams(values)),
    get_payment: (values) => encodeRpcPaymentHashParams(toRpcPaymentHashParams(values)),
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
