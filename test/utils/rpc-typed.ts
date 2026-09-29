import { hexToBytes } from "@noble/hashes/utils.js";
import type { DepType, Transaction } from "../../src/common";
import type {
    AbandonChannelParams,
    Channel,
    ChannelState,
    ListChannelsParams,
    OpenChannelWithExternalFundingParams,
    OpenChannelWithExternalFundingResult,
    RpcMethod,
    RpcParamsWire,
    SubmitSignedFundingTxParams,
    SubmitSignedFundingTxResult,
} from "../../src/rpc";
import {
    encodeAbandonChannelParams,
    encodeListChannelsParams,
    encodeOpenChannelWithExternalFundingParams,
    encodeSubmitSignedFundingTxParams,
} from "../../src/rpc";
import { toOutPoint, toScript, toScriptOrNull } from "./digest-inputs";
import { wireHex } from "./wire-requests";
import type {
    ChannelIdParamsVector,
    ChannelStateVector,
    ChannelVector,
    ListChannelsParamsVector,
    OpenChannelParamsVector,
    OpenChannelResultVector,
    RpcVectorShapes,
    SubmitSignedFundingTxParamsVector,
    SubmitSignedFundingTxResultVector,
    TransactionVector,
} from "./rpc-vectors";

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

export function toChannelState(vector: ChannelStateVector): ChannelState {
    return { name: vector.name, flags: vector.flags } as ChannelState;
}

export function toChannel(vector: ChannelVector): Channel {
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

type ParamsEncoders = { [Method in RpcMethod]: (values: RpcVectorShapes[Method]["params"]) => RpcParamsWire };

/**
 * Filled in as each method's encoder lands.
 */
export const RPC_PARAMS_ENCODERS: Partial<ParamsEncoders> = {
    open_channel_with_external_funding: (values) =>
        encodeOpenChannelWithExternalFundingParams(toOpenChannelWithExternalFundingParams(values)),
    submit_signed_funding_tx: (values) => encodeSubmitSignedFundingTxParams(toSubmitSignedFundingTxParams(values)),
    abandon_channel: (values) => encodeAbandonChannelParams(toAbandonChannelParams(values)),
    list_channels: (values) => encodeListChannelsParams(toListChannelsParams(values)),
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
