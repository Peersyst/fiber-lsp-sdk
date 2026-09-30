import { COMPRESSED_POINT_LENGTH, HASH256_LENGTH, UINT64_MAX, assertBoolean, assertOneOf } from "../common";
import type { Field } from "../wire";
import {
    assertWireHexBytes,
    decodeBareHexBytes,
    decodeEnum,
    decodeFlags,
    decodeHexBytes,
    decodeNull,
    decodeOrNull,
    decodeScriptOrNull,
    decodeString,
    decodeTransaction,
    decodeUintHex,
    encodeBareHexBytes,
    encodeScript,
    encodeTransaction,
    malformed,
    readArray,
    readObject,
    requireHexBytes,
} from "../wire";
import { CHANNEL_STATE_FLAGS, CHANNEL_STATE_NAMES, LIST_CHANNELS_FILTERS } from "./rpc.constants";
import type {
    AbandonChannelParams,
    Channel,
    ChannelIdParamsWire,
    ChannelState,
    ChannelStateFlag,
    ChannelStateName,
    ChannelStateWire,
    ChannelWire,
    ListChannelsParams,
    ListChannelsParamsWire,
    ListChannelsResultWire,
    OpenChannelWithExternalFundingParams,
    OpenChannelWithExternalFundingParamsWire,
    OpenChannelWithExternalFundingResult,
    OpenChannelWithExternalFundingResultWire,
    SubmitSignedFundingTxParams,
    SubmitSignedFundingTxParamsWire,
    SubmitSignedFundingTxResult,
    SubmitSignedFundingTxResultWire,
} from "./rpc.types";
import { decodeRpcShannons, encodeRpcShannons } from "./utils";

/**
 * Writes the params of `open_channel_with_external_funding`, leaving the rest to the node's defaults.
 * @param params The open's params.
 * @returns The wire params.
 */
export function encodeOpenChannelWithExternalFundingParams(
    params: OpenChannelWithExternalFundingParams,
): OpenChannelWithExternalFundingParamsWire {
    assertBoolean("public", params.public);
    return {
        pubkey: encodeBareHexBytes("peerPubkey", params.peerPubkey, COMPRESSED_POINT_LENGTH),
        funding_amount: encodeRpcShannons("fundingAmountShannons", params.fundingAmountShannons),
        public: params.public,
        shutdown_script: encodeScript("shutdownScript", params.shutdownScript),
        funding_lock_script: encodeScript("fundingLockScript", params.fundingLockScript),
    };
}

/**
 * Reads the result of `open_channel_with_external_funding`.
 * @param field The result field.
 * @returns The final channel id and the unsigned funding transaction.
 */
export function decodeOpenChannelWithExternalFundingResult(field: Field): OpenChannelWithExternalFundingResult {
    const at = readObject<OpenChannelWithExternalFundingResultWire>(field);
    return {
        channelId: requireHexBytes(at("channel_id"), HASH256_LENGTH),
        unsignedFundingTx: decodeTransaction(at("unsigned_funding_tx")),
    };
}

/**
 * Writes the params of `submit_signed_funding_tx`.
 * @param params The channel and its signed funding transaction.
 * @returns The wire params.
 */
export function encodeSubmitSignedFundingTxParams(params: SubmitSignedFundingTxParams): SubmitSignedFundingTxParamsWire {
    assertWireHexBytes("channelId", params.channelId, HASH256_LENGTH);
    return { channel_id: params.channelId, signed_funding_tx: encodeTransaction("signedFundingTx", params.signedFundingTx) };
}

/**
 * Reads the result of `submit_signed_funding_tx`.
 * @param field The result field.
 * @returns The channel id and the funding transaction's hash.
 */
export function decodeSubmitSignedFundingTxResult(field: Field): SubmitSignedFundingTxResult {
    const at = readObject<SubmitSignedFundingTxResultWire>(field);
    return {
        channelId: requireHexBytes(at("channel_id"), HASH256_LENGTH),
        fundingTxHash: decodeHexBytes(at("funding_tx_hash"), HASH256_LENGTH),
    };
}

/**
 * Writes the params of `abandon_channel`.
 * @param params The channel to abandon.
 * @returns The wire params.
 */
export function encodeAbandonChannelParams(params: AbandonChannelParams): ChannelIdParamsWire {
    assertWireHexBytes("channelId", params.channelId, HASH256_LENGTH);
    return { channel_id: params.channelId };
}

/**
 * Reads the result of `abandon_channel`, which is `null`.
 * @param field The result field.
 */
export function decodeAbandonChannelResult(field: Field): void {
    decodeNull(field);
}

/**
 * Writes the params of `list_channels`, empty for the default mode.
 * @param params The listing's filter, if any.
 * @returns The wire params.
 */
export function encodeListChannelsParams(params: ListChannelsParams): ListChannelsParamsWire {
    if (params.filter === undefined) return {};
    assertOneOf("filter", params.filter, LIST_CHANNELS_FILTERS);
    return params.filter === "include_closed" ? { include_closed: true } : { only_pending: true };
}

/**
 * Reads the result of `list_channels`.
 * @param field The result field.
 * @returns The channels.
 */
export function decodeListChannelsResult(field: Field): Channel[] {
    return readArray(readObject<ListChannelsResultWire>(field)("channels")).map(decodeChannel);
}

/**
 * Reads one channel of a listing.
 * @param field Field to read.
 * @returns The channel.
 */
function decodeChannel(field: Field): Channel {
    const at = readObject<ChannelWire>(field);
    return {
        channelId: requireHexBytes(at("channel_id"), HASH256_LENGTH),
        peerPubkey: decodeBareHexBytes(at("pubkey"), COMPRESSED_POINT_LENGTH),
        fundingUdtTypeScript: decodeScriptOrNull(at("funding_udt_type_script")),
        state: decodeChannelState(at("state")),
        localBalanceShannons: decodeRpcShannons(at("local_balance")),
        remoteBalanceShannons: decodeRpcShannons(at("remote_balance")),
        offeredTlcBalanceShannons: decodeRpcShannons(at("offered_tlc_balance")),
        receivedTlcBalanceShannons: decodeRpcShannons(at("received_tlc_balance")),
        createdAtMs: decodeUintHex(at("created_at"), UINT64_MAX),
        shutdownTransactionHash: decodeOrNull(at("shutdown_transaction_hash"), (hash) => decodeHexBytes(hash, HASH256_LENGTH)),
        failureDetail: decodeOrNull(at("failure_detail"), decodeString),
    };
}

/**
 * Reads a channel state.
 * @param field Field to read.
 * @returns The state.
 */
export function decodeChannelState(field: Field): ChannelState {
    const at = readObject<ChannelStateWire>(field);
    return stateOf(decodeEnum(at("state_name"), CHANNEL_STATE_NAMES), at("state_flags"));
}

/**
 * Reads the flags of a state whose name is known.
 * @param name The state's name.
 * @param flagsField The `state_flags` field.
 * @returns The state.
 */
function stateOf<Name extends ChannelStateName>(name: Name, flagsField: Field): ChannelState {
    const names: readonly ChannelStateFlag<Name>[] = CHANNEL_STATE_FLAGS[name];
    if (names.length > 0) return { name, flags: decodeFlags(flagsField, names) } as ChannelState;
    // Fiber's unit variants carry no `state_flags` at all, so even `""` did not come from it.
    if (flagsField.value !== undefined) malformed(flagsField, `must be absent for ${name}`);
    return { name, flags: [] } as ChannelState;
}
