import {
    COMPRESSED_POINT_LENGTH,
    HASH256_LENGTH,
    PUBLIC_NONCE_LENGTH,
    UINT64_MAX,
    assertBoolean,
    assertOneOf,
    isPlainObject,
} from "../common";
import type { WireField, WireFieldReader } from "../wire";
import {
    assertWireHexBytes,
    decodeBareHexBytes,
    decodeEnum,
    decodeFlags,
    decodeHexBytes,
    decodeNull,
    decodeOrNull,
    decodeScript,
    decodeScriptOrNull,
    decodeString,
    decodeTransaction,
    decodeUintHex,
    encodeBareHexBytes,
    encodeHexBytes,
    encodeScript,
    encodeTransaction,
    encodeUintHex,
    malformedWireField,
    readArray,
    readObject,
    requireHexBytes,
    WIRE_FLAG_SEPARATOR,
} from "../wire";
import { LIST_CHANNELS_FILTERS, RPC_CHANNEL_STATE_FLAGS, RPC_CHANNEL_STATE_NAMES } from "./rpc.constants";
import type {
    ChannelOpenSignerMaterial,
    ChannelOpenSignerMaterialWire,
    ListChannelsParams,
    ListChannelsParamsWire,
    ListChannelsResultWire,
    OpenChannelWithExternalFundingParams,
    OpenChannelWithExternalFundingParamsWire,
    OpenChannelWithExternalFundingResult,
    OpenChannelWithExternalFundingResultWire,
    OpenTenantChannelParams,
    OpenTenantChannelParamsWire,
    OpenTenantChannelResult,
    OpenTenantChannelResultWire,
    RpcChannel,
    RpcChannelState,
    RpcChannelStateFlag,
    RpcChannelStateName,
    RpcChannelStateWire,
    RpcChannelWire,
    RpcListedChannelState,
    ShutdownChannelParams,
    ShutdownChannelParamsWire,
    SubmitSignedFundingTxParams,
    SubmitSignedFundingTxParamsWire,
    SubmitSignedFundingTxResult,
    SubmitSignedFundingTxResultWire,
    TenantChannelOpeningContext,
    TenantChannelOpeningContextWire,
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
export function decodeOpenChannelWithExternalFundingResult(field: WireField): OpenChannelWithExternalFundingResult {
    const at = readObject<OpenChannelWithExternalFundingResultWire>(field);
    return {
        channelId: requireHexBytes(at("channel_id"), HASH256_LENGTH),
        unsignedFundingTx: decodeTransaction(at("unsigned_funding_tx")),
    };
}

/**
 * Writes the params of `open_tenant_channel`: the external-funding open, private, with the device's public signer material.
 * @param params The channel to open and the material of its signer.
 * @returns The wire params.
 */
export function encodeOpenTenantChannelParams(params: OpenTenantChannelParams): OpenTenantChannelParamsWire {
    const { peerPubkey, fundingAmountShannons, shutdownScript, fundingLockScript, commitmentDelayEpoch, commitmentFeeRate } = params;
    return {
        ...encodeOpenChannelWithExternalFundingParams({
            peerPubkey,
            fundingAmountShannons,
            public: false,
            shutdownScript,
            fundingLockScript,
        }),
        // Repeated after the spread to narrow `public` to the literal the wire type states.
        public: false,
        ...(commitmentDelayEpoch === undefined
            ? {}
            : { commitment_delay_epoch: encodeUintHex("commitmentDelayEpoch", commitmentDelayEpoch, UINT64_MAX) }),
        ...(commitmentFeeRate === undefined
            ? {}
            : { commitment_fee_rate: encodeUintHex("commitmentFeeRate", commitmentFeeRate, UINT64_MAX) }),
        external_channel_signer: encodeChannelOpenSignerMaterial(params.signerMaterial),
    };
}

/**
 * Writes the public signer material an open carries: the points bare, the nonces with their prefix.
 * @param material The material.
 * @returns The wire material.
 */
function encodeChannelOpenSignerMaterial(material: ChannelOpenSignerMaterial): ChannelOpenSignerMaterialWire {
    const name = "signerMaterial";
    if (!isPlainObject(material)) throw new TypeError(`${name} must be an object`);
    const { channelAnnouncementNonce } = material;
    return {
        base_public_keys: {
            funding_pubkey: encodeBareHexBytes(`${name}.fundingPubkey`, material.fundingPubkey, COMPRESSED_POINT_LENGTH),
            tlc_base_key: encodeBareHexBytes(`${name}.tlcBaseKey`, material.tlcBaseKey, COMPRESSED_POINT_LENGTH),
        },
        first_commitment_point: encodeBareHexBytes(`${name}.firstCommitmentPoint`, material.firstCommitmentPoint, COMPRESSED_POINT_LENGTH),
        second_commitment_point: encodeBareHexBytes(
            `${name}.secondCommitmentPoint`,
            material.secondCommitmentPoint,
            COMPRESSED_POINT_LENGTH,
        ),
        commitment_nonce: encodeHexBytes(`${name}.commitmentNonce`, material.commitmentNonce, PUBLIC_NONCE_LENGTH),
        next_commitment_nonce: encodeHexBytes(`${name}.nextCommitmentNonce`, material.nextCommitmentNonce, PUBLIC_NONCE_LENGTH),
        revocation_nonce: encodeHexBytes(`${name}.revocationNonce`, material.revocationNonce, PUBLIC_NONCE_LENGTH),
        ...(channelAnnouncementNonce === null
            ? {}
            : {
                  channel_announcement_nonce: encodeHexBytes(
                      `${name}.channelAnnouncementNonce`,
                      channelAnnouncementNonce,
                      PUBLIC_NONCE_LENGTH,
                  ),
              }),
    };
}

/**
 * Reads the result of `open_tenant_channel`.
 * @param field The result field.
 * @returns The final channel id, the unsigned funding transaction and the terms the node froze.
 */
export function decodeOpenTenantChannelResult(field: WireField): OpenTenantChannelResult {
    const at = readObject<OpenTenantChannelResultWire>(field);
    return {
        ...decodeOpenChannelWithExternalFundingResult(field),
        openingContext: decodeTenantChannelOpeningContext(at("opening_context")),
    };
}

/**
 * Reads the opening context of a tenant channel.
 * @param field Field to read.
 * @returns The context.
 */
function decodeTenantChannelOpeningContext(field: WireField): TenantChannelOpeningContext {
    const at = readObject<TenantChannelOpeningContextWire>(field);
    return {
        remoteFundingKey: decodeBareHexBytes(at("remote_funding_key"), COMPRESSED_POINT_LENGTH),
        remoteSettlementKey: decodeBareHexBytes(at("remote_settlement_key"), COMPRESSED_POINT_LENGTH),
        remoteShutdownScript: decodeScript(at("remote_shutdown_script")),
        commitmentDelayEpoch: decodeUintHex(at("commitment_delay_epoch"), UINT64_MAX),
        commitmentFeeRate: decodeUintHex(at("commitment_fee_rate"), UINT64_MAX),
        localAmountShannons: decodeRpcShannons(at("local_amount")),
        remoteAmountShannons: decodeRpcShannons(at("remote_amount")),
        localReservedCkbShannons: decodeUintHex(at("local_reserved_ckb_amount"), UINT64_MAX).toString(),
        remoteReservedCkbShannons: decodeUintHex(at("remote_reserved_ckb_amount"), UINT64_MAX).toString(),
    };
}

/**
 * Writes the params of `shutdown_channel`, an absent option left out for the node's default.
 * @param params The channel to close and the close's options.
 * @returns The wire params.
 */
export function encodeShutdownChannelParams(params: ShutdownChannelParams): ShutdownChannelParamsWire {
    const { closeScript, feeRate, force } = params;
    assertWireHexBytes("channelId", params.channelId, HASH256_LENGTH);
    if (closeScript !== undefined && !isPlainObject(closeScript)) throw new TypeError("closeScript must be an object");
    if (force !== undefined) assertBoolean("force", force);
    return {
        channel_id: params.channelId,
        ...(closeScript === undefined ? {} : { close_script: encodeScript("closeScript", closeScript) }),
        ...(feeRate === undefined ? {} : { fee_rate: encodeUintHex("feeRate", feeRate, UINT64_MAX) }),
        ...(force === undefined ? {} : { force }),
    };
}

/**
 * Reads the result of `shutdown_channel`, which is `null`.
 * @param field The result field.
 */
export function decodeShutdownChannelResult(field: WireField): void {
    decodeNull(field);
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
export function decodeSubmitSignedFundingTxResult(field: WireField): SubmitSignedFundingTxResult {
    const at = readObject<SubmitSignedFundingTxResultWire>(field);
    return {
        channelId: requireHexBytes(at("channel_id"), HASH256_LENGTH),
        fundingTxHash: decodeHexBytes(at("funding_tx_hash"), HASH256_LENGTH),
    };
}

/**
 * Reads the result of `abandon_channel`, which is `null`.
 * @param field The result field.
 */
export function decodeAbandonChannelResult(field: WireField): void {
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
export function decodeListChannelsResult(field: WireField): RpcChannel[] {
    return readArray(readObject<ListChannelsResultWire>(field)("channels")).map(decodeRpcChannel);
}

/**
 * Reads only the ids of a `list_channels` result: a channel in a form this SDK does not know still yields its id.
 * @param field The result field.
 * @returns The channel ids, in the node's order.
 */
export function decodeListChannelIdsResult(field: WireField): string[] {
    return readListedChannels(field).map((channel) => readListedChannelId(readObject<RpcChannelWire>(channel)));
}

/**
 * Reads only the ids and states of a `list_channels` result, the states as strings fiber may add to.
 * @param field The result field.
 * @returns The channels' ids and states, in the node's order.
 */
export function decodeListChannelStatesResult(field: WireField): RpcListedChannelState[] {
    return readListedChannels(field).map((channel) => {
        const at = readObject<RpcChannelWire>(channel);
        const channelId = readListedChannelId(at);
        const state = readObject<RpcChannelStateWire>(at("state"));
        const flagsField = state("state_flags");
        // Fiber's unit variants carry no `state_flags`.
        const flags = flagsField.value === undefined ? "" : decodeString(flagsField);
        return {
            channelId,
            stateName: decodeString(state("state_name")),
            stateFlags: flags === "" ? [] : flags.split(WIRE_FLAG_SEPARATOR),
        };
    });
}

/**
 * Reads the entries of a `list_channels` result.
 * @param field The result field.
 * @returns The entries' fields.
 */
function readListedChannels(field: WireField): WireField[] {
    return readArray(readObject<ListChannelsResultWire>(field)("channels"));
}

/**
 * Reads a listed channel's id.
 * @param at The channel's reader.
 * @returns The id, as wire hex.
 */
function readListedChannelId(at: WireFieldReader<RpcChannelWire>): string {
    return requireHexBytes(at("channel_id"), HASH256_LENGTH);
}

/**
 * Reads one channel of a listing.
 * @param field Field to read.
 * @returns The channel.
 */
function decodeRpcChannel(field: WireField): RpcChannel {
    const at = readObject<RpcChannelWire>(field);
    return {
        channelId: requireHexBytes(at("channel_id"), HASH256_LENGTH),
        peerPubkey: decodeBareHexBytes(at("pubkey"), COMPRESSED_POINT_LENGTH),
        fundingUdtTypeScript: decodeScriptOrNull(at("funding_udt_type_script")),
        state: decodeRpcChannelState(at("state")),
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
export function decodeRpcChannelState(field: WireField): RpcChannelState {
    const at = readObject<RpcChannelStateWire>(field);
    return stateOf(decodeEnum(at("state_name"), RPC_CHANNEL_STATE_NAMES), at("state_flags"));
}

/**
 * Reads the flags of a state whose name is known.
 * @param name The state's name.
 * @param flagsField The `state_flags` field.
 * @returns The state.
 */
function stateOf<Name extends RpcChannelStateName>(name: Name, flagsField: WireField): RpcChannelState {
    const names: readonly RpcChannelStateFlag<Name>[] = RPC_CHANNEL_STATE_FLAGS[name];
    if (names.length > 0) return { name, flags: decodeFlags(flagsField, names) } as RpcChannelState;
    // Fiber's unit variants carry no `state_flags` at all, so even `""` did not come from it.
    if (flagsField.value !== undefined) malformedWireField(flagsField, `must be absent for ${name}`);
    return { name, flags: [] } as RpcChannelState;
}
