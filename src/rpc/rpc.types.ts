import type { Script, Transaction } from "../common";
import type { BareHexWire, Field, HexWire, ScriptWire, TransactionWire, UintHexWire } from "../wire";
import type { IFetchLike } from "./interfaces";
import type { CHANNEL_STATE_FLAGS, CHANNEL_STATE_NAMES, JSON_RPC_VERSION, LIST_CHANNELS_FILTERS, RPC_METHODS } from "./rpc.constants";

export type RpcMethod = (typeof RPC_METHODS)[number];

export type RpcParamsWire = Record<string, unknown>;

export type RpcRequestWire = { jsonrpc: typeof JSON_RPC_VERSION; id: number; method: RpcMethod; params: [RpcParamsWire] };

export type RpcErrorObjectWire = { code: number; message: string };

export type RpcResponseWire = { jsonrpc: string; id: number | null; result: unknown; error: RpcErrorObjectWire };

export type RpcResponse = { result: Field } | { error: RpcErrorObjectWire };

export type RpcResultDecoder<Result> = (field: Field) => Result;

export type FiberRpcClientOptions = {
    url: string;
    /**
     * Biscuit token, base64; omitted when the node's RPC has no auth.
     */
    token?: string;
    fetch: IFetchLike;
};

export type OpenChannelWithExternalFundingParamsWire = {
    pubkey: BareHexWire;
    funding_amount: UintHexWire;
    public: boolean;
    shutdown_script: ScriptWire;
    funding_lock_script: ScriptWire;
};

export type OpenChannelWithExternalFundingResultWire = { channel_id: HexWire; unsigned_funding_tx: TransactionWire };

export type SubmitSignedFundingTxParamsWire = { channel_id: HexWire; signed_funding_tx: TransactionWire };

export type SubmitSignedFundingTxResultWire = { channel_id: HexWire; funding_tx_hash: HexWire };

export type ChannelIdParamsWire = { channel_id: HexWire };

export type ListChannelsParamsWire = { include_closed?: true; only_pending?: true };

export type ChannelStateName = (typeof CHANNEL_STATE_NAMES)[number];

/**
 * Absent on the two states without flags.
 */
export type ChannelStateWire = { state_name: ChannelStateName; state_flags?: string };

/**
 * The members the client reads; fiber writes more.
 */
export type ChannelWire = {
    channel_id: HexWire;
    pubkey: BareHexWire;
    funding_udt_type_script: ScriptWire | null;
    state: ChannelStateWire;
    local_balance: UintHexWire;
    offered_tlc_balance: UintHexWire;
    remote_balance: UintHexWire;
    received_tlc_balance: UintHexWire;
    created_at: UintHexWire;
    shutdown_transaction_hash: HexWire | null;
    failure_detail: string | null;
};

export type ListChannelsResultWire = { channels: ChannelWire[] };

/**
 * Filled in as each method's encoder lands.
 */
export type RpcParamsWireByMethod = {
    open_channel_with_external_funding: OpenChannelWithExternalFundingParamsWire;
    submit_signed_funding_tx: SubmitSignedFundingTxParamsWire;
    abandon_channel: ChannelIdParamsWire;
    list_channels: ListChannelsParamsWire;
};

export type RpcParamsWireOf<Method extends RpcMethod> = Method extends keyof RpcParamsWireByMethod
    ? RpcParamsWireByMethod[Method]
    : RpcParamsWire;

export type OpenChannelWithExternalFundingParams = {
    peerPubkey: Uint8Array;
    /**
     * The total, reserved CKB included.
     */
    fundingAmountShannons: string;
    public: boolean;
    shutdownScript: Script;
    fundingLockScript: Script;
};

export type OpenChannelWithExternalFundingResult = {
    /**
     * The final id, not the temporary one.
     */
    channelId: string;
    /**
     * The only copy of it: no other method returns it.
     */
    unsignedFundingTx: Transaction;
};

export type SubmitSignedFundingTxParams = { channelId: string; signedFundingTx: Transaction };

export type SubmitSignedFundingTxResult = { channelId: string; fundingTxHash: Uint8Array };

export type AbandonChannelParams = { channelId: string };

export type ListChannelsFilter = (typeof LIST_CHANNELS_FILTERS)[number];

export type ListChannelsParams = { filter?: ListChannelsFilter };

export type ChannelStateFlag<Name extends ChannelStateName> = (typeof CHANNEL_STATE_FLAGS)[Name][number];

export type ChannelState = { [Name in ChannelStateName]: { name: Name; flags: ChannelStateFlag<Name>[] } }[ChannelStateName];

export type Channel = {
    /**
     * Wire hex: the key the policy's channel alias is stored under.
     */
    channelId: string;
    peerPubkey: Uint8Array;
    fundingUdtTypeScript: Script | null;
    state: ChannelState;
    localBalanceShannons: string;
    remoteBalanceShannons: string;
    offeredTlcBalanceShannons: string;
    receivedTlcBalanceShannons: string;
    createdAtMs: bigint;
    /**
     * Set only once the closing transaction confirmed.
     */
    shutdownTransactionHash: Uint8Array | null;
    /**
     * Fiber's free text on a failed opening, the only thing telling an abandon from a timeout.
     */
    failureDetail: string | null;
};
