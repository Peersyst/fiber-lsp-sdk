export const RPC_METHODS = [
    "open_channel_with_external_funding",
    "submit_signed_funding_tx",
    "abandon_channel",
    "list_channels",
    "new_invoice",
    "get_invoice",
    "settle_invoice",
    "cancel_invoice",
    "send_payment",
    "get_payment",
] as const;

export const JSON_RPC_VERSION = "2.0";

export const JSON_CONTENT_TYPE = "application/json";

/**
 * Fiber's middleware matches the prefix case-sensitively.
 */
export const BEARER_PREFIX = "Bearer ";

/**
 * Fiber's auth refusal; its message varies, so only the code identifies it.
 */
export const RPC_UNAUTHORIZED_CODE = -32999;

/**
 * jsonrpsee's `CALL_EXECUTION_FAILED_CODE`, which every fiber handler error carries.
 */
export const RPC_CALL_FAILED_CODE = -32000;

export const CHANNEL_STATE_NAMES = [
    "NegotiatingFunding",
    "CollaboratingFundingTx",
    "SigningCommitment",
    "AwaitingTxSignatures",
    "AwaitingChannelReady",
    "ChannelReady",
    "ShuttingDown",
    "Closed",
    "Stale",
] as const;

/**
 * Fiber's flag names per channel state (`fiber-json-types/src/channel.rs`), composites included: a name is written whenever
 * its bits overlap, so `OUR_INIT_SENT` alone reads `OUR_INIT_SENT|INIT_SENT`.
 */
export const CHANNEL_STATE_FLAGS = {
    NegotiatingFunding: ["OUR_INIT_SENT", "THEIR_INIT_SENT", "INIT_SENT", "AWAITING_EXTERNAL_FUNDING"],
    CollaboratingFundingTx: [
        "AWAITING_REMOTE_TX_COLLABORATION_MSG",
        "PREPARING_LOCAL_TX_COLLABORATION_MSG",
        "OUR_TX_COMPLETE_SENT",
        "THEIR_TX_COMPLETE_SENT",
        "COLLABORATION_COMPLETED",
    ],
    SigningCommitment: ["OUR_COMMITMENT_SIGNED_SENT", "THEIR_COMMITMENT_SIGNED_SENT", "COMMITMENT_SIGNED_SENT"],
    AwaitingTxSignatures: ["OUR_TX_SIGNATURES_SENT", "THEIR_TX_SIGNATURES_SENT", "TX_SIGNATURES_SENT"],
    AwaitingChannelReady: ["OUR_CHANNEL_READY", "THEIR_CHANNEL_READY", "CHANNEL_READY"],
    ChannelReady: [],
    ShuttingDown: [
        "OUR_SHUTDOWN_SENT",
        "THEIR_SHUTDOWN_SENT",
        "AWAITING_PENDING_TLCS",
        "DROPPING_PENDING",
        "WAITING_COMMITMENT_CONFIRMATION",
    ],
    Closed: ["COOPERATIVE", "UNCOOPERATIVE_LOCAL", "ABANDONED", "FUNDING_ABORTED", "UNCOOPERATIVE_REMOTE", "WAITING_ONCHAIN_SETTLEMENT"],
    Stale: [],
} as const satisfies Record<(typeof CHANNEL_STATE_NAMES)[number], readonly string[]>;

/**
 * Fiber refuses both `list_channels` options at once, hence one filter.
 */
export const LIST_CHANNELS_FILTERS = ["include_closed", "only_pending"] as const;
