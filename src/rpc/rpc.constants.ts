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
