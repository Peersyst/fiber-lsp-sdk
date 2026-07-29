export const PROTOCOL_VERSION = 1;

export const SIGNER_ERROR_CODES = ["unknown_channel", "malformed", "stale_state", "policy_refusal"] as const;

export type SignerErrorCode = (typeof SIGNER_ERROR_CODES)[number];
