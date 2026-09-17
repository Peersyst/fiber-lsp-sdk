import type { InboundFrameWire } from "./protocol.types";

export const PROTOCOL_VERSION = 1;

export const SIGNER_METHODS = [
    "get_base_public_keys",
    "get_commitment_point",
    "get_commitment_pub_nonce",
    "get_revocation_pub_nonce",
    "get_channel_announcement_pub_nonce",
    "get_settlement_keys",
    "partial_sign_commitment_tx",
    "partial_sign_closing_tx",
    "partial_sign_revocation",
    "partial_sign_channel_announcement",
] as const;

export const INBOUND_FRAME_TYPES = [
    "challenge",
    "session_established",
    "ping",
    "pong",
    "channel_registered",
    "error",
    "sign_request",
] as const satisfies readonly InboundFrameWire["type"][];

export const CHALLENGE_LENGTH = 32;

/**
 * Opaque to the device and echoed verbatim; bounded so an id cannot carry a payload.
 */
export const MAX_REQUEST_ID_LENGTH = 64;

/**
 * Domain separation of the session challenge: the identity key never signs bare bytes the bridge chose.
 */
export const SESSION_CHALLENGE_LABEL = "fiber-lsp-sdk session challenge v1";
