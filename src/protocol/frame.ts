import { SCHNORR_SIGNATURE_LENGTH, X_ONLY_PUBLIC_KEY_LENGTH, assertBytes } from "../common";
import type { Field } from "../wire";
import {
    decodeEnum,
    decodeHexBytes,
    decodeNonEmptyString,
    decodeString,
    decodeUnsignedInteger,
    encodeHexBytes,
    malformed,
    readObject,
} from "../wire";
import { decodeChannelRegistered, encodeRegisterChannel } from "./channel-registration";
import { CHALLENGE_LENGTH, INBOUND_FRAME_TYPES, PROTOCOL_VERSION } from "./protocol.constants";
import type {
    ChallengeWire,
    ErrorWire,
    InboundFrame,
    InboundFrameWire,
    OutboundFrame,
    OutboundFrameWire,
    SessionEstablishedWire,
} from "./protocol.types";
import { decodeSignRequest, encodeSignResponse } from "./sign-request";
import { decodeRequestId } from "./utils";

const FRAME_PATH = "frame";

/**
 * Reads a socket message as a typed inbound frame: text only, one JSON object, dispatched on its `type`.
 * @param data What the socket delivered, of whatever type the runtime gives it.
 * @returns The frame; a `sign_request` carries its envelope, with the params still to decode.
 */
export function decodeInboundFrame(data: unknown): InboundFrame {
    const frame: Field = { value: parseFrame(data), path: FRAME_PATH };
    const type = decodeEnum(readObject<InboundFrameWire>(frame)("type"), INBOUND_FRAME_TYPES);
    const body: Field = { value: frame.value, path: type };
    switch (type) {
        case "challenge":
            return decodeChallenge(body);
        case "session_established":
            return decodeSessionEstablished(body);
        case "ping":
        case "pong":
            return { type };
        case "channel_registered":
            return decodeChannelRegistered(body);
        case "error":
            return decodeErrorFrame(body);
        case "sign_request":
            return { type, request: decodeSignRequest(body) };
    }
}

/**
 * Writes an outbound frame as the text the socket sends.
 * @param frame Frame to write.
 * @returns The JSON text.
 */
export function encodeOutboundFrame(frame: OutboundFrame): string {
    return JSON.stringify(encodeFrame(frame));
}

/**
 * Parses a socket message as JSON, refusing anything that is not text.
 * @param data What the socket delivered.
 * @returns The parsed value, still unknown.
 */
function parseFrame(data: unknown): unknown {
    const field: Field = { value: data, path: FRAME_PATH };
    if (typeof data !== "string") malformed(field, "must be a text frame");
    try {
        return JSON.parse(data) as unknown;
    } catch {
        malformed(field, "must be valid JSON");
    }
}

/**
 * Reads a `challenge` frame.
 * @param field The frame.
 * @returns The challenge bytes.
 */
function decodeChallenge(field: Field): Extract<InboundFrame, { type: "challenge" }> {
    const at = readObject<ChallengeWire>(field);
    return { type: "challenge", challenge: decodeHexBytes(at("challenge"), CHALLENGE_LENGTH) };
}

/**
 * Reads a `session_established` frame; whether the version matches is the session's decision, not a decode refusal.
 * @param field The frame.
 * @returns The bridge's version and pending count.
 */
function decodeSessionEstablished(field: Field): Extract<InboundFrame, { type: "session_established" }> {
    const at = readObject<SessionEstablishedWire>(field);
    return {
        type: "session_established",
        protocolVersion: decodeUnsignedInteger(at("protocol_version"), Number.MAX_SAFE_INTEGER),
        pendingRequests: decodeUnsignedInteger(at("pending_requests"), Number.MAX_SAFE_INTEGER),
    };
}

/**
 * Reads an `error` frame, the failure of a device-initiated request.
 * @param field The frame.
 * @returns The failure, with the bridge's own code.
 */
function decodeErrorFrame(field: Field): Extract<InboundFrame, { type: "error" }> {
    const at = readObject<ErrorWire>(field);
    return {
        type: "error",
        requestId: decodeRequestId(at("request_id")),
        code: decodeNonEmptyString(at("code")),
        message: decodeString(at("message")),
    };
}

/**
 * Writes an outbound frame as its wire object.
 * @param frame Frame to write.
 * @returns The wire object.
 */
function encodeFrame(frame: OutboundFrame): OutboundFrameWire {
    switch (frame.type) {
        case "signed_challenge":
            assertBytes("publicKey", frame.publicKey, X_ONLY_PUBLIC_KEY_LENGTH);
            assertBytes("signature", frame.signature, SCHNORR_SIGNATURE_LENGTH);
            return {
                type: "signed_challenge",
                protocol_version: PROTOCOL_VERSION,
                public_key: encodeHexBytes(frame.publicKey),
                signature: encodeHexBytes(frame.signature),
            };
        case "ping":
        case "pong":
            return { type: frame.type };
        case "register_channel":
            return encodeRegisterChannel(frame.requestId, frame.registration);
        case "sign_response":
            return encodeSignResponse(frame);
    }
}
