import { hexToBytes } from "@noble/hashes/utils.js";
import { PROTOCOL_VERSION, ProtocolError, decodeInboundFrame, encodeOutboundFrame } from "../../../src/protocol";
import { answerableRefusal, refusal } from "../../utils/refusal";
import { withField } from "../../utils/with-field";

const CHANNEL_ID = `0x${"1f".repeat(32)}`;
const CHALLENGE_HEX = "5a".repeat(32);
const SIGN_REQUEST = {
    type: "sign_request",
    request_id: "0x2a",
    channel_id: CHANNEL_ID,
    method: "get_commitment_point",
    params: { commitment_number: "0x5" },
    state_version: "0x7",
};

function decode(frame: unknown) {
    return decodeInboundFrame(JSON.stringify(frame));
}

describe("decodeInboundFrame", () => {
    it.each([new Uint8Array(3), new ArrayBuffer(3), {}, undefined, null, 1])("refuses %p, since only text frames are spoken", (data) => {
        expect(refusal(() => decodeInboundFrame(data)).message).toBe("frame must be a text frame");
    });

    it.each(["{", "", "{type: challenge}", "{'type': 'ping'}"])("refuses %p as invalid JSON", (data) => {
        expect(refusal(() => decodeInboundFrame(data)).message).toBe("frame must be valid JSON");
    });

    it.each(["[]", '"challenge"', "1", "null", "true"])("refuses %s, which is JSON but not a frame", (data) => {
        expect(refusal(() => decodeInboundFrame(data)).message).toBe("frame must be an object");
    });

    it.each([{}, { type: "hello" }, { type: "signed_challenge" }, { type: "sign_response" }, { type: "register_channel" }, { type: 1 }])(
        "refuses %p, whose type is not one the bridge sends",
        (frame) => {
            const error = refusal(() => decode(frame));
            expect(error.path).toBe("frame.type");
            expect(error.message).toBe(
                "frame.type must be one of challenge, session_established, ping, pong, channel_registered, error, sign_request",
            );
        },
    );

    describe("challenge", () => {
        it("reads the 32 challenge bytes", () => {
            expect(decode({ type: "challenge", challenge: `0x${CHALLENGE_HEX}` })).toEqual({
                type: "challenge",
                challenge: hexToBytes(CHALLENGE_HEX),
            });
        });

        it.each([`0x${"5a".repeat(31)}`, `0x${"5a".repeat(33)}`, CHALLENGE_HEX, `0x${"5A".repeat(32)}`, undefined, 32])(
            "refuses a challenge of %p",
            (challenge) => {
                const error = refusal(() => decode({ type: "challenge", challenge }));
                expect(error.message).toBe("challenge.challenge must be 32 bytes of 0x-prefixed lowercase hex");
                expect(error).not.toBeInstanceOf(ProtocolError);
            },
        );
    });

    describe("session_established", () => {
        it("reads the bridge's version and its pending count as plain numbers", () => {
            expect(decode({ type: "session_established", protocol_version: 1, pending_requests: 3 })).toEqual({
                type: "session_established",
                protocolVersion: 1,
                pendingRequests: 3,
            });
            expect(decode({ type: "session_established", protocol_version: 2, pending_requests: 0 }).type).toBe("session_established");
        });

        it("reads both up to the safe integer bound", () => {
            const bound = 2 ** 53 - 1;
            expect(decode({ type: "session_established", protocol_version: bound, pending_requests: bound })).toEqual({
                type: "session_established",
                protocolVersion: bound,
                pendingRequests: bound,
            });
        });

        it.each([
            ["protocol_version", "1"],
            ["protocol_version", "0x1"],
            ["protocol_version", -1],
            ["protocol_version", 1.5],
            ["protocol_version", 2 ** 53],
            ["protocol_version", undefined],
            ["pending_requests", "3"],
            ["pending_requests", -1],
            ["pending_requests", 2 ** 53],
            ["pending_requests", undefined],
        ])("refuses %s = %p", (path, value) => {
            const frame = withField({ type: "session_established", protocol_version: 1, pending_requests: 3 }, path, value);
            expect(refusal(() => decode(frame)).path).toBe(`session_established.${path}`);
        });
    });

    describe("ping and pong", () => {
        it("reads both, carrying nothing", () => {
            expect(decode({ type: "ping" })).toEqual({ type: "ping" });
            expect(decode({ type: "pong" })).toEqual({ type: "pong" });
            expect(decode({ type: "ping", at: 12 })).toEqual({ type: "ping" });
        });
    });

    describe("channel_registered", () => {
        it("reads the acknowledgement", () => {
            expect(decode({ type: "channel_registered", request_id: "reg-1", channel_id: CHANNEL_ID })).toEqual({
                type: "channel_registered",
                requestId: "reg-1",
                channelId: CHANNEL_ID,
            });
        });

        it("refuses a bad field without a request id to answer with, since it answers nothing", () => {
            const error = refusal(() => decode({ type: "channel_registered", request_id: "reg-1", channel_id: "0x1f" }));
            expect(error.path).toBe("channel_registered.channel_id");
            expect(error).not.toBeInstanceOf(ProtocolError);
        });
    });

    describe("error", () => {
        it("reads the failure of a device-initiated request", () => {
            expect(decode({ type: "error", request_id: "reg-1", code: "rejected", message: "" })).toEqual({
                type: "error",
                requestId: "reg-1",
                code: "rejected",
                message: "",
            });
        });

        it.each([
            ["request_id", undefined],
            ["request_id", ""],
            ["request_id", "a".repeat(65)],
            ["request_id", "req-é"],
            ["code", ""],
            ["code", undefined],
            ["code", 1],
            ["message", undefined],
            ["message", null],
        ])("refuses %s = %p", (path, value) => {
            const frame = withField({ type: "error", request_id: "reg-1", code: "rejected", message: "no" }, path, value);
            const error = refusal(() => decode(frame));
            expect(error.path).toBe(`error.${path}`);
            expect(error).not.toBeInstanceOf(ProtocolError);
        });
    });

    describe("sign_request", () => {
        it("reads the envelope, with the params left for the dispatch to decode", () => {
            expect(decode(SIGN_REQUEST)).toEqual({
                type: "sign_request",
                request: {
                    requestId: "0x2a",
                    channelId: CHANNEL_ID,
                    method: "get_commitment_point",
                    params: { commitment_number: "0x5" },
                    stateVersion: 7,
                },
            });
        });

        it("refuses a bad field past the request id with that id, so the refusal can be answered", () => {
            const error = answerableRefusal(() => decode({ ...SIGN_REQUEST, method: "get_everything" }));
            expect(error.path).toBe("sign_request.method");
            expect(error.requestId).toBe("0x2a");
        });

        it("refuses an unreadable request id without one, so the frame is dropped instead", () => {
            const error = refusal(() => decode({ ...SIGN_REQUEST, request_id: 42 }));
            expect(error.path).toBe("sign_request.request_id");
            expect(error).not.toBeInstanceOf(ProtocolError);
        });
    });

    it("tolerates fields it does not know in every frame", () => {
        expect(decode({ type: "challenge", challenge: `0x${CHALLENGE_HEX}`, issued_at: "0x1" }).type).toBe("challenge");
        expect(decode({ ...SIGN_REQUEST, deadline: "0x1" }).type).toBe("sign_request");
    });
});

describe("encodeOutboundFrame", () => {
    const X_ONLY_KEY = hexToBytes("ab".repeat(32));
    const SIGNATURE = hexToBytes("cd".repeat(64));
    const POINT = hexToBytes(`02${"ab".repeat(32)}`);
    const REGISTRATION = {
        fundingPubkey: POINT,
        tlcBasePubkey: hexToBytes(`03${"cd".repeat(32)}`),
        localSettlementKey: hexToBytes("ef".repeat(32)),
    };

    it("writes the signed challenge with the device's own protocol version", () => {
        expect(JSON.parse(encodeOutboundFrame({ type: "signed_challenge", publicKey: X_ONLY_KEY, signature: SIGNATURE }))).toEqual({
            type: "signed_challenge",
            protocol_version: PROTOCOL_VERSION,
            public_key: `0x${"ab".repeat(32)}`,
            signature: `0x${"cd".repeat(64)}`,
        });
    });

    it("rejects an identity or a signature of the wrong wire size", () => {
        expect(() => encodeOutboundFrame({ type: "signed_challenge", publicKey: POINT, signature: SIGNATURE })).toThrow(TypeError);
        expect(() => encodeOutboundFrame({ type: "signed_challenge", publicKey: X_ONLY_KEY, signature: SIGNATURE.slice(1) })).toThrow(
            TypeError,
        );
    });

    it("writes ping and pong as bare frames", () => {
        expect(encodeOutboundFrame({ type: "ping" })).toBe('{"type":"ping"}');
        expect(encodeOutboundFrame({ type: "pong" })).toBe('{"type":"pong"}');
    });

    it("writes a channel registration", () => {
        expect(JSON.parse(encodeOutboundFrame({ type: "register_channel", requestId: "reg-1", registration: REGISTRATION }))).toEqual({
            type: "register_channel",
            request_id: "reg-1",
            funding_pubkey: `0x02${"ab".repeat(32)}`,
            tlc_base_pubkey: `0x03${"cd".repeat(32)}`,
            local_settlement_key: `0x${"ef".repeat(32)}`,
        });
    });

    it("writes a sign response, result or refusal", () => {
        const result = encodeOutboundFrame({
            type: "sign_response",
            requestId: "0x2a",
            result: { kind: "commitment_point", commitmentPoint: POINT },
        });
        expect(JSON.parse(result)).toEqual({
            type: "sign_response",
            request_id: "0x2a",
            result: { commitment_point: `0x02${"ab".repeat(32)}` },
        });
        const message = "sign_request.params.commitment_number must be at most 281474976710655";
        const error = encodeOutboundFrame({ type: "sign_response", requestId: "0x2a", error: { code: "malformed", message } });
        expect(JSON.parse(error)).toEqual({ type: "sign_response", request_id: "0x2a", error: { code: "malformed", message } });
    });
});
