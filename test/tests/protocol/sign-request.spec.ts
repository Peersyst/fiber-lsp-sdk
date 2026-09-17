import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { SignerErrorCode } from "../../../src/common";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation";
import { COMMITMENT_LOCK_MAINNET, COMMITMENT_LOCK_TESTNET } from "../../../src/digest";
import { ANNOUNCEMENT_SLOT_NUMBER, PolicyEngine, PolicyRefusalError, SignerStore } from "../../../src/policy";
import type { PolicySignRequest, SignSession } from "../../../src/policy";
import { ProtocolError, SIGNER_METHODS, decodeSignParams } from "../../../src/protocol";
import type { SignParams, SignRequest, SignResult, SignatureMethod } from "../../../src/protocol";
import { decodeSignRequest, encodeSignResponse } from "../../../src/protocol/sign-request";
import { InMemorySignerStorage } from "../../mocks/policy";
import { toChannelAnnouncementInput, toCommitmentTxInput, toRevocationInput, toShutdownTxInput } from "../../utils/digest-inputs";
import { caseOf, loadInteropVectors } from "../../utils/interop-vectors";
import { answerableRefusal, refusal } from "../../utils/refusal";
import { withField } from "../../utils/with-field";
import {
    toChannelAnnouncementWire,
    toCommitmentTxWire,
    toRevocationWire,
    toShutdownTxWire,
    toSignSessionWire,
    wireUint,
} from "../../utils/wire-requests";

const vectors = loadInteropVectors();
const digest = vectors.digest;
const REMOTE = digest.remote;
const CHANNEL_INDEX = vectors.sdk_scheme.channel.channel_index;
const KEYS = deriveChannelKeys(hexToBytes(vectors.sdk_scheme.channel.seed));
const LOCAL_FUNDING_PUBKEY = pubkeyOf(KEYS.fundingKey);
const REMOTE_FUNDING_PUBKEY = hexToBytes(REMOTE.funding_pubkey);
const AGGREGATED_NONCE_HEX = "02".repeat(33) + "03".repeat(33);

const CHANNEL_ID = `0x${"1f".repeat(32)}`;
const REQUEST_ID = "0x2a";
const STATE_VERSION = 7;

const THREE_TLCS = caseOf(digest.commitment_cases, "ckb, three tlcs, for remote");
const CKB_SHUTDOWN = caseOf(digest.shutdown_cases, "ckb");
const SEND_SIDE_REVOCATION = caseOf(digest.revocation_cases, "ckb, send side");
const CKB_ANNOUNCEMENT = caseOf(digest.announcement_cases, "ckb");

// Fiber signs a close with the commitment nonce of the current local number, and a revocation one above the revoked number.
const SHUTDOWN_NONCE_NUMBER = 20;
const REVOCATION_NONCE_NUMBER = SEND_SIDE_REVOCATION.revoked_commitment_number + 1;

function envelope(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
        type: "sign_request",
        request_id: REQUEST_ID,
        channel_id: CHANNEL_ID,
        method: "get_commitment_point",
        params: { commitment_number: "0x5" },
        state_version: wireUint(STATE_VERSION),
        ...overrides,
    };
}

function request(method: SignRequest["method"], params: Record<string, unknown>): SignRequest {
    return { requestId: REQUEST_ID, channelId: CHANNEL_ID, method, params, stateVersion: STATE_VERSION };
}

function sessionWire(messageHex: string) {
    return toSignSessionWire([bytesToHex(LOCAL_FUNDING_PUBKEY), REMOTE.funding_pubkey], AGGREGATED_NONCE_HEX, messageHex);
}

function session(messageHex: string): SignSession {
    return {
        orderedPublicKeys: [LOCAL_FUNDING_PUBKEY, REMOTE_FUNDING_PUBKEY],
        aggregatedNonce: hexToBytes(AGGREGATED_NONCE_HEX),
        message: hexToBytes(messageHex),
    };
}

function policyRequest(
    nonceCommitmentNumber: number | undefined,
    messageHex: string,
    operation: PolicySignRequest["operation"],
): PolicySignRequest {
    return { channelId: CHANNEL_ID, stateVersion: STATE_VERSION, nonceCommitmentNumber, session: session(messageHex), operation };
}

type SigningCase = [SignatureMethod, Record<string, unknown>, PolicySignRequest];

const SIGNING_CASES: SigningCase[] = [
    [
        "partial_sign_commitment_tx",
        {
            session: sessionWire(THREE_TLCS.digest),
            nonce_commitment_number: wireUint(THREE_TLCS.commitment_number),
            commitment_tx: toCommitmentTxWire(THREE_TLCS, REMOTE),
        },
        policyRequest(THREE_TLCS.commitment_number, THREE_TLCS.digest, {
            kind: "commitment_tx",
            input: toCommitmentTxInput(THREE_TLCS, REMOTE),
        }),
    ],
    [
        "partial_sign_closing_tx",
        {
            session: sessionWire(CKB_SHUTDOWN.digest),
            nonce_commitment_number: wireUint(SHUTDOWN_NONCE_NUMBER),
            shutdown_tx: toShutdownTxWire(CKB_SHUTDOWN, REMOTE),
        },
        policyRequest(SHUTDOWN_NONCE_NUMBER, CKB_SHUTDOWN.digest, { kind: "shutdown_tx", input: toShutdownTxInput(CKB_SHUTDOWN, REMOTE) }),
    ],
    [
        "partial_sign_revocation",
        {
            session: sessionWire(SEND_SIDE_REVOCATION.digest),
            nonce_commitment_number: wireUint(REVOCATION_NONCE_NUMBER),
            revocation: toRevocationWire(SEND_SIDE_REVOCATION, REMOTE),
        },
        policyRequest(REVOCATION_NONCE_NUMBER, SEND_SIDE_REVOCATION.digest, {
            kind: "revocation",
            input: toRevocationInput(SEND_SIDE_REVOCATION, REMOTE),
        }),
    ],
    [
        "partial_sign_channel_announcement",
        { session: sessionWire(CKB_ANNOUNCEMENT.digest), channel_announcement: toChannelAnnouncementWire(CKB_ANNOUNCEMENT, REMOTE) },
        policyRequest(undefined, CKB_ANNOUNCEMENT.digest, {
            kind: "channel_announcement",
            input: toChannelAnnouncementInput(CKB_ANNOUNCEMENT, REMOTE),
        }),
    ],
];

function signingCase(method: SignatureMethod): SigningCase {
    const found = SIGNING_CASES.find(([name]) => name === method);
    if (found === undefined) throw new Error(`no signing case for ${method}`);
    return found;
}

function signingRequest(params: SignParams): PolicySignRequest {
    if (!("request" in params)) throw new Error("not a signing request");
    return params.request;
}

describe("decodeSignRequest", () => {
    it("reads the envelope and leaves the params as the node sent them", () => {
        const params = { commitment_number: "0x5", extra: true };
        expect(decodeSignRequest({ value: envelope({ params }), path: "sign_request" })).toEqual({
            requestId: REQUEST_ID,
            channelId: CHANNEL_ID,
            method: "get_commitment_point",
            params,
            stateVersion: STATE_VERSION,
        });
    });

    it("reads every method name and no other", () => {
        for (const method of SIGNER_METHODS) {
            expect(decodeSignRequest({ value: envelope({ method }), path: "sign_request" }).method).toBe(method);
        }
        expect(refusal(() => decodeSignRequest({ value: envelope({ method: "sign_anything" }), path: "sign_request" })).path).toBe(
            "sign_request.method",
        );
    });

    it("reads a state version of zero and up to the safe integer bound", () => {
        expect(decodeSignRequest({ value: envelope({ state_version: "0x0" }), path: "sign_request" }).stateVersion).toBe(0);
        expect(decodeSignRequest({ value: envelope({ state_version: "0x1fffffffffffff" }), path: "sign_request" }).stateVersion).toBe(
            Number.MAX_SAFE_INTEGER,
        );
    });

    it("tolerates fields it does not know", () => {
        expect(decodeSignRequest({ value: envelope({ priority: "high" }), path: "sign_request" }).requestId).toBe(REQUEST_ID);
    });

    it.each([
        ["request_id", undefined],
        ["request_id", ""],
        ["request_id", "a".repeat(65)],
        ["request_id", "req-é"],
        ["request_id", 42],
    ])("refuses %s = %p as unanswerable", (path, value) => {
        const error = refusal(() => decodeSignRequest({ value: withField(envelope(), path, value), path: "sign_request" }));
        expect(error.path).toBe(`sign_request.${path}`);
        expect(error).not.toBeInstanceOf(ProtocolError);
    });

    it.each([
        ["channel_id", `0x${"1f".repeat(31)}`],
        ["channel_id", `0x${"1F".repeat(32)}`],
        ["channel_id", "1f".repeat(32)],
        ["channel_id", undefined],
        ["method", undefined],
        ["method", ""],
        ["method", "GET_COMMITMENT_POINT"],
        ["params", null],
        ["params", []],
        ["params", "{}"],
        ["params", undefined],
        ["state_version", "0x00"],
        ["state_version", 7],
        ["state_version", "0x20000000000000"],
        ["state_version", undefined],
    ])("refuses %s = %p, carrying the request id", (path, value) => {
        const error = answerableRefusal(() => decodeSignRequest({ value: withField(envelope(), path, value), path: "sign_request" }));
        expect(error.path).toBe(`sign_request.${path}`);
        expect(error.requestId).toBe(REQUEST_ID);
    });
});

describe("decodeSignParams", () => {
    describe("the methods without params", () => {
        it.each(["get_base_public_keys", "get_channel_announcement_pub_nonce"] as const)("reads %s from an empty object", (method) => {
            expect(decodeSignParams(request(method, {}), COMMITMENT_LOCK_TESTNET)).toEqual({ method });
        });

        it.each(["get_base_public_keys", "get_channel_announcement_pub_nonce"] as const)(
            "ignores a commitment number sent to %s",
            (method) => {
                expect(decodeSignParams(request(method, { commitment_number: "0x5" }), COMMITMENT_LOCK_TESTNET)).toEqual({ method });
            },
        );
    });

    describe("the methods keyed by a commitment number", () => {
        const METHODS = ["get_commitment_point", "get_commitment_pub_nonce", "get_revocation_pub_nonce", "get_settlement_keys"] as const;

        it.each(METHODS)("reads the number of %s", (method) => {
            expect(decodeSignParams(request(method, { commitment_number: "0x5" }), COMMITMENT_LOCK_TESTNET)).toEqual({
                method,
                commitmentNumber: 5,
            });
            expect(decodeSignParams(request(method, { commitment_number: "0x0" }), COMMITMENT_LOCK_TESTNET)).toEqual({
                method,
                commitmentNumber: 0,
            });
            expect(decodeSignParams(request(method, { commitment_number: "0xffffffffffff" }), COMMITMENT_LOCK_TESTNET)).toEqual({
                method,
                commitmentNumber: 2 ** 48 - 1,
            });
        });

        it.each(METHODS)("refuses a number %s cannot key, carrying the request id", (method) => {
            for (const value of ["0x1000000000000", "0x05", "5", 5, undefined]) {
                const error = answerableRefusal(() =>
                    decodeSignParams(request(method, { commitment_number: value }), COMMITMENT_LOCK_TESTNET),
                );
                expect(error.path).toBe("sign_request.params.commitment_number");
                expect(error.requestId).toBe(REQUEST_ID);
            }
        });
    });

    describe("the signing methods", () => {
        it.each(SIGNING_CASES)("reads %s into exactly the policy engine's input", (method, params, expected) => {
            expect(decodeSignParams(request(method, params), COMMITMENT_LOCK_TESTNET)).toEqual({ method, request: expected });
        });

        it.each(SIGNING_CASES)("hands %s to the policy gate as a fresh, digest-matching request", async (method, params, expected) => {
            const engine = new PolicyEngine(new SignerStore(new InMemorySignerStorage()));
            await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, "0");
            const decoded = signingRequest(decodeSignParams(request(method, params), COMMITMENT_LOCK_TESTNET));
            const contexts = {
                commitment_tx: "COMMITMENT",
                shutdown_tx: "COMMITMENT",
                revocation: "REVOKE",
                channel_announcement: "ANNOUNCEMENT",
            };
            await expect(engine.checkAndClaim(KEYS, decoded)).resolves.toEqual({
                status: "fresh",
                context: contexts[expected.operation.kind],
                commitmentNumber: expected.nonceCommitmentNumber ?? ANNOUNCEMENT_SLOT_NUMBER,
            });
        });

        it("reads a nonce number up to the highest commitment number of the chain", () => {
            const [, params] = signingCase("partial_sign_commitment_tx");
            const decoded = signingRequest(
                decodeSignParams(
                    request("partial_sign_commitment_tx", { ...params, nonce_commitment_number: "0xffffffffffff" }),
                    COMMITMENT_LOCK_TESTNET,
                ),
            );
            expect(decoded.nonceCommitmentNumber).toBe(2 ** 48 - 1);
        });

        it("reads no nonce number for the announcement, whose slot the policy gate fixes", () => {
            const [, params] = signingCase("partial_sign_channel_announcement");
            const decoded = signingRequest(
                decodeSignParams(
                    request("partial_sign_channel_announcement", { ...params, nonce_commitment_number: "garbage" }),
                    COMMITMENT_LOCK_TESTNET,
                ),
            );
            expect(decoded.nonceCommitmentNumber).toBeUndefined();
        });

        it("supplies the commitment lock the caller holds to both operations that take one", () => {
            const [, commitmentParams] = signingCase("partial_sign_commitment_tx");
            const [, revocationParams] = signingCase("partial_sign_revocation");
            const commitment = signingRequest(
                decodeSignParams(request("partial_sign_commitment_tx", commitmentParams), COMMITMENT_LOCK_MAINNET),
            ).operation;
            const revocation = signingRequest(
                decodeSignParams(request("partial_sign_revocation", revocationParams), COMMITMENT_LOCK_MAINNET),
            ).operation;
            if (commitment.kind !== "commitment_tx" || revocation.kind !== "revocation") throw new Error("not the operations asked for");
            expect(commitment.input.commitmentLock).toBe(COMMITMENT_LOCK_MAINNET);
            expect(revocation.input.commitmentLock).toBe(COMMITMENT_LOCK_MAINNET);
        });

        it.each([
            ["partial_sign_commitment_tx", "session", undefined],
            [
                "partial_sign_commitment_tx",
                "session.ordered_pubkeys",
                [`0x${"02".repeat(33)}`, `0x${"03".repeat(33)}`, `0x${"04".repeat(33)}`],
            ],
            ["partial_sign_commitment_tx", "session.aggregated_nonce", `0x${"02".repeat(33)}`],
            ["partial_sign_commitment_tx", "session.message", `0x${"ab".repeat(33)}`],
            ["partial_sign_commitment_tx", "nonce_commitment_number", undefined],
            ["partial_sign_commitment_tx", "nonce_commitment_number", "0x1000000000000"],
            ["partial_sign_commitment_tx", "nonce_commitment_number", 0],
            ["partial_sign_commitment_tx", "commitment_tx", undefined],
            ["partial_sign_commitment_tx", "commitment_tx.to_local", "0x"],
            ["partial_sign_commitment_tx", "commitment_tx.tlcs[2].payment_hash", "0x"],
            ["partial_sign_closing_tx", "session.ordered_pubkeys", [`0x${"02".repeat(33)}`]],
            ["partial_sign_closing_tx", "nonce_commitment_number", "20"],
            ["partial_sign_closing_tx", "shutdown_tx", null],
            ["partial_sign_closing_tx", "shutdown_tx.local_close_script.args", "0xb"],
            ["partial_sign_revocation", "nonce_commitment_number", "0x05"],
            ["partial_sign_revocation", "revocation", []],
            ["partial_sign_revocation", "revocation.revoked_commitment_number", "0x1000000000000"],
            ["partial_sign_channel_announcement", "session", "session"],
            ["partial_sign_channel_announcement", "channel_announcement", undefined],
            ["partial_sign_channel_announcement", "channel_announcement.node_ids", []],
        ] as [SignatureMethod, string, unknown][])("refuses %s with %s = %p, carrying the request id", (method, path, value) => {
            const [, params] = signingCase(method);
            const error = answerableRefusal(() =>
                decodeSignParams(request(method, withField(params, path, value)), COMMITMENT_LOCK_TESTNET),
            );
            expect(error.path).toBe(`sign_request.params.${path}`);
            expect(error.requestId).toBe(REQUEST_ID);
        });

        it("refuses the operation object of another method", () => {
            const [, closing] = signingCase("partial_sign_closing_tx");
            const error = answerableRefusal(() =>
                decodeSignParams(request("partial_sign_commitment_tx", closing), COMMITMENT_LOCK_TESTNET),
            );
            expect(error.message).toBe("sign_request.params.commitment_tx must be an object");
        });
    });

    it("lets a fault that is not a refusal through as itself, uncorrelated", () => {
        const fault = new Error("storage exploded");
        const params = Object.defineProperty({}, "commitment_number", {
            get() {
                throw fault;
            },
            enumerable: true,
        });
        expect(() => decodeSignParams(request("get_commitment_point", params), COMMITMENT_LOCK_TESTNET)).toThrow(fault);
    });

    it("never names a value in a refusal", () => {
        const [, params] = signingCase("partial_sign_commitment_tx");
        const wires = [
            withField(params, "session.message", `0x${"5ECRE7".repeat(11)}`),
            withField(params, "session.ordered_pubkeys[0]", "BADCAFE"),
            withField(params, "nonce_commitment_number", "0xBADCAFE"),
        ];
        for (const wire of wires) {
            const error = answerableRefusal(() => decodeSignParams(request("partial_sign_commitment_tx", wire), COMMITMENT_LOCK_TESTNET));
            expect(error.message).not.toContain("5ECRE7");
            expect(error.message).not.toContain("BADCAFE");
        }
    });
});

describe("encodeSignResponse", () => {
    const POINT = hexToBytes(`02${"ab".repeat(32)}`);
    const OTHER_POINT = hexToBytes(`03${"cd".repeat(32)}`);
    const NONCE = hexToBytes(AGGREGATED_NONCE_HEX);
    const SCALAR = hexToBytes("ef".repeat(32));
    const OTHER_SCALAR = hexToBytes("01".repeat(32));

    function response(result: SignResult) {
        return encodeSignResponse({ type: "sign_response", requestId: REQUEST_ID, result });
    }

    it("writes the base public keys", () => {
        expect(response({ kind: "base_public_keys", fundingPubkey: POINT, tlcBasePubkey: OTHER_POINT })).toEqual({
            type: "sign_response",
            request_id: REQUEST_ID,
            result: { funding_pubkey: `0x02${"ab".repeat(32)}`, tlc_base_pubkey: `0x03${"cd".repeat(32)}` },
        });
    });

    it("writes a commitment point", () => {
        expect(response({ kind: "commitment_point", commitmentPoint: POINT })).toEqual({
            type: "sign_response",
            request_id: REQUEST_ID,
            result: { commitment_point: `0x02${"ab".repeat(32)}` },
        });
    });

    it("writes a public nonce", () => {
        expect(response({ kind: "pub_nonce", pubNonce: NONCE })).toEqual({
            type: "sign_response",
            request_id: REQUEST_ID,
            result: { pub_nonce: `0x${AGGREGATED_NONCE_HEX}` },
        });
    });

    it("writes the settlement keys", () => {
        expect(response({ kind: "settlement_keys", localSettlementKey: SCALAR, tlcKey: OTHER_SCALAR })).toEqual({
            type: "sign_response",
            request_id: REQUEST_ID,
            result: { local_settlement_key: `0x${"ef".repeat(32)}`, tlc_key: `0x${"01".repeat(32)}` },
        });
    });

    it("writes a partial signature", () => {
        expect(response({ kind: "partial_signature", partialSignature: SCALAR })).toEqual({
            type: "sign_response",
            request_id: REQUEST_ID,
            result: { partial_signature: `0x${"ef".repeat(32)}` },
        });
    });

    it("writes a refusal with its code and message", () => {
        expect(
            encodeSignResponse({ type: "sign_response", requestId: REQUEST_ID, error: { code: "stale_state", message: "older" } }),
        ).toEqual({
            type: "sign_response",
            request_id: REQUEST_ID,
            error: { code: "stale_state", message: "older" },
        });
    });

    it.each([
        [new PolicyRefusalError("stale_state", "older"), { code: "stale_state", message: "older" }],
        [
            new ProtocolError("sign_request.method", "must be one of the ten methods", REQUEST_ID),
            { code: "malformed", message: "sign_request.method must be one of the ten methods" },
        ],
    ])("writes exactly the code and message of a refusal carried by %p", (error, expected) => {
        expect(encodeSignResponse({ type: "sign_response", requestId: REQUEST_ID, error })).toStrictEqual({
            type: "sign_response",
            request_id: REQUEST_ID,
            error: expected,
        });
    });

    it("rejects a code outside the four, which is a device bug and not a refusal", () => {
        const error = { code: "retry_later" as SignerErrorCode, message: "busy" };
        expect(() => encodeSignResponse({ type: "sign_response", requestId: REQUEST_ID, error })).toThrow(TypeError);
        expect(() => encodeSignResponse({ type: "sign_response", requestId: REQUEST_ID, error })).toThrow(
            "error.code must be one of unknown_channel, malformed, stale_state, policy_refusal",
        );
    });

    it("rejects an id the wire cannot carry, which is a device bug and not a refusal", () => {
        const result: SignResult = { kind: "partial_signature", partialSignature: SCALAR };
        expect(() => encodeSignResponse({ type: "sign_response", requestId: "", result })).toThrow(TypeError);
        expect(() =>
            encodeSignResponse({ type: "sign_response", requestId: "a".repeat(65), error: { code: "malformed", message: "no" } }),
        ).toThrow(TypeError);
    });

    it("rejects a result of the wrong wire size, which is a device bug and not a refusal", () => {
        const short = SCALAR.slice(1);
        expect(() => response({ kind: "base_public_keys", fundingPubkey: short, tlcBasePubkey: OTHER_POINT })).toThrow(TypeError);
        expect(() => response({ kind: "base_public_keys", fundingPubkey: POINT, tlcBasePubkey: short })).toThrow(TypeError);
        expect(() => response({ kind: "commitment_point", commitmentPoint: short })).toThrow(TypeError);
        expect(() => response({ kind: "pub_nonce", pubNonce: POINT })).toThrow(TypeError);
        expect(() => response({ kind: "settlement_keys", localSettlementKey: short, tlcKey: OTHER_SCALAR })).toThrow(TypeError);
        expect(() => response({ kind: "settlement_keys", localSettlementKey: SCALAR, tlcKey: short })).toThrow(TypeError);
        expect(() => response({ kind: "partial_signature", partialSignature: short })).toThrow(TypeError);
    });
});
