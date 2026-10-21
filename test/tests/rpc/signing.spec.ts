import { hexToBytes } from "@noble/hashes/utils.js";
import type { NextChannelSignerMaterial, SubmitChannelSignatureParams, SubmitWatchtowerSignatureParams } from "../../../src/rpc";
import {
    FiberRpcClient,
    RPC_SUBMISSION_RESULTS,
    RpcError,
    decodeRpcSigningStatusResult,
    decodeRpcSubmissionResult,
    encodeRpcChannelIdParams,
    encodeSubmitChannelSignatureParams,
    encodeSubmitWatchtowerSignatureParams,
} from "../../../src/rpc";
import { FetchMock } from "../../mocks/rpc";
import { refusal } from "../../utils/refusal";
import { rejection } from "../../utils/rejection";
import { RPC_RESULT_PATH as RESULT, answering, refusing, resultField as result, sent } from "../../utils/rpc-answers";
import {
    toRpcSigningStatusResult,
    toRpcSubmissionResult,
    toSubmitChannelSignatureParams,
    toSubmitWatchtowerSignatureParams,
    withoutNulls,
} from "../../utils/rpc-typed";
import { loadRpcVectors } from "../../utils/rpc-vectors";
import { withField } from "../../utils/with-field";

const vectors = loadRpcVectors();
const {
    get_channel_signing_status: getChannel,
    submit_channel_signature: submitChannel,
    get_watchtower_signing_status: getWatchtower,
    submit_watchtower_signature: submitWatchtower,
} = vectors.methods;

const URL = "http://fiber.example:8227";
const CHANNEL_ID = `0x${"11".repeat(32)}`;
const REQUEST_ID = "7e".repeat(32);
const PARTIAL_SIGNATURE = "5c".repeat(32);
const NEXT_POINT = `02${"a1".repeat(32)}`;
const NEXT_COMMITMENT_NONCE = `02${"b1".repeat(32)}03${"b2".repeat(32)}`;
const NEXT_REVOCATION_NONCE = `02${"b3".repeat(32)}03${"b4".repeat(32)}`;
const RECOVERABLE_SIGNATURE = `${"9a".repeat(64)}01`;

const NEXT_MATERIAL: NextChannelSignerMaterial = {
    nextCommitmentPoint: hexToBytes(NEXT_POINT),
    nextCommitmentNonce: hexToBytes(NEXT_COMMITMENT_NONCE),
    nextRevocationNonce: hexToBytes(NEXT_REVOCATION_NONCE),
};

const NEXT_MATERIAL_WIRE = {
    next_commitment_point: NEXT_POINT,
    next_commitment_nonce: `0x${NEXT_COMMITMENT_NONCE}`,
    next_revocation_nonce: `0x${NEXT_REVOCATION_NONCE}`,
};

const SUBMIT_CHANNEL: SubmitChannelSignatureParams = {
    channelId: CHANNEL_ID,
    requestId: hexToBytes(REQUEST_ID),
    partialSignature: hexToBytes(PARTIAL_SIGNATURE),
    nextMaterial: NEXT_MATERIAL,
};

const SUBMIT_WATCHTOWER: SubmitWatchtowerSignatureParams = {
    channelId: CHANNEL_ID,
    requestId: hexToBytes(REQUEST_ID),
    signature: hexToBytes(RECOVERABLE_SIGNATURE),
};

const NO_SIGNATURE_REQUIRED = { channel_id: CHANNEL_ID, status: { type: "NoSignatureRequired" } };

const SIGNATURE_REQUIRED = {
    channel_id: CHANNEL_ID,
    status: { type: "SignatureRequired", request_id: `0x${REQUEST_ID}`, content: { message: `0x${"33".repeat(32)}` } },
};

describe("decodeRpcSigningStatusResult", () => {
    it.each([...getChannel.results, ...getWatchtower.results].map((entry) => [entry.name, entry] as const))("reads the %s", (_, entry) => {
        expect(decodeRpcSigningStatusResult(result(entry.json))).toEqual(toRpcSigningStatusResult(entry.values));
    });

    it("reads the channel id as the wire string and positions the status under the result", () => {
        expect(decodeRpcSigningStatusResult(result(NO_SIGNATURE_REQUIRED))).toEqual({
            channelId: CHANNEL_ID,
            status: { value: { type: "NoSignatureRequired" }, path: `${RESULT}.status` },
        });
    });

    it.each([
        ["a signature required", SIGNATURE_REQUIRED.status],
        ["a bare tag", "NoSignatureRequired"],
        ["an unknown tag", { type: "Paused" }],
        ["null", null],
        ["a number", 5],
        ["absent", undefined],
    ])("hands %s over untouched, the same value with its path", (_, status) => {
        const decoded = decodeRpcSigningStatusResult(result({ channel_id: CHANNEL_ID, status }));
        expect(decoded.status.value).toBe(status);
        expect(decoded.status.path).toBe(`${RESULT}.status`);
    });

    it("ignores the members it does not read", () => {
        expect(decodeRpcSigningStatusResult(result({ ...NO_SIGNATURE_REQUIRED, extra: 1 }))).toEqual(
            decodeRpcSigningStatusResult(result(NO_SIGNATURE_REQUIRED)),
        );
    });

    it.each([
        ["channel_id", "11".repeat(32)],
        ["channel_id", `0x${"11".repeat(31)}`],
        ["channel_id", `0x${"AA".repeat(32)}`],
        ["channel_id", undefined],
        ["channel_id", null],
        ["channel_id", 1],
    ])("refuses %s = %p, naming the field from the result", (path, value) => {
        expect(refusal(() => decodeRpcSigningStatusResult(result(withField(SIGNATURE_REQUIRED, path, value)))).path).toBe(
            `${RESULT}.${path}`,
        );
    });

    it.each([null, [], "NoSignatureRequired"])("refuses the result %p, which is not an object", (value) => {
        expect(refusal(() => decodeRpcSigningStatusResult(result(value))).message).toBe(`${RESULT} must be an object`);
    });
});

describe("submit_channel_signature", () => {
    describe("encodeSubmitChannelSignatureParams", () => {
        it("writes the ids and the signature with their prefix, and the material with its three members", () => {
            const wire = encodeSubmitChannelSignatureParams(SUBMIT_CHANNEL);
            expect(wire).toEqual({
                channel_id: CHANNEL_ID,
                request_id: `0x${REQUEST_ID}`,
                partial_signature: `0x${PARTIAL_SIGNATURE}`,
                next_material: NEXT_MATERIAL_WIRE,
            });
            expect(Object.keys(wire)).toEqual(["channel_id", "request_id", "partial_signature", "next_material"]);
            expect(Object.keys(wire.next_material ?? {})).toEqual([
                "next_commitment_point",
                "next_commitment_nonce",
                "next_revocation_nonce",
            ]);
        });

        it("leaves next_material out, never sent as null, when there is none", () => {
            const wire = encodeSubmitChannelSignatureParams({ ...SUBMIT_CHANNEL, nextMaterial: null });
            expect(wire).toEqual({ channel_id: CHANNEL_ID, request_id: `0x${REQUEST_ID}`, partial_signature: `0x${PARTIAL_SIGNATURE}` });
            expect(Object.keys(wire)).toEqual(["channel_id", "request_id", "partial_signature"]);
        });

        it.each(submitChannel.params.map((entry) => [entry.name, entry] as const))(
            "writes the %s case as fiber's serde does",
            (_, entry) => {
                expect(encodeSubmitChannelSignatureParams(toSubmitChannelSignatureParams(entry.values))).toEqual(withoutNulls(entry.json));
            },
        );

        it.each<[string, Record<string, unknown>, Error]>([
            [
                "a bare channel id",
                { channelId: CHANNEL_ID.slice(2) },
                new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex"),
            ],
            ["a missing channel id", { channelId: undefined }, new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex")],
            ["a request id of 31 bytes", { requestId: new Uint8Array(31) }, new TypeError("requestId must be 32 bytes, got 31")],
            ["a request id of 33 bytes", { requestId: new Uint8Array(33) }, new TypeError("requestId must be 32 bytes, got 33")],
            ["a request id as hex", { requestId: `0x${REQUEST_ID}` }, new TypeError("requestId must be a Uint8Array")],
            ["a missing request id", { requestId: undefined }, new TypeError("requestId must be a Uint8Array")],
            [
                "a partial signature of 31 bytes",
                { partialSignature: new Uint8Array(31) },
                new TypeError("partialSignature must be 32 bytes, got 31"),
            ],
            [
                "a partial signature of 33 bytes",
                { partialSignature: new Uint8Array(33) },
                new TypeError("partialSignature must be 32 bytes, got 33"),
            ],
            [
                "a full signature in the partial's place",
                { partialSignature: new Uint8Array(64) },
                new TypeError("partialSignature must be 32 bytes, got 64"),
            ],
            ["a missing partial signature", { partialSignature: undefined }, new TypeError("partialSignature must be a Uint8Array")],
            [
                "a missing next material, which is null and not absent",
                { nextMaterial: undefined },
                new TypeError("nextMaterial must be an object or null"),
            ],
            ["a next material as a string", { nextMaterial: "none" }, new TypeError("nextMaterial must be an object or null")],
            [
                "a next point of 32 bytes",
                { nextMaterial: { ...NEXT_MATERIAL, nextCommitmentPoint: new Uint8Array(32) } },
                new TypeError("nextMaterial.nextCommitmentPoint must be 33 bytes, got 32"),
            ],
            [
                "a next point of 34 bytes",
                { nextMaterial: { ...NEXT_MATERIAL, nextCommitmentPoint: new Uint8Array(34) } },
                new TypeError("nextMaterial.nextCommitmentPoint must be 33 bytes, got 34"),
            ],
            [
                "a missing next point",
                { nextMaterial: { ...NEXT_MATERIAL, nextCommitmentPoint: undefined } },
                new TypeError("nextMaterial.nextCommitmentPoint must be a Uint8Array"),
            ],
            [
                "a next commitment nonce of 65 bytes",
                { nextMaterial: { ...NEXT_MATERIAL, nextCommitmentNonce: new Uint8Array(65) } },
                new TypeError("nextMaterial.nextCommitmentNonce must be 66 bytes, got 65"),
            ],
            [
                "a next commitment nonce of 67 bytes",
                { nextMaterial: { ...NEXT_MATERIAL, nextCommitmentNonce: new Uint8Array(67) } },
                new TypeError("nextMaterial.nextCommitmentNonce must be 66 bytes, got 67"),
            ],
            [
                "a next commitment nonce as hex",
                { nextMaterial: { ...NEXT_MATERIAL, nextCommitmentNonce: `0x${NEXT_COMMITMENT_NONCE}` } },
                new TypeError("nextMaterial.nextCommitmentNonce must be a Uint8Array"),
            ],
            [
                "a next revocation nonce of 65 bytes",
                { nextMaterial: { ...NEXT_MATERIAL, nextRevocationNonce: new Uint8Array(65) } },
                new TypeError("nextMaterial.nextRevocationNonce must be 66 bytes, got 65"),
            ],
            [
                "a next revocation nonce of 33 bytes",
                { nextMaterial: { ...NEXT_MATERIAL, nextRevocationNonce: new Uint8Array(33) } },
                new TypeError("nextMaterial.nextRevocationNonce must be 66 bytes, got 33"),
            ],
        ])("refuses %s", (_, change, expected) => {
            expect(() => encodeSubmitChannelSignatureParams({ ...SUBMIT_CHANNEL, ...change } as SubmitChannelSignatureParams)).toThrow(
                expected,
            );
        });
    });
});

describe("submit_watchtower_signature", () => {
    describe("encodeSubmitWatchtowerSignatureParams", () => {
        it("writes the ids and the recoverable signature with their prefix", () => {
            const wire = encodeSubmitWatchtowerSignatureParams(SUBMIT_WATCHTOWER);
            expect(wire).toEqual({ channel_id: CHANNEL_ID, request_id: `0x${REQUEST_ID}`, signature: `0x${RECOVERABLE_SIGNATURE}` });
            expect(Object.keys(wire)).toEqual(["channel_id", "request_id", "signature"]);
        });

        it.each(submitWatchtower.params.map((entry) => [entry.name, entry] as const))(
            "writes the %s case as fiber's serde does",
            (_, entry) => {
                expect(encodeSubmitWatchtowerSignatureParams(toSubmitWatchtowerSignatureParams(entry.values))).toEqual(
                    withoutNulls(entry.json),
                );
            },
        );

        it.each<[string, Record<string, unknown>, Error]>([
            [
                "a bare channel id",
                { channelId: CHANNEL_ID.slice(2) },
                new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex"),
            ],
            ["a channel id given as null", { channelId: null }, new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex")],
            ["a request id of 31 bytes", { requestId: new Uint8Array(31) }, new TypeError("requestId must be 32 bytes, got 31")],
            ["a request id of 33 bytes", { requestId: new Uint8Array(33) }, new TypeError("requestId must be 32 bytes, got 33")],
            ["a missing request id", { requestId: undefined }, new TypeError("requestId must be a Uint8Array")],
            ["a compact signature of 64 bytes", { signature: new Uint8Array(64) }, new TypeError("signature must be 65 bytes, got 64")],
            ["a signature of 66 bytes", { signature: new Uint8Array(66) }, new TypeError("signature must be 65 bytes, got 66")],
            ["a signature as hex", { signature: `0x${RECOVERABLE_SIGNATURE}` }, new TypeError("signature must be a Uint8Array")],
            ["a missing signature", { signature: undefined }, new TypeError("signature must be a Uint8Array")],
        ])("refuses %s", (_, change, expected) => {
            expect(() =>
                encodeSubmitWatchtowerSignatureParams({ ...SUBMIT_WATCHTOWER, ...change } as SubmitWatchtowerSignatureParams),
            ).toThrow(expected);
        });
    });
});

describe("decodeRpcSubmissionResult", () => {
    it.each([...submitChannel.results, ...submitWatchtower.results].map((entry) => [entry.name, entry] as const))(
        "reads the %s",
        (_, entry) => {
            expect(decodeRpcSubmissionResult(result(entry.json))).toBe(toRpcSubmissionResult(entry.values));
        },
    );

    it.each(RPC_SUBMISSION_RESULTS)("reads the tag %s", (outcome) => {
        expect(decodeRpcSubmissionResult(result({ type: outcome }))).toBe(outcome);
    });

    it("ignores the members it does not read", () => {
        expect(decodeRpcSubmissionResult(result({ type: "Applied", request_id: 1 }))).toBe("Applied");
    });

    it.each([
        ["type", "applied"],
        ["type", "Rejected"],
        ["type", "Applied "],
        ["type", "AlreadyApplied|Applied"],
        ["type", undefined],
        ["type", null],
        ["type", 1],
    ])("refuses %s = %p, naming the field from the result", (path, value) => {
        expect(refusal(() => decodeRpcSubmissionResult(result(withField({ type: "Applied" }, path, value)))).path).toBe(
            `${RESULT}.${path}`,
        );
    });

    it("lists the outcomes fiber has in the refusal of another", () => {
        expect(refusal(() => decodeRpcSubmissionResult(result({ type: "Rejected" }))).message).toBe(
            `${RESULT}.type must be one of Applied, AlreadyApplied`,
        );
    });

    it.each([null, [], "Applied"])("refuses the result %p, which is not an object", (value) => {
        expect(refusal(() => decodeRpcSubmissionResult(result(value))).message).toBe(`${RESULT} must be an object`);
    });
});

describe("FiberRpcClient signing methods", () => {
    function clientOf(mock: FetchMock): FiberRpcClient {
        return new FiberRpcClient({ url: URL, fetch: mock.fetch });
    }

    it("reads a watchtower's signing status through call, the status positioned under the result", async () => {
        const mock = answering(SIGNATURE_REQUIRED);
        const params = encodeRpcChannelIdParams({ channelId: CHANNEL_ID });
        await expect(clientOf(mock).call("get_watchtower_signing_status", params, decodeRpcSigningStatusResult)).resolves.toEqual({
            channelId: CHANNEL_ID,
            status: { value: SIGNATURE_REQUIRED.status, path: "response.result.status" },
        });
        expect(sent(mock)).toEqual({
            jsonrpc: "2.0",
            id: 1,
            method: "get_watchtower_signing_status",
            params: [{ channel_id: CHANNEL_ID }],
        });
    });

    it("passes the node's refusal through, its message verbatim", async () => {
        const mock = refusing(-32000, "no pending signature request for this channel");
        const params = encodeSubmitWatchtowerSignatureParams(SUBMIT_WATCHTOWER);
        const error = await rejection(clientOf(mock).call("submit_watchtower_signature", params, decodeRpcSubmissionResult));
        expect(error).toBeInstanceOf(RpcError);
        expect(error).toMatchObject({
            method: "submit_watchtower_signature",
            code: -32000,
            message: "no pending signature request for this channel",
        });
    });
});
