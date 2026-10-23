import { hexToBytes } from "@noble/hashes/utils.js";
import type { Transaction } from "../../../src/common";
import type { WatchtowerKeyPurpose } from "../../../src/policy";
import type { WatchtowerSigningRequest, WatchtowerSigningStatus } from "../../../src/protocol";
import { ProtocolError, decodeWatchtowerSigningStatus } from "../../../src/protocol";
import type { TransactionWire } from "../../../src/wire";
import { encodeTransaction } from "../../../src/wire";
import { refusal } from "../../utils/refusal";
import { toTransaction } from "../../utils/rpc-typed";
import type { WatchtowerSignatureRequiredVector } from "../../utils/rpc-vectors";
import { loadRpcVectors } from "../../utils/rpc-vectors";
import { loadSigningVectors, toWatchtowerKeyPurpose, watchtowerStatusField } from "../../utils/signing-vectors";
import { ABOVE_U64, U64_MAX_HEX } from "../../utils/uint-hex";
import { withField } from "../../utils/with-field";

const STATUS_PATH = "response.result.status";

const RPC_RESULTS = loadRpcVectors().methods.get_watchtower_signing_status.results;

const SPENDS = loadSigningVectors().watchtower.views.flatMap((view) => view.spends);

const MAX_COMMITMENT_HEX = "0xffffffffffff";
const ABOVE_MAX_COMMITMENT_HEX = "0x1000000000000";
const ABOVE_MAX_COMMITMENT = "must be at most 281474976710655";

const OBJECT = "must be an object";
const ARRAY = "must be an array";
const HEX_32 = "must be 32 bytes of 0x-prefixed lowercase hex";
const ANY_HEX = "must be whole bytes of 0x-prefixed lowercase hex";
const UINT_HEX = "must be an unsigned integer in 0x hex without leading zeros";
const STATUS_TYPES = "must be one of NoSignatureRequired, SignatureRequired";
const PURPOSE_TYPES = "must be one of Settlement, Tlc";

const REQUEST_ID_HEX = "0x8d53c4b7abb91a47e4fd07954fa7599c4291ba51fa4af5683bfdc0c7f21f974a";

const SPEND_WIRE: TransactionWire = {
    version: "0x0",
    cell_deps: [
        {
            out_point: { tx_hash: "0x2c5c2e1c0b3d8a7f0e6b4f1d9a8c7b6e5d4c3b2a1908f7e6d5c4b3a291807f6e", index: "0x0" },
            dep_type: "code",
        },
        {
            out_point: { tx_hash: "0x2c5c2e1c0b3d8a7f0e6b4f1d9a8c7b6e5d4c3b2a1908f7e6d5c4b3a291807f6e", index: "0x1" },
            dep_type: "code",
        },
        {
            out_point: { tx_hash: "0x9e6fd0b1c2a3f4e5d6c7b8a9f0e1d2c3b4a5968778695a4b3c2d1e0f1a2b3c4d", index: "0x0" },
            dep_type: "dep_group",
        },
    ],
    header_deps: [],
    inputs: [
        {
            since: "0xa000000000000006",
            previous_output: { tx_hash: "0x5f4e3d2c1b0a99887766554433221100ffeeddccbbaa99887766554433221100", index: "0x0" },
        },
    ],
    outputs: [
        {
            capacity: "0x1588b2a7c0",
            lock: {
                code_hash: "0x740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc90b1a748438afcdf81d8",
                hash_type: "type",
                args: "0x5c5dfaf84654cd9ca715c1e585b951d5d0d62c9601000000000100a00000000000000004072dc1e95ec2be0bbcd1f9a5ab1af169a340f1050001",
            },
            type: null,
        },
        {
            capacity: "0x8bb2c97000",
            lock: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x36c329ed630d6ce750712a477543672adab57f4c",
            },
            type: null,
        },
    ],
    outputs_data: ["0x", "0x"],
    witnesses: ["0x000000000000000000000000000000000102ff"],
};

function bytes(hex: string): Uint8Array {
    return hexToBytes(hex.slice(2));
}

const SPEND: Transaction = {
    version: 0,
    cellDeps: [
        {
            outPoint: { txHash: bytes("0x2c5c2e1c0b3d8a7f0e6b4f1d9a8c7b6e5d4c3b2a1908f7e6d5c4b3a291807f6e"), index: 0 },
            depType: "code",
        },
        {
            outPoint: { txHash: bytes("0x2c5c2e1c0b3d8a7f0e6b4f1d9a8c7b6e5d4c3b2a1908f7e6d5c4b3a291807f6e"), index: 1 },
            depType: "code",
        },
        {
            outPoint: { txHash: bytes("0x9e6fd0b1c2a3f4e5d6c7b8a9f0e1d2c3b4a5968778695a4b3c2d1e0f1a2b3c4d"), index: 0 },
            depType: "dep_group",
        },
    ],
    headerDeps: [],
    inputs: [
        {
            since: 0xa000000000000006n,
            previousOutput: { txHash: bytes("0x5f4e3d2c1b0a99887766554433221100ffeeddccbbaa99887766554433221100"), index: 0 },
        },
    ],
    outputs: [
        {
            capacityShannons: 0x1588b2a7c0n,
            lock: {
                codeHash: bytes("0x740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc90b1a748438afcdf81d8"),
                hashType: "type",
                args: bytes(
                    "0x5c5dfaf84654cd9ca715c1e585b951d5d0d62c9601000000000100a00000000000000004072dc1e95ec2be0bbcd1f9a5ab1af169a340f1050001",
                ),
            },
            type: null,
        },
        {
            capacityShannons: 0x8bb2c97000n,
            lock: {
                codeHash: bytes("0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"),
                hashType: "type",
                args: bytes("0x36c329ed630d6ce750712a477543672adab57f4c"),
            },
            type: null,
        },
    ],
    outputsData: [bytes("0x"), bytes("0x")],
    witnesses: [bytes("0x000000000000000000000000000000000102ff")],
};

const TLC_STATUS = {
    type: "SignatureRequired",
    request_id: REQUEST_ID_HEX,
    content: { key_purpose: { type: "Tlc", commitment_number: "0x4" }, transaction: SPEND_WIRE },
};

const SETTLEMENT_STATUS = {
    type: "SignatureRequired",
    request_id: REQUEST_ID_HEX,
    content: { key_purpose: { type: "Settlement" }, transaction: SPEND_WIRE },
};

function decode(value: unknown): WatchtowerSigningStatus {
    return decodeWatchtowerSigningStatus({ value, path: STATUS_PATH });
}

function refusalOf(value: unknown): ProtocolError {
    const error = refusal(() => decode(value));
    expect(error).toBeInstanceOf(ProtocolError);
    return error as ProtocolError;
}

function expectRefused(status: object, path: string, value: unknown, reason: string, at: string = path): void {
    const error = refusalOf(withField(status, path, value));
    expect({ path: error.path, reason: error.reason }).toEqual({ path: `${STATUS_PATH}.${at}`, reason });
}

function commitmentNumberOf(value: string): number {
    const status = decode(withField(TLC_STATUS, "content.key_purpose.commitment_number", value));
    if (status.kind !== "required" || status.purpose.kind !== "tlc") throw new Error("the status carries no TLC request");
    return status.purpose.commitmentNumber;
}

function requestOf(status: WatchtowerSigningStatus): WatchtowerSigningRequest {
    if (status.kind !== "required") throw new Error("the status carries no request");
    return status;
}

function rpcPurposeOf(vector: WatchtowerSignatureRequiredVector): WatchtowerKeyPurpose {
    const purpose = vector.key_purpose;
    return purpose.name === "Settlement" ? { kind: "settlement" } : { kind: "tlc", commitmentNumber: Number(purpose.commitment_number) };
}

describe("decodeWatchtowerSigningStatus", () => {
    it("reads NoSignatureRequired as no request", () => {
        expect(decode({ type: "NoSignatureRequired" })).toEqual({ kind: "none" });
    });

    it("reads a TLC spend into the typed request", () => {
        expect(decode(TLC_STATUS)).toEqual({
            kind: "required",
            requestId: bytes(REQUEST_ID_HEX),
            purpose: { kind: "tlc", commitmentNumber: 4 },
            transaction: SPEND,
        });
    });

    it("reads a settlement spend into the typed request", () => {
        expect(decode(SETTLEMENT_STATUS)).toEqual({
            kind: "required",
            requestId: bytes(REQUEST_ID_HEX),
            purpose: { kind: "settlement" },
            transaction: SPEND,
        });
    });

    describe("the vectors", () => {
        it("carry both purposes in the rpc results and in the spends", () => {
            const rpcPurposes = RPC_RESULTS.flatMap(({ values }) => ("request_id" in values ? [values.key_purpose.name] : []));
            expect(new Set(rpcPurposes)).toEqual(new Set(["Settlement", "Tlc"]));
            expect(new Set(SPENDS.map((spend) => spend.key_purpose.type))).toEqual(new Set(["Settlement", "Tlc"]));
        });

        it.each(RPC_RESULTS.map((entry) => [entry.name, entry] as const))("reads the rpc case %s", (_name, { values, json }) => {
            const status = decode((json as { status: unknown }).status);
            if (!("request_id" in values)) {
                expect(status).toEqual({ kind: "none" });
                return;
            }
            const request = requestOf(status);
            expect(request).toEqual({
                kind: "required",
                requestId: hexToBytes(values.request_id),
                purpose: rpcPurposeOf(values),
                transaction: toTransaction(values.transaction),
            });
            const wire = (json as { status: { content: { transaction: unknown } } }).status.content.transaction;
            expect(encodeTransaction("transaction", request.transaction)).toEqual(wire);
        });

        it.each(SPENDS.map((spend) => [spend.name, spend] as const))("reads the status of the spend %s", (_name, spend) => {
            const request = requestOf(decodeWatchtowerSigningStatus(watchtowerStatusField(spend)));
            expect({ requestId: request.requestId, purpose: request.purpose }).toEqual({
                requestId: bytes(spend.request_id),
                purpose: toWatchtowerKeyPurpose(spend.key_purpose),
            });
            expect(encodeTransaction("transaction", request.transaction)).toEqual(spend.transaction);
        });
    });

    it.each([
        ["a stray request_id on NoSignatureRequired", { type: "NoSignatureRequired", request_id: REQUEST_ID_HEX }, { kind: "none" }],
        [
            "a stray commitment_number on Settlement",
            withField(SETTLEMENT_STATUS, "content.key_purpose.commitment_number", "0x4"),
            { kind: "required", requestId: bytes(REQUEST_ID_HEX), purpose: { kind: "settlement" }, transaction: SPEND },
        ],
        [
            "an unknown member of the request",
            withField(TLC_STATUS, "transition", "SendCommitmentSigned"),
            { kind: "required", requestId: bytes(REQUEST_ID_HEX), purpose: { kind: "tlc", commitmentNumber: 4 }, transaction: SPEND },
        ],
    ])("ignores %s, as serde does without deny_unknown_fields", (_name, value, expected) => {
        expect(decode(value)).toEqual(expected);
    });

    it.each([
        ["null", null],
        ["an array", []],
        ["a string", "SignatureRequired"],
    ])("refuses a status that is %s", (_name, value) => {
        expect(refusalOf(value)).toMatchObject({ path: STATUS_PATH, reason: OBJECT });
    });

    it("refuses at the first field that fails, in the order of the wire", () => {
        const broken: [string, unknown, string][] = [
            ["request_id", undefined, HEX_32],
            ["content.key_purpose.type", "Revocation", PURPOSE_TYPES],
            ["content.transaction", undefined, OBJECT],
        ];
        for (const [index, [path, , reason]] of broken.entries()) {
            const status = broken.slice(index).reduce((value, [at, replacement]) => withField(value, at, replacement), TLC_STATUS);
            const error = refusalOf(status);
            expect({ path: error.path, reason: error.reason }).toEqual({ path: `${STATUS_PATH}.${path}`, reason });
        }
    });

    it("refuses the request id before a content that is no object", () => {
        const error = refusalOf(withField(withField(TLC_STATUS, "request_id", undefined), "content", null));
        expect({ path: error.path, reason: error.reason }).toEqual({ path: `${STATUS_PATH}.request_id`, reason: HEX_32 });
    });

    describe("the envelope", () => {
        it.each([
            ["type", undefined, STATUS_TYPES],
            ["type", null, STATUS_TYPES],
            ["type", 1, STATUS_TYPES],
            ["type", "signature_required", STATUS_TYPES],
            ["type", "SignatureNeeded", STATUS_TYPES],
            ["request_id", undefined, HEX_32],
            ["request_id", null, HEX_32],
            ["request_id", 1, HEX_32],
            ["request_id", `0x${"ab".repeat(31)}`, HEX_32],
            ["request_id", `0x${"ab".repeat(33)}`, HEX_32],
            ["request_id", "ab".repeat(32), HEX_32],
            ["request_id", `0x${"AB".repeat(32)}`, HEX_32],
            ["content", undefined, OBJECT],
            ["content", null, OBJECT],
            ["content", [], OBJECT],
            ["content", "0x", OBJECT],
        ])("refuses %s = %p", (path, value, reason) => {
            expectRefused(TLC_STATUS, path, value, reason);
        });
    });

    describe("the key purpose", () => {
        it.each([
            ["content.key_purpose", undefined, OBJECT],
            ["content.key_purpose", null, OBJECT],
            ["content.key_purpose", [], OBJECT],
            ["content.key_purpose", "Settlement", OBJECT],
            ["content.key_purpose.type", undefined, PURPOSE_TYPES],
            ["content.key_purpose.type", null, PURPOSE_TYPES],
            ["content.key_purpose.type", 1, PURPOSE_TYPES],
            ["content.key_purpose.type", "settlement", PURPOSE_TYPES],
            ["content.key_purpose.type", "TLC", PURPOSE_TYPES],
            ["content.key_purpose.type", "Revocation", PURPOSE_TYPES],
        ])("refuses %s = %p", (path, value, reason) => {
            expectRefused(TLC_STATUS, path, value, reason);
        });

        it.each([undefined, null, 4, "4", "0x04", "0X4", "0x", "", "0x-1"])(
            "refuses a TLC commitment number of %p, out of fiber's U64Hex",
            (value) => {
                expectRefused(TLC_STATUS, "content.key_purpose.commitment_number", value, UINT_HEX);
            },
        );

        it("refuses an uppercase TLC commitment number, which fiber's U64Hex reads but never writes", () => {
            expectRefused(TLC_STATUS, "content.key_purpose.commitment_number", "0xA", UINT_HEX);
        });

        it("reads a TLC commitment number from 0 up to the derivation's bound", () => {
            expect(commitmentNumberOf("0x0")).toBe(0);
            expect(commitmentNumberOf("0xa")).toBe(10);
            expect(commitmentNumberOf(MAX_COMMITMENT_HEX)).toBe(2 ** 48 - 1);
        });

        it.each([ABOVE_MAX_COMMITMENT_HEX, U64_MAX_HEX, ABOVE_U64])(
            "refuses a TLC commitment number of %s, above the derivation's bound",
            (value) => {
                expectRefused(TLC_STATUS, "content.key_purpose.commitment_number", value, ABOVE_MAX_COMMITMENT);
            },
        );
    });

    describe("the transaction", () => {
        it.each([SETTLEMENT_STATUS, TLC_STATUS])("refuses one absent or not an object", (status) => {
            for (const value of [undefined, null, [], "0x"]) expectRefused(status, "content.transaction", value, OBJECT);
        });

        it.each([
            ["content.transaction.version", "0x00", UINT_HEX],
            ["content.transaction.cell_deps", undefined, ARRAY],
            ["content.transaction.cell_deps[2].dep_type", "depGroup", "must be one of code, dep_group"],
            ["content.transaction.inputs[0].since", "0xA000000000000006", UINT_HEX],
            ["content.transaction.inputs[0].previous_output", null, OBJECT],
            ["content.transaction.outputs[1].lock.hash_type", "type1", "must be one of data, type, data1, data2"],
            ["content.transaction.outputs[0].type", undefined, OBJECT],
            ["content.transaction.outputs_data[1]", "0x0", ANY_HEX],
            ["content.transaction.witnesses[0]", "000000000000000000000000000000000102ff", ANY_HEX],
        ])("refuses %s = %p at its nested path", (path, value, reason) => {
            expectRefused(TLC_STATUS, path, value, reason);
        });

        it("refuses a header dep at its index", () => {
            const deps = [`0x${"ab".repeat(31)}`];
            expectRefused(TLC_STATUS, "content.transaction.header_deps", deps, HEX_32, "content.transaction.header_deps[0]");
        });
    });
});
