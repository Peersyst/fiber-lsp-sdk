import { hexToBytes } from "@noble/hashes/utils.js";
import type { UnsignedInvoice } from "../../../src/invoice";
import { encodeInvoice } from "../../../src/invoice";
import { FiberRpcClient, RpcError, RpcTransportError } from "../../../src/rpc";
import type { SdkErrorCode, SdkFeeEstimatingContext, SdkNetworkConfig } from "../../../src/sdk";
import { SDK_NETWORK_PRESETS, SdkError, estimateSdkTransferFee } from "../../../src/sdk";
import { ScriptedNode } from "../../mocks/rpc";
import { signInvoice } from "../../utils/invoice-signing";
import { rejection } from "../../utils/rejection";

const URL = "http://127.0.0.1:8227";
const LSP_SECRET_KEY = hexToBytes("22".repeat(32));
const LSP_PUBKEY = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";
// The payee, another tenant of the LSP.
const PAYEE_SECRET_KEY = hexToBytes("11".repeat(32));
const PAYEE_PUBKEY = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
const PAYMENT_HASH = "5a".repeat(32);
const OTHER_HASH = "7e".repeat(32);
const AMOUNT = "250000000";
// A minute past the invoice's timestamp.
const NOW_MS = 1_791_367_260_000;

// A tenant's invoice of 2.5 CKB, as fiber writes it.
const INVOICE: UnsignedInvoice = {
    currency: "Fibt",
    amountShannons: AMOUNT,
    timestampMs: 1_791_367_200_000n,
    paymentHash: hexToBytes(PAYMENT_HASH),
    attributes: [
        { type: "expiryTime", seconds: 3600n },
        { type: "feature", bits: Uint8Array.of(0x20) },
        { type: "trampolineRouteHint", nodeId: hexToBytes(LSP_PUBKEY) },
        { type: "finalHtlcMinimumExpiryDelta", milliseconds: 86_400_000n },
        { type: "hashAlgorithm", algorithm: "ckb-hash" },
        { type: "payeePublicKey", publicKey: hexToBytes(PAYEE_PUBKEY) },
    ],
};

// The LSP's own invoice for the same payment.
const LSP_INVOICE: UnsignedInvoice = {
    ...INVOICE,
    attributes: [
        { type: "expiryTime", seconds: 3600n },
        { type: "hashAlgorithm", algorithm: "ckb-hash" },
        { type: "payeePublicKey", publicKey: hexToBytes(LSP_PUBKEY) },
    ],
};

// transfer's default budget for AMOUNT: ceil(250000000 * 5 / 1000).
const DEFAULT_BUDGET = "1250000";

// A dry run's answer under trampoline: never stored, its fee the whole budget the hop to the LSP carries.
const DRY_RUN_ANSWER = {
    payment_hash: `0x${PAYMENT_HASH}`,
    payment_preimage: null,
    status: "Created",
    created_at: "0x1a115cf2760",
    last_updated_at: "0x1a115cf2760",
    failed_error: null,
    fee: "0x1312d0",
    custom_records: null,
};

type Harness = { node: ScriptedNode; now: jest.Mock<number, []>; context: SdkFeeEstimatingContext };

function harness(network: SdkNetworkConfig = SDK_NETWORK_PRESETS.testnet): Harness {
    const node = new ScriptedNode();
    const now = jest.fn<number, []>(() => NOW_MS);
    const context: SdkFeeEstimatingContext = {
        network,
        lspPubkey: hexToBytes(LSP_PUBKEY),
        now,
        rpc: new FiberRpcClient({ url: URL, fetch: node.fetch }),
    };
    return { node, now, context };
}

function stringOf(invoice: UnsignedInvoice = INVOICE, secretKey: Uint8Array = PAYEE_SECRET_KEY): string {
    return encodeInvoice(signInvoice(invoice, secretKey));
}

// `toEqual` compares an error's message alone.
function expectSdkError(error: unknown, expected: SdkError): void {
    expect(error).toBeInstanceOf(SdkError);
    expect(error).toEqual(expected);
    expect((error as SdkError).code).toBe(expected.code);
}

describe("estimateSdkTransferFee", () => {
    it("asks a dry run through the LSP as trampoline under transfer's default budget, and hands back its fee", async () => {
        const h = harness();
        h.node.result(DRY_RUN_ANSWER);
        const invoice = stringOf();
        await expect(estimateSdkTransferFee(h.context, invoice)).resolves.toStrictEqual({
            paymentHashHex: `0x${PAYMENT_HASH}`,
            amountShannons: AMOUNT,
            feeShannons: DEFAULT_BUDGET,
        });
        expect(h.node.calls()).toEqual([
            { method: "send_payment", params: { invoice, max_fee_amount: "0x1312d0", dry_run: true, trampoline_hops: [LSP_PUBKEY] } },
        ]);
    });

    it("asks it under the budget given, and hands back the dry run's fee as fiber answers it", async () => {
        const h = harness();
        h.node.result({ ...DRY_RUN_ANSWER, fee: "0x3d091" });
        const invoice = stringOf();
        await expect(estimateSdkTransferFee(h.context, invoice, { maxFeeShannons: "250000" })).resolves.toMatchObject({
            feeShannons: "250001",
        });
        expect(h.node.calls()).toEqual([
            { method: "send_payment", params: { invoice, max_fee_amount: "0x3d090", dry_run: true, trampoline_hops: [LSP_PUBKEY] } },
        ]);
    });

    it("asks a dry run of the LSP's own invoice directly, under the budget transfer sends, and hands back its route's fee", async () => {
        const h = harness();
        h.node.result({ ...DRY_RUN_ANSWER, fee: "0x3e8" });
        const invoice = stringOf(LSP_INVOICE, LSP_SECRET_KEY);
        await expect(estimateSdkTransferFee(h.context, invoice)).resolves.toStrictEqual({
            paymentHashHex: `0x${PAYMENT_HASH}`,
            amountShannons: AMOUNT,
            feeShannons: "1000",
        });
        expect(h.node.calls()).toEqual([{ method: "send_payment", params: { invoice, max_fee_amount: "0x1312d0", dry_run: true } }]);
    });

    it("reads the clock once", async () => {
        const h = harness();
        h.node.result(DRY_RUN_ANSWER);
        await estimateSdkTransferFee(h.context, stringOf());
        expect(h.now).toHaveBeenCalledTimes(1);
    });

    describe("its argument and the invoice", () => {
        it.each<[string, unknown]>([
            ["no invoice", undefined],
            ["a null invoice", null],
            ["an invoice in bytes", new TextEncoder().encode("fibt1")],
        ])("refuses %s as transfer does, asking nothing", async (_, invoice) => {
            const h = harness();
            const thrown = await rejection(estimateSdkTransferFee(h.context, invoice as string));
            expect(thrown).toEqual(new TypeError("encodedInvoice must be a string"));
            expect(thrown).toBeInstanceOf(TypeError);
            expect(h.now).not.toHaveBeenCalled();
            expect(h.node.calls()).toEqual([]);
        });

        it("refuses another network's invoice as invoice_unpayable, asking nothing", async () => {
            const h = harness(SDK_NETWORK_PRESETS.mainnet);
            const error = await rejection(estimateSdkTransferFee(h.context, stringOf()));
            expectSdkError(
                error,
                new SdkError("invoice_unpayable", "the invoice cannot be paid: currency is Fibt, not the network's Fibb"),
            );
            expect(h.node.calls()).toEqual([]);
        });

        it.each<[string, unknown, Error]>([
            ["options that are not an object", "250000", new TypeError("options must be an object")],
            [
                "a budget as a number",
                { maxFeeShannons: 250000 },
                new TypeError("options.maxFeeShannons must be an amount in decimal shannons"),
            ],
        ])("refuses %s as transfer does, asking nothing", async (_, options, expected) => {
            const h = harness();
            const thrown = await rejection(estimateSdkTransferFee(h.context, stringOf(), options as never));
            expect(thrown).toEqual(expected);
            expect(thrown).toBeInstanceOf(expected.constructor);
            expect(h.node.calls()).toEqual([]);
        });

        it("asks an amount and a budget adding up to fiber's u128", async () => {
            const h = harness();
            h.node.result({ ...DRY_RUN_ANSWER, fee: "0xa" });
            const invoice = stringOf({ ...INVOICE, amountShannons: "340282366920938463463374607431768211445" });
            await expect(estimateSdkTransferFee(h.context, invoice, { maxFeeShannons: "10" })).resolves.toMatchObject({
                feeShannons: "10",
            });
        });

        it("refuses one shannon past it as transfer does, asking nothing", async () => {
            const h = harness();
            const invoice = stringOf({ ...INVOICE, amountShannons: "340282366920938463463374607431768211445" });
            const thrown = await rejection(estimateSdkTransferFee(h.context, invoice, { maxFeeShannons: "11" }));
            expect(thrown).toEqual(
                new RangeError(
                    "the invoice's amount and the fee budget must add up to at most 340282366920938463463374607431768211455 shannons, got 340282366920938463463374607431768211456",
                ),
            );
            expect(thrown).toBeInstanceOf(RangeError);
            expect(h.node.calls()).toEqual([]);
        });
    });

    describe("the node's answer", () => {
        it.each<[string, SdkErrorCode, string]>([
            [
                "a single path short of outbound liquidity",
                "insufficient_balance",
                "Send payment error: Failed to build route, Insufficient balance: max outbound liquidity 0 is insufficient, required amount: 250000000",
            ],
            ["no path", "no_route", "Send payment error: Failed to build route, PathFind error: no path found"],
            [
                "a first hop's fee past the budget",
                "fee_budget_too_low",
                "Send payment error: Failed to build route, Graph other error: max_fee_amount is too low for trampoline routing: first_hop_fee=1250001 current_fee=1250000",
            ],
            [
                "a session already held",
                "payment_session_exists",
                `InvalidParameter: Payment session already exists: Hash256(0x${PAYMENT_HASH}) with payment session status: Inflight`,
            ],
            ["any other refusal", "payment_rejected", 'InvalidParameter: Failed to validate payment request: "invoice is expired"'],
            ["fiber's lost actor reply", "payment_unresolved", "Messaging failed because channel is closed"],
        ])("refuses fiber's answer to %s as %s, its error the cause", async (_, code, text) => {
            const h = harness();
            h.node.error(-32000, text);
            const error = await rejection(estimateSdkTransferFee(h.context, stringOf()));
            expect(error).toBeInstanceOf(SdkError);
            expect((error as SdkError).code).toBe(code);
            expect((error as SdkError).cause).toBeInstanceOf(RpcError);
            expect((error as SdkError).cause).toMatchObject({ method: "send_payment", code: -32000, message: text });
        });

        it("refuses a transport failure as payment_unresolved, its error the cause", async () => {
            const h = harness();
            h.node.reject(new TypeError("fetch failed"));
            const error = await rejection(estimateSdkTransferFee(h.context, stringOf()));
            expect(error).toBeInstanceOf(SdkError);
            expect((error as SdkError).code).toBe("payment_unresolved");
            expect((error as SdkError).cause).toBeInstanceOf(RpcTransportError);
        });

        it("refuses an answer about another hash as payment_unresolved", async () => {
            const h = harness();
            h.node.result({ ...DRY_RUN_ANSWER, payment_hash: `0x${OTHER_HASH}` });
            const error = await rejection(estimateSdkTransferFee(h.context, stringOf()));
            expectSdkError(
                error,
                new SdkError(
                    "payment_unresolved",
                    `the payment's outcome is unknown: the node answered the dry run of 0x${PAYMENT_HASH} with that of 0x${OTHER_HASH}`,
                ),
            );
        });
    });
});
