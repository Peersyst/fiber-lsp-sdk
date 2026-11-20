import { hexToBytes } from "@noble/hashes/utils.js";
import type { UnsignedInvoice } from "../../../src/invoice";
import { InvoiceError, encodeInvoice } from "../../../src/invoice";
import { DebitIntentError, PolicyEngine, SignerStore } from "../../../src/policy";
import { FiberRpcClient, RpcError, RpcResponseError, RpcTransportError } from "../../../src/rpc";
import type { IFetchLike } from "../../../src/rpc";
import type {
    SdkErrorCode,
    SdkEvent,
    SdkNetworkConfig,
    SdkPaymentRecord,
    SdkPaymentSendingContext,
    SdkTransferOptions,
    StoredPaymentRecord,
} from "../../../src/sdk";
import {
    ActivityPoller,
    ActivityTracker,
    PaymentHistory,
    SDK_NETWORK_PRESETS,
    SdkError,
    buildPaymentStep,
    classifySdkPaymentFailure,
    getSdkPayment,
    listSdkPayments,
    prepareSdkTransfer,
    transferSdkPayment,
} from "../../../src/sdk";
import { TimerMock } from "../../mocks/common";
import { InMemorySignerStorage } from "../../mocks/policy";
import type { SentCall } from "../../mocks/rpc";
import { ScriptedNode, rpcResultAnswer } from "../../mocks/rpc";
import { signInvoice } from "../../utils/invoice-signing";
import { rejection } from "../../utils/rejection";
import type { StepRun } from "../../utils/step-run";
import { live } from "../../utils/step-run";
import { storedAt, writes } from "../../utils/stored-records";
import { getPaymentCall } from "../../utils/payment-calls";

const URL = "http://127.0.0.1:8227";
// The LSP's secret and its public key.
const LSP_SECRET_KEY = hexToBytes("22".repeat(32));
const LSP_PUBKEY = "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27";
// The payee, another tenant of the LSP: its secret and its public key.
const PAYEE_SECRET_KEY = hexToBytes("11".repeat(32));
const PAYEE_PUBKEY = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
// The public key of the secret 0x33 repeated.
const OTHER_PUBKEY = "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1";
const PAYMENT_HASH = "5a".repeat(32);
const OTHER_HASH = "7e".repeat(32);
// A hash sharing with PAYMENT_HASH the 20 bytes a TLC's witness binds.
const TWIN_HASH = `${"5a".repeat(20)}${"00".repeat(12)}`;
const AMOUNT = "250000000";
const UINT128_MAX = "340282366920938463463374607431768211455";
// An hour past the invoice's timestamp.
const EXPIRES_AT_MS = 1_791_370_800_000;
// A minute past the invoice's timestamp.
const NOW_MS = 1_791_367_260_000;

const ACTIVITY_KEY = "fiber-lsp-sdk:activity";
const INTENT_KEY = `fiber-lsp-sdk:intent:${PAYMENT_HASH.slice(0, 40)}`;
const RECORD_KEY = `fiber-lsp-sdk:payment-history:${PAYMENT_HASH}`;
const INDEX_KEY = "fiber-lsp-sdk:payment-history";

// Fiber's refusal of a send it finds no route for, which leaves a `Failed` row.
const ROUTE_FAILURE = "Send payment error: Failed to build route, PathFind error: no path found";
const NOT_FOUND = `InvalidParameter: Payment session not found: Hash256(0x${PAYMENT_HASH})`;

// Another tenant's invoice of 2.5 CKB, as fiber writes a tenant's.
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

// Fiber's answer to a send it took under trampoline, as a release build writes it: the session created, nothing paid yet.
const SENT_ANSWER = {
    payment_hash: `0x${PAYMENT_HASH}`,
    payment_preimage: null,
    status: "Created",
    created_at: "0x1a115cf2760",
    last_updated_at: "0x1a115cf2760",
    failed_error: null,
    fee: "0x1312d0",
    custom_records: null,
};

// The intent of INVOICE's amount and fiber's default fee budget, 0.5% of it.
const INTENT = { version: 1, paymentHash: PAYMENT_HASH, maxShannons: "251250000", open: true, channelIndexes: [] };

type Harness = {
    storage: InMemorySignerStorage;
    node: ScriptedNode;
    now: jest.Mock<number, []>;
    pollNow: jest.SpyInstance<void, []>;
    context: SdkPaymentSendingContext;
};

function harness(network: SdkNetworkConfig = SDK_NETWORK_PRESETS.testnet, lspPubkey: string = LSP_PUBKEY): Harness {
    const storage = new InMemorySignerStorage();
    const store = new SignerStore(storage);
    const node = new ScriptedNode();
    const now = jest.fn<number, []>(() => NOW_MS);
    const poller = new ActivityPoller({
        timer: new TimerMock(),
        intervalMs: 5_000,
        stepTimeoutMs: 30_000,
        steps: [],
        emit: () => undefined,
    });
    const pollNow = jest.spyOn(poller, "pollNow");
    const context: SdkPaymentSendingContext = {
        network,
        lspPubkey: hexToBytes(lspPubkey),
        now,
        rpc: new FiberRpcClient({ url: URL, fetch: node.fetch }),
        policy: new PolicyEngine(store),
        activity: new ActivityTracker(store),
        history: new PaymentHistory(store),
        poller,
        sending: new Set<string>(),
        reading: new Set<string>(),
    };
    return { storage, node, now, pollNow, context };
}

function stringOf(invoice: UnsignedInvoice = INVOICE, secretKey: Uint8Array = PAYEE_SECRET_KEY): string {
    return encodeInvoice(signInvoice(invoice, secretKey));
}

function sendCall(invoice: string = stringOf(), sent: Record<string, unknown> = {}): SentCall {
    return {
        method: "send_payment",
        params: { invoice, max_fee_amount: "0x1312d0", dry_run: false, trampoline_hops: [LSP_PUBKEY], ...sent },
    };
}

function watching(...hashes: string[]): unknown {
    return { version: 1, channels: {}, payments: Object.fromEntries(hashes.map((hash) => [hash, { status: null }])), invoices: {} };
}

function paymentAnswer(paymentHash: string, status: string, failedError: string | null = null): unknown {
    return { ...SENT_ANSWER, payment_hash: `0x${paymentHash}`, status, failed_error: failedError };
}

// `maxFeeShannons` is fiber's default budget for INVOICE.
function pendingStored(fields: Partial<StoredPaymentRecord> = {}): StoredPaymentRecord {
    return {
        version: 1,
        paymentHashHex: `0x${PAYMENT_HASH}`,
        direction: "send",
        status: "pending",
        amountShannons: AMOUNT,
        invoice: stringOf(),
        description: null,
        maxFeeShannons: "1250000",
        feeShannons: null,
        failedReason: null,
        createdAtMs: NOW_MS,
        settledAtMs: null,
        ...fields,
    };
}

function failedStored(reason: string, fields: Partial<StoredPaymentRecord> = {}): StoredPaymentRecord {
    return pendingStored({ status: "failed", failedReason: reason, settledAtMs: NOW_MS, ...fields });
}

function readOf({ version, ...record }: StoredPaymentRecord): SdkPaymentRecord {
    expect(version).toBe(1);
    return record;
}

async function seedRecord(h: Harness, record: StoredPaymentRecord): Promise<void> {
    await h.context.history.update(record.paymentHashHex.slice(2), () => record);
}

// `toEqual` compares an error's message alone: its class and its code are held besides.
function expectSdkError(error: unknown, expected: SdkError): void {
    expect(error).toBeInstanceOf(SdkError);
    expect(error).toEqual(expected);
    expect((error as SdkError).code).toBe(expected.code);
}

function inFlight(): SdkError {
    return new SdkError("payment_in_flight", `the device refuses the payment: the one under 0x${PAYMENT_HASH} is not reported yet`);
}

function stepOf(h: Harness, events: SdkEvent[], onEmit: (event: SdkEvent) => void = () => undefined): (run: StepRun) => Promise<void> {
    return buildPaymentStep({
        rpc: h.context.rpc,
        policy: h.context.policy,
        activity: h.context.activity,
        history: h.context.history,
        now: h.now,
        sending: h.context.sending,
        reading: h.context.reading,
        emit: (event) => {
            events.push(event);
            onEmit(event);
        },
    });
}

type Gate = { reached: Promise<void>; open: () => void; wait: () => Promise<void> };

// `wait` marks the gate reached and resolves once `open` is called.
function gate(): Gate {
    let reach: () => void = () => undefined;
    let open: () => void = () => undefined;
    const reached = new Promise<void>((resolve) => {
        reach = resolve;
    });
    const opened = new Promise<void>((resolve) => {
        open = resolve;
    });
    return {
        reached,
        open: () => open(),
        wait: () => {
            reach();
            return opened;
        },
    };
}

// Runs, before the node, the first hook named after a call's method and hash.
function hookCalls(h: Harness, hooks: [string, () => Promise<void>][]): void {
    const fetch: IFetchLike = async (url, init) => {
        const { method, params } = JSON.parse(init.body) as { method: string; params: { payment_hash?: string }[] };
        const hash = params[0]?.payment_hash;
        const name = hash === undefined ? method : `${method} ${hash}`;
        const at = hooks.findIndex(([hooked]) => hooked === name);
        if (at !== -1) await hooks.splice(at, 1)[0]?.[1]();
        return h.node.fetch(url, init);
    };
    h.context.rpc = new FiberRpcClient({ url: URL, fetch });
}

// Each key's writes fail once, after the given number pass.
function failingWrites(h: Harness, failures: [string, number][]): void {
    const set = h.storage.set.bind(h.storage);
    const seen = new Map<string, number>();
    jest.spyOn(h.storage, "set").mockImplementation((at, value) => {
        const count = seen.get(at) ?? 0;
        seen.set(at, count + 1);
        if (failures.some(([key, after]) => key === at && count === after)) throw new Error("storage offline");
        set(at, value);
    });
}

function failingWrite(h: Harness, key: string, after = 0): void {
    const set = h.storage.set.bind(h.storage);
    let seen = 0;
    jest.spyOn(h.storage, "set").mockImplementation((at, value) => {
        if (at === key && seen++ >= after) throw new Error("storage offline");
        set(at, value);
    });
}

describe("transferSdkPayment", () => {
    it("sends the invoice for real, with fiber's default fee budget, through the LSP as trampoline", async () => {
        const h = harness();
        h.node.result(SENT_ANSWER);
        await transferSdkPayment(h.context, stringOf());
        expect(h.node.calls()).toEqual([sendCall()]);
    });

    it("hands back the payment hash in 0x hex, the amount and the fee budget sent", async () => {
        const h = harness();
        h.node.result(SENT_ANSWER);
        await expect(transferSdkPayment(h.context, stringOf())).resolves.toStrictEqual({
            paymentHashHex: `0x${PAYMENT_HASH}`,
            amountShannons: AMOUNT,
            maxFeeShannons: "1250000",
        });
    });

    it("watches the hash, then opens the intent of the amount and the fee, before the node hears of the payment", async () => {
        const h = harness();
        let seen: unknown;
        h.node.onCall("send_payment", () => {
            seen = {
                activity: storedAt(h.storage, ACTIVITY_KEY),
                intent: storedAt(h.storage, INTENT_KEY),
                record: storedAt(h.storage, RECORD_KEY),
                index: storedAt(h.storage, INDEX_KEY),
                polls: h.pollNow.mock.calls.length,
            };
        });
        h.node.result(SENT_ANSWER);
        await transferSdkPayment(h.context, stringOf());
        expect(seen).toEqual({
            activity: watching(PAYMENT_HASH),
            intent: INTENT,
            record: pendingStored(),
            index: { version: 1, entries: [{ paymentHash: PAYMENT_HASH, createdAtMs: NOW_MS }] },
            polls: 0,
        });
        expect(writes(h.storage)).toEqual([ACTIVITY_KEY, INTENT_KEY, RECORD_KEY, INDEX_KEY]);
    });

    it("asks the poller for a tick once the node took the payment, keeping the intent and the watch for its step", async () => {
        const h = harness();
        h.node.result(SENT_ANSWER);
        await transferSdkPayment(h.context, stringOf());
        expect(h.pollNow).toHaveBeenCalledTimes(1);
        expect(storedAt(h.storage, INTENT_KEY)).toEqual(INTENT);
        expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
    });

    describe("the fee budget", () => {
        it.each<[string, string, string, string, string]>([
            ["an amount fiber's rate divides exactly", AMOUNT, "1250000", "0x1312d0", "251250000"],
            ["an amount whose fee rounds up", "250000001", "1250001", "0x1312d1", "251250002"],
            ["200 shannons, a shannon of fee exactly", "200", "1", "0x1", "201"],
            ["201 shannons, whose fee rounds up to two", "201", "2", "0x2", "203"],
            ["one shannon, whose fee rounds up to one", "1", "1", "0x1", "2"],
        ])("defaults to fiber's 0.5%%, rounded up as fiber rounds, for %s", async (_, amountShannons, fee, feeHex, budget) => {
            const h = harness();
            h.node.result(SENT_ANSWER);
            const invoice = stringOf({ ...INVOICE, amountShannons });
            await expect(transferSdkPayment(h.context, invoice)).resolves.toMatchObject({ amountShannons, maxFeeShannons: fee });
            expect(h.node.calls()).toEqual([sendCall(invoice, { max_fee_amount: feeHex })]);
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, maxShannons: budget });
        });

        it.each<[string, string, string, string]>([
            ["a budget below the default", "1000", "0x3e8", "250001000"],
            ["no fee at all", "0", "0x0", AMOUNT],
            ["a budget above fiber's 0.5%, which fiber caps", "5000000", "0x4c4b40", "255000000"],
            [
                "the largest budget the intent can hold over the amount",
                "340282366920938463463374607431518211455",
                "0xfffffffffffffffffffffffff1194d7f",
                UINT128_MAX,
            ],
        ])("sends the host's for %s, and approves the amount and it", async (_, maxFeeShannons, feeHex, budget) => {
            const h = harness();
            h.node.result(SENT_ANSWER);
            await expect(transferSdkPayment(h.context, stringOf(), { maxFeeShannons })).resolves.toMatchObject({ maxFeeShannons });
            expect(h.node.calls()).toEqual([sendCall(stringOf(), { max_fee_amount: feeHex })]);
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, maxShannons: budget });
        });

        it.each<[string, SdkTransferOptions]>([
            ["empty options", {}],
            ["a fee left undefined", { maxFeeShannons: undefined }],
        ])("takes %s as the default", async (_, options) => {
            const h = harness();
            h.node.result(SENT_ANSWER);
            await transferSdkPayment(h.context, stringOf(), options);
            expect(h.node.calls()).toEqual([sendCall()]);
        });

        it("reads the host's fee once, so the budget approved is the one sent", async () => {
            const h = harness();
            let reads = 0;
            const options = {
                get maxFeeShannons(): string {
                    reads += 1;
                    return reads === 1 ? "1000" : "9000000";
                },
            };
            h.node.result(SENT_ANSWER);
            await transferSdkPayment(h.context, stringOf(), options);
            expect(reads).toBe(1);
            expect(h.node.calls()).toEqual([sendCall(stringOf(), { max_fee_amount: "0x3e8" })]);
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, maxShannons: "250001000" });
        });

        it.each<[string, string, SdkTransferOptions | undefined, string]>([
            ["an amount whose default fee overflows the u128", UINT128_MAX, undefined, "341983778755543155780691480468927052513"],
            [
                "a host's budget a shannon past what the amount leaves",
                AMOUNT,
                { maxFeeShannons: "340282366920938463463374607431518211456" },
                "340282366920938463463374607431768211456",
            ],
        ])("refuses %s, writing and sending nothing", async (_, amountShannons, options, budget) => {
            const h = harness();
            const error = await rejection(transferSdkPayment(h.context, stringOf({ ...INVOICE, amountShannons }), options));
            expect(error).toEqual(
                new RangeError(`the invoice's amount and the fee budget must add up to at most ${UINT128_MAX} shannons, got ${budget}`),
            );
            expect(error).toBeInstanceOf(RangeError);
            expect(h.storage.ops).toEqual([]);
            expect(h.node.calls()).toEqual([]);
        });
    });

    describe("the trampoline", () => {
        it("pays the LSP's own invoice directly, with no trampoline", async () => {
            const h = harness();
            h.node.result(SENT_ANSWER);
            const invoice = stringOf(LSP_INVOICE, LSP_SECRET_KEY);
            await transferSdkPayment(h.context, invoice);
            // Fiber refuses an empty list, so the client leaves the member out.
            expect(h.node.calls()).toEqual([{ method: "send_payment", params: { invoice, max_fee_amount: "0x1312d0", dry_run: false } }]);
        });

        it("routes through the device's LSP, not the one the invoice's hint names", async () => {
            const h = harness(SDK_NETWORK_PRESETS.testnet, OTHER_PUBKEY);
            h.node.result(SENT_ANSWER);
            await transferSdkPayment(h.context, stringOf());
            expect(h.node.calls()).toEqual([sendCall(stringOf(), { trampoline_hops: [OTHER_PUBKEY] })]);
        });

        it("routes through the device's LSP an invoice whose payee is another LSP", async () => {
            const h = harness(SDK_NETWORK_PRESETS.testnet, OTHER_PUBKEY);
            h.node.result(SENT_ANSWER);
            const invoice = stringOf(LSP_INVOICE, LSP_SECRET_KEY);
            await transferSdkPayment(h.context, invoice);
            expect(h.node.calls()).toEqual([sendCall(invoice, { trampoline_hops: [OTHER_PUBKEY] })]);
        });
    });

    describe("the invoice", () => {
        it.each<[string, () => Harness, string, string]>([
            [
                "another network's currency",
                () => harness(SDK_NETWORK_PRESETS.mainnet),
                stringOf(),
                "currency is Fibt, not the network's Fibb",
            ],
            [
                "a development chain's currency on testnet",
                () => harness(),
                stringOf({ ...INVOICE, currency: "Fibd" }),
                "currency is Fibd, not the network's Fibt",
            ],
            ["no amount", () => harness(), stringOf({ ...INVOICE, amountShannons: null }), "amountShannons is missing"],
        ])("refuses %s as invoice_unpayable, writing and sending nothing", async (_, build, invoice, detail) => {
            const h = build();
            const error = await rejection(transferSdkPayment(h.context, invoice));
            expectSdkError(error, new SdkError("invoice_unpayable", `the invoice cannot be paid: ${detail}`));
            expect(h.storage.ops).toEqual([]);
            expect(h.node.calls()).toEqual([]);
        });

        it("refuses a string that does not decode over the decoder's refusal, writing and sending nothing", async () => {
            const h = harness();
            const error = await rejection(transferSdkPayment(h.context, stringOf().toUpperCase()));
            expectSdkError(
                error,
                new SdkError("invoice_unpayable", "the invoice cannot be paid: encodedInvoice does not decode: invoice must be lowercase"),
            );
            expect((error as SdkError).cause).toBeInstanceOf(InvoiceError);
            expect(h.storage.ops).toEqual([]);
        });

        it("pays the invoice a millisecond before it runs out by the device's clock", async () => {
            const h = harness();
            h.now.mockReturnValue(EXPIRES_AT_MS - 1);
            h.node.result(SENT_ANSWER);
            await transferSdkPayment(h.context, stringOf());
            expect(h.node.calls()).toEqual([sendCall()]);
        });

        it("refuses it at the millisecond it runs out by the device's clock, writing and sending nothing", async () => {
            const h = harness();
            h.now.mockReturnValue(EXPIRES_AT_MS);
            expectSdkError(
                await rejection(transferSdkPayment(h.context, stringOf())),
                new SdkError(
                    "invoice_unpayable",
                    `the invoice cannot be paid: expiryTime ran out at ${EXPIRES_AT_MS}, the device's clock reading ${EXPIRES_AT_MS}`,
                ),
            );
            expect(h.storage.ops).toEqual([]);
            expect(h.node.calls()).toEqual([]);
        });
    });

    describe("the clock", () => {
        it("is read before anything is written, then once for the pending record, each without a receiver", async () => {
            const h = harness();
            const receivers: unknown[] = [];
            const writtenBefore: string[][] = [];
            h.now.mockImplementation(function (this: unknown): number {
                receivers.push(this);
                writtenBefore.push(writes(h.storage));
                return NOW_MS + receivers.length - 1;
            });
            h.node.result(SENT_ANSWER);
            await transferSdkPayment(h.context, stringOf());
            expect(receivers).toEqual([undefined, undefined]);
            expect(writtenBefore).toEqual([[], [ACTIVITY_KEY, INTENT_KEY]]);
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(pendingStored({ createdAtMs: NOW_MS + 1 }));
        });

        it("closes the intent and drops the watch when its reading for the pending record is refused, sending nothing", async () => {
            const h = harness();
            h.now.mockReturnValueOnce(NOW_MS).mockReturnValueOnce(-1);
            expect(await rejection(transferSdkPayment(h.context, stringOf()))).toEqual(
                new RangeError("now() must be an integer between 0 and 9007199254740991, got -1"),
            );
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, open: false });
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching());
            expect(storedAt(h.storage, RECORD_KEY)).toBeUndefined();
            expect(h.node.calls()).toEqual([]);
        });

        it.each<[string, unknown]>([
            ["a fractional reading", 1.5],
            ["a negative reading", -1],
            ["a reading in a string", "1791367260000"],
        ])("refuses %s, writing and sending nothing", async (_, reading) => {
            const h = harness();
            h.now.mockReturnValue(reading as number);
            expect(await rejection(transferSdkPayment(h.context, stringOf()))).toEqual(
                new RangeError(`now() must be an integer between 0 and 9007199254740991, got ${String(reading)}`),
            );
            expect(h.storage.ops).toEqual([]);
            expect(h.node.calls()).toEqual([]);
        });
    });

    describe("its arguments", () => {
        const notInvoice = new TypeError("encodedInvoice must be a string");
        const notOptions = new TypeError("options must be an object");
        const notFee = new TypeError("options.maxFeeShannons must be an amount in decimal shannons");

        it.each<[string, unknown, unknown, Error]>([
            ["no invoice", undefined, undefined, notInvoice],
            ["a null invoice", null, undefined, notInvoice],
            ["an invoice in bytes", new TextEncoder().encode("fibt1"), undefined, notInvoice],
            ["null options", "INVOICE", null, notOptions],
            ["options in a list", "INVOICE", [], notOptions],
            ["options in a string", "INVOICE", "1000", notOptions],
            ["a null fee", "INVOICE", { maxFeeShannons: null }, notFee],
            ["a fee in a number", "INVOICE", { maxFeeShannons: 1000 }, notFee],
            ["a fee in a bigint", "INVOICE", { maxFeeShannons: 1000n }, notFee],
            ["an empty fee", "INVOICE", { maxFeeShannons: "" }, notFee],
            ["a negative fee", "INVOICE", { maxFeeShannons: "-1" }, notFee],
            ["a fractional fee", "INVOICE", { maxFeeShannons: "1.5" }, notFee],
            ["a fee in hex", "INVOICE", { maxFeeShannons: "0x3e8" }, notFee],
            ["a fee with a leading zero", "INVOICE", { maxFeeShannons: "01000" }, notFee],
            ["a fee one past a u128", "INVOICE", { maxFeeShannons: "340282366920938463463374607431768211456" }, notFee],
        ])("refuses %s, reading no clock, writing and sending nothing", async (_, invoice, options, error) => {
            const h = harness();
            const encodedInvoice = invoice === "INVOICE" ? stringOf() : invoice;
            const thrown = await rejection(transferSdkPayment(h.context, encodedInvoice as string, options as SdkTransferOptions));
            expect(thrown).toEqual(error);
            expect(thrown).toBeInstanceOf(error.constructor);
            expect(h.now).not.toHaveBeenCalled();
            expect(h.storage.ops).toEqual([]);
            expect(h.node.calls()).toEqual([]);
        });
    });

    describe("a hash still watched", () => {
        it("is refused after an unknown outcome, as payment_in_flight, writing and sending nothing more", async () => {
            const h = harness();
            h.node.reject(new Error("offline"));
            await rejection(transferSdkPayment(h.context, stringOf()));
            h.storage.ops.length = 0;
            const error = await rejection(transferSdkPayment(h.context, stringOf(), { maxFeeShannons: "1000" }));
            expectSdkError(error, inFlight());
            expect(writes(h.storage)).toEqual([]);
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(pendingStored());
            expect(h.node.calls()).toEqual([sendCall()]);
            expect(storedAt(h.storage, INTENT_KEY)).toEqual(INTENT);
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
        });

        it("is refused to a listener retrying on the step's PAYMENT_FAILED before its forget, then paid on the retry after", async () => {
            const h = harness();
            h.node.reject(new Error("offline"));
            await rejection(transferSdkPayment(h.context, stringOf()));
            const events: SdkEvent[] = [];
            let retried: Promise<unknown> | undefined;
            const step = stepOf(h, events, (event) => {
                if (event.type === "PAYMENT_FAILED") retried = rejection(transferSdkPayment(h.context, stringOf()));
            });
            h.node.result(paymentAnswer(PAYMENT_HASH, "Failed", ROUTE_FAILURE));
            await step(live());
            expect(events).toEqual([
                {
                    type: "PAYMENT_FAILED",
                    paymentHashHex: `0x${PAYMENT_HASH}`,
                    reason: ROUTE_FAILURE,
                    payment: readOf(failedStored(ROUTE_FAILURE)),
                },
            ]);
            expectSdkError(await retried, inFlight());
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching());
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, open: false });
            h.node.result(SENT_ANSWER);
            await expect(transferSdkPayment(h.context, stringOf(), { maxFeeShannons: "1000" })).resolves.toMatchObject({
                maxFeeShannons: "1000",
            });
            expect(h.node.calls()).toEqual([sendCall(), getPaymentCall(PAYMENT_HASH), sendCall(stringOf(), { max_fee_amount: "0x3e8" })]);
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, maxShannons: "250001000" });
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
        });
    });

    describe("the hashes being sent", () => {
        it("lets one of two concurrent transfers of the hash through", async () => {
            const h = harness();
            h.node.result(SENT_ANSWER);
            const outcomes = await Promise.allSettled([
                transferSdkPayment(h.context, stringOf()),
                transferSdkPayment(h.context, stringOf(), { maxFeeShannons: "1000" }),
            ]);
            expect(outcomes.map((outcome) => outcome.status)).toEqual(["fulfilled", "rejected"]);
            expectSdkError((outcomes[1] as PromiseRejectedResult).reason, inFlight());
            expect(h.node.calls()).toEqual([sendCall()]);
            expect(writes(h.storage)).toEqual([ACTIVITY_KEY, INTENT_KEY, RECORD_KEY, INDEX_KEY]);
            expect(storedAt(h.storage, INTENT_KEY)).toEqual(INTENT);
        });

        it("holds the hash from before its watch until the node answered the send", async () => {
            const h = harness();
            const held: boolean[] = [];
            const set = h.storage.set.bind(h.storage);
            jest.spyOn(h.storage, "set").mockImplementation((key, value) => {
                if (key === ACTIVITY_KEY) held.push(h.context.sending.has(PAYMENT_HASH));
                set(key, value);
            });
            h.node.onCall("send_payment", () => held.push(h.context.sending.has(PAYMENT_HASH)));
            h.node.result(SENT_ANSWER);
            await transferSdkPayment(h.context, stringOf());
            expect(held).toEqual([true, true]);
            expect([...h.context.sending]).toEqual([]);
        });

        it("asks the poller for its tick once the hash is no longer held", async () => {
            const h = harness();
            let held: boolean | undefined;
            h.pollNow.mockImplementation(() => {
                held = h.context.sending.has(PAYMENT_HASH);
            });
            h.node.result(SENT_ANSWER);
            await transferSdkPayment(h.context, stringOf());
            expect(held).toBe(false);
        });

        it("refuses a hash the step is reading as payment_in_flight, touching no storage and leaving the step's hold", async () => {
            const h = harness();
            h.context.reading.add(PAYMENT_HASH);
            const error = await rejection(transferSdkPayment(h.context, stringOf()));
            expectSdkError(error, inFlight());
            expect(h.storage.ops).toEqual([]);
            expect(h.node.calls()).toEqual([]);
            expect([...h.context.reading]).toEqual([PAYMENT_HASH]);
            expect([...h.context.sending]).toEqual([]);
        });

        it("refuses a hash another call is sending as payment_in_flight, touching no storage and leaving that call's hold", async () => {
            const h = harness();
            h.context.sending.add(PAYMENT_HASH);
            const error = await rejection(transferSdkPayment(h.context, stringOf()));
            expectSdkError(error, inFlight());
            expect(h.storage.ops).toEqual([]);
            expect(h.node.calls()).toEqual([]);
            expect([...h.context.sending]).toEqual([PAYMENT_HASH]);
        });

        it("holds nothing for an invoice it refuses", async () => {
            const h = harness();
            const add = jest.spyOn(h.context.sending, "add");
            await rejection(transferSdkPayment(h.context, stringOf({ ...INVOICE, amountShannons: "0" })));
            expect(add).not.toHaveBeenCalled();
        });

        it.each<[string, (h: Harness) => Promise<void>]>([
            ["the node took the payment", async (h) => void h.node.result(SENT_ANSWER)],
            ["the node refused it", async (h) => void h.node.error(-32000, ROUTE_FAILURE)],
            ["its outcome is unknown", async (h) => void h.node.reject(new Error("offline"))],
            ["the hash is still watched", (h) => h.context.activity.watch("payment", PAYMENT_HASH)],
            ["the intent is refused", (h) => h.context.policy.recordHoldInvoice(PAYMENT_HASH, AMOUNT, "ckb-hash", 1_791_367_200_250)],
            ["the storage fails at the intent", async (h) => failingWrite(h, INTENT_KEY)],
        ])("lets the hash go once the call settles, when %s", async (_, setUp) => {
            const h = harness();
            await setUp(h);
            await transferSdkPayment(h.context, stringOf()).catch(() => undefined);
            expect([...h.context.sending]).toEqual([]);
        });

        it("keeps a tick between the watch and the node's answer off the hash, and lets the next one read it", async () => {
            const h = harness();
            await h.context.activity.watch("payment", OTHER_HASH);
            const events: SdkEvent[] = [];
            let duringSend: unknown;
            hookCalls(h, [
                [
                    "send_payment",
                    async () => {
                        await step(live());
                        duringSend = { calls: h.node.calls(), events: [...events] };
                    },
                ],
            ]);
            const step = stepOf(h, events);
            // The client numbers the send 1 and the tick's read 2, which reaches the node first.
            h.node.mock.answer(
                rpcResultAnswer(2, paymentAnswer(OTHER_HASH, "Inflight")),
                rpcResultAnswer(1, SENT_ANSWER),
                rpcResultAnswer(3, paymentAnswer(OTHER_HASH, "Inflight")),
                rpcResultAnswer(4, paymentAnswer(PAYMENT_HASH, "Success")),
            );
            await transferSdkPayment(h.context, stringOf());
            expect(duringSend).toEqual({ calls: [getPaymentCall(OTHER_HASH)], events: [] });
            await step(live());
            expect(h.node.calls()).toEqual([
                getPaymentCall(OTHER_HASH),
                sendCall(),
                getPaymentCall(OTHER_HASH),
                getPaymentCall(PAYMENT_HASH),
            ]);
            expect(events).toEqual([
                {
                    type: "PAYMENT_SENT",
                    paymentHashHex: `0x${PAYMENT_HASH}`,
                    feeShannons: "1250000",
                    payment: readOf(pendingStored({ status: "completed", feeShannons: "1250000", settledAtMs: NOW_MS })),
                },
            ]);
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, open: false });
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(OTHER_HASH));
        });
    });

    describe("a refusal of the intent", () => {
        it("refuses an open intent left unwatched as payment_in_flight, keeping the watch so the step closes it", async () => {
            const h = harness();
            await h.context.policy.recordDebitIntent(PAYMENT_HASH, "1000");
            const error = await rejection(transferSdkPayment(h.context, stringOf()));
            expectSdkError(
                error,
                new SdkError("payment_in_flight", `the device refuses the payment: a debit intent for ${PAYMENT_HASH} is already open`),
            );
            expect((error as SdkError).cause).toBeInstanceOf(DebitIntentError);
            expect((error as SdkError).cause).toMatchObject({ code: "intent_open" });
            expect(h.node.calls()).toEqual([]);
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, maxShannons: "1000" });
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
            expect(storedAt(h.storage, RECORD_KEY)).toBeUndefined();
        });

        it("refuses a charged intent as payment_charged, its watch dropped", async () => {
            const h = harness();
            const cause = new DebitIntentError(
                "intent_charged",
                `a payment under ${PAYMENT_HASH} has already been charged, it cannot be authorised again`,
            );
            jest.spyOn(h.context.policy, "recordDebitIntent").mockRejectedValue(cause);
            const error = await rejection(transferSdkPayment(h.context, stringOf()));
            expectSdkError(error, new SdkError("payment_charged", `the device refuses the payment: ${cause.message}`));
            expect((error as SdkError).cause).toBe(cause);
            expect(h.node.calls()).toEqual([]);
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching());
            expect(storedAt(h.storage, RECORD_KEY)).toBeUndefined();
        });

        it("refuses the hash of a hold invoice of the device as own_invoice, its watch dropped", async () => {
            const h = harness();
            await h.context.policy.recordHoldInvoice(PAYMENT_HASH, AMOUNT, "ckb-hash", 1_791_367_200_250);
            const error = await rejection(transferSdkPayment(h.context, stringOf()));
            expectSdkError(
                error,
                new SdkError("own_invoice", `the device refuses the payment: ${PAYMENT_HASH} is the hash of a hold invoice of this device`),
            );
            expect((error as SdkError).cause).toMatchObject({ code: "own_invoice" });
            expect(h.node.calls()).toEqual([]);
            expect(storedAt(h.storage, INTENT_KEY)).toBeUndefined();
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching());
            expect(storedAt(h.storage, RECORD_KEY)).toBeUndefined();
        });

        it.each<[string, (h: Harness) => Promise<void>]>([
            ["another payment's intent", (h) => h.context.policy.recordDebitIntent(TWIN_HASH, "1000")],
            ["a hold invoice of the device", (h) => h.context.policy.recordHoldInvoice(TWIN_HASH, AMOUNT, "ckb-hash", 1_791_367_200_250)],
        ])("refuses a hash twin of %s as invoice_unpayable, its watch dropped and nothing sent", async (_, record) => {
            const h = harness();
            await record(h);
            const error = await rejection(transferSdkPayment(h.context, stringOf()));
            expectSdkError(
                error,
                new SdkError(
                    "invoice_unpayable",
                    `the invoice cannot be paid: the 20 bytes of ${PAYMENT_HASH} a TLC's witness binds are another payment's`,
                ),
            );
            expect((error as SdkError).cause).toBeInstanceOf(DebitIntentError);
            expect((error as SdkError).cause).toMatchObject({ code: "hash_twin" });
            expect(h.node.calls()).toEqual([]);
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching());
            expect(await h.context.policy.readDebitIntent(PAYMENT_HASH)).toBeNull();
            expect(storedAt(h.storage, RECORD_KEY)).toBeUndefined();
        });
    });

    describe("the node's answer", () => {
        it.each<[string, SdkErrorCode, string]>([
            [
                "a single path short of outbound liquidity",
                "insufficient_balance",
                "Send payment error: Failed to build route, Insufficient balance: max outbound liquidity 0 is insufficient, required amount: 250000000",
            ],
            [
                "every path together short of outbound liquidity",
                "insufficient_balance",
                "Send payment error: Failed to build route, Insufficient balance: total outbound liquidity 249999999 is insufficient, required amount: 340282366920938463463374607431768211455",
            ],
            [
                "a hop past its outbound liquidity",
                "insufficient_balance",
                "Send payment error: Failed to build route, Insufficient balance: route hop amount 251250000 exceeds outbound liquidity 7",
            ],
            ["no path", "no_route", ROUTE_FAILURE],
            [
                "a hop's minimum TLC",
                "no_route",
                "Send payment error: Failed to build route, Path find failed for min_tlc_value error: 1000",
            ],
            [
                "a hop past its channel's capacity",
                "no_route",
                "Send payment error: Failed to build route, Insufficient balance: route hop amount 251250000 exceeds channel capacity 100000000",
            ],
            ["too few MPP routes", "no_route", "Send payment error: Failed to build enough routes for MPP payment"],
            [
                "a budget below the trampoline's floor",
                "fee_budget_too_low",
                "Send payment error: Failed to build route, Graph other error: max_fee_amount is too low for trampoline routing: recommend_minimal_fee=250000, maximal_fee=2500000 current_fee=0",
            ],
            [
                "a budget below the first hop's fee",
                "fee_budget_too_low",
                "Send payment error: Failed to build route, Graph other error: max_fee_amount is too low for trampoline routing: first_hop_fee=12 current_fee=11",
            ],
            [
                "a budget leaving a trampoline hop no fee",
                "fee_budget_too_low",
                "Send payment error: Failed to build route, Graph other error: max_fee_amount is too low for trampoline routing: fee for a trampoline hop is zero",
            ],
            [
                "a budget below a direct route's fee",
                "fee_budget_too_low",
                "Send payment error: max_fee_amount is too low for selected route",
            ],
        ])("refuses fiber's answer to %s as %s, the intent closed and the hash no longer watched", async (_, code, text) => {
            const h = harness();
            h.node.error(-32000, text);
            const error = await rejection(transferSdkPayment(h.context, stringOf()));
            expectSdkError(error, new SdkError(code, `the node refuses the payment: ${text}`));
            expect((error as SdkError).cause).toBeInstanceOf(RpcError);
            expect((error as SdkError).cause).toMatchObject({ method: "send_payment", code: -32000, message: text });
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, open: false });
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching());
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(failedStored(`the node refuses the payment: ${text}`));
            expect(h.pollNow).not.toHaveBeenCalled();
        });

        it.each<[string, number, string]>([
            [
                "a number written signed",
                -32000,
                "Send payment error: Failed to build route, Insufficient balance: max outbound liquidity -1 is insufficient, required amount: 250000000",
            ],
            [
                "a number written as a fraction",
                -32000,
                "Send payment error: Failed to build route, Insufficient balance: route hop amount 2.5 exceeds outbound liquidity 7",
            ],
            [
                "a number missing",
                -32000,
                "Send payment error: Failed to build route, Insufficient balance: total outbound liquidity  is insufficient, required amount: 1",
            ],
            ["text past it", -32000, `${ROUTE_FAILURE} `],
            ["its start cut", -32000, "Failed to build route, PathFind error: no path found"],
            [
                "the graph's own wrapper",
                -32000,
                "Network Graph error: Insufficient balance: max outbound liquidity 0 is insufficient, required amount: 250000000",
            ],
            ["another code", -32602, "Send payment error: max_fee_amount is too low for selected route"],
            ["the trampoline's collapsed failure", -32000, "Send payment error: TemporaryNodeFailure"],
            [
                "an undelivered call",
                -32000,
                "Messaging failed to enqueue the message to the specified actor, the actor is likely terminated",
            ],
            ["a lost reply under another code", -32603, "Messaging failed because channel is closed"],
            ["a lost reply's text extended", -32000, "Messaging failed because channel is closed."],
        ])(
            "refuses as payment_rejected fiber's answer with %s, the intent closed and the hash no longer watched",
            async (_, code, text) => {
                const h = harness();
                h.node.error(code, text);
                const error = await rejection(transferSdkPayment(h.context, stringOf()));
                expectSdkError(error, new SdkError("payment_rejected", `the node refuses the payment: ${text}`));
                expect((error as SdkError).cause).toMatchObject({ method: "send_payment", code, message: text });
                expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, open: false });
                expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching());
                expect(storedAt(h.storage, RECORD_KEY)).toEqual(failedStored(`the node refuses the payment: ${text}`));
            },
        );

        it("lets a retry after the node's refusal open the intent again, with its new budget", async () => {
            const h = harness();
            h.node.error(-32000, ROUTE_FAILURE);
            await rejection(transferSdkPayment(h.context, stringOf()));
            h.node.result(SENT_ANSWER);
            await transferSdkPayment(h.context, stringOf(), { maxFeeShannons: "1000" });
            expect(h.node.calls()).toEqual([sendCall(), sendCall(stringOf(), { max_fee_amount: "0x3e8" })]);
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, maxShannons: "250001000" });
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
        });

        it.each([
            ["an unknown outcome", (node: ScriptedNode) => node.reject(new Error("offline")), RpcTransportError],
            ["an answer the client cannot read", (node: ScriptedNode) => node.result({}), RpcResponseError],
        ])("refuses %s as payment_unresolved, the intent open and the hash watched for the step", async (_, answer, errorClass) => {
            const h = harness();
            answer(h.node);
            const error = await rejection(transferSdkPayment(h.context, stringOf()));
            expect(error).toBeInstanceOf(SdkError);
            expect((error as SdkError).code).toBe("payment_unresolved");
            expect((error as SdkError).cause).toBeInstanceOf(errorClass);
            expect((error as SdkError).message).toBe(`the payment's outcome is unknown: ${((error as SdkError).cause as Error).message}`);
            expect(storedAt(h.storage, INTENT_KEY)).toEqual(INTENT);
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(pendingStored());
            expect(h.pollNow).not.toHaveBeenCalled();
        });

        it("refuses fiber's lost actor reply as payment_unresolved, the intent open and the hash watched: the send may have run", async () => {
            const h = harness();
            h.node.error(-32000, "Messaging failed because channel is closed");
            const error = await rejection(transferSdkPayment(h.context, stringOf()));
            expectSdkError(
                error,
                new SdkError("payment_unresolved", "the payment's outcome is unknown: Messaging failed because channel is closed"),
            );
            expect((error as SdkError).cause).toBeInstanceOf(RpcError);
            expect((error as SdkError).cause).toMatchObject({
                method: "send_payment",
                code: -32000,
                message: "Messaging failed because channel is closed",
            });
            expect(storedAt(h.storage, INTENT_KEY)).toEqual(INTENT);
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
            expect(h.pollNow).not.toHaveBeenCalled();
        });

        it("refuses any other failure of the send as payment_unresolved over it, the intent open and the hash watched", async () => {
            const h = harness();
            const failure = new TypeError("a bug");
            jest.spyOn(h.context.rpc, "sendPayment").mockRejectedValue(failure);
            const error = await rejection(transferSdkPayment(h.context, stringOf()));
            expectSdkError(error, new SdkError("payment_unresolved", "the payment's outcome is unknown: a bug"));
            expect((error as SdkError).cause).toBe(failure);
            expect(storedAt(h.storage, INTENT_KEY)).toEqual(INTENT);
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
            expect(h.pollNow).not.toHaveBeenCalled();
        });

        it("refuses a thrown value that is no error as payment_unresolved with the bare reason, holding the value as its cause", async () => {
            const h = harness();
            jest.spyOn(h.context.rpc, "sendPayment").mockRejectedValue("a string");
            const error = await rejection(transferSdkPayment(h.context, stringOf()));
            expectSdkError(error, new SdkError("payment_unresolved", "the payment's outcome is unknown"));
            expect((error as SdkError).cause).toBe("a string");
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
        });

        it.each<[string, string]>([
            [
                "its payment actor still running",
                `Payment session already exists, stop start new payment actor for Hash256(0x${PAYMENT_HASH})`,
            ],
            [
                "a session created",
                `InvalidParameter: Payment session already exists: Hash256(0x${PAYMENT_HASH}) with payment session status: Created`,
            ],
            [
                "a session in flight",
                `InvalidParameter: Payment session already exists: Hash256(0x${PAYMENT_HASH}) with payment session status: Inflight`,
            ],
            [
                "a session paid",
                `InvalidParameter: Payment session already exists: Hash256(0x${PAYMENT_HASH}) with payment session status: Success`,
            ],
            [
                "a failed session with attempts still in flight",
                `InvalidParameter: Payment session Hash256(0x${PAYMENT_HASH}) has attempts that are in flight state, can not retry`,
            ],
        ])(
            "refuses as payment_session_exists fiber's answer to %s under the hash, the intent and the watch kept for the step",
            async (_, text) => {
                const h = harness();
                h.node.error(-32000, text);
                const error = await rejection(transferSdkPayment(h.context, stringOf()));
                expectSdkError(
                    error,
                    new SdkError("payment_session_exists", `the node already holds a payment under 0x${PAYMENT_HASH}: ${text}`),
                );
                expect((error as SdkError).cause).toBeInstanceOf(RpcError);
                expect((error as SdkError).cause).toMatchObject({ method: "send_payment", code: -32000, message: text });
                expect(storedAt(h.storage, INTENT_KEY)).toEqual(INTENT);
                expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
                expect(storedAt(h.storage, RECORD_KEY)).toEqual(pendingStored());
                expect(h.pollNow).not.toHaveBeenCalled();
            },
        );

        it.each<[string, number, string]>([
            [
                "its actor under another hash",
                -32000,
                `Payment session already exists, stop start new payment actor for Hash256(0x${OTHER_HASH})`,
            ],
            [
                "a session under another hash",
                -32000,
                `InvalidParameter: Payment session already exists: Hash256(0x${OTHER_HASH}) with payment session status: Inflight`,
            ],
            [
                "a failed session, which fiber sends again",
                -32000,
                `InvalidParameter: Payment session already exists: Hash256(0x${PAYMENT_HASH}) with payment session status: Failed`,
            ],
            [
                "attempts in flight under another hash",
                -32000,
                `InvalidParameter: Payment session Hash256(0x${OTHER_HASH}) has attempts that are in flight state, can not retry`,
            ],
            [
                "the hash without fiber's Hash256 form",
                -32000,
                `Payment session already exists, stop start new payment actor for 0x${PAYMENT_HASH}`,
            ],
            ["another code", -32602, `Payment session already exists, stop start new payment actor for Hash256(0x${PAYMENT_HASH})`],
        ])(
            "refuses as payment_rejected a text like those but naming %s, the intent closed and the hash unwatched",
            async (_, code, text) => {
                const h = harness();
                h.node.error(code, text);
                const error = await rejection(transferSdkPayment(h.context, stringOf()));
                expectSdkError(error, new SdkError("payment_rejected", `the node refuses the payment: ${text}`));
                expect((error as SdkError).cause).toMatchObject({ code, message: text });
                expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, open: false });
                expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching());
                expect(storedAt(h.storage, RECORD_KEY)).toEqual(failedStored(`the node refuses the payment: ${text}`));
            },
        );

        it("reports nothing of a route failure to a tick that lands in the middle of it", async () => {
            const h = harness();
            await h.context.activity.watch("payment", OTHER_HASH);
            const events: SdkEvent[] = [];
            const otherRead = gate();
            let tick: Promise<void> | undefined;
            hookCalls(h, [
                [
                    "send_payment",
                    async () => {
                        tick = step(live());
                        await otherRead.reached;
                    },
                ],
                [`get_payment 0x${OTHER_HASH}`, () => otherRead.wait()],
            ]);
            const step = stepOf(h, events);
            h.node.error(-32000, ROUTE_FAILURE);
            h.node.result(paymentAnswer(OTHER_HASH, "Inflight"));
            h.node.result(paymentAnswer(PAYMENT_HASH, "Failed", ROUTE_FAILURE));
            expect(await rejection(transferSdkPayment(h.context, stringOf()))).toMatchObject({ code: "no_route" });
            otherRead.open();
            await tick;
            expect(h.node.calls()).toEqual([sendCall(), getPaymentCall(OTHER_HASH), getPaymentCall(PAYMENT_HASH)]);
            expect(events).toEqual([]);
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, open: false });
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(OTHER_HASH));
        });

        it("refuses a retry sent while a tick reads the failed first try, touching no storage, and takes it after the tick", async () => {
            const h = harness();
            await h.context.activity.watch("payment", OTHER_HASH);
            const events: SdkEvent[] = [];
            const otherRead = gate();
            let tick: Promise<void> | undefined;
            let duringRead: unknown;
            hookCalls(h, [
                [
                    "send_payment",
                    async () => {
                        tick = step(live());
                        await otherRead.reached;
                    },
                ],
                [`get_payment 0x${OTHER_HASH}`, () => otherRead.wait()],
                [
                    `get_payment 0x${PAYMENT_HASH}`,
                    async () => {
                        const ops = h.storage.ops.length;
                        const error = await rejection(transferSdkPayment(h.context, stringOf(), { maxFeeShannons: "1000" }));
                        duringRead = { error, ops: h.storage.ops.slice(ops), sending: [...h.context.sending] };
                    },
                ],
            ]);
            const step = stepOf(h, events);
            h.node.error(-32000, ROUTE_FAILURE);
            h.node.result(paymentAnswer(OTHER_HASH, "Inflight"));
            h.node.result(paymentAnswer(PAYMENT_HASH, "Failed", ROUTE_FAILURE));
            h.node.result(SENT_ANSWER);
            await rejection(transferSdkPayment(h.context, stringOf()));
            otherRead.open();
            await tick;
            expect(duringRead).toEqual({ error: inFlight(), ops: [], sending: [] });
            expectSdkError((duringRead as { error: unknown }).error, inFlight());
            expect(events).toEqual([]);
            expect([...h.context.reading]).toEqual([]);
            await expect(transferSdkPayment(h.context, stringOf(), { maxFeeShannons: "1000" })).resolves.toMatchObject({
                maxFeeShannons: "1000",
            });
            expect(h.node.calls()).toEqual([
                sendCall(),
                getPaymentCall(OTHER_HASH),
                getPaymentCall(PAYMENT_HASH),
                sendCall(stringOf(), { max_fee_amount: "0x3e8" }),
            ]);
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, maxShannons: "250001000" });
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(OTHER_HASH, PAYMENT_HASH));
        });
    });

    describe("the history", () => {
        it("refuses a hash whose record completed as payment_charged, watching, approving and sending nothing", async () => {
            const h = harness();
            const completed = pendingStored({ status: "completed", feeShannons: "1000", settledAtMs: NOW_MS - 1, createdAtMs: NOW_MS - 9 });
            await seedRecord(h, completed);
            h.storage.ops.length = 0;
            const error = await rejection(transferSdkPayment(h.context, stringOf()));
            expectSdkError(
                error,
                new SdkError("payment_charged", `the device refuses the payment: the one under 0x${PAYMENT_HASH} already completed`),
            );
            expect(writes(h.storage)).toEqual([]);
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(completed);
            expect(h.node.calls()).toEqual([]);
            expect(h.pollNow).not.toHaveBeenCalled();
            expect([...h.context.sending]).toEqual([]);
        });

        it.each<[string, Partial<StoredPaymentRecord>]>([
            ["pending", {}],
            ["failed", { status: "failed", failedReason: ROUTE_FAILURE, settledAtMs: NOW_MS - 1 }],
        ])("sends again a hash whose record is %s, the record pending from the new send on", async (_, fields) => {
            const h = harness();
            await seedRecord(h, pendingStored({ createdAtMs: NOW_MS - 9, maxFeeShannons: "7", ...fields }));
            h.node.result(SENT_ANSWER);
            await transferSdkPayment(h.context, stringOf());
            expect(h.node.calls()).toEqual([sendCall()]);
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(pendingStored());
        });

        it("keeps the invoice's description and the host's budget in the pending record", async () => {
            const h = harness();
            const invoice = stringOf({ ...INVOICE, attributes: [...INVOICE.attributes, { type: "description", text: "two coffees" }] });
            h.node.result(SENT_ANSWER);
            await transferSdkPayment(h.context, invoice, { maxFeeShannons: "1000" });
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(pendingStored({ invoice, description: "two coffees", maxFeeShannons: "1000" }));
            await expect(getSdkPayment(h.context, `0x${PAYMENT_HASH}`)).resolves.toStrictEqual(
                readOf(pendingStored({ invoice, description: "two coffees", maxFeeShannons: "1000" })),
            );
        });

        it("leaves alone a record that completed between its check and the pending write", async () => {
            const h = harness();
            const completed = pendingStored({ status: "completed", feeShannons: "1000", settledAtMs: NOW_MS - 1 });
            await seedRecord(h, completed);
            jest.spyOn(h.context.history, "read").mockResolvedValueOnce(null);
            h.node.result(SENT_ANSWER);
            await transferSdkPayment(h.context, stringOf());
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(completed);
        });

        it("rethrows a record it cannot read, writing and sending nothing", async () => {
            const h = harness();
            h.storage.map.set(RECORD_KEY, "{");
            expect(await rejection(transferSdkPayment(h.context, stringOf()))).toEqual(
                new TypeError(`stored value at ${RECORD_KEY} is not valid JSON`),
            );
            expect(writes(h.storage)).toEqual([]);
            expect(h.node.calls()).toEqual([]);
        });

        it("puts a retry of a failed send back to pending, at the front of the list", async () => {
            const h = harness();
            h.node.error(-32000, ROUTE_FAILURE);
            await rejection(transferSdkPayment(h.context, stringOf()));
            const other = pendingStored({ paymentHashHex: `0x${OTHER_HASH}`, createdAtMs: NOW_MS + 500 });
            await seedRecord(h, other);
            const failed = failedStored(`the node refuses the payment: ${ROUTE_FAILURE}`);
            await expect(listSdkPayments(h.context)).resolves.toStrictEqual([readOf(other), readOf(failed)]);
            h.now.mockReturnValue(NOW_MS + 1000);
            h.node.result(SENT_ANSWER);
            await transferSdkPayment(h.context, stringOf(), { maxFeeShannons: "1000" });
            const retried = pendingStored({ maxFeeShannons: "1000", createdAtMs: NOW_MS + 1000 });
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(retried);
            await expect(listSdkPayments(h.context)).resolves.toStrictEqual([readOf(retried), readOf(other)]);
        });

        it("ends completed a send fiber failed falsely, once its retry succeeds", async () => {
            const h = harness();
            const events: SdkEvent[] = [];
            const step = stepOf(h, events);
            h.node.result(SENT_ANSWER).result(paymentAnswer(PAYMENT_HASH, "Failed", ROUTE_FAILURE));
            await transferSdkPayment(h.context, stringOf());
            await step(live());
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(failedStored(ROUTE_FAILURE));
            h.now.mockReturnValue(NOW_MS + 1000);
            h.node.result(SENT_ANSWER).result(paymentAnswer(PAYMENT_HASH, "Success"));
            await transferSdkPayment(h.context, stringOf());
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(pendingStored({ createdAtMs: NOW_MS + 1000 }));
            await step(live());
            const completed = pendingStored({
                status: "completed",
                feeShannons: "1250000",
                createdAtMs: NOW_MS + 1000,
                settledAtMs: NOW_MS + 1000,
            });
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(completed);
            expect(events.map((event) => event.type)).toEqual(["PAYMENT_FAILED", "PAYMENT_SENT"]);
            expect(events[1]).toStrictEqual({
                type: "PAYMENT_SENT",
                paymentHashHex: `0x${PAYMENT_HASH}`,
                feeShannons: "1250000",
                payment: readOf(completed),
            });
            await expect(getSdkPayment(h.context, `0x${PAYMENT_HASH}`)).resolves.toStrictEqual(readOf(completed));
        });
    });

    describe("a failure of the storage", () => {
        it("at the watch records and sends nothing", async () => {
            const h = harness();
            failingWrite(h, ACTIVITY_KEY);
            expect(await rejection(transferSdkPayment(h.context, stringOf()))).toEqual(new Error("storage offline"));
            expect(storedAt(h.storage, ACTIVITY_KEY)).toBeUndefined();
            expect(storedAt(h.storage, INTENT_KEY)).toBeUndefined();
            expect(h.node.calls()).toEqual([]);
        });

        it("at the intent sends nothing and keeps the watch, which the step's not found resolves", async () => {
            const h = harness();
            failingWrite(h, INTENT_KEY);
            expect(await rejection(transferSdkPayment(h.context, stringOf()))).toEqual(new Error("storage offline"));
            expect(storedAt(h.storage, INTENT_KEY)).toBeUndefined();
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
            expect(h.node.calls()).toEqual([]);
        });

        it("at the pending write of the record closes the intent and drops the watch, writing no record and sending nothing", async () => {
            const h = harness();
            failingWrite(h, RECORD_KEY);
            expect(await rejection(transferSdkPayment(h.context, stringOf()))).toEqual(new Error("storage offline"));
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, open: false });
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching());
            expect(storedAt(h.storage, RECORD_KEY)).toBeUndefined();
            expect(storedAt(h.storage, INDEX_KEY)).toBeUndefined();
            expect(h.node.calls()).toEqual([]);
            expect(h.pollNow).not.toHaveBeenCalled();
        });

        it("at the pending write of the index fails the record it left with the write's error, closing the intent and the watch", async () => {
            const h = harness();
            failingWrites(h, [[INDEX_KEY, 0]]);
            expect(await rejection(transferSdkPayment(h.context, stringOf()))).toEqual(new Error("storage offline"));
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(failedStored("storage offline"));
            expect(storedAt(h.storage, INDEX_KEY)).toEqual({ version: 1, entries: [{ paymentHash: PAYMENT_HASH, createdAtMs: NOW_MS }] });
            await expect(listSdkPayments(h.context)).resolves.toStrictEqual([readOf(failedStored("storage offline"))]);
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, open: false });
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching());
            expect(h.node.calls()).toEqual([]);
            expect(h.pollNow).not.toHaveBeenCalled();
        });

        it("fails the record left behind with a thrown value that is no error as its reason, rethrowing the value", async () => {
            const h = harness();
            const update = h.context.history.update.bind(h.context.history);
            jest.spyOn(h.context.history, "update").mockImplementationOnce(async (...args) => {
                await update(...args);
                throw "index offline";
            });
            expect(await rejection(transferSdkPayment(h.context, stringOf()))).toBe("index offline");
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(failedStored("index offline"));
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, open: false });
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching());
        });

        it("at the pending write of the index keeps the intent and the watch when failing the record fails too, for the step's not found to fail it", async () => {
            const h = harness();
            const failure = new Error("storage offline");
            const set = h.storage.set.bind(h.storage);
            let recordWrites = 0;
            jest.spyOn(h.storage, "set").mockImplementation((key, value) => {
                if (key === INDEX_KEY) throw failure;
                if (key === RECORD_KEY && recordWrites++ > 0) throw new Error("storage still offline");
                set(key, value);
            });
            const thrown = await rejection(transferSdkPayment(h.context, stringOf()));
            expect(thrown).toBe(failure);
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(pendingStored());
            expect(storedAt(h.storage, INDEX_KEY)).toBeUndefined();
            expect(storedAt(h.storage, INTENT_KEY)).toEqual(INTENT);
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
            expect(h.node.calls()).toEqual([]);
            jest.mocked(h.storage.set).mockRestore();
            const events: SdkEvent[] = [];
            h.node.error(-32000, NOT_FOUND);
            await stepOf(h, events)(live());
            const reason = "the node holds no session of the payment: it was never sent";
            expect(events).toEqual([
                { type: "PAYMENT_FAILED", paymentHashHex: `0x${PAYMENT_HASH}`, reason, payment: readOf(failedStored(reason)) },
            ]);
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(failedStored(reason));
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, open: false });
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching());
        });

        it("at the pending write lets a retry approve and send it", async () => {
            const h = harness();
            failingWrite(h, RECORD_KEY);
            await rejection(transferSdkPayment(h.context, stringOf()));
            jest.mocked(h.storage.set).mockRestore();
            h.node.result(SENT_ANSWER);
            await transferSdkPayment(h.context, stringOf());
            expect(h.node.calls()).toEqual([sendCall()]);
            expect(storedAt(h.storage, INTENT_KEY)).toEqual(INTENT);
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(pendingStored());
        });

        it("at failing the record the node refused throws the store's error and keeps the intent open and the hash watched, for the step to fail it", async () => {
            const h = harness();
            failingWrite(h, RECORD_KEY, 1);
            h.node.error(-32000, ROUTE_FAILURE);
            expect(await rejection(transferSdkPayment(h.context, stringOf()))).toEqual(new Error("storage offline"));
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(pendingStored());
            expect(storedAt(h.storage, INTENT_KEY)).toEqual(INTENT);
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
            jest.mocked(h.storage.set).mockRestore();
            const events: SdkEvent[] = [];
            h.node.result(paymentAnswer(PAYMENT_HASH, "Failed", ROUTE_FAILURE));
            await stepOf(h, events)(live());
            expect(events).toEqual([
                {
                    type: "PAYMENT_FAILED",
                    paymentHashHex: `0x${PAYMENT_HASH}`,
                    reason: ROUTE_FAILURE,
                    payment: readOf(failedStored(ROUTE_FAILURE)),
                },
            ]);
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(failedStored(ROUTE_FAILURE));
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, open: false });
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching());
        });

        it("at closing the intent the node refused keeps the intent open and watched, for the step to close", async () => {
            const h = harness();
            failingWrite(h, INTENT_KEY, 1);
            h.node.error(-32000, ROUTE_FAILURE);
            expect(await rejection(transferSdkPayment(h.context, stringOf()))).toEqual(new Error("storage offline"));
            expect(storedAt(h.storage, INTENT_KEY)).toEqual(INTENT);
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
        });

        it("at forgetting the hash the node refused keeps it watched: the step's tick reports the failure again, at least once", async () => {
            const h = harness();
            failingWrite(h, ACTIVITY_KEY, 1);
            h.node.error(-32000, ROUTE_FAILURE);
            expect(await rejection(transferSdkPayment(h.context, stringOf()))).toEqual(new Error("storage offline"));
            expect(storedAt(h.storage, INTENT_KEY)).toEqual({ ...INTENT, open: false });
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
            jest.mocked(h.storage.set).mockRestore();
            const events: SdkEvent[] = [];
            h.node.result(paymentAnswer(PAYMENT_HASH, "Failed", ROUTE_FAILURE));
            await stepOf(h, events)(live());
            // The refusal's record keeps the node's text, not fiber's row.
            const failed = failedStored(`the node refuses the payment: ${ROUTE_FAILURE}`);
            expect(events).toEqual([
                { type: "PAYMENT_FAILED", paymentHashHex: `0x${PAYMENT_HASH}`, reason: ROUTE_FAILURE, payment: readOf(failed) },
            ]);
            expect(storedAt(h.storage, RECORD_KEY)).toEqual(failed);
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching());
        });

        it.each<[string, (h: Harness) => Promise<void>, (h: Harness) => void, SdkEvent[]]>([
            [
                "a charged intent",
                async (h) => {
                    // Fiber's false Failed: the record failed while a TLC of the send was charged.
                    await seedRecord(h, failedStored(ROUTE_FAILURE, { createdAtMs: NOW_MS - 1000, settledAtMs: NOW_MS - 500 }));
                    const cause = new DebitIntentError(
                        "intent_charged",
                        `a payment under ${PAYMENT_HASH} has already been charged, it cannot be authorised again`,
                    );
                    jest.spyOn(h.context.policy, "recordDebitIntent").mockRejectedValue(cause);
                },
                // A charged intent is a session the node holds.
                (h) => h.node.result(paymentAnswer(PAYMENT_HASH, "Success")),
                [
                    {
                        type: "PAYMENT_SENT",
                        paymentHashHex: `0x${PAYMENT_HASH}`,
                        feeShannons: "1250000",
                        payment: readOf(
                            pendingStored({ status: "completed", feeShannons: "1250000", createdAtMs: NOW_MS - 1000, settledAtMs: NOW_MS }),
                        ),
                    },
                ],
            ],
            // No record: nothing was sent, so no event.
            [
                "an own invoice",
                (h) => h.context.policy.recordHoldInvoice(PAYMENT_HASH, AMOUNT, "ckb-hash", 1_791_367_200_250),
                (h) => h.node.error(-32000, NOT_FOUND),
                [],
            ],
        ])("at forgetting the hash after %s keeps it watched: the step's tick ends it", async (_, refuse, answer, expected) => {
            const h = harness();
            await refuse(h);
            failingWrite(h, ACTIVITY_KEY, 1);
            expect(await rejection(transferSdkPayment(h.context, stringOf()))).toEqual(new Error("storage offline"));
            expect(storedAt(h.storage, INTENT_KEY)).toBeUndefined();
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
            expect(h.node.calls()).toEqual([]);
            jest.mocked(h.storage.set).mockRestore();
            const events: SdkEvent[] = [];
            answer(h);
            await stepOf(h, events)(live());
            expect(events).toEqual(expected);
            expect(storedAt(h.storage, ACTIVITY_KEY)).toEqual(watching());
        });
    });
});

describe("prepareSdkTransfer", () => {
    it("computes what a send of another tenant's invoice is given, through the LSP as trampoline", () => {
        const h = harness();
        const invoice = stringOf();
        expect(prepareSdkTransfer(h.context, invoice, undefined)).toEqual({
            encodedInvoice: invoice,
            paymentHashHex: PAYMENT_HASH,
            amountShannons: AMOUNT,
            description: null,
            maxFeeShannons: "1250000",
            budgetShannons: "251250000",
            trampolineHops: [hexToBytes(LSP_PUBKEY)],
        });
    });

    it("sends the LSP's own invoice with no hop and the host's budget", () => {
        const h = harness();
        expect(prepareSdkTransfer(h.context, stringOf(LSP_INVOICE, LSP_SECRET_KEY), { maxFeeShannons: "0" })).toMatchObject({
            maxFeeShannons: "0",
            budgetShannons: AMOUNT,
            trampolineHops: [],
        });
    });

    it("touches neither the storage nor the node, nor holds the hash", () => {
        const h = harness();
        prepareSdkTransfer(h.context, stringOf(), undefined);
        expect(h.storage.ops).toEqual([]);
        expect(h.node.calls()).toEqual([]);
        expect([...h.context.sending]).toEqual([]);
    });

    it("refuses what transfer refuses before anything else", () => {
        const h = harness();
        expect(() => prepareSdkTransfer(h.context, stringOf(), { maxFeeShannons: "-1" })).toThrow(TypeError);
        expect(() => prepareSdkTransfer(h.context, stringOf(), { maxFeeShannons: UINT128_MAX })).toThrow(RangeError);
    });
});

describe("classifySdkPaymentFailure", () => {
    it("names the hash it was given in a session's refusal, and takes another hash's as a plain refusal", () => {
        const text = `Payment session already exists, stop start new payment actor for Hash256(0x${OTHER_HASH})`;
        const error = new RpcError("send_payment", -32000, text);
        expect(classifySdkPaymentFailure(error, OTHER_HASH).code).toBe("payment_session_exists");
        expect(classifySdkPaymentFailure(error, PAYMENT_HASH).code).toBe("payment_rejected");
    });

    it("holds the call's error as the cause", () => {
        const error = new RpcError("send_payment", -32000, ROUTE_FAILURE);
        expect(classifySdkPaymentFailure(error, PAYMENT_HASH).cause).toBe(error);
    });
});
