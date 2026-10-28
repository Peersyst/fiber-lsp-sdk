import { hexToBytes } from "@noble/hashes/utils.js";
import type { UnsignedInvoice } from "../../../src/invoice";
import { InvoiceError, encodeInvoice } from "../../../src/invoice";
import { PolicyEngine, SignerStore } from "../../../src/policy";
import { FiberRpcClient, RpcError, RpcResponseError, RpcTransportError } from "../../../src/rpc";
import type { SdkInvoiceCreationContext, SdkNetworkConfig } from "../../../src/sdk";
import { ActivityTracker, IndexAllocator, SDK_NETWORK_PRESETS, SdkError, createSdkInvoice } from "../../../src/sdk";
import { HoldInvoicePreimages } from "../../../src/signer";
import { InMemorySignerStorage } from "../../mocks/policy";
import type { SentCall } from "../../mocks/rpc";
import { ScriptedNode } from "../../mocks/rpc";
import { invoiceJson } from "../../utils/invoice-json";
import { signInvoice } from "../../utils/invoice-signing";
import { rejection } from "../../utils/rejection";

const URL = "http://127.0.0.1:8227";
const MASTER_SEED = hexToBytes("24".repeat(32));
// The clock reads invoice index 1_791_367_200_250.
const NOW_MS = 1_791_367_200_250;
// The latest timestamp the device takes from the node: NOW_MS and its 10 minutes of tolerance.
const LATEST_TIMESTAMP_MS = 1_791_367_800_250n;
const INDEX = 1_791_367_200_250;
const NEXT_INDEX = 1_791_367_200_251;
// The ckb-hash of the hold invoice preimages of the master seed 0x24 repeated at INDEX and NEXT_INDEX.
const PAYMENT_HASH = "f4855a4de3b32708585d93e9ad5617eac60965866532d09dbef68c270bac6b5e";
const NEXT_PAYMENT_HASH = "3b046d76f32667e691479ea22739b8e2d5827ce5aa560719b5173d469dc9ff3c";
// The RPC vector's peer.
const LSP_PUBKEY = "02106fa580a1c56411d6ee7deabcc98aae6f6479858f924487cf58c4c2ca302304";
// The public key of the secret 0x33 repeated.
const OTHER_PUBKEY = "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1";
// The tenant's key that signs the node's invoices: the invoice vectors' payee.
const TENANT_SECRET_KEY = hexToBytes("11".repeat(32));
const TENANT_PUBKEY = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
const AMOUNT = "250000000";
const UINT128_MAX = "340282366920938463463374607431768211455";

const ALLOCATOR_KEY = "fiber-lsp-sdk:allocator:invoice";
const ACTIVITY_KEY = "fiber-lsp-sdk:activity";
const INVOICE_KEY = `fiber-lsp-sdk:invoice:${PAYMENT_HASH.slice(0, 40)}`;
const NEXT_INVOICE_KEY = `fiber-lsp-sdk:invoice:${NEXT_PAYMENT_HASH.slice(0, 40)}`;

const NEW_INVOICE_PARAMS = {
    amount: "0xee6b280",
    currency: "Fibt",
    payment_hash: `0x${PAYMENT_HASH}`,
    expiry: "0xe10",
    final_expiry_delta: "0x5265c00",
    hash_algorithm: "ckb_hash",
};

// The node's invoice for NEW_INVOICE_PARAMS, as fiber writes a tenant's: the trampoline bit and hint, signed by the tenant.
const ANSWER_INVOICE: UnsignedInvoice = {
    currency: "Fibt",
    amountShannons: AMOUNT,
    timestampMs: 1_791_367_200_300n,
    paymentHash: hexToBytes(PAYMENT_HASH),
    attributes: [
        { type: "expiryTime", seconds: 3600n },
        { type: "feature", bits: Uint8Array.of(0x20) },
        { type: "trampolineRouteHint", nodeId: hexToBytes(LSP_PUBKEY) },
        { type: "finalHtlcMinimumExpiryDelta", milliseconds: 86_400_000n },
        { type: "hashAlgorithm", algorithm: "ckb-hash" },
        { type: "payeePublicKey", publicKey: hexToBytes(TENANT_PUBKEY) },
    ],
};

const RECORD = {
    version: 1,
    paymentHash: PAYMENT_HASH,
    amountShannons: AMOUNT,
    hashAlgorithm: "ckb-hash",
    invoiceIndex: INDEX,
    released: false,
    channelIndexes: [],
};

type Harness = {
    storage: InMemorySignerStorage;
    node: ScriptedNode;
    now: jest.Mock<number, []>;
    context: SdkInvoiceCreationContext;
};

function harness(network: SdkNetworkConfig = SDK_NETWORK_PRESETS.testnet): Harness {
    const storage = new InMemorySignerStorage();
    const store = new SignerStore(storage);
    const node = new ScriptedNode();
    const now = jest.fn<number, []>(() => NOW_MS);
    const context: SdkInvoiceCreationContext = {
        network,
        lspPubkey: hexToBytes(LSP_PUBKEY),
        now,
        preimages: new HoldInvoicePreimages(MASTER_SEED),
        rpc: new FiberRpcClient({ url: URL, fetch: node.fetch }),
        policy: new PolicyEngine(store),
        allocator: new IndexAllocator(store, () => NOW_MS),
        activity: new ActivityTracker(store),
    };
    return { storage, node, now, context };
}

function stringOf(invoice: UnsignedInvoice): string {
    return encodeInvoice(signInvoice(invoice, TENANT_SECRET_KEY));
}

function answerOf(invoice: UnsignedInvoice = ANSWER_INVOICE): unknown {
    const signed = signInvoice(invoice, TENANT_SECRET_KEY);
    return { invoice_address: encodeInvoice(signed), invoice: invoiceJson(signed) };
}

function withAttributes(...attributes: UnsignedInvoice["attributes"]): UnsignedInvoice {
    const types = new Set(attributes.map((attribute) => attribute.type));
    return {
        ...ANSWER_INVOICE,
        attributes: [...ANSWER_INVOICE.attributes.filter((attribute) => !types.has(attribute.type)), ...attributes],
    };
}

function storedAt(h: Harness, key: string): unknown {
    const raw = h.storage.map.get(key);
    return raw === undefined ? undefined : JSON.parse(raw);
}

function writes(h: Harness): string[] {
    return h.storage.ops.filter((op) => op.startsWith("set ")).map((op) => op.slice("set ".length));
}

function newInvoiceCall(params: unknown = NEW_INVOICE_PARAMS): SentCall {
    return { method: "new_invoice", params };
}

function invoiceRejected(detail: string): SdkError {
    return new SdkError("invoice_rejected", `the node's invoice is refused: ${detail}`);
}

function watching(...hashes: string[]): unknown {
    return { version: 1, channels: {}, payments: {}, invoices: Object.fromEntries(hashes.map((hash) => [hash, { status: null }])) };
}

describe("createSdkInvoice", () => {
    it("asks the node for the derived hash under ckb-hash, the network's currency, an hour's expiry and a day's final delta", async () => {
        const h = harness();
        h.node.result(answerOf());
        await createSdkInvoice(h.context, AMOUNT);
        expect(h.node.calls()).toEqual([newInvoiceCall()]);
    });

    it("hands back the node's string and the payment hash in 0x hex", async () => {
        const h = harness();
        h.node.result(answerOf());
        await expect(createSdkInvoice(h.context, AMOUNT)).resolves.toStrictEqual({
            invoice: stringOf(ANSWER_INVOICE),
            paymentHashHex: `0x${PAYMENT_HASH}`,
        });
    });

    it("records the invoice under a freshly allocated index before the node hears its hash", async () => {
        const h = harness();
        let recorded: unknown;
        h.node.onCall("new_invoice", () => {
            recorded = storedAt(h, INVOICE_KEY);
        });
        h.node.result(answerOf());
        await createSdkInvoice(h.context, AMOUNT);
        expect(recorded).toEqual(RECORD);
        expect(storedAt(h, ALLOCATOR_KEY)).toBe(INDEX);
    });

    it("asks the node nothing when the record cannot be written", async () => {
        const h = harness();
        const set = h.storage.set.bind(h.storage);
        jest.spyOn(h.storage, "set").mockImplementation((key, value) => {
            if (key === INVOICE_KEY) throw new Error("storage offline");
            set(key, value);
        });
        expect(await rejection(createSdkInvoice(h.context, AMOUNT))).toEqual(new Error("storage offline"));
        expect(h.node.calls()).toEqual([]);
    });

    it("allocates, records and watches, in that order, the watch once the string passed", async () => {
        const h = harness();
        h.node.result(answerOf());
        await createSdkInvoice(h.context, AMOUNT);
        expect(writes(h)).toEqual([ALLOCATOR_KEY, INVOICE_KEY, ACTIVITY_KEY]);
        expect(storedAt(h, INVOICE_KEY)).toEqual(RECORD);
        expect(storedAt(h, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
    });

    it("sends the description and the expiry asked, and checks the string against them", async () => {
        const h = harness();
        h.node.result(answerOf(withAttributes({ type: "expiryTime", seconds: 7200n }, { type: "description", text: "coffee" })));
        await createSdkInvoice(h.context, AMOUNT, { description: "coffee", expirySeconds: 7200 });
        expect(h.node.calls()).toEqual([newInvoiceCall({ ...NEW_INVOICE_PARAMS, description: "coffee", expiry: "0x1c20" })]);
        expect(storedAt(h, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
    });

    it("sends an empty description when one is asked, which the string must carry", async () => {
        const h = harness();
        h.node.result(answerOf(withAttributes({ type: "description", text: "" })));
        await createSdkInvoice(h.context, AMOUNT, { description: "" });
        expect(h.node.calls()).toEqual([newInvoiceCall({ ...NEW_INVOICE_PARAMS, description: "" })]);
    });

    it.each<[string, Parameters<typeof createSdkInvoice>[2]]>([
        ["empty options", {}],
        ["options left undefined", { description: undefined, expirySeconds: undefined }],
    ])("takes %s as the defaults", async (_, options) => {
        const h = harness();
        h.node.result(answerOf());
        await createSdkInvoice(h.context, AMOUNT, options);
        expect(h.node.calls()).toEqual([newInvoiceCall()]);
    });

    it("reads the device's clock once, after the node answered, and without a receiver", async () => {
        const h = harness();
        const receivers: unknown[] = [];
        h.now.mockImplementation(function (this: unknown): number {
            receivers.push(this);
            return NOW_MS;
        });
        let readsBeforeAnswer: number | undefined;
        h.node.onCall("new_invoice", () => {
            readsBeforeAnswer = h.now.mock.calls.length;
        });
        h.node.result(answerOf());
        await createSdkInvoice(h.context, AMOUNT);
        expect(readsBeforeAnswer).toBe(0);
        expect(receivers).toEqual([undefined]);
    });

    it.each<[string, bigint]>([
        ["a timestamp the tolerance past the device's clock", LATEST_TIMESTAMP_MS],
        ["a past timestamp, which only shortens the invoice", 0n],
    ])("takes %s", async (_, timestampMs) => {
        const h = harness();
        h.node.result(answerOf({ ...ANSWER_INVOICE, timestampMs }));
        await expect(createSdkInvoice(h.context, AMOUNT)).resolves.toMatchObject({ paymentHashHex: `0x${PAYMENT_HASH}` });
        expect(storedAt(h, ACTIVITY_KEY)).toEqual(watching(PAYMENT_HASH));
    });

    it.each<[string, unknown]>([
        ["a fractional reading", 1.5],
        ["a negative reading", -1],
        ["a reading in a string", "1791367200250"],
    ])("refuses %s of the device's clock, the record kept and nothing watched", async (_, reading) => {
        const h = harness();
        h.now.mockReturnValue(reading as number);
        h.node.result(answerOf());
        expect(await rejection(createSdkInvoice(h.context, AMOUNT))).toEqual(
            new RangeError(`now() must be an integer between 0 and 9007199254740991, got ${String(reading)}`),
        );
        expect(writes(h)).toEqual([ALLOCATOR_KEY, INVOICE_KEY]);
    });

    it("checks the string under a development chain's currency", async () => {
        const h = harness({ ...SDK_NETWORK_PRESETS.testnet, invoiceCurrency: "Fibd" });
        h.node.result(answerOf({ ...ANSWER_INVOICE, currency: "Fibd" }));
        await expect(createSdkInvoice(h.context, AMOUNT)).resolves.toMatchObject({ paymentHashHex: `0x${PAYMENT_HASH}` });
        expect(h.node.calls()).toEqual([newInvoiceCall({ ...NEW_INVOICE_PARAMS, currency: "Fibd" })]);
    });

    it("reads each option once, so the value checked is the value sent", async () => {
        const h = harness();
        const reads = { description: 0, expirySeconds: 0 };
        const options = {
            get description(): string {
                reads.description += 1;
                return reads.description === 1 ? "coffee" : "tea";
            },
            get expirySeconds(): number {
                reads.expirySeconds += 1;
                return reads.expirySeconds === 1 ? 7200 : 0;
            },
        };
        h.node.result(answerOf(withAttributes({ type: "expiryTime", seconds: 7200n }, { type: "description", text: "coffee" })));
        await createSdkInvoice(h.context, AMOUNT, options);
        expect(reads).toEqual({ description: 1, expirySeconds: 1 });
        expect(h.node.calls()).toEqual([newInvoiceCall({ ...NEW_INVOICE_PARAMS, description: "coffee", expiry: "0x1c20" })]);
    });

    describe("a string that is not the invoice asked", () => {
        it.each<[string, () => Harness, Parameters<typeof createSdkInvoice>[2], UnsignedInvoice, string]>([
            [
                "another network's currency",
                () => harness(SDK_NETWORK_PRESETS.mainnet),
                undefined,
                ANSWER_INVOICE,
                "currency is Fibt, not the network's Fibb",
            ],
            [
                "another amount",
                () => harness(),
                undefined,
                { ...ANSWER_INVOICE, amountShannons: "250000001" },
                "amountShannons is 250000001, not the 250000000 asked",
            ],
            [
                "a timestamp a millisecond past the device's clock and its tolerance",
                () => harness(),
                undefined,
                { ...ANSWER_INVOICE, timestampMs: 1_791_367_800_251n },
                "timestampMs is 1791367800251, more than 600000 ms past the device's 1791367200250",
            ],
            [
                "the next index's hash",
                () => harness(),
                undefined,
                { ...ANSWER_INVOICE, paymentHash: hexToBytes(NEXT_PAYMENT_HASH) },
                "paymentHash is not the hash the device derived",
            ],
            [
                "sha256",
                () => harness(),
                undefined,
                withAttributes({ type: "hashAlgorithm", algorithm: "sha256" }),
                "hashAlgorithm is sha256, not the ckb-hash asked",
            ],
            [
                "another expiry than the default",
                () => harness(),
                undefined,
                withAttributes({ type: "expiryTime", seconds: 7200n }),
                "expiryTime is 7200 s, not the 3600 s asked",
            ],
            [
                "another expiry than asked",
                () => harness(),
                { expirySeconds: 7200 },
                ANSWER_INVOICE,
                "expiryTime is 3600 s, not the 7200 s asked",
            ],
            [
                "fiber's default final delta",
                () => harness(),
                undefined,
                withAttributes({ type: "finalHtlcMinimumExpiryDelta", milliseconds: 9_600_000n }),
                "finalHtlcMinimumExpiryDelta is 9600000 ms, not the 86400000 ms asked",
            ],
            [
                "a description when none was asked",
                () => harness(),
                undefined,
                withAttributes({ type: "description", text: "coffee" }),
                "description was not asked for",
            ],
            ["no description when one was asked", () => harness(), { description: "coffee" }, ANSWER_INVOICE, "description is missing"],
            [
                "a hint to another node than the LSP",
                () => harness(),
                undefined,
                withAttributes({ type: "trampolineRouteHint", nodeId: hexToBytes(OTHER_PUBKEY) }),
                "trampolineRouteHint is not the LSP's key",
            ],
        ])("is invoice_rejected for %s, the record kept and nothing watched", async (_, build, options, answer, detail) => {
            const h = build();
            h.node.result(answerOf(answer));
            const error = await rejection(createSdkInvoice(h.context, AMOUNT, options));
            expect(error).toEqual(invoiceRejected(detail));
            expect(error).toMatchObject({ code: "invoice_rejected" });
            expect(writes(h)).toEqual([ALLOCATOR_KEY, INVOICE_KEY]);
            expect(storedAt(h, ACTIVITY_KEY)).toBeUndefined();
        });

        it("is invoice_rejected over the decoder's refusal of a string fiber would write otherwise, the record kept", async () => {
            const h = harness();
            h.node.result({ invoice_address: stringOf(ANSWER_INVOICE).toUpperCase() });
            const error = await rejection(createSdkInvoice(h.context, AMOUNT));
            expect(error).toEqual(invoiceRejected("invoiceAddress does not decode: invoice must be lowercase"));
            expect((error as SdkError).cause).toBeInstanceOf(InvoiceError);
            expect(storedAt(h, INVOICE_KEY)).toEqual(RECORD);
            expect(storedAt(h, ACTIVITY_KEY)).toBeUndefined();
        });
    });

    describe("a failure of the node", () => {
        it("lets the node's refusal through unwrapped, the record kept and nothing watched", async () => {
            const h = harness();
            h.node.error(-32000, "hosted invoice trampoline route hint does not match Public T");
            const error = await rejection(createSdkInvoice(h.context, AMOUNT));
            expect(error).toBeInstanceOf(RpcError);
            expect(error).toMatchObject({
                method: "new_invoice",
                code: -32000,
                message: "hosted invoice trampoline route hint does not match Public T",
            });
            expect(writes(h)).toEqual([ALLOCATOR_KEY, INVOICE_KEY]);
            expect(storedAt(h, INVOICE_KEY)).toEqual(RECORD);
        });

        it.each([
            ["an unknown outcome", (node: ScriptedNode) => node.reject(new Error("offline")), RpcTransportError],
            ["an answer the client cannot read", (node: ScriptedNode) => node.result({}), RpcResponseError],
        ])("lets %s through, the record kept and nothing watched", async (_, answer, errorClass) => {
            const h = harness();
            answer(h.node);
            expect(await rejection(createSdkInvoice(h.context, AMOUNT))).toBeInstanceOf(errorClass);
            expect(writes(h)).toEqual([ALLOCATOR_KEY, INVOICE_KEY]);
        });

        it("leaves a retry to another index and another hash, both records kept, only the second watched", async () => {
            const h = harness();
            h.node.error(-32000, "invoice already exists");
            await rejection(createSdkInvoice(h.context, AMOUNT));
            h.node.result(answerOf({ ...ANSWER_INVOICE, paymentHash: hexToBytes(NEXT_PAYMENT_HASH) }));
            await expect(createSdkInvoice(h.context, AMOUNT)).resolves.toMatchObject({ paymentHashHex: `0x${NEXT_PAYMENT_HASH}` });
            expect(h.node.calls()).toEqual([
                newInvoiceCall(),
                newInvoiceCall({ ...NEW_INVOICE_PARAMS, payment_hash: `0x${NEXT_PAYMENT_HASH}` }),
            ]);
            expect(storedAt(h, INVOICE_KEY)).toEqual(RECORD);
            expect(storedAt(h, NEXT_INVOICE_KEY)).toEqual({ ...RECORD, paymentHash: NEXT_PAYMENT_HASH, invoiceIndex: NEXT_INDEX });
            expect(storedAt(h, ACTIVITY_KEY)).toEqual(watching(NEXT_PAYMENT_HASH));
        });
    });

    describe("its arguments", () => {
        const notShannons = new TypeError("amountShannons must be an amount in decimal shannons");
        const notOptions = new TypeError("options must be an object");
        const notDescription = new TypeError("options.description must be a string");
        const notExpiry = (value: string): RangeError =>
            new RangeError(`options.expirySeconds must be an integer between 1 and 9007199254740991, got ${value}`);

        it.each<[string, unknown, unknown, Error]>([
            ["no amount", undefined, undefined, notShannons],
            ["an amount in a number", 250_000_000, undefined, notShannons],
            ["an amount in a bigint", 250_000_000n, undefined, notShannons],
            ["an empty amount", "", undefined, notShannons],
            ["a negative amount", "-1", undefined, notShannons],
            ["a fractional amount", "1.5", undefined, notShannons],
            ["an amount in hex", "0xee6b280", undefined, notShannons],
            ["an amount with a leading zero", "0250000000", undefined, notShannons],
            ["an amount one past a u128", "340282366920938463463374607431768211456", undefined, notShannons],
            ["an amount of zero", "0", undefined, new RangeError("amountShannons must be greater than 0, got 0")],
            ["null options", AMOUNT, null, notOptions],
            ["options in a list", AMOUNT, [], notOptions],
            ["options in a string", AMOUNT, "coffee", notOptions],
            ["a null description", AMOUNT, { description: null }, notDescription],
            ["a description in a number", AMOUNT, { description: 42 }, notDescription],
            [
                "a description of 640 bytes of UTF-8 in 320 characters",
                AMOUNT,
                { description: "é".repeat(320) },
                new RangeError("options.description must be at most 639 bytes of UTF-8, got 640"),
            ],
            [
                "a description with a lone surrogate",
                AMOUNT,
                { description: "coffee \ud83d" },
                new TypeError("options.description must be well-formed Unicode"),
            ],
            ["a null expiry", AMOUNT, { expirySeconds: null }, notExpiry("null")],
            ["an expiry of zero", AMOUNT, { expirySeconds: 0 }, notExpiry("0")],
            ["a negative expiry", AMOUNT, { expirySeconds: -1 }, notExpiry("-1")],
            ["a fractional expiry", AMOUNT, { expirySeconds: 1.5 }, notExpiry("1.5")],
            ["an expiry in a string", AMOUNT, { expirySeconds: "3600" }, notExpiry("3600")],
            ["an expiry in a bigint", AMOUNT, { expirySeconds: 3600n }, notExpiry("3600")],
            ["an expiry of NaN", AMOUNT, { expirySeconds: Number.NaN }, notExpiry("NaN")],
            ["an infinite expiry", AMOUNT, { expirySeconds: Number.POSITIVE_INFINITY }, notExpiry("Infinity")],
            [
                "an expiry one past the largest safe integer",
                AMOUNT,
                { expirySeconds: 9_007_199_254_740_992 },
                notExpiry("9007199254740992"),
            ],
        ])("refuses %s, reading, writing and sending nothing", async (_, amount, options, error) => {
            const h = harness();
            const thrown = await rejection(createSdkInvoice(h.context, amount as string, options as never));
            expect(thrown).toEqual(error);
            expect(thrown).toBeInstanceOf(error.constructor);
            expect(h.storage.ops).toEqual([]);
            expect(h.node.calls()).toEqual([]);
        });

        it.each<[string, string, Parameters<typeof createSdkInvoice>[2], Record<string, string>]>([
            ["an amount of one shannon", "1", undefined, { amount: "0x1" }],
            [
                "a description of fiber's 639 bytes of UTF-8",
                AMOUNT,
                { description: `${"é".repeat(319)}a` },
                { description: `${"é".repeat(319)}a` },
            ],
            ["an amount of a u128's whole range", UINT128_MAX, undefined, { amount: "0xffffffffffffffffffffffffffffffff" }],
            ["an expiry of one second", AMOUNT, { expirySeconds: 1 }, { expiry: "0x1" }],
            ["an expiry of the largest safe integer", AMOUNT, { expirySeconds: 9_007_199_254_740_991 }, { expiry: "0x1fffffffffffff" }],
        ])("asks the node for %s", async (_, amount, options, sent) => {
            const h = harness();
            h.node.reject(new Error("offline"));
            await rejection(createSdkInvoice(h.context, amount, options));
            expect(h.node.calls()).toEqual([newInvoiceCall({ ...NEW_INVOICE_PARAMS, ...sent })]);
            expect(storedAt(h, INVOICE_KEY)).toEqual({ ...RECORD, amountShannons: amount });
        });
    });
});
