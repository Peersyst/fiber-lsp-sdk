import { hexToBytes } from "@noble/hashes/utils.js";
import { COMMITMENT_LOCK_TESTNET, FUNDING_LOCK_TESTNET } from "../../../src/digest";
import { decodeInvoice } from "../../../src/invoice";
import type { IFetchLike } from "../../../src/rpc";
import type { FiberLspSdkOptions, SdkChannelInfo, SdkEvent } from "../../../src/sdk";
import { PolicyEngine, SignerStore } from "../../../src/policy";
import { FiberLspSdk, SdkError } from "../../../src/sdk";
import { TimerMock } from "../../mocks/common";
import { InMemorySignerStorage } from "../../mocks/policy";
import { flush } from "../../utils/flush";
import { asRecord } from "../../utils/json-shape";
import { rejection } from "../../utils/rejection";
import { loadSigningVectors } from "../../utils/signing-vectors";
import { CHANNEL, FUNDED, LSP_PUBKEY, TENANT_NODE_URL, post, tenantNode, tick } from "../../utils/tenant-flow";
import type { InMemoryTenantNode, TenantNodeInvoiceTamper, TenantNodeReceivedPayment } from "../../utils/tenant-node";

const vectors = loadSigningVectors();

const MASTER_SEED = hexToBytes(vectors.device.master_seed);

// Past the allocation floor: the channel takes index 1_791_367_200, the first invoice index 1_791_367_200_000.
const NOW_MS = 1_791_367_200_000;

const OPENING_INDEX = 1_791_367_200;

const OPENING_CHANNEL_ID = "0x5df11183f0223c41ea85677270eeaf085d3d2fa00f4a35b1b870b7af25b0287f";

const AMOUNT = "250000000";

const INVOICE_INDEX = 1_791_367_200_000;

// The ckb-hash of the preimage of invoice index 1_791_367_200_000.
const PAYMENT_HASH = "0x493700fb4c465bcfffd7b7db88160a5609731c27a46ab369b6da7750d00c3a8e";

const OTHER_INVOICE_INDEX = 1_791_367_200_001;

// The ckb-hash of the preimage of invoice index 1_791_367_200_001.
const OTHER_PAYMENT_HASH = "0xe9001f1b14fc684915870f1d0edaf3d48fc7d26f5bcaaa3fde2655cb2f0df8cb";

// The default expiry, an hour, is past from this reading on: fiber's `is_expired` is strict.
const INVOICE_EXPIRED_MS = 1_791_370_800_001;

// A TLC received at NOW_MS expires a day later, the delta the device asks: 1_791_453_600_000.
const PAYMENT: TenantNodeReceivedPayment = { paymentHash: PAYMENT_HASH.slice(2), amountShannons: AMOUNT, hashAlgorithm: "ckb-hash" };

// Past the TLC's expiry less the release margin: two thirds of the pinned one-epoch delay and ten minutes, 10_200_000 ms.
const TOO_CLOSE_MS = 1_791_443_400_001;

// Fiber's maintenance fails it from two thirds of the delay and a check interval before its expiry, 9_660_000 ms.
const FAILED_BY_NODE_MS = 1_791_443_940_001;

// The opened channel as `listChannels` shows it, before any payment.
const LISTED: SdkChannelInfo = {
    channelId: OPENING_CHANNEL_ID,
    localBalanceShannons: "62000000000",
    remoteBalanceShannons: "18500000000",
    offeredTlcBalanceShannons: "0",
    receivedTlcBalanceShannons: "0",
    state: "ready",
    hasRecord: true,
};

const SIGNED_TICK = [
    "list_channels",
    "list_channels",
    "get_channel_signing_status",
    "submit_channel_signature",
    "list_channels",
    "get_watchtower_signing_status",
];

const IDLE_TICK = ["list_channels", "list_channels", "get_channel_signing_status", "list_channels", "get_watchtower_signing_status"];

// The peer's round that adds the TLC, then the node's that removes it, one request answered per tick.
const ADD_ROUND = [
    "CompleteReceivedCommitment Commitment@2 Applied",
    "SendRevokeAndAck Revocation@2 Applied",
    "SendCommitmentSigned Commitment@2 Applied",
    "CompleteReceivedRevokeAndAck Revocation@2 Applied",
];

const REMOVE_ROUND = [
    "SendCommitmentSigned Commitment@3 Applied",
    "CompleteReceivedRevokeAndAck Revocation@3 Applied",
    "CompleteReceivedCommitment Commitment@4 Applied",
    "SendRevokeAndAck Revocation@3 Applied",
];

const ADD_SIGNINGS = [
    "SIGNING CompleteReceivedCommitment signed",
    "SIGNING SendRevokeAndAck signed",
    "SIGNING SendCommitmentSigned warning",
    "SIGNING CompleteReceivedRevokeAndAck warning",
];

const REMOVE_SIGNINGS = [
    "SIGNING SendCommitmentSigned signed",
    "SIGNING CompleteReceivedRevokeAndAck signed",
    "SIGNING CompleteReceivedCommitment signed",
    "SIGNING SendRevokeAndAck warning",
];

type Clock = { nowMs: number };

type InvoiceFlow = {
    node: InMemoryTenantNode;
    sdk: FiberLspSdk;
    storage: InMemorySignerStorage;
    timer: TimerMock;
    clock: Clock;
    events: SdkEvent[];
};

type FetchOf = (node: InMemoryTenantNode) => IFetchLike;

// The device and the node read one clock.
function flow(fetchOf: FetchOf = (node) => node.fetch, network: FiberLspSdkOptions["network"] = "testnet"): InvoiceFlow {
    const clock: Clock = { nowMs: NOW_MS };
    const now = (): number => clock.nowMs;
    const node = tenantNode([OPENING_INDEX], now);
    const timer = new TimerMock();
    const storage = new InMemorySignerStorage();
    // Fiber's nonce lifecycle signs some slots twice.
    const sdk = new FiberLspSdk(MASTER_SEED, {
        network,
        storage,
        rpcUrl: TENANT_NODE_URL,
        lspPubkey: LSP_PUBKEY,
        fetch: fetchOf(node),
        timer,
        now,
        nonceReuse: "allow",
    });
    const events: SdkEvent[] = [];
    sdk.onEvent((event) => events.push(event));
    return { node, sdk, storage, timer, clock, events };
}

async function connect(h: InvoiceFlow): Promise<void> {
    h.sdk.connect();
    await flush();
}

// Connected, with the channel ready and its events cleared.
async function opened(fetchOf?: FetchOf, network?: FiberLspSdkOptions["network"]): Promise<InvoiceFlow> {
    const h = flow(fetchOf, network);
    await connect(h);
    // The double compares the funding tx's raw data alone, which the host's witnesses leave as it is.
    await h.sdk.openChannel(FUNDED, CHANNEL.localCloseScript, (unsigned) => Promise.resolve(unsigned));
    await tick(h, 3);
    expect(eventsOf(h)).toEqual(["SIGNING SendCommitmentSigned signed", "SIGNING CompleteReceivedCommitment warning", "CHANNEL_READY"]);
    h.events.length = 0;
    return h;
}

// The connection drops before the node hears the method's next call, once.
function losingNext(method: string): FetchOf {
    return (node) => {
        let lost = false;
        return (url, init) => {
            if (lost || (JSON.parse(init.body) as { method: string }).method !== method) return node.fetch(url, init);
            lost = true;
            return Promise.reject(new TypeError("fetch failed: the connection dropped before the request"));
        };
    };
}

function eventsOf(h: InvoiceFlow): string[] {
    return h.events.map((event) => {
        switch (event.type) {
            case "SIGNING":
                return `SIGNING ${event.transition ?? "unread"} ${event.outcome === "refused" ? `refused ${event.error.code}` : event.outcome}`;
            case "PAYMENT_PENDING":
            case "PAYMENT_RECEIVED":
            case "PAYMENT_EXPIRED":
                return `${event.type} ${event.paymentHashHex === PAYMENT_HASH ? "invoice" : event.paymentHashHex}`;
            case "ERROR":
                return `ERROR ${event.error.code}: ${event.error.message}`;
            default:
                return event.type;
        }
    });
}

function methods(h: InvoiceFlow, from: number): string[] {
    return h.node.calls.slice(from).map((call) => call.method);
}

// The open's two requests aside.
function requests(h: InvoiceFlow): string[] {
    return h.node.served.slice(2).map((request) => `${request.transition} ${request.slot} ${request.answers.join("+") || "unanswered"}`);
}

function signed(...invoice: string[]): string[] {
    return [...SIGNED_TICK, ...invoice];
}

function idle(...invoice: string[]): string[] {
    return [...IDLE_TICK, ...invoice];
}

async function invoiceOf(h: InvoiceFlow): Promise<Record<string, unknown>> {
    const answer = asRecord(
        await post(h.node, { jsonrpc: "2.0", id: 1, method: "get_invoice", params: [{ payment_hash: PAYMENT_HASH }] }),
        "answer",
    );
    return asRecord(answer.result, "result");
}

describe("hold invoices over the tenant node", () => {
    it("receives with the app open: the node's invoice checked, the TLC signed in, the preimage released, the fulfil signed", async () => {
        const h = await opened();
        const created = await h.sdk.createInvoice(AMOUNT, { description: "coffee" });
        expect(created.paymentHashHex).toBe(PAYMENT_HASH);
        expect(h.node.calls.at(-1)).toEqual({
            method: "new_invoice",
            params: {
                amount: "0xee6b280",
                description: "coffee",
                currency: "Fibt",
                payment_hash: PAYMENT_HASH,
                expiry: "0xe10",
                final_expiry_delta: "0x5265c00",
                hash_algorithm: "ckb_hash",
            },
        });
        const invoice = decodeInvoice(created.invoice);
        expect(invoice.amountShannons).toBe(AMOUNT);
        expect(invoice.attributes.find((attribute) => attribute.type === "description")).toEqual({ type: "description", text: "coffee" });
        expect(await invoiceOf(h)).toMatchObject({ invoice_address: created.invoice, status: "Open" });
        let pendingWhenPaid: string | undefined;
        h.sdk.onEvent((event) => {
            if (event.type === "PAYMENT_RECEIVED") pendingWhenPaid = requests(h).at(-1);
        });
        const from = h.node.calls.length;
        h.node.receivePayment(PAYMENT);
        await tick(h, 10);
        expect(methods(h, from)).toEqual(
            [
                signed("get_invoice"),
                signed("get_invoice"),
                signed("get_invoice"),
                // The TLC is committed in both views: the node marks the invoice received, the device releases and settles.
                signed("get_invoice", "settle_invoice"),
                // The tick `pollNow` asks for, then each tick until the fulfil is applied settles again, harmlessly.
                signed("get_invoice", "settle_invoice"),
                signed("get_invoice", "settle_invoice"),
                // Paid on the peer's commitment_signed, the node's revoke_and_ack still to sign: the device stops watching.
                signed("get_invoice"),
                // The revoke_and_ack is signed with no invoice left to read.
                signed(),
                idle(),
                idle(),
                idle(),
            ].flat(),
        );
        expect(requests(h)).toEqual([...ADD_ROUND, ...REMOVE_ROUND]);
        expect(eventsOf(h)).toEqual([
            ...ADD_SIGNINGS,
            "PAYMENT_PENDING invoice",
            ...REMOVE_SIGNINGS.slice(0, 3),
            "PAYMENT_RECEIVED invoice",
            REMOVE_SIGNINGS[3],
        ]);
        expect(pendingWhenPaid).toBe("SendRevokeAndAck Revocation@3 unanswered");
        expect(await invoiceOf(h)).toMatchObject({ status: "Paid" });
        expect(await h.sdk.listChannels()).toEqual([
            { ...LISTED, localBalanceShannons: "62250000000", remoteBalanceShannons: "18250000000" },
        ]);
    });

    it("never marks released an invoice whose recorded index derives another hash, and hands the node no preimage", async () => {
        const h = await opened();
        await h.sdk.createInvoice(AMOUNT);
        const key = `fiber-lsp-sdk:invoice:${PAYMENT_HASH.slice(2, 42)}`;
        const record = asRecord(JSON.parse(h.storage.map.get(key) ?? "null"), "record");
        expect(record.invoiceIndex).toBe(INVOICE_INDEX);
        h.storage.map.set(key, JSON.stringify({ ...record, invoiceIndex: OTHER_INVOICE_INDEX }));
        const from = h.node.calls.length;
        h.node.receivePayment(PAYMENT);
        await tick(h, 5);
        expect(methods(h, from)).toEqual(
            [signed("get_invoice"), signed("get_invoice"), signed("get_invoice"), signed("get_invoice"), idle("get_invoice")].flat(),
        );
        expect(eventsOf(h)).toEqual([
            ...ADD_SIGNINGS,
            "PAYMENT_PENDING invoice",
            `ERROR poll_failed: the invoice poll of ${PAYMENT_HASH} failed: the invoice index recorded for ${PAYMENT_HASH} derives the preimage of ${OTHER_PAYMENT_HASH}`,
            `ERROR poll_failed: the invoice poll of ${PAYMENT_HASH} failed: the invoice index recorded for ${PAYMENT_HASH} derives the preimage of ${OTHER_PAYMENT_HASH}`,
        ]);
        expect((await new PolicyEngine(new SignerStore(h.storage)).readHoldInvoice(PAYMENT_HASH.slice(2))).released).toBe(false);
        expect(await invoiceOf(h)).toMatchObject({ status: "Received" });
    });

    it("keeps the TLC and its requests waiting on the node while the app is closed, and receives once it connects", async () => {
        const h = await opened();
        await h.sdk.createInvoice(AMOUNT);
        h.sdk.disconnect();
        const from = h.node.calls.length;
        h.node.receivePayment(PAYMENT);
        await tick(h, 3);
        expect(methods(h, from)).toEqual([]);
        expect(requests(h)).toEqual(["CompleteReceivedCommitment Commitment@2 unanswered"]);
        expect(await invoiceOf(h)).toMatchObject({ status: "Open" });
        await connect(h);
        await tick(h, 8);
        expect(requests(h)).toEqual([...ADD_ROUND, ...REMOVE_ROUND]);
        expect(eventsOf(h)).toEqual([
            ...ADD_SIGNINGS,
            "PAYMENT_PENDING invoice",
            ...REMOVE_SIGNINGS.slice(0, 3),
            "PAYMENT_RECEIVED invoice",
            REMOVE_SIGNINGS[3],
        ]);
        expect(await invoiceOf(h)).toMatchObject({ status: "Paid" });
    });

    it("receives an overpay whole: fiber holds a TLC of at least the amount", async () => {
        const h = await opened();
        await h.sdk.createInvoice(AMOUNT);
        h.node.receivePayment({ ...PAYMENT, amountShannons: "300000000" });
        await tick(h, 9);
        expect(eventsOf(h)).toEqual([
            ...ADD_SIGNINGS,
            "PAYMENT_PENDING invoice",
            ...REMOVE_SIGNINGS.slice(0, 3),
            "PAYMENT_RECEIVED invoice",
            REMOVE_SIGNINGS[3],
        ]);
        expect(await invoiceOf(h)).toMatchObject({ status: "Paid" });
        expect(await h.sdk.listChannels()).toEqual([
            { ...LISTED, localBalanceShannons: "62300000000", remoteBalanceShannons: "18200000000" },
        ]);
    });

    it("never releases a TLC the clock brought too close to its expiry: the node fails it back and the invoice ends expired", async () => {
        const h = await opened();
        await h.sdk.createInvoice(AMOUNT);
        h.node.receivePayment(PAYMENT);
        // The app goes to the background as it signs the TLC in, before it reads the invoice.
        const off = h.sdk.onEvent((event) => {
            if (event.type === "SIGNING" && event.transition === "CompleteReceivedRevokeAndAck") h.sdk.disconnect();
        });
        await tick(h, 4);
        off();
        expect(eventsOf(h)).toEqual(ADD_SIGNINGS);
        expect(await invoiceOf(h)).toMatchObject({ status: "Received" });
        h.clock.nowMs = TOO_CLOSE_MS;
        expect(() => h.node.failHeldTlc(PAYMENT.paymentHash)).toThrow(
            "fiber's maintenance fails only a TLC expiring before 1791453060001, not at 1791453600000",
        );
        const from = h.node.calls.length;
        await connect(h);
        await tick(h, 2);
        // Received is announced, and the release waits silently: no settle_invoice.
        expect(methods(h, from)).toEqual([idle("get_invoice"), idle("get_invoice"), idle("get_invoice")].flat());
        expect(eventsOf(h).slice(4)).toEqual(["PAYMENT_PENDING invoice"]);
        h.clock.nowMs = FAILED_BY_NODE_MS;
        h.node.failHeldTlc(PAYMENT.paymentHash);
        const failing = h.node.calls.length;
        await tick(h, 5);
        expect(methods(h, failing)).toEqual(
            [
                signed("get_invoice"),
                signed("get_invoice"),
                // Both views' last commitments drop the TLC, past the invoice's expiry: it ends unpaid.
                signed("get_invoice"),
                signed(),
                idle(),
            ].flat(),
        );
        expect(requests(h)).toEqual([...ADD_ROUND, ...REMOVE_ROUND]);
        expect(eventsOf(h).slice(5)).toEqual([...REMOVE_SIGNINGS.slice(0, 3), "PAYMENT_EXPIRED invoice", REMOVE_SIGNINGS[3]]);
        // A received invoice whose TLC failed stays received in fiber's store.
        expect(await invoiceOf(h)).toMatchObject({ status: "Received" });
        expect(await h.sdk.listChannels()).toEqual([LISTED]);
    });

    it("judges the release under the network's own epoch: a debug build's 2 s epoch clears a TLC the release build's holds back", async () => {
        const h = await opened(undefined, {
            commitmentLock: COMMITMENT_LOCK_TESTNET,
            fundingLock: FUNDING_LOCK_TESTNET,
            invoiceCurrency: "Fibt",
            fundingLockCellDepsCount: 2,
            millisecondsPerEpoch: 2_000,
        });
        await h.sdk.createInvoice(AMOUNT);
        h.node.receivePayment(PAYMENT);
        const off = h.sdk.onEvent((event) => {
            if (event.type === "SIGNING" && event.transition === "CompleteReceivedRevokeAndAck") h.sdk.disconnect();
        });
        await tick(h, 4);
        off();
        h.clock.nowMs = TOO_CLOSE_MS;
        const from = h.node.calls.length;
        await connect(h);
        // Released at once, where the release build's margin waits; the tick `pollNow` asks for signs the fulfil.
        expect(methods(h, from)).toEqual([idle("get_invoice", "settle_invoice"), signed("get_invoice", "settle_invoice")].flat());
    });

    it("announces an open invoice expired once the node reports it expired, then stops watching it", async () => {
        const h = flow();
        await h.sdk.createInvoice(AMOUNT);
        await connect(h);
        h.clock.nowMs = INVOICE_EXPIRED_MS - 1;
        await tick(h);
        expect(eventsOf(h)).toEqual([]);
        h.clock.nowMs = INVOICE_EXPIRED_MS;
        const from = h.node.calls.length;
        await tick(h, 2);
        expect(methods(h, from)).toEqual(["list_channels", "list_channels", "get_invoice", "list_channels", "list_channels"]);
        expect(eventsOf(h)).toEqual(["PAYMENT_EXPIRED invoice"]);
        expect(await invoiceOf(h)).toMatchObject({ status: "Expired" });
    });

    it("settles again on the next tick a release whose settle_invoice the node never heard", async () => {
        const h = await opened(losingNext("settle_invoice"));
        await h.sdk.createInvoice(AMOUNT);
        const from = h.node.calls.length;
        h.node.receivePayment(PAYMENT);
        await tick(h, 10);
        expect(methods(h, from)).toEqual(
            [
                signed("get_invoice"),
                signed("get_invoice"),
                signed("get_invoice"),
                // Marked released; the settlement is lost on its way.
                signed("get_invoice"),
                idle("get_invoice", "settle_invoice"),
                signed("get_invoice", "settle_invoice"),
                signed("get_invoice", "settle_invoice"),
                // Paid before the node's revoke_and_ack, which the next tick signs.
                signed("get_invoice"),
                signed(),
                idle(),
            ].flat(),
        );
        expect(requests(h)).toEqual([...ADD_ROUND, ...REMOVE_ROUND]);
        expect(eventsOf(h)).toEqual([
            ...ADD_SIGNINGS,
            "PAYMENT_PENDING invoice",
            `ERROR poll_failed: the invoice poll of ${PAYMENT_HASH} failed: settle_invoice: the request failed`,
            ...REMOVE_SIGNINGS.slice(0, 3),
            "PAYMENT_RECEIVED invoice",
            REMOVE_SIGNINGS[3],
        ]);
        expect(await invoiceOf(h)).toMatchObject({ status: "Paid" });
    });

    it("settles again a release whose answer was lost, which the node accepts while the fulfil is signed", async () => {
        const h = await opened();
        await h.sdk.createInvoice(AMOUNT);
        h.node.dropNextAnswer("settle_invoice");
        const from = h.node.calls.length;
        h.node.receivePayment(PAYMENT);
        await tick(h, 9);
        expect(methods(h, from)).toEqual(
            [
                signed("get_invoice"),
                signed("get_invoice"),
                signed("get_invoice"),
                // The node takes the preimage and starts the fulfil; its answer is lost, so no tick is asked for.
                signed("get_invoice", "settle_invoice"),
                signed("get_invoice", "settle_invoice"),
                signed("get_invoice", "settle_invoice"),
                // Paid before the node's revoke_and_ack, which the next tick signs.
                signed("get_invoice"),
                signed(),
                idle(),
            ].flat(),
        );
        expect(requests(h)).toEqual([...ADD_ROUND, ...REMOVE_ROUND]);
        expect(eventsOf(h)).toEqual([
            ...ADD_SIGNINGS,
            "PAYMENT_PENDING invoice",
            `ERROR poll_failed: the invoice poll of ${PAYMENT_HASH} failed: settle_invoice: the request failed`,
            ...REMOVE_SIGNINGS.slice(0, 3),
            "PAYMENT_RECEIVED invoice",
            REMOVE_SIGNINGS[3],
        ]);
        expect(await invoiceOf(h)).toMatchObject({ status: "Paid" });
    });

    it("refuses to sign the node's fail of a TLC whose preimage it released, keeping the TLC in its commitments", async () => {
        const h = await opened(losingNext("settle_invoice"));
        await h.sdk.createInvoice(AMOUNT);
        h.node.receivePayment(PAYMENT);
        await tick(h, 4);
        expect(eventsOf(h).slice(4, 6)).toEqual([
            "PAYMENT_PENDING invoice",
            `ERROR poll_failed: the invoice poll of ${PAYMENT_HASH} failed: settle_invoice: the request failed`,
        ]);
        // The app sleeps until the node's maintenance fails the TLC.
        h.clock.nowMs = FAILED_BY_NODE_MS;
        h.node.failHeldTlc(PAYMENT.paymentHash);
        const from = h.node.calls.length;
        await tick(h, 2);
        // The device settles again and the node takes the preimage, but its TLC is already failing back.
        expect(methods(h, from)).toEqual([idle("get_invoice", "settle_invoice"), idle("get_invoice", "settle_invoice")].flat());
        expect(requests(h)).toEqual([...ADD_ROUND, "SendCommitmentSigned Commitment@3 unanswered"]);
        expect(eventsOf(h).slice(6)).toEqual([
            "SIGNING SendCommitmentSigned refused policy_refusal",
            "SIGNING SendCommitmentSigned refused policy_refusal",
        ]);
        const refused = h.events.at(-1);
        if (refused?.type !== "SIGNING" || refused.outcome !== "refused") throw new Error("the last event is no refusal");
        // The balance rule counts a released TLC as the device's.
        expect(refused.error.message).toBe("the remote commitment lowers the holdings by 250000000 shannons, which no offered TLC took");
        expect(await invoiceOf(h)).toMatchObject({ status: "Received" });
    });

    it.each<[string, TenantNodeInvoiceTamper, string]>([
        ["another payment hash", { kind: "paymentHash", paymentHash: "66".repeat(32) }, "paymentHash is not the hash the device derived"],
        ["another amount", { kind: "amount", amountShannons: "250000001" }, "amountShannons is 250000001, not the 250000000 asked"],
        [
            "a timestamp a millisecond past the device's clock and its tolerance",
            { kind: "timestamp", timestampMs: 1_791_367_800_001n },
            "timestampMs is 1791367800001, more than 600000 ms past the device's 1791367200000",
        ],
        ["no trampoline hint", { kind: "noHint" }, "trampolineRouteHint is missing"],
        ["another hint", { kind: "hint", nodeId: vectors.peer.funding_pubkey }, "trampolineRouteHint is not the LSP's key"],
        [
            "a fallback address",
            { kind: "extraAttribute", attribute: { type: "fallbackAddr", address: "ckt1qyqrdsefa43s6m882pcj53m4gdnj4k440axqswmu83" } },
            "fallbackAddr was not asked for",
        ],
        [
            "a description none asked",
            { kind: "extraAttribute", attribute: { type: "description", text: "coffee" } },
            "description was not asked for",
        ],
        ["another feature", { kind: "feature", bits: "28" }, "feature is not trampoline routing's optional bit alone"],
        [
            "a signature by another key than the payee's",
            { kind: "signer", secretKey: "5c".repeat(32) },
            "invoiceAddress does not decode: signature must be by the payee key the invoice carries",
        ],
        ["the string uppercase", { kind: "uppercase" }, "invoiceAddress does not decode: invoice must be lowercase"],
    ])("refuses the node's invoice with %s, and watches nothing", async (_, tamper, detail) => {
        const h = flow();
        h.node.tamperInvoice(tamper);
        const error = await rejection(h.sdk.createInvoice(AMOUNT));
        expect(error).toBeInstanceOf(SdkError);
        expect(error).toMatchObject({ code: "invoice_rejected", message: `the node's invoice is refused: ${detail}` });
        const from = h.node.calls.length;
        await connect(h);
        await tick(h);
        expect(methods(h, from)).toEqual(["list_channels", "list_channels", "list_channels", "list_channels"]);
    });
});
