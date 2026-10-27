import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { UnsignedInvoice } from "../../../src/invoice";
import { encodeInvoice } from "../../../src/invoice";
import { PolicyEngine, SignerStore } from "../../../src/policy";
import { RpcError, RpcTransportError } from "../../../src/rpc";
import type { SdkChannelInfo, SdkEvent, SdkPayment } from "../../../src/sdk";
import { ActivityTracker, FiberLspSdk, SDK_PAYMENT_NEVER_SENT_REASON, SdkError } from "../../../src/sdk";
import { TimerMock } from "../../mocks/common";
import { InMemorySignerStorage } from "../../mocks/policy";
import { flush } from "../../utils/flush";
import { signInvoice } from "../../utils/invoice-signing";
import { asRecord } from "../../utils/json-shape";
import { forgetSecondSession } from "../../utils/nonce-cap-bypass";
import { rejection } from "../../utils/rejection";
import { loadSigningVectors } from "../../utils/signing-vectors";
import { CHANNEL, FUNDED, LSP_PUBKEY, TENANT_NODE_URL, post, tenantNode, tick } from "../../utils/tenant-flow";
import type { InMemoryTenantNode } from "../../utils/tenant-node";

const vectors = loadSigningVectors();

const MASTER_SEED = hexToBytes(vectors.device.master_seed);

// Past the allocation floor: the channel takes index 1_791_367_200.
const NOW_MS = 1_791_367_200_000;

const OPENING_INDEX = 1_791_367_200;

const OPENING_CHANNEL_ID = "0x5df11183f0223c41ea85677270eeaf085d3d2fa00f4a35b1b870b7af25b0287f";

// The secret of LSP_PUBKEY, which signs the invoices the LSP itself is paid by.
const LSP_SECRET_KEY = hexToBytes("4c".repeat(32));

// Another node's, reached through the LSP as trampoline.
const PAYEE_SECRET_KEY = hexToBytes("6b".repeat(32));

const PAYEE_PUBKEY = hexToBytes("03e53ad26503d4037f9410ac309be101ef58dd512cf463ff62782c7b47e837fc39");

const PREIMAGE = "a1".repeat(32);

// The ckb-hash of PREIMAGE.
const PAYMENT_HASH = "0x32d0c025ace2accaa7bbfcc42ab4dd31ba8647da25b459ff90bb17269cbcd937";

const AMOUNT = "1000000000";

// PAYEE_INVOICE's expiry, an hour past its timestamp.
const EXPIRES_AT_MS = 1_791_370_800_000;

// Fiber's default cap, 5 per mille of the amount, which the device asks by default.
const DEFAULT_MAX_FEE = "5000000";

// The amount and the default fee: the debit intent's maximum, and what the hop to the LSP carries.
const BUDGET = "1005000000";

// The ckb-hash of the preimage of invoice index 1_791_367_200_000, the device's first invoice.
const OWN_PAYMENT_HASH = "0x493700fb4c465bcfffd7b7db88160a5609731c27a46ab369b6da7750d00c3a8e";

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

// The device's round that adds the TLC, then the peer's fulfil, one request answered per tick; the fulfil's commitment_signed is
// Commitment@3's third session, past fiber's nonce stall through the bypass.
const SEND_ROUND = [
    "SendCommitmentSigned Commitment@2 Applied",
    "CompleteReceivedRevokeAndAck Revocation@2 Applied",
    "CompleteReceivedCommitment Commitment@3 Applied",
    "SendRevokeAndAck Revocation@2 Applied",
];

const FULFIL_ROUND = [
    "CompleteReceivedCommitment Commitment@3 Applied",
    "SendRevokeAndAck Revocation@3 Applied",
    "SendCommitmentSigned Commitment@3 Applied",
    "CompleteReceivedRevokeAndAck Revocation@3 Applied",
];

const SEND_SIGNINGS = [
    "SIGNING SendCommitmentSigned signed",
    "SIGNING CompleteReceivedRevokeAndAck signed",
    "SIGNING CompleteReceivedCommitment signed",
    "SIGNING SendRevokeAndAck warning",
];

const FULFIL_SIGNINGS = [
    "SIGNING CompleteReceivedCommitment warning",
    "SIGNING SendRevokeAndAck signed",
    "SIGNING SendCommitmentSigned warning",
    "SIGNING CompleteReceivedRevokeAndAck warning",
];

const IDLE_TICK = ["list_channels", "list_channels", "get_channel_signing_status", "list_channels", "get_watchtower_signing_status"];

// Fiber reads its own clock, which may run ahead of the device's.
type Clock = { deviceMs: number; nodeMs: number };

type PaymentFlow = {
    node: InMemoryTenantNode;
    sdk: FiberLspSdk;
    storage: InMemorySignerStorage;
    clock: Clock;
    timer: TimerMock;
    events: SdkEvent[];
};

// An invoice of another node's that a tenant of the LSP's would issue: its hint names the LSP.
const PAYEE_INVOICE: UnsignedInvoice = {
    currency: "Fibt",
    amountShannons: AMOUNT,
    timestampMs: 1_791_367_200_000n,
    paymentHash: hexToBytes(PAYMENT_HASH.slice(2)),
    attributes: [
        { type: "expiryTime", seconds: 3600n },
        { type: "feature", bits: Uint8Array.of(0x20) },
        { type: "trampolineRouteHint", nodeId: LSP_PUBKEY },
        { type: "finalHtlcMinimumExpiryDelta", milliseconds: 86_400_000n },
        { type: "payeePublicKey", publicKey: PAYEE_PUBKEY },
    ],
};

// An invoice of the LSP's own node, which the device pays directly.
const LSP_INVOICE: UnsignedInvoice = {
    currency: "Fibt",
    amountShannons: AMOUNT,
    timestampMs: 1_791_367_200_000n,
    paymentHash: hexToBytes(PAYMENT_HASH.slice(2)),
    attributes: [
        { type: "expiryTime", seconds: 3600n },
        { type: "finalHtlcMinimumExpiryDelta", milliseconds: 86_400_000n },
        { type: "payeePublicKey", publicKey: LSP_PUBKEY },
    ],
};

const PAYEE_INVOICE_STRING = encodeInvoice(signInvoice(PAYEE_INVOICE, PAYEE_SECRET_KEY));

const LSP_INVOICE_STRING = encodeInvoice(signInvoice(LSP_INVOICE, LSP_SECRET_KEY));

// The device's channel holds 62000000000 shannons.
const BEYOND_BALANCE_INVOICE_STRING = encodeInvoice(signInvoice({ ...PAYEE_INVOICE, amountShannons: "62500000000" }, PAYEE_SECRET_KEY));

// Fiber's nonce lifecycle signs some slots twice, and a payment's fulfil a third time.
function flow(): PaymentFlow {
    const clock: Clock = { deviceMs: NOW_MS, nodeMs: NOW_MS };
    const node = tenantNode([OPENING_INDEX], () => clock.nodeMs);
    const timer = new TimerMock();
    const storage = new InMemorySignerStorage();
    const sdk = new FiberLspSdk(MASTER_SEED, {
        network: "testnet",
        storage,
        rpcUrl: TENANT_NODE_URL,
        lspPubkey: LSP_PUBKEY,
        fetch: node.fetch,
        timer,
        now: () => clock.deviceMs,
        nonceReuse: "allow",
    });
    node.bypassNonceCap((slot) => forgetSecondSession(storage, OPENING_INDEX, slot));
    const events: SdkEvent[] = [];
    sdk.onEvent((event) => events.push(event));
    return { node, sdk, storage, clock, timer, events };
}

async function opened(): Promise<PaymentFlow> {
    const h = flow();
    h.sdk.connect();
    await flush();
    // The double compares the funding tx's raw data alone, which the host's witnesses leave as it is.
    await h.sdk.openChannel(FUNDED, CHANNEL.localCloseScript, (unsigned) => Promise.resolve(unsigned));
    await tick(h, 3);
    expect(eventsOf(h)).toEqual(["SIGNING SendCommitmentSigned signed", "SIGNING CompleteReceivedCommitment warning", "CHANNEL_READY"]);
    h.events.length = 0;
    return h;
}

// Lets the tick `transfer`'s `pollNow` starts run out.
async function transferred(h: PaymentFlow, invoice: string, maxFeeShannons?: string): Promise<SdkPayment> {
    const sent = await h.sdk.transfer(invoice, maxFeeShannons === undefined ? undefined : { maxFeeShannons });
    await flush();
    return sent;
}

function eventsOf(h: PaymentFlow): string[] {
    return h.events.map((event) => {
        switch (event.type) {
            case "SIGNING":
                return `SIGNING ${event.transition ?? "unread"} ${event.outcome === "refused" ? `refused ${event.error.code}` : event.outcome}`;
            case "PAYMENT_SENT":
                return `PAYMENT_SENT ${event.paymentHashHex === PAYMENT_HASH ? "payment" : event.paymentHashHex}`;
            case "PAYMENT_FAILED":
                return `PAYMENT_FAILED ${event.paymentHashHex === PAYMENT_HASH ? "payment" : event.paymentHashHex}: ${event.reason}`;
            case "PAYMENT_PENDING":
            case "PAYMENT_RECEIVED":
                return `${event.type} ${event.paymentHashHex === OWN_PAYMENT_HASH ? "invoice" : event.paymentHashHex}`;
            case "ERROR":
                return `ERROR ${event.error.code}: ${event.error.message}`;
            default:
                return event.type;
        }
    });
}

function signed(count: number): string[] {
    return Array.from({ length: count }, () => [...SIGNED_TICK, "get_payment"]).flat();
}

function methods(h: PaymentFlow, from: number): string[] {
    return h.node.calls.slice(from).map((call) => call.method);
}

// The open's two requests aside.
function requests(h: PaymentFlow): string[] {
    return h.node.served.slice(2).map((request) => `${request.transition} ${request.slot} ${request.answers.join("+") || "unanswered"}`);
}

async function paymentOf(h: PaymentFlow): Promise<Record<string, unknown>> {
    const answer = asRecord(
        await post(h.node, { jsonrpc: "2.0", id: 1, method: "get_payment", params: [{ payment_hash: PAYMENT_HASH }] }),
        "answer",
    );
    return asRecord(answer.result, "result");
}

async function intentOf(h: PaymentFlow, paymentHash = PAYMENT_HASH): Promise<unknown> {
    return new PolicyEngine(new SignerStore(h.storage)).readDebitIntent(paymentHash.slice(2));
}

async function watchedPayments(h: PaymentFlow): Promise<string[]> {
    return Object.keys((await new ActivityTracker(new SignerStore(h.storage)).read()).payments);
}

// Signs the device's round, has the peer fulfil and signs its round: the payment ends on the last signature's tick.
async function paidThrough(h: PaymentFlow): Promise<void> {
    await tick(h, 3);
    h.node.fulfil(PAYMENT_HASH.slice(2), PREIMAGE);
    await tick(h, 4);
}

// Two payments of eight signed rounds each pass jest's 5 s default under a full parallel run.
jest.setTimeout(20_000);

describe("payments over the tenant node", () => {
    it("pays with the app open through the LSP as trampoline, then refuses the same invoice as charged", async () => {
        const h = await opened();
        const from = h.node.calls.length;
        expect(await transferred(h, PAYEE_INVOICE_STRING)).toEqual({
            paymentHashHex: PAYMENT_HASH,
            amountShannons: AMOUNT,
            maxFeeShannons: DEFAULT_MAX_FEE,
        });
        expect(h.node.calls[from]).toEqual({
            method: "send_payment",
            params: {
                invoice: PAYEE_INVOICE_STRING,
                max_fee_amount: "0x4c4b40",
                dry_run: false,
                trampoline_hops: [bytesToHex(LSP_PUBKEY)],
            },
        });
        expect(await intentOf(h)).toMatchObject({ maxShannons: BUDGET, open: true });
        await paidThrough(h);
        // The tick `pollNow` asks for signs the add; the step reads the payment on every tick until it ends.
        expect(methods(h, from)).toEqual(["send_payment", ...signed(8)]);
        expect(requests(h)).toEqual([...SEND_ROUND, ...FULFIL_ROUND]);
        expect(eventsOf(h)).toEqual([...SEND_SIGNINGS, ...FULFIL_SIGNINGS, "PAYMENT_SENT payment"]);
        expect(await paymentOf(h)).toMatchObject({ status: "Success", payment_preimage: `0x${PREIMAGE}`, fee: "0x4c4b40" });
        expect(await intentOf(h)).toEqual({
            version: 1,
            paymentHash: PAYMENT_HASH.slice(2),
            maxShannons: BUDGET,
            open: false,
            channelIndexes: [OPENING_INDEX],
        });
        expect(await watchedPayments(h)).toEqual([]);
        expect(await h.sdk.listChannels()).toEqual([
            { ...LISTED, localBalanceShannons: "60995000000", remoteBalanceShannons: "19505000000" },
        ]);
        const again = h.node.calls.length;
        const error = await rejection(h.sdk.transfer(PAYEE_INVOICE_STRING));
        expect(error).toBeInstanceOf(SdkError);
        expect(error).toMatchObject({
            code: "payment_charged",
            message: `the device refuses the payment: a payment under ${PAYMENT_HASH.slice(2)} has already been charged, it cannot be authorised again`,
        });
        expect(methods(h, again)).toEqual([]);
        expect(await watchedPayments(h)).toEqual([]);
    });

    it("throws the node's route failure for want of balance, watching nothing, and pays the same invoice once the balance is there", async () => {
        const h = await opened();
        const from = h.node.calls.length;
        const error = await rejection(h.sdk.transfer(BEYOND_BALANCE_INVOICE_STRING));
        const failure =
            "Send payment error: Failed to build route, Insufficient balance: max outbound liquidity 62000000000 is insufficient, required amount: 62500000000";
        expect(error).toBeInstanceOf(RpcError);
        expect(error).toMatchObject({ method: "send_payment", code: -32000, message: failure });
        await tick(h);
        expect(methods(h, from)).toEqual(["send_payment", ...IDLE_TICK]);
        expect(eventsOf(h)).toEqual([]);
        // Fiber keeps the failed session, which no one watches.
        expect(await paymentOf(h)).toMatchObject({ status: "Failed", failed_error: failure, fee: "0x0" });
        expect(await intentOf(h)).toMatchObject({ maxShannons: "62812500000", open: false, channelIndexes: [] });
        expect(await watchedPayments(h)).toEqual([]);
        expect((await h.sdk.createInvoice(AMOUNT)).paymentHashHex).toBe(OWN_PAYMENT_HASH);
        h.node.receivePayment({ paymentHash: OWN_PAYMENT_HASH.slice(2), amountShannons: AMOUNT, hashAlgorithm: "ckb-hash" });
        await tick(h, 10);
        expect(eventsOf(h).filter((event) => !event.startsWith("SIGNING"))).toEqual([
            "PAYMENT_PENDING invoice",
            "PAYMENT_RECEIVED invoice",
        ]);
        expect(await h.sdk.listChannels()).toEqual([
            { ...LISTED, localBalanceShannons: "63000000000", remoteBalanceShannons: "17500000000" },
        ]);
        h.events.length = 0;
        // Fiber sends a failed session again, under a new one.
        expect(await transferred(h, BEYOND_BALANCE_INVOICE_STRING)).toEqual({
            paymentHashHex: PAYMENT_HASH,
            amountShannons: "62500000000",
            maxFeeShannons: "312500000",
        });
        await paidThrough(h);
        expect(requests(h).slice(8)).toEqual([
            "SendCommitmentSigned Commitment@4 Applied",
            "CompleteReceivedRevokeAndAck Revocation@4 Applied",
            "CompleteReceivedCommitment Commitment@5 Applied",
            "SendRevokeAndAck Revocation@4 Applied",
            "CompleteReceivedCommitment Commitment@5 Applied",
            "SendRevokeAndAck Revocation@5 Applied",
            "SendCommitmentSigned Commitment@5 Applied",
            "CompleteReceivedRevokeAndAck Revocation@5 Applied",
        ]);
        expect(eventsOf(h)).toEqual([
            // Commitment@4's second session: the received TLC's removal signed its first.
            "SIGNING SendCommitmentSigned warning",
            ...SEND_SIGNINGS.slice(1),
            ...FULFIL_SIGNINGS,
            "PAYMENT_SENT payment",
        ]);
        expect(await paymentOf(h)).toMatchObject({ status: "Success", failed_error: null, fee: "0x12a05f20" });
        expect(await intentOf(h)).toMatchObject({ open: false, channelIndexes: [OPENING_INDEX] });
        expect(await h.sdk.listChannels()).toEqual([
            { ...LISTED, localBalanceShannons: "187500000", remoteBalanceShannons: "80312500000" },
        ]);
    });

    it("reports the TLC the LSP failed back with fiber's reason, then pays the invoice again under a fresh budget", async () => {
        const h = await opened();
        const from = h.node.calls.length;
        await transferred(h, PAYEE_INVOICE_STRING);
        await tick(h, 3);
        h.node.failOffered(PAYMENT_HASH.slice(2), "TemporaryNodeFailure");
        await tick(h, 4);
        expect(methods(h, from)).toEqual(["send_payment", ...signed(8)]);
        expect(requests(h)).toEqual([...SEND_ROUND, ...FULFIL_ROUND]);
        expect(eventsOf(h)).toEqual([...SEND_SIGNINGS, ...FULFIL_SIGNINGS, "PAYMENT_FAILED payment: TemporaryNodeFailure"]);
        expect(await intentOf(h)).toMatchObject({ maxShannons: BUDGET, open: false });
        expect(await watchedPayments(h)).toEqual([]);
        expect(await h.sdk.listChannels()).toEqual([LISTED]);
        h.events.length = 0;
        // No commitment holds the TLC any more: the closed intent takes a new budget.
        expect(await transferred(h, PAYEE_INVOICE_STRING, "6000000")).toEqual({
            paymentHashHex: PAYMENT_HASH,
            amountShannons: AMOUNT,
            maxFeeShannons: "6000000",
        });
        expect(await intentOf(h)).toMatchObject({ maxShannons: "1006000000", open: true });
        await paidThrough(h);
        expect(eventsOf(h)).toEqual([...SEND_SIGNINGS, ...FULFIL_SIGNINGS, "PAYMENT_SENT payment"]);
        expect(await intentOf(h)).toMatchObject({ open: false });
        expect(await h.sdk.listChannels()).toEqual([
            { ...LISTED, localBalanceShannons: "60995000000", remoteBalanceShannons: "19505000000" },
        ]);
    });

    it("keeps a payment whose answer was lost, refusing to send it again meanwhile, and reports it sent", async () => {
        const h = await opened();
        h.node.dropNextAnswer("send_payment");
        const from = h.node.calls.length;
        const error = await rejection(h.sdk.transfer(PAYEE_INVOICE_STRING));
        expect(error).toBeInstanceOf(RpcTransportError);
        expect(error).toMatchObject({ message: "send_payment: the request failed" });
        expect(await intentOf(h)).toMatchObject({ maxShannons: BUDGET, open: true });
        expect(await watchedPayments(h)).toEqual([PAYMENT_HASH.slice(2)]);
        const again = await rejection(h.sdk.transfer(PAYEE_INVOICE_STRING));
        expect(again).toBeInstanceOf(SdkError);
        expect(again).toMatchObject({
            code: "payment_in_flight",
            message: `the device refuses the payment: the one under ${PAYMENT_HASH} is not reported yet`,
        });
        // The node ran the send: no tick was asked for, the next one signs the add.
        await tick(h, 4);
        expect(eventsOf(h)).toEqual(SEND_SIGNINGS);
        h.node.fulfil(PAYMENT_HASH.slice(2), PREIMAGE);
        await tick(h, 4);
        expect(methods(h, from)).toEqual(["send_payment", ...signed(8)]);
        expect(eventsOf(h)).toEqual([...SEND_SIGNINGS, ...FULFIL_SIGNINGS, "PAYMENT_SENT payment"]);
        expect(await intentOf(h)).toMatchObject({ open: false });
        expect(await watchedPayments(h)).toEqual([]);
    });

    it("reports a payment whose request never reached the node as failed, closing its intent", async () => {
        const h = await opened();
        h.node.dropNextCall("send_payment");
        const from = h.node.calls.length;
        const error = await rejection(h.sdk.transfer(PAYEE_INVOICE_STRING));
        expect(error).toBeInstanceOf(RpcTransportError);
        expect(error).toMatchObject({ message: "send_payment: the request failed" });
        await tick(h, 2);
        expect(methods(h, from)).toEqual(["send_payment", ...IDLE_TICK, "get_payment", ...IDLE_TICK]);
        expect(requests(h)).toEqual([]);
        expect(eventsOf(h)).toEqual([`PAYMENT_FAILED payment: ${SDK_PAYMENT_NEVER_SENT_REASON}`]);
        expect(await intentOf(h)).toMatchObject({ maxShannons: BUDGET, open: false, channelIndexes: [] });
        expect(await watchedPayments(h)).toEqual([]);
        expect(await post(h.node, { jsonrpc: "2.0", id: 1, method: "get_payment", params: [{ payment_hash: PAYMENT_HASH }] })).toEqual({
            jsonrpc: "2.0",
            id: 1,
            error: { code: -32000, message: `InvalidParameter: Payment session not found: Hash256(${PAYMENT_HASH})` },
        });
    });

    it("refuses to sign a TLC past the budget the node adds, and no money moves", async () => {
        const h = await opened();
        h.node.overchargeNextPayment("1");
        const from = h.node.calls.length;
        await transferred(h, PAYEE_INVOICE_STRING);
        await tick(h, 2);
        expect(methods(h, from)).toEqual(["send_payment", ...[1, 2, 3].flatMap(() => [...IDLE_TICK, "get_payment"])]);
        expect(requests(h)).toEqual(["SendCommitmentSigned Commitment@2 unanswered"]);
        expect(eventsOf(h)).toEqual([
            "SIGNING SendCommitmentSigned refused policy_refusal",
            "SIGNING SendCommitmentSigned refused policy_refusal",
            "SIGNING SendCommitmentSigned refused policy_refusal",
        ]);
        const refused = h.events.at(-1);
        if (refused?.type !== "SIGNING" || refused.outcome !== "refused") throw new Error("the last event is no refusal");
        expect(refused.error.message).toBe(
            `the remote view draws 1005000001 shannons under ${PAYMENT_HASH.slice(2, 42)}, above its debit intent of ${BUDGET}`,
        );
        // The node shows the TLC it added; neither side's balance moves without the device's signature.
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, offeredTlcBalanceShannons: "1005000001" }]);
        expect(await paymentOf(h)).toMatchObject({ status: "Inflight" });
        expect(await watchedPayments(h)).toEqual([PAYMENT_HASH.slice(2)]);
    });

    it("refuses to pay the device's own invoice, sending nothing and watching nothing", async () => {
        const h = flow();
        const created = await h.sdk.createInvoice(AMOUNT);
        const from = h.node.calls.length;
        const error = await rejection(h.sdk.transfer(created.invoice));
        expect(error).toBeInstanceOf(SdkError);
        expect(error).toMatchObject({
            code: "own_invoice",
            message: `the device refuses the payment: ${OWN_PAYMENT_HASH.slice(2)} is the hash of a hold invoice of this device`,
        });
        expect(methods(h, from)).toEqual([]);
        expect(await watchedPayments(h)).toEqual([]);
        expect(await intentOf(h, OWN_PAYMENT_HASH)).toBeNull();
    });

    it("pays an invoice of the LSP's own directly: no hops, and the TLC carries the amount alone", async () => {
        const h = await opened();
        const from = h.node.calls.length;
        expect(await transferred(h, LSP_INVOICE_STRING)).toEqual({
            paymentHashHex: PAYMENT_HASH,
            amountShannons: AMOUNT,
            maxFeeShannons: DEFAULT_MAX_FEE,
        });
        expect(h.node.calls[from]).toEqual({
            method: "send_payment",
            params: { invoice: LSP_INVOICE_STRING, max_fee_amount: "0x4c4b40", dry_run: false },
        });
        await tick(h, 3);
        // Fiber's local balance keeps an offered TLC until it is fulfilled.
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, offeredTlcBalanceShannons: AMOUNT }]);
        expect(await paymentOf(h)).toMatchObject({ status: "Inflight", fee: "0x0" });
        h.node.fulfil(PAYMENT_HASH.slice(2), PREIMAGE);
        await tick(h, 4);
        expect(eventsOf(h)).toEqual([...SEND_SIGNINGS, ...FULFIL_SIGNINGS, "PAYMENT_SENT payment"]);
        expect(await h.sdk.listChannels()).toEqual([
            { ...LISTED, localBalanceShannons: "61000000000", remoteBalanceShannons: "19500000000" },
        ]);
    });

    it("sends the fee the host asks, which fiber caps: the TLC carries the amount and the capped fee", async () => {
        const h = await opened();
        const from = h.node.calls.length;
        expect(await transferred(h, PAYEE_INVOICE_STRING, "9000000")).toEqual({
            paymentHashHex: PAYMENT_HASH,
            amountShannons: AMOUNT,
            maxFeeShannons: "9000000",
        });
        expect(h.node.calls[from]).toEqual({
            method: "send_payment",
            params: {
                invoice: PAYEE_INVOICE_STRING,
                max_fee_amount: "0x895440",
                dry_run: false,
                trampoline_hops: [bytesToHex(LSP_PUBKEY)],
            },
        });
        expect(await intentOf(h)).toMatchObject({ maxShannons: "1009000000", open: true });
        await tick(h, 3);
        expect(await h.sdk.listChannels()).toEqual([{ ...LISTED, offeredTlcBalanceShannons: BUDGET }]);
        expect(await paymentOf(h)).toMatchObject({ status: "Inflight", fee: "0x4c4b40" });
        h.node.fulfil(PAYMENT_HASH.slice(2), PREIMAGE);
        await tick(h, 4);
        expect(eventsOf(h)).toEqual([...SEND_SIGNINGS, ...FULFIL_SIGNINGS, "PAYMENT_SENT payment"]);
        expect(await h.sdk.listChannels()).toEqual([
            { ...LISTED, localBalanceShannons: "60995000000", remoteBalanceShannons: "19505000000" },
        ]);
    });

    it("throws the route failure of a zero fee under trampoline, keeping the node's failed session unwatched", async () => {
        const h = await opened();
        const error = await rejection(h.sdk.transfer(PAYEE_INVOICE_STRING, { maxFeeShannons: "0" }));
        // A trampoline asks at least 1 per mille of the amount, rounded up, and offers ten times that as its most.
        const failure =
            "Send payment error: Failed to build route, Graph other error: max_fee_amount is too low for trampoline routing: recommend_minimal_fee=1000000, maximal_fee=10000000 current_fee=0";
        expect(error).toBeInstanceOf(RpcError);
        expect(error).toMatchObject({ method: "send_payment", code: -32000, message: failure });
        expect(await paymentOf(h)).toMatchObject({ status: "Failed", failed_error: failure, fee: "0x0" });
        expect(await intentOf(h)).toMatchObject({ maxShannons: AMOUNT, open: false, channelIndexes: [] });
        expect(await watchedPayments(h)).toEqual([]);
        await tick(h);
        expect(eventsOf(h)).toEqual([]);
    });

    it("throws the node's refusal of an invoice its clock reads expired, two milliseconds ahead of the device's, leaving no session", async () => {
        const h = await opened();
        // The device's check passes a millisecond before the expiry; fiber's, strict, refuses a millisecond after it.
        h.clock.deviceMs = EXPIRES_AT_MS - 1;
        h.clock.nodeMs = EXPIRES_AT_MS + 1;
        const error = await rejection(h.sdk.transfer(PAYEE_INVOICE_STRING));
        expect(error).toBeInstanceOf(RpcError);
        expect(error).toMatchObject({
            method: "send_payment",
            code: -32000,
            message: 'InvalidParameter: Failed to validate payment request: "invoice is expired"',
        });
        expect(await post(h.node, { jsonrpc: "2.0", id: 1, method: "get_payment", params: [{ payment_hash: PAYMENT_HASH }] })).toEqual({
            jsonrpc: "2.0",
            id: 1,
            error: { code: -32000, message: `InvalidParameter: Payment session not found: Hash256(${PAYMENT_HASH})` },
        });
        expect(await intentOf(h)).toMatchObject({ open: false, channelIndexes: [] });
        expect(await watchedPayments(h)).toEqual([]);
    });

    it("throws the route failure of a payment to the tenant's own node, whose key the device cannot tell from a payee's", async () => {
        const h = await opened();
        // An invoice the node issues for a hash the device never recorded as its own.
        const issued = asRecord(
            await post(h.node, {
                jsonrpc: "2.0",
                id: 1,
                method: "new_invoice",
                params: [
                    {
                        amount: "0x3b9aca00",
                        currency: "Fibt",
                        payment_hash: PAYMENT_HASH,
                        expiry: "0xe10",
                        final_expiry_delta: "0x5265c00",
                        hash_algorithm: "ckb_hash",
                    },
                ],
            }),
            "answer",
        );
        const invoice = asRecord(issued.result, "result").invoice_address;
        if (typeof invoice !== "string") throw new Error("the node issued no invoice");
        const error = await rejection(h.sdk.transfer(invoice));
        const failure =
            "Send payment error: Failed to build route, Feature not enabled: allow_self_payment is not enabled, can not pay to self";
        expect(error).toBeInstanceOf(RpcError);
        expect(error).toMatchObject({ method: "send_payment", code: -32000, message: failure });
        expect(await paymentOf(h)).toMatchObject({ status: "Failed", failed_error: failure, fee: "0x0" });
        expect(await intentOf(h)).toMatchObject({ open: false, channelIndexes: [] });
        expect(await watchedPayments(h)).toEqual([]);
    });

    it.each<[string, number, string]>([
        ["within its actor's minute", 0, `Payment session already exists, stop start new payment actor for Hash256(${PAYMENT_HASH})`],
        [
            "once its actor has stopped",
            60_000,
            `InvalidParameter: Payment session already exists: Hash256(${PAYMENT_HASH}) with payment session status: Inflight`,
        ],
    ])("refuses the retry of a send that landed late, %s, as in flight, and reports how the session ends", async (_, laterMs, existing) => {
        const h = await opened();
        h.node.dropNextCall("send_payment");
        expect(await rejection(h.sdk.transfer(PAYEE_INVOICE_STRING))).toBeInstanceOf(RpcTransportError);
        await tick(h);
        expect(eventsOf(h)).toEqual([`PAYMENT_FAILED payment: ${SDK_PAYMENT_NEVER_SENT_REASON}`]);
        expect(await intentOf(h)).toMatchObject({ open: false });
        // The send reaches the node after all: the device refuses its add under the closed intent.
        h.node.landDroppedCall();
        await tick(h);
        expect(eventsOf(h).slice(1)).toEqual(["SIGNING SendCommitmentSigned refused policy_refusal"]);
        const refused = h.events.at(-1);
        if (refused?.type !== "SIGNING" || refused.outcome !== "refused") throw new Error("the last event is no refusal");
        expect(refused.error.message).toBe(
            `the remote commitment draws more under ${PAYMENT_HASH.slice(2, 42)}, whose debit intent is closed`,
        );
        h.clock.deviceMs += laterMs;
        h.clock.nodeMs += laterMs;
        const from = h.node.calls.length;
        const error = await rejection(h.sdk.transfer(PAYEE_INVOICE_STRING));
        expect(error).toBeInstanceOf(SdkError);
        expect(error).toMatchObject({ code: "payment_in_flight" });
        const cause = (error as SdkError).cause;
        expect(cause).toBeInstanceOf(RpcError);
        expect(cause).toMatchObject({ method: "send_payment", code: -32000, message: existing });
        expect(methods(h, from)).toEqual(["send_payment"]);
        // The retry reopened the intent the node's session needs.
        expect(await intentOf(h)).toMatchObject({ maxShannons: BUDGET, open: true });
        expect(await watchedPayments(h)).toEqual([PAYMENT_HASH.slice(2)]);
        h.events.length = 0;
        await tick(h, 4);
        h.node.fulfil(PAYMENT_HASH.slice(2), PREIMAGE);
        await tick(h, 4);
        expect(requests(h)).toEqual([...SEND_ROUND, ...FULFIL_ROUND]);
        // The PAYMENT_FAILED before named a send the node had not run yet.
        expect(eventsOf(h)).toEqual([...SEND_SIGNINGS, ...FULFIL_SIGNINGS, "PAYMENT_SENT payment"]);
        expect(await intentOf(h)).toMatchObject({ open: false });
        expect(await watchedPayments(h)).toEqual([]);
    });
});
