import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { MILLISECONDS_PER_SECOND } from "../common";
import { decodeInvoice, findInvoiceAttribute } from "../invoice";
import type { HoldInvoiceErrorCode, PolicyEngine } from "../policy";
import { HoldInvoiceError } from "../policy";
import type { FiberRpcClient, RpcInvoice } from "../rpc";
import { RpcError } from "../rpc";
import type { HoldInvoicePreimages } from "../signer";
import { tlcExpiryDelay } from "../signer";
import type { ActivityTracker } from "./activity";
import type { PollRun, PollStep } from "./poller";
import { SDK_INVOICE_ALREADY_PAID_ERROR, SDK_RELEASE_EXPIRY_SLACK_MS } from "./sdk.constants";
import type { ActivityEntry, SdkEvent } from "./sdk.types";
import { answerEachPolled, deliverStepEvent } from "./utils";

export type InvoiceStepOptions = {
    rpc: FiberRpcClient;
    policy: PolicyEngine;
    preimages: HoldInvoicePreimages;
    activity: ActivityTracker;
    /**
     * Fiber's `MILLI_SECONDS_PER_EPOCH`.
     */
    millisecondsPerEpoch: number;
    /**
     * Milliseconds since the epoch.
     */
    now: () => number;
    emit: (event: SdkEvent) => void;
    /**
     * Asks for a tick right after this one, so a settlement's fulfil is signed without waiting an interval.
     */
    pollNow: () => void;
};

const POLL = "invoice";

// The release waits these out and tries again on the next tick: a payment out beside the held TLC resolves on its own.
const RELEASE_WAITS: readonly HoldInvoiceErrorCode[] = ["not_held", "expiry_too_close", "offered_in_flight"];

/**
 * Tells whether an invoice is past its expiry as fiber's `is_expired` judges it, refusing a string that is another invoice's.
 * @param invoiceAddress The invoice string the node answered.
 * @param paymentHash The payment hash watched, lowercase hex.
 * @param nowMs The host's clock.
 * @returns Whether its expiry passed; never for an invoice that carries none.
 */
function isPastInvoiceExpiry(invoiceAddress: string, paymentHash: string, nowMs: number): boolean {
    const invoice = decodeInvoice(invoiceAddress);
    const answered = bytesToHex(invoice.paymentHash);
    if (answered !== paymentHash) throw new Error(`the node answered the invoice of 0x${paymentHash} with that of 0x${answered}`);
    const expiry = findInvoiceAttribute(invoice, "expiryTime");
    if (expiry === undefined) return false;
    return invoice.timestampMs + expiry.seconds * MILLISECONDS_PER_SECOND < BigInt(nowMs);
}

/**
 * Tells whether `settle_invoice` failed only because the invoice is already paid.
 * @param error What the call threw.
 * @returns Whether it is fiber's answer for a paid invoice.
 */
function isInvoiceAlreadyPaid(error: unknown): boolean {
    const { code, message } = SDK_INVOICE_ALREADY_PAID_ERROR;
    return error instanceof RpcError && error.code === code && error.message === message;
}

/**
 * Builds the poll step that follows each watched invoice, releasing its preimage once its channels hold the payment.
 * @param options The node's client, the policy gate, the preimages, the activity list, the epoch, the clock, the emitter and `pollNow`.
 * @returns The step; it rejects only when the watched invoices cannot be read.
 */
export function buildInvoiceStep(options: InvoiceStepOptions): PollStep {
    const { rpc, policy, preimages, activity, millisecondsPerEpoch, now, emit, pollNow } = options;

    /**
     * Computes the margin a held TLC's expiry must clear for the release, from its channel's pinned delay.
     * @param commitmentDelayEpoch The channel's delay, its full `EpochNumberWithFraction` value.
     * @returns The margin, in milliseconds.
     */
    const releaseMarginMs = (commitmentDelayEpoch: bigint): bigint =>
        tlcExpiryDelay(commitmentDelayEpoch, millisecondsPerEpoch) + SDK_RELEASE_EXPIRY_SLACK_MS;

    /**
     * Derives an invoice's preimage, refusing an index recorded for the watched hash that derives another one.
     * @param paymentHash The payment hash, lowercase hex.
     * @param invoiceIndex The index recorded for it.
     * @returns The preimage that opens the hash.
     */
    const preimageOf = (paymentHash: string, invoiceIndex: number): Uint8Array => {
        const derived = bytesToHex(preimages.paymentHash(invoiceIndex));
        if (derived !== paymentHash) {
            throw new TypeError(`the invoice index recorded for 0x${paymentHash} derives the preimage of 0x${derived}`);
        }
        return preimages.preimage(invoiceIndex);
    };

    /**
     * Hands the node an invoice's preimage; an invoice already paid is the settlement done.
     * @param paymentHash The payment hash, lowercase hex.
     * @param paymentPreimage The preimage that opens it.
     */
    const settle = async (paymentHash: string, paymentPreimage: Uint8Array): Promise<void> => {
        try {
            await rpc.settleInvoice({ paymentHash: hexToBytes(paymentHash), paymentPreimage });
        } catch (error) {
            if (!isInvoiceAlreadyPaid(error)) throw error;
        }
    };

    /**
     * Announces an invoice's final status, then stops watching it.
     * @param run The run.
     * @param paymentHash The payment hash, lowercase hex.
     * @param type The event.
     */
    const finish = async (run: PollRun, paymentHash: string, type: "PAYMENT_RECEIVED" | "PAYMENT_EXPIRED"): Promise<void> => {
        deliverStepEvent(run, emit, { type, paymentHashHex: `0x${paymentHash}` });
        if (run.abandoned) return;
        await activity.forget("invoice", paymentHash);
    };

    /**
     * Releases a received invoice's preimage once policy allows it and settles it, or settles again one already released.
     * @param run The run.
     * @param paymentHash The payment hash, lowercase hex.
     * @param invoice The invoice as the node answered it.
     */
    const release = async (run: PollRun, paymentHash: string, invoice: RpcInvoice): Promise<void> => {
        const record = await policy.readHoldInvoice(paymentHash);
        if (run.abandoned) return;
        // Before the mark: a record whose index derives another hash is never released.
        const paymentPreimage = preimageOf(paymentHash, record.invoiceIndex);
        // Harmless while `Received`: it repairs a stop between the mark and the settlement.
        if (record.released) {
            await settle(paymentHash, paymentPreimage);
            return;
        }
        let reading: number | undefined;
        /**
         * Reads the host's clock once, so the expiry is judged against the release's reading.
         * @returns The reading.
         */
        const readNow = (): number => (reading ??= now());
        try {
            await policy.markHoldInvoiceReleased(paymentHash, { now: readNow, releaseMarginMs });
        } catch (error) {
            if (!(error instanceof HoldInvoiceError) || !RELEASE_WAITS.includes(error.code)) throw error;
            // Fiber keeps an invoice whose TLC failed `Received` for good.
            if (isPastInvoiceExpiry(invoice.invoiceAddress, paymentHash, readNow()) && !(await policy.listsHoldInvoiceTlc(paymentHash))) {
                await finish(run, paymentHash, "PAYMENT_EXPIRED");
            }
            return;
        }
        if (run.abandoned) return;
        await settle(paymentHash, paymentPreimage);
        if (run.abandoned) return;
        pollNow();
    };

    /**
     * Answers one watched invoice's status.
     * @param run The run.
     * @param paymentHash The payment hash, lowercase hex.
     * @param entry What was last announced for it.
     */
    const answer = async (run: PollRun, paymentHash: string, entry: ActivityEntry<"invoice">): Promise<void> => {
        const invoice = await rpc.getInvoice({ paymentHash: hexToBytes(paymentHash) });
        const { status } = invoice;
        if (status === "Received") {
            if (entry.status !== "Received") {
                deliverStepEvent(run, emit, { type: "PAYMENT_PENDING", paymentHashHex: `0x${paymentHash}` });
                if (run.abandoned) return;
                await activity.mark("invoice", paymentHash, "Received");
            }
            await release(run, paymentHash, invoice);
        } else if (status === "Paid") {
            // Only the device's preimage pays the invoice, and it leaves only once released.
            if (!(await policy.readHoldInvoice(paymentHash)).released) {
                throw new Error(`the node reports 0x${paymentHash} paid, but the device never released its preimage`);
            }
            await finish(run, paymentHash, "PAYMENT_RECEIVED");
        } else if (status === "Expired" || status === "Cancelled") {
            // Only an invoice never released ends unpaid: a released preimage may still pay it, so the anomaly keeps it watched.
            if ((await policy.readHoldInvoice(paymentHash)).released) {
                throw new Error(`the node reports 0x${paymentHash} ${status.toLowerCase()}, but the device released its preimage`);
            }
            await finish(run, paymentHash, "PAYMENT_EXPIRED");
        }
    };

    return async (run) => {
        const watched = Object.entries((await activity.read()).invoices);
        await answerEachPolled(
            run,
            emit,
            POLL,
            watched,
            ([paymentHash]) => `0x${paymentHash}`,
            ([paymentHash, entry]) => answer(run, paymentHash, entry),
        );
    };
}
