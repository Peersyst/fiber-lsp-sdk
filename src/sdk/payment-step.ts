import type { PolicyEngine } from "../policy";
import type { FiberRpcClient } from "../rpc";
import type { ActivityTracker } from "./activity";
import type { PaymentHistory } from "./payment-history";
import { readSdkPayment } from "./payment-query";
import type { PollRun, PollStep } from "./poller";
import { SDK_PAYMENT_NEVER_SENT_REASON, SDK_PAYMENT_UNEXPLAINED_FAILURE_REASON } from "./sdk.constants";
import type { SdkEvent, SdkPaymentRecord } from "./sdk.types";
import type { PaymentHistoryOutcome } from "./utils";
import { answerEachPolled, deliverStepEvent, readSdkClock, settlePaymentRecord, toSdkPaymentRecord } from "./utils";

export type PaymentStepOptions = {
    rpc: FiberRpcClient;
    policy: PolicyEngine;
    activity: ActivityTracker;
    history: PaymentHistory;
    /**
     * Milliseconds since the epoch.
     */
    now: () => number;
    sending: ReadonlySet<string>;
    reading: Set<string>;
    emit: (event: SdkEvent) => void;
};

const POLL = "payment";

/**
 * Builds the poll step that follows each watched payment out, closing its debit intent once fiber ends it.
 * @param options The node's client, the policy gate, the activity list, the history, the clock, the hashes being sent and read, and the emitter.
 * @returns The step; it rejects only when the watched payments cannot be read.
 */
export function buildPaymentStep(options: PaymentStepOptions): PollStep {
    const { rpc, policy, activity, history, now, sending, reading, emit } = options;

    /**
     * Closes a finished payment's intent, if any, settles its record, announces it and stops watching it, if still watched.
     * @param run The run.
     * @param paymentHash The payment hash, lowercase hex.
     * @param outcome How it ended.
     * @param announce Builds the event from the settled record.
     * @param neverSent Whether the node holds no session of it.
     */
    const finish = async (
        run: PollRun,
        paymentHash: string,
        outcome: PaymentHistoryOutcome,
        announce: (payment: SdkPaymentRecord) => SdkEvent,
        neverSent: boolean,
    ): Promise<void> => {
        // Forgotten since the tick listed it, by a `transfer` whose refusal was already thrown.
        if (!Object.hasOwn((await activity.read()).payments, paymentHash)) return;
        // A false `Failed` costs nothing past the budget: the TLCs already shown stay signable.
        if ((await policy.readDebitIntent(paymentHash)) !== null) {
            if (run.abandoned) return;
            await policy.closeDebitIntent(paymentHash);
        }
        if (run.abandoned) return;
        const nowMs = readSdkClock(now);
        const record = await history.update(paymentHash, (current) => settlePaymentRecord(current, outcome, nowMs));
        // A `completed` record is final: a later `Failed` for it announces nothing.
        if (record === null) {
            // The record is written before the send, so a watch without one stopped before the node heard of it.
            if (!neverSent) throw new TypeError(`the node holds a payment under 0x${paymentHash}, whose record is missing`);
        } else if (record.status === outcome.status) {
            deliverStepEvent(run, emit, announce(toSdkPaymentRecord(record)));
        }
        if (run.abandoned) return;
        await activity.forget("payment", paymentHash);
    };

    /**
     * Answers one watched payment's status, unless its `transfer` is in progress.
     * @param run The run.
     * @param paymentHash The payment hash, lowercase hex.
     */
    const answer = async (run: PollRun, paymentHash: string): Promise<void> => {
        // Its "not found" would fail a send still on its way: the tick after the call settles reads it.
        if (sending.has(paymentHash)) return;
        // Taken in the same turn as the check, so no `transfer` sends under the hash until the answer to this read is done.
        reading.add(paymentHash);
        try {
            const payment = await readSdkPayment(rpc, paymentHash);
            if (run.abandoned) return;
            const paymentHashHex = `0x${paymentHash}`;
            /**
             * Fails the payment for a reason.
             * @param reason Fiber's or the device's.
             * @param neverSent Whether the node holds no session of it.
             * @returns Settles once it is reported.
             */
            const fail = (reason: string, neverSent: boolean): Promise<void> =>
                finish(
                    run,
                    paymentHash,
                    { status: "failed", reason },
                    (record) => ({ type: "PAYMENT_FAILED", paymentHashHex, reason, payment: record }),
                    neverSent,
                );
            if (payment === null) {
                // The send never ran: a late one finds the intent closed and its add refused.
                await fail(SDK_PAYMENT_NEVER_SENT_REASON, true);
            } else if (payment.status === "Success") {
                const { feeShannons } = payment;
                await finish(
                    run,
                    paymentHash,
                    { status: "completed", feeShannons },
                    (record) => ({ type: "PAYMENT_SENT", paymentHashHex, feeShannons, payment: record }),
                    false,
                );
            } else if (payment.status === "Failed") {
                await fail(payment.failedError ?? SDK_PAYMENT_UNEXPLAINED_FAILURE_REASON, false);
            }
        } finally {
            reading.delete(paymentHash);
        }
    };

    return async (run) => {
        const watched = Object.keys((await activity.read()).payments);
        await answerEachPolled(
            run,
            emit,
            POLL,
            watched,
            (paymentHash) => `0x${paymentHash}`,
            (paymentHash) => answer(run, paymentHash),
        );
    };
}
