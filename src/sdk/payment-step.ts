import { hexToBytes } from "@noble/hashes/utils.js";
import type { PolicyEngine } from "../policy";
import type { FiberRpcClient, RpcPayment } from "../rpc";
import type { ActivityTracker } from "./activity";
import type { PollRun, PollStep } from "./poller";
import { SDK_PAYMENT_NEVER_SENT_REASON, SDK_PAYMENT_NOT_FOUND_ERROR, SDK_PAYMENT_UNEXPLAINED_FAILURE_REASON } from "./sdk.constants";
import type { SdkEvent } from "./sdk.types";
import { answerEachPolled, assertSdkAnsweredHash, deliverStepEvent, isFiberRefusalUnderHash } from "./utils";

export type PaymentStepOptions = {
    rpc: FiberRpcClient;
    policy: PolicyEngine;
    activity: ActivityTracker;
    sending: ReadonlySet<string>;
    reading: Set<string>;
    emit: (event: SdkEvent) => void;
};

const POLL = "payment";

/**
 * Builds the poll step that follows each watched payment out, closing its debit intent once fiber ends it.
 * @param options The node's client, the policy gate, the activity list, the hashes being sent and read, and the emitter.
 * @returns The step; it rejects only when the watched payments cannot be read.
 */
export function buildPaymentStep(options: PaymentStepOptions): PollStep {
    const { rpc, policy, activity, sending, reading, emit } = options;

    /**
     * Reads a watched payment, or null when the node holds no session of it.
     * @param paymentHash The payment hash, lowercase hex.
     * @returns The payment, held to the watched hash.
     */
    const readPayment = async (paymentHash: string): Promise<RpcPayment | null> => {
        let payment: RpcPayment;
        try {
            payment = await rpc.getPayment({ paymentHash: hexToBytes(paymentHash) });
        } catch (error) {
            if (isFiberRefusalUnderHash(error, [SDK_PAYMENT_NOT_FOUND_ERROR], paymentHash)) return null;
            throw error;
        }
        assertSdkAnsweredHash("payment", paymentHash, payment.paymentHash);
        return payment;
    };

    /**
     * Closes a finished payment's debit intent, if any, announces it and stops watching it, unless it is no longer watched.
     * @param run The run.
     * @param paymentHash The payment hash, lowercase hex.
     * @param event The event that announces it.
     */
    const finish = async (run: PollRun, paymentHash: string, event: SdkEvent): Promise<void> => {
        // Forgotten since the tick listed it, by a `transfer` whose refusal was already thrown.
        if (!Object.hasOwn((await activity.read()).payments, paymentHash)) return;
        // A false `Failed` costs nothing past the budget: the TLCs already shown stay signable.
        if ((await policy.readDebitIntent(paymentHash)) !== null) {
            if (run.abandoned) return;
            await policy.closeDebitIntent(paymentHash);
        }
        deliverStepEvent(run, emit, event);
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
            const payment = await readPayment(paymentHash);
            if (run.abandoned) return;
            const paymentHashHex = `0x${paymentHash}`;
            if (payment === null) {
                // The send never ran: a late one finds the intent closed and its add refused.
                await finish(run, paymentHash, { type: "PAYMENT_FAILED", paymentHashHex, reason: SDK_PAYMENT_NEVER_SENT_REASON });
            } else if (payment.status === "Success") {
                await finish(run, paymentHash, { type: "PAYMENT_SENT", paymentHashHex });
            } else if (payment.status === "Failed") {
                const reason = payment.failedError ?? SDK_PAYMENT_UNEXPLAINED_FAILURE_REASON;
                await finish(run, paymentHash, { type: "PAYMENT_FAILED", paymentHashHex, reason });
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
