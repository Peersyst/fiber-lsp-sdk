import { equalBytes } from "@noble/curves/utils.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { MAX_AMOUNT_SHANNONS, assertDecimalShannons, assertString, isPlainObject } from "../common";
import type { DebitIntentErrorCode } from "../policy";
import { DebitIntentError } from "../policy";
import { RpcError } from "../rpc";
import {
    DEFAULT_SDK_MAX_FEE_PER_MILLE,
    SDK_ACTOR_REPLY_LOST_ERROR,
    SDK_INVOICE_UNPAYABLE,
    SDK_MAX_FEE_RATE_DENOMINATOR,
    SDK_PAYMENT_REFUSED,
    SDK_PAYMENT_SESSION_EXISTS_ERRORS,
} from "./sdk.constants";
import { SdkError } from "./sdk.error";
import type { SdkContext, SdkErrorCode, SdkPayment, SdkTransferOptions } from "./sdk.types";
import { checkPayableInvoice, describeSdkFailure, isFiberRefusal, isFiberRefusalUnderHash, readSdkClock } from "./utils";

export type SdkPaymentSendingContext = Pick<
    SdkContext,
    "network" | "lspPubkey" | "now" | "rpc" | "policy" | "activity" | "poller" | "sending" | "reading"
>;

type PaymentToSend = {
    encodedInvoice: string;
    paymentHashHex: string;
    payeePublicKey: Uint8Array;
    maxFeeShannons: string;
    budgetShannons: string;
};

// `payment_charged` is no proof of payment, only that a TLC under the hash was charged. A twin's TLC would bind to another
// payment's record, so its invoice is unpayable.
const DEBIT_INTENT_REFUSALS = {
    intent_open: "payment_in_flight",
    intent_charged: "payment_charged",
    own_invoice: "own_invoice",
    hash_twin: "invoice_unpayable",
} as const satisfies Record<DebitIntentErrorCode, SdkErrorCode>;

/**
 * Pays an invoice through the LSP: checked, watched, its budget approved, then sent; the step reports how it ends.
 * @param context What the payment reads and writes.
 * @param encodedInvoice The invoice string.
 * @param options The fee budget, if any.
 * @returns The payment hash, the amount and the fee budget sent.
 */
export async function transferSdkPayment(
    context: SdkPaymentSendingContext,
    encodedInvoice: string,
    options?: SdkTransferOptions,
): Promise<SdkPayment> {
    const askedMaxFeeShannons = readTransferArguments(encodedInvoice, options);
    const nowMs = readSdkClock(context.now);
    const { paymentHash, amountShannons, payeePublicKey } = checkPayableInvoice(encodedInvoice, context.network.invoiceCurrency, nowMs);
    const maxFeeShannons = askedMaxFeeShannons ?? defaultMaxFeeShannons(amountShannons);
    const budgetShannons = debitBudgetShannons(amountShannons, maxFeeShannons);
    const paymentHashHex = bytesToHex(paymentHash);
    const { sending, reading } = context;
    // Held until the call settles: the step never reads a hash mid-send, nor is one sent mid-read.
    if (sending.has(paymentHashHex) || reading.has(paymentHashHex)) throw paymentInFlight(paymentHashHex);
    sending.add(paymentHashHex);
    try {
        await sendWatchedPayment(context, { encodedInvoice, paymentHashHex, payeePublicKey, maxFeeShannons, budgetShannons });
    } finally {
        sending.delete(paymentHashHex);
    }
    context.poller.pollNow();
    return { paymentHashHex: `0x${paymentHashHex}`, amountShannons, maxFeeShannons };
}

/**
 * Watches the hash, records the intent and sends the payment, keeping for the step whatever an unknown outcome leaves.
 * @param context What the payment reads and writes.
 * @param payment The checked invoice and what the device computed from it.
 */
async function sendWatchedPayment(context: SdkPaymentSendingContext, payment: PaymentToSend): Promise<void> {
    const { activity, policy, rpc, lspPubkey } = context;
    const { encodedInvoice, paymentHashHex, payeePublicKey, maxFeeShannons, budgetShannons } = payment;
    // Watched before the intent, so no failure in between leaves an open intent the step never closes; a hash still
    // watched is a payment not yet reported.
    if (!(await activity.watchIfAbsent("payment", paymentHashHex))) throw paymentInFlight(paymentHashHex);
    await recordPaymentIntent(context, paymentHashHex, budgetShannons);
    try {
        await rpc.sendPayment({
            invoice: encodedInvoice,
            maxFeeAmountShannons: maxFeeShannons,
            dryRun: false,
            // A tenant's graph holds its own channels alone, so a payee other than the LSP is reached through it as trampoline.
            trampolineHops: equalBytes(payeePublicKey, lspPubkey) ? [] : [lspPubkey],
        });
    } catch (error) {
        if (isFiberRefusalUnderHash(error, SDK_PAYMENT_SESSION_EXISTS_ERRORS, paymentHashHex)) {
            // Its intent and its watch are kept, so the step reports the session the node already runs.
            const what = `the node already holds a payment under 0x${paymentHashHex}`;
            throw new SdkError("payment_in_flight", describeSdkFailure(what, error), { cause: error });
        }
        if (error instanceof RpcError && !isFiberRefusal(error, SDK_ACTOR_REPLY_LOST_ERROR)) {
            // Any other refusal ran nothing under the intent; a route failure's `Failed` row is left unwatched.
            await policy.closeDebitIntent(paymentHashHex);
            await activity.forget("payment", paymentHashHex);
        }
        throw error;
    }
}

/**
 * Builds the refusal of a payment whose hash is still being sent, read or watched.
 * @param paymentHashHex The payment hash, lowercase hex.
 * @returns The error to throw.
 */
function paymentInFlight(paymentHashHex: string): SdkError {
    return new SdkError("payment_in_flight", `${SDK_PAYMENT_REFUSED}: the one under 0x${paymentHashHex} is not reported yet`);
}

/**
 * Asserts the invoice string and the options, reading the fee budget once.
 * @param encodedInvoice The invoice string.
 * @param options The host's options, if any.
 * @returns The fee budget the host asked, or `undefined` for the default.
 */
function readTransferArguments(encodedInvoice: string, options: SdkTransferOptions | undefined): string | undefined {
    assertString("encodedInvoice", encodedInvoice);
    if (options === undefined) return undefined;
    if (!isPlainObject(options)) throw new TypeError("options must be an object");
    const { maxFeeShannons } = options;
    if (maxFeeShannons !== undefined) assertDecimalShannons("options.maxFeeShannons", maxFeeShannons);
    return maxFeeShannons;
}

/**
 * Computes fiber's default fee budget for an amount, rounded up as `calculate_fee_with_base` rounds it (`fiber/fee.rs:151-175`).
 * @param amountShannons The invoice's amount.
 * @returns The fee budget, in decimal shannons.
 */
function defaultMaxFeeShannons(amountShannons: string): string {
    const scaled = BigInt(amountShannons) * DEFAULT_SDK_MAX_FEE_PER_MILLE;
    return ((scaled + SDK_MAX_FEE_RATE_DENOMINATOR - 1n) / SDK_MAX_FEE_RATE_DENOMINATOR).toString();
}

/**
 * Adds the amount and the fee budget into what the debit intent approves, refusing a sum past fiber's u128.
 * @param amountShannons The invoice's amount.
 * @param maxFeeShannons The fee budget.
 * @returns The debit intent's maximum, in decimal shannons.
 */
function debitBudgetShannons(amountShannons: string, maxFeeShannons: string): string {
    const budget = BigInt(amountShannons) + BigInt(maxFeeShannons);
    if (budget > MAX_AMOUNT_SHANNONS) {
        throw new RangeError(
            `the invoice's amount and the fee budget must add up to at most ${MAX_AMOUNT_SHANNONS} shannons, got ${budget}`,
        );
    }
    return budget.toString();
}

/**
 * Records the payment's debit intent, turning the policy's refusal into the facade's and dropping the watch unless an intent is open.
 * @param context The policy and the activity list.
 * @param paymentHashHex The payment hash, lowercase hex.
 * @param budgetShannons The amount and the fee budget.
 */
async function recordPaymentIntent(context: SdkPaymentSendingContext, paymentHashHex: string, budgetShannons: string): Promise<void> {
    try {
        await context.policy.recordDebitIntent(paymentHashHex, budgetShannons);
    } catch (error) {
        if (!(error instanceof DebitIntentError)) throw error;
        // An open intent left unwatched keeps the watch just added, so the step's `get_payment` closes it.
        if (error.code !== "intent_open") await context.activity.forget("payment", paymentHashHex);
        const code = DEBIT_INTENT_REFUSALS[error.code];
        // A twin is the invoice's doing, worded as the invoice check's refusals.
        const refused = code === "invoice_unpayable" ? SDK_INVOICE_UNPAYABLE : SDK_PAYMENT_REFUSED;
        throw new SdkError(code, describeSdkFailure(refused, error), { cause: error });
    }
}
