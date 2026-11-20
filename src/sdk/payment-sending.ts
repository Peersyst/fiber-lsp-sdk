import { equalBytes } from "@noble/curves/utils.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { MAX_AMOUNT_SHANNONS, assertDecimalShannons, assertString, isPlainObject } from "../common";
import type { DebitIntentErrorCode } from "../policy";
import { DebitIntentError } from "../policy";
import { RPC_CALL_FAILED_CODE, RpcError } from "../rpc";
import {
    DEFAULT_SDK_MAX_FEE_PER_MILLE,
    SDK_ACTOR_REPLY_LOST_ERROR,
    SDK_INVOICE_UNPAYABLE,
    SDK_MAX_FEE_RATE_DENOMINATOR,
    SDK_PAYMENT_REFUSAL_TEMPLATES,
    SDK_PAYMENT_REFUSED,
    SDK_PAYMENT_SESSION_EXISTS_ERRORS,
} from "./sdk.constants";
import { SdkError } from "./sdk.error";
import type { SdkContext, SdkErrorCode, SdkPayment, SdkTransferOptions } from "./sdk.types";
import {
    checkPayableInvoice,
    describeSdkFailure,
    isFiberRefusal,
    isFiberRefusalByTemplate,
    isFiberRefusalUnderHash,
    pendingSendRecord,
    readSdkClock,
    settlePaymentRecord,
} from "./utils";

export type SdkPaymentSendingContext = Pick<
    SdkContext,
    "network" | "lspPubkey" | "now" | "rpc" | "policy" | "activity" | "history" | "poller" | "sending" | "reading"
>;

export type SdkTransferPreparingContext = Pick<SdkContext, "network" | "lspPubkey" | "now">;

export type SdkPreparedTransfer = {
    encodedInvoice: string;
    /**
     * Lowercase hex, unprefixed.
     */
    paymentHashHex: string;
    amountShannons: string;
    description: string | null;
    maxFeeShannons: string;
    /**
     * The amount plus the fee budget, which the debit intent approves.
     */
    budgetShannons: string;
    trampolineHops: Uint8Array[];
};

// `payment_charged` is no proof of payment, only that a TLC under the hash was charged. A twin's TLC would bind to another
// payment's record, so its invoice is unpayable.
const DEBIT_INTENT_REFUSALS = {
    intent_open: "payment_in_flight",
    intent_charged: "payment_charged",
    own_invoice: "own_invoice",
    hash_twin: "invoice_unpayable",
} as const satisfies Record<DebitIntentErrorCode, SdkErrorCode>;

const PAYMENT_REFUSAL_CODES = Object.keys(SDK_PAYMENT_REFUSAL_TEMPLATES) as (keyof typeof SDK_PAYMENT_REFUSAL_TEMPLATES)[];

// These sends may have left, so their intent and watch stay for the step to report.
const PAYMENT_STILL_WATCHED: readonly SdkErrorCode[] = ["payment_session_exists", "payment_unresolved"];

const PAYMENT_NODE_REFUSED = "the node refuses the payment";

const PAYMENT_OUTCOME_UNKNOWN = "the payment's outcome is unknown";

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
    const transfer = prepareSdkTransfer(context, encodedInvoice, options);
    const { paymentHashHex, amountShannons, maxFeeShannons } = transfer;
    const { sending, reading } = context;
    // Held until the call settles: the step never reads a hash mid-send, nor is one sent mid-read.
    if (sending.has(paymentHashHex) || reading.has(paymentHashHex)) throw paymentInFlightRefusal(paymentHashHex);
    sending.add(paymentHashHex);
    try {
        await sendWatchedPayment(context, transfer);
    } finally {
        sending.delete(paymentHashHex);
    }
    context.poller.pollNow();
    return { paymentHashHex: `0x${paymentHashHex}`, amountShannons, maxFeeShannons };
}

/**
 * Checks the arguments and the invoice and computes what its send is given, touching nothing.
 * @param context The network, the LSP and the clock.
 * @param encodedInvoice The invoice string.
 * @param options The fee budget, if any.
 * @returns The checked invoice, its budget and its trampoline hops.
 */
export function prepareSdkTransfer(
    context: SdkTransferPreparingContext,
    encodedInvoice: string,
    options: SdkTransferOptions | undefined,
): SdkPreparedTransfer {
    const askedMaxFeeShannons = readTransferArguments(encodedInvoice, options);
    const nowMs = readSdkClock(context.now);
    const { paymentHash, amountShannons, payeePublicKey, description } = checkPayableInvoice(
        encodedInvoice,
        context.network.invoiceCurrency,
        nowMs,
    );
    const maxFeeShannons = askedMaxFeeShannons ?? defaultMaxFeeShannons(amountShannons);
    return {
        encodedInvoice,
        paymentHashHex: bytesToHex(paymentHash),
        amountShannons,
        description,
        maxFeeShannons,
        budgetShannons: debitBudgetShannons(amountShannons, maxFeeShannons),
        // A tenant's graph holds its own channels alone, so a payee other than the LSP is reached through it as trampoline.
        trampolineHops: equalBytes(payeePublicKey, context.lspPubkey) ? [] : [context.lspPubkey],
    };
}

/**
 * Turns what a `send_payment` threw into the facade's error, by what it proves of the send.
 * @param error What the call threw.
 * @param paymentHashHex The payment hash, lowercase hex.
 * @returns The error to throw, the call's own as its cause.
 */
export function classifySdkPaymentFailure(error: unknown, paymentHashHex: string): SdkError {
    if (isFiberRefusalUnderHash(error, SDK_PAYMENT_SESSION_EXISTS_ERRORS, paymentHashHex)) {
        const what = `the node already holds a payment under 0x${paymentHashHex}`;
        return new SdkError("payment_session_exists", describeSdkFailure(what, error), { cause: error });
    }
    // The lost reply is no refusal: the call may have run.
    if (!(error instanceof RpcError) || isFiberRefusal(error, SDK_ACTOR_REPLY_LOST_ERROR)) {
        return new SdkError("payment_unresolved", describeSdkFailure(PAYMENT_OUTCOME_UNKNOWN, error), { cause: error });
    }
    const code =
        PAYMENT_REFUSAL_CODES.find((refusal) =>
            isFiberRefusalByTemplate(error, RPC_CALL_FAILED_CODE, SDK_PAYMENT_REFUSAL_TEMPLATES[refusal]),
        ) ?? "payment_rejected";
    return new SdkError(code, describeSdkFailure(PAYMENT_NODE_REFUSED, error), { cause: error });
}

/**
 * Watches the hash, records the intent and the pending record, and sends the payment, keeping for the step whatever may have left.
 * @param context What the payment reads and writes.
 * @param transfer The checked invoice and what the device computed from it.
 */
async function sendWatchedPayment(context: SdkPaymentSendingContext, transfer: SdkPreparedTransfer): Promise<void> {
    const { activity, policy, rpc, history } = context;
    const { encodedInvoice, paymentHashHex, maxFeeShannons, budgetShannons, trampolineHops } = transfer;
    // A completed record is final: its retry is refused before anything is watched or approved.
    if ((await history.read(paymentHashHex))?.status === "completed") throw paymentChargedRefusal(paymentHashHex);
    // Watched before the intent, so no failure in between leaves an open intent the step never closes; a hash still
    // watched is a payment not yet reported.
    if (!(await activity.watchIfAbsent("payment", paymentHashHex))) throw paymentInFlightRefusal(paymentHashHex);
    await recordPaymentIntent(context, paymentHashHex, budgetShannons);
    await recordPendingSend(context, transfer);
    try {
        await rpc.sendPayment({ invoice: encodedInvoice, maxFeeAmountShannons: maxFeeShannons, dryRun: false, trampolineHops });
    } catch (error) {
        const failure = classifySdkPaymentFailure(error, paymentHashHex);
        // The node refused it, so nothing ran under the intent; a route failure's `Failed` row is left unwatched. A record
        // the store leaves pending throws the store's error and keeps the watch, whose step then fails it.
        if (!PAYMENT_STILL_WATCHED.includes(failure.code)) {
            await recordRefusedSend(context, paymentHashHex, failure.message);
            await policy.closeDebitIntent(paymentHashHex);
            await activity.forget("payment", paymentHashHex);
        }
        throw failure;
    }
}

/**
 * Records a send as pending before the node hears of it, closing its intent and its watch when the store refuses the write.
 * @param context The history, the policy, the activity list and the clock.
 * @param transfer The checked invoice and its budget.
 */
async function recordPendingSend(context: SdkPaymentSendingContext, transfer: SdkPreparedTransfer): Promise<void> {
    const { paymentHashHex, amountShannons, encodedInvoice, description, maxFeeShannons } = transfer;
    const send = { paymentHashHex: `0x${paymentHashHex}`, amountShannons, invoice: encodedInvoice, description, maxFeeShannons };
    try {
        const nowMs = readSdkClock(context.now);
        await context.history.update(paymentHashHex, (current) =>
            current?.status === "completed" ? current : pendingSendRecord(send, nowMs),
        );
    } catch (error) {
        // A record written but left out of the index must not stay pending for a payment never sent.
        try {
            await recordRefusedSend(context, paymentHashHex, error instanceof Error ? error.message : String(error));
        } catch {
            // Left pending, it keeps its intent and its watch: the step's "not found" fails it.
            throw error;
        }
        await context.policy.closeDebitIntent(paymentHashHex);
        await context.activity.forget("payment", paymentHashHex);
        throw error;
    }
}

/**
 * Fails the record of a send that never left, if it has one.
 * @param context The history and the clock.
 * @param paymentHashHex The payment hash, lowercase hex.
 * @param reason Why it never left.
 */
async function recordRefusedSend(context: SdkPaymentSendingContext, paymentHashHex: string, reason: string): Promise<void> {
    const nowMs = readSdkClock(context.now);
    await context.history.update(paymentHashHex, (current) => settlePaymentRecord(current, { status: "failed", reason }, nowMs));
}

/**
 * Builds the refusal of a payment whose record already completed.
 * @param paymentHashHex The payment hash, lowercase hex.
 * @returns The error to throw.
 */
function paymentChargedRefusal(paymentHashHex: string): SdkError {
    return new SdkError("payment_charged", `${SDK_PAYMENT_REFUSED}: the one under 0x${paymentHashHex} already completed`);
}

/**
 * Builds the refusal of a payment whose hash is still being sent, read or watched.
 * @param paymentHashHex The payment hash, lowercase hex.
 * @returns The error to throw.
 */
function paymentInFlightRefusal(paymentHashHex: string): SdkError {
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
