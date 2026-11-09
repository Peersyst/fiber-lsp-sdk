import { hexToBytes } from "@noble/hashes/utils.js";
import { PAYMENT_HASH_LENGTH } from "../common";
import type { PolicyEngine } from "../policy";
import { HoldInvoiceError } from "../policy";
import type { FiberRpcClient } from "../rpc";
import { assertWireHexBytes } from "../wire";
import { SDK_INVOICE_ALREADY_CANCELLED_ERROR } from "./sdk.constants";
import { SdkError } from "./sdk.error";
import type { SdkContext } from "./sdk.types";
import { isFiberRefusal } from "./utils";

export type SdkInvoiceCancellingContext = Pick<SdkContext, "rpc" | "policy" | "poller">;

/**
 * Cancels a hold invoice: marked first, so a release crossing it finds the mark, then asked of the node.
 * @param context The policy gate, the node's client and the poller.
 * @param paymentHashHex The payment hash, `0x`-prefixed lowercase hex, as the events carry it.
 */
export async function cancelSdkInvoice(context: SdkInvoiceCancellingContext, paymentHashHex: string): Promise<void> {
    assertWireHexBytes("paymentHashHex", paymentHashHex, PAYMENT_HASH_LENGTH);
    const paymentHash = paymentHashHex.slice(2);
    await markInvoiceCancelled(context.policy, paymentHash);
    // The mark stays if this fails: a retry, or the invoice step once the invoice is received, repeats the cancel.
    await cancelInvoiceOnNode(context.rpc, paymentHash);
    context.poller.pollNow();
}

/**
 * Asks the node to cancel an invoice; one already cancelled is the cancel done.
 * @param rpc The node's client.
 * @param paymentHash The payment hash, lowercase hex.
 */
export async function cancelInvoiceOnNode(rpc: FiberRpcClient, paymentHash: string): Promise<void> {
    try {
        await rpc.cancelInvoice({ paymentHash: hexToBytes(paymentHash) });
    } catch (error) {
        if (!isFiberRefusal(error, SDK_INVOICE_ALREADY_CANCELLED_ERROR)) throw error;
    }
}

/**
 * Marks an invoice cancelled, turning the host's two mistaken cases into the facade's errors.
 * @param policy The policy gate.
 * @param paymentHash The payment hash, lowercase hex.
 */
async function markInvoiceCancelled(policy: PolicyEngine, paymentHash: string): Promise<void> {
    try {
        await policy.markHoldInvoiceCancelled(paymentHash);
    } catch (error) {
        if (error instanceof HoldInvoiceError && error.code === "not_recorded") {
            throw new SdkError("unknown_invoice", `this device recorded no invoice 0x${paymentHash}`, { cause: error });
        }
        if (error instanceof HoldInvoiceError && error.code === "released") {
            throw new SdkError("invoice_released", `the invoice 0x${paymentHash} cannot be cancelled: its preimage was released`, {
                cause: error,
            });
        }
        throw error;
    }
}
