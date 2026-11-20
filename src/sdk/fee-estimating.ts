import type { RpcPayment } from "../rpc";
import { classifySdkPaymentFailure, prepareSdkTransfer } from "./payment-sending";
import type { SdkContext, SdkFeeEstimate, SdkTransferOptions } from "./sdk.types";
import { assertSdkAnsweredHash } from "./utils";

export type SdkFeeEstimatingContext = Pick<SdkContext, "network" | "lspPubkey" | "now" | "rpc">;

/**
 * Finds the fee a `transfer` of the invoice under the same options is charged, by a dry run that sends nothing.
 * @param context The network, the LSP, the clock and the node's client.
 * @param encodedInvoice The invoice string.
 * @param options The fee budget, as `transfer` takes it.
 * @returns The payment hash, amount and fee.
 */
export async function estimateSdkTransferFee(
    context: SdkFeeEstimatingContext,
    encodedInvoice: string,
    options?: SdkTransferOptions,
): Promise<SdkFeeEstimate> {
    const { paymentHashHex, amountShannons, maxFeeShannons, trampolineHops } = prepareSdkTransfer(context, encodedInvoice, options);
    let payment: RpcPayment;
    try {
        payment = await context.rpc.sendPayment({
            invoice: encodedInvoice,
            maxFeeAmountShannons: maxFeeShannons,
            dryRun: true,
            trampolineHops,
        });
        assertSdkAnsweredHash("dry run", paymentHashHex, payment.paymentHash);
    } catch (error) {
        throw classifySdkPaymentFailure(error, paymentHashHex);
    }
    return { paymentHashHex: `0x${paymentHashHex}`, amountShannons, feeShannons: payment.feeShannons };
}
