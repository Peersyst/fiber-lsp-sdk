import type { SentCall } from "../mocks/rpc";

export function getPaymentCall(paymentHash: string): SentCall {
    return { method: "get_payment", params: { payment_hash: `0x${paymentHash}` } };
}
