import { PAYMENT_HASH_LENGTH } from "../../common";
import { encodeHexBytes } from "../../wire";
import type { RpcPaymentHashParams, RpcPaymentHashParamsWire } from "../rpc.types";

/**
 * Writes the params of a method that names an invoice or a payment by its hash.
 * @param params The payment hash.
 * @returns The wire params.
 */
export function encodeRpcPaymentHashParams(params: RpcPaymentHashParams): RpcPaymentHashParamsWire {
    return { payment_hash: encodeHexBytes("paymentHash", params.paymentHash, PAYMENT_HASH_LENGTH) };
}
