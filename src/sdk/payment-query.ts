import { hexToBytes } from "@noble/hashes/utils.js";
import { PAYMENT_HASH_LENGTH, assertUnsignedInteger, isPlainObject } from "../common";
import type { FiberRpcClient, RpcPayment } from "../rpc";
import { assertWireHexBytes } from "../wire";
import { DEFAULT_SDK_PAYMENT_PAGE_LIMIT, SDK_PAYMENT_NOT_FOUND_ERROR } from "./sdk.constants";
import type { SdkContext, SdkPaymentListOptions, SdkPaymentRecord } from "./sdk.types";
import { assertSdkAnsweredHash, isFiberRefusalUnderHash, toSdkPaymentRecord } from "./utils";

export type SdkPaymentQueryContext = Pick<SdkContext, "history">;

/**
 * Reads one payment of the history.
 * @param context The history.
 * @param paymentHashHex The payment hash, `0x`-prefixed lowercase hex, as the events carry it.
 * @returns A copy of the record, or `null` when the history holds none.
 */
export async function getSdkPayment(context: SdkPaymentQueryContext, paymentHashHex: string): Promise<SdkPaymentRecord | null> {
    assertWireHexBytes("paymentHashHex", paymentHashHex, PAYMENT_HASH_LENGTH);
    const record = await context.history.read(paymentHashHex.slice(2));
    return record === null ? null : toSdkPaymentRecord(record);
}

/**
 * Reads a page of the history, newest first.
 * @param context The history.
 * @param options The page's size, 20 by default, and the records skipped before it.
 * @returns Copies of the records.
 */
export async function listSdkPayments(context: SdkPaymentQueryContext, options?: SdkPaymentListOptions): Promise<SdkPaymentRecord[]> {
    const { limit, offset } = readListArguments(options);
    return (await context.history.list(limit, offset)).map(toSdkPaymentRecord);
}

/**
 * Reads a payment from the node.
 * @param rpc The node's client.
 * @param paymentHash The payment hash, lowercase hex.
 * @returns The payment, held to the hash asked, or `null` when the node holds no session of it.
 */
export async function readSdkPayment(rpc: FiberRpcClient, paymentHash: string): Promise<RpcPayment | null> {
    let payment: RpcPayment;
    try {
        payment = await rpc.getPayment({ paymentHash: hexToBytes(paymentHash) });
    } catch (error) {
        if (isFiberRefusalUnderHash(error, [SDK_PAYMENT_NOT_FOUND_ERROR], paymentHash)) return null;
        throw error;
    }
    assertSdkAnsweredHash("payment", paymentHash, payment.paymentHash);
    return payment;
}

/**
 * Asserts a page's options, reading each once.
 * @param options The host's options, if any.
 * @returns The limit, defaulted, and the offset, 0 by default.
 */
function readListArguments(options: SdkPaymentListOptions | undefined): { limit: number; offset: number } {
    if (options === undefined) return { limit: DEFAULT_SDK_PAYMENT_PAGE_LIMIT, offset: 0 };
    if (!isPlainObject(options)) throw new TypeError("options must be an object");
    const { limit = DEFAULT_SDK_PAYMENT_PAGE_LIMIT, offset = 0 } = options;
    assertUnsignedInteger("options.limit", limit, Number.MAX_SAFE_INTEGER);
    assertUnsignedInteger("options.offset", offset, Number.MAX_SAFE_INTEGER);
    return { limit, offset };
}
