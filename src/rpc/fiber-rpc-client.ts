import { assertNonEmptyString } from "../common";
import { asWireError } from "../wire";
import {
    decodeAbandonChannelResult,
    decodeListChannelsResult,
    decodeOpenChannelWithExternalFundingResult,
    decodeSubmitSignedFundingTxResult,
    encodeAbandonChannelParams,
    encodeListChannelsParams,
    encodeOpenChannelWithExternalFundingParams,
    encodeSubmitSignedFundingTxParams,
} from "./channels";
import type { FetchResponseLike, IFetchLike } from "./interfaces";
import {
    decodeNewInvoiceResult,
    decodeRpcInvoice,
    decodeSettleInvoiceResult,
    encodeNewInvoiceParams,
    encodeSettleInvoiceParams,
} from "./invoices";
import { decodeRpcResponse, encodeRpcRequest } from "./json-rpc";
import { decodeRpcPayment, encodeSendPaymentParams } from "./payments";
import { RPC_BEARER_PREFIX, RPC_CONTENT_TYPE } from "./rpc.constants";
import { RpcError, RpcResponseError, RpcTransportError } from "./rpc.error";
import type {
    AbandonChannelParams,
    RpcChannel,
    FiberRpcClientOptions,
    ListChannelsParams,
    NewInvoiceParams,
    NewInvoiceResult,
    OpenChannelWithExternalFundingParams,
    OpenChannelWithExternalFundingResult,
    RpcInvoice,
    RpcMethod,
    RpcParamsWireByMethod,
    RpcPayment,
    RpcPaymentHashParams,
    RpcResultDecoder,
    SendPaymentParams,
    SettleInvoiceParams,
    SubmitSignedFundingTxParams,
    SubmitSignedFundingTxResult,
} from "./rpc.types";
import { encodeRpcPaymentHashParams } from "./utils";

// A header value every runtime accepts, so a bad token fails at construction.
const TOKEN_PATTERN = /^[\x21-\x7e]+$/;

export class FiberRpcClient {
    private readonly url: string;

    private readonly headers: Record<string, string>;

    private readonly fetch: IFetchLike;

    private nextId = 1;

    /**
     * Creates a client of one fiber node.
     * @param options The node's url, its Biscuit token if any, and the host's fetch if not the runtime's.
     */
    constructor(options: FiberRpcClientOptions) {
        assertNonEmptyString("url", options.url);
        this.url = options.url;
        this.headers = { "content-type": RPC_CONTENT_TYPE };
        if (options.token !== undefined) {
            // The pattern alone would read `null` as the token "null".
            if (typeof options.token !== "string" || !TOKEN_PATTERN.test(options.token)) {
                throw new TypeError("token must be printable ASCII without spaces");
            }
            this.headers.authorization = RPC_BEARER_PREFIX + options.token;
        }
        this.fetch = options.fetch ?? this.runtimeFetch();
    }

    /**
     * Calls a method and decodes its result.
     * @param method Method to call.
     * @param params The method's params, in wire form.
     * @param decode Reader of the method's result.
     * @returns The decoded result.
     */
    async call<Method extends RpcMethod, Result>(
        method: Method,
        params: RpcParamsWireByMethod[Method],
        decode: RpcResultDecoder<Result>,
    ): Promise<Result> {
        const id = this.nextId++;
        const text = await this.post(method, encodeRpcRequest(id, method, params));
        const response = this.readAnswer(method, () => decodeRpcResponse(text, id));
        if ("error" in response) throw new RpcError(method, response.error.code, response.error.message);
        return this.readAnswer(method, () => decode(response.result));
    }

    /**
     * Opens a channel funded by the user's cells, blocking until the node has built the funding transaction.
     * @param params The channel to open.
     * @returns The final channel id and the unsigned funding transaction.
     */
    async openChannelWithExternalFunding(params: OpenChannelWithExternalFundingParams): Promise<OpenChannelWithExternalFundingResult> {
        return this.call(
            "open_channel_with_external_funding",
            encodeOpenChannelWithExternalFundingParams(params),
            decodeOpenChannelWithExternalFundingResult,
        );
    }

    /**
     * Hands the node the funding transaction the host signed.
     * @param params The channel and its signed funding transaction.
     * @returns The channel id and the funding transaction's hash, before broadcast.
     */
    async submitSignedFundingTx(params: SubmitSignedFundingTxParams): Promise<SubmitSignedFundingTxResult> {
        return this.call("submit_signed_funding_tx", encodeSubmitSignedFundingTxParams(params), decodeSubmitSignedFundingTxResult);
    }

    /**
     * Abandons a channel whose opening has not released our signatures.
     * @param params The channel to abandon.
     */
    async abandonChannel(params: AbandonChannelParams): Promise<void> {
        await this.call("abandon_channel", encodeAbandonChannelParams(params), decodeAbandonChannelResult);
    }

    /**
     * Lists the node's channels.
     * @param params The filter, if any.
     * @returns The channels.
     */
    async listChannels(params: ListChannelsParams = {}): Promise<RpcChannel[]> {
        return this.call("list_channels", encodeListChannelsParams(params), decodeListChannelsResult);
    }

    /**
     * Creates a hold invoice: the node gets the hash, never the preimage.
     * @param params The invoice to create.
     * @returns The encoded invoice.
     */
    async newInvoice(params: NewInvoiceParams): Promise<NewInvoiceResult> {
        return this.call("new_invoice", encodeNewInvoiceParams(params), decodeNewInvoiceResult);
    }

    /**
     * Reads an invoice of the node.
     * @param params The invoice's payment hash.
     * @returns The encoded invoice and its status.
     */
    async getInvoice(params: RpcPaymentHashParams): Promise<RpcInvoice> {
        return this.call("get_invoice", encodeRpcPaymentHashParams(params), decodeRpcInvoice);
    }

    /**
     * Hands the node an invoice's preimage; the funds are claimed at `Paid`, not when this resolves.
     * @param params The invoice and its preimage.
     */
    async settleInvoice(params: SettleInvoiceParams): Promise<void> {
        await this.call("settle_invoice", encodeSettleInvoiceParams(params), decodeSettleInvoiceResult);
    }

    /**
     * Cancels an unpaid invoice, failing the payment it holds, if any.
     * @param params The invoice's payment hash.
     * @returns The encoded invoice and its status, `Cancelled`.
     */
    async cancelInvoice(params: RpcPaymentHashParams): Promise<RpcInvoice> {
        return this.call("cancel_invoice", encodeRpcPaymentHashParams(params), decodeRpcInvoice);
    }

    /**
     * Pays an invoice, or with a dry run only finds its route.
     * @param params The invoice to pay and the fee bound.
     * @returns The payment as it stands, rarely final.
     */
    async sendPayment(params: SendPaymentParams): Promise<RpcPayment> {
        return this.call("send_payment", encodeSendPaymentParams(params), decodeRpcPayment);
    }

    /**
     * Reads a payment the node sent.
     * @param params The payment's hash.
     * @returns The payment.
     */
    async getPayment(params: RpcPaymentHashParams): Promise<RpcPayment> {
        return this.call("get_payment", encodeRpcPaymentHashParams(params), decodeRpcPayment);
    }

    /**
     * Posts a request and reads the response body of a 2xx status.
     * @param method Method being called, for the errors.
     * @param body The request text.
     * @returns The response text.
     */
    private async post(method: RpcMethod, body: string): Promise<string> {
        const send = this.fetch;
        let response: FetchResponseLike;
        try {
            response = await send(this.url, { method: "POST", headers: { ...this.headers }, body });
        } catch (cause) {
            throw new RpcTransportError(method, "the request failed", undefined, { cause });
        }
        const { status } = response;
        if (!Number.isInteger(status) || status < 200 || status > 299) throw new RpcTransportError(method, `HTTP status ${status}`, status);
        try {
            return await response.text();
        } catch (cause) {
            throw new RpcTransportError(method, "the response body could not be read", status, { cause });
        }
    }

    /**
     * Finds the runtime's global `fetch`, read once so a missing one fails at construction.
     * @returns The runtime's `fetch`.
     */
    private runtimeFetch(): IFetchLike {
        const candidate: unknown = (globalThis as { fetch?: unknown }).fetch;
        if (typeof candidate !== "function") throw new TypeError("this runtime has no fetch: pass one in the options");
        return candidate as IFetchLike;
    }

    /**
     * Runs a read of the node's answer, turning a wire refusal into an `RpcResponseError`.
     * @param method Method being called.
     * @param read The read to run.
     * @returns What the read returned.
     */
    private readAnswer<Value>(method: RpcMethod, read: () => Value): Value {
        try {
            return read();
        } catch (error) {
            throw new RpcResponseError(method, asWireError(error));
        }
    }
}
