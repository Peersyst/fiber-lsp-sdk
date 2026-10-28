import { assertNonEmptyString } from "../common";
import { asWireError } from "../wire";
import {
    decodeAbandonChannelResult,
    decodeListChannelIdsResult,
    decodeListChannelStatesResult,
    decodeListChannelsResult,
    decodeOpenChannelWithExternalFundingResult,
    decodeOpenTenantChannelResult,
    decodeSubmitSignedFundingTxResult,
    encodeListChannelsParams,
    encodeOpenChannelWithExternalFundingParams,
    encodeOpenTenantChannelParams,
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
import {
    decodeRpcSigningStatusResult,
    decodeRpcSubmissionResult,
    encodeSubmitChannelSignatureParams,
    encodeSubmitWatchtowerSignatureParams,
} from "./signing";
import {
    decodeGetTenantRegistryNonceResult,
    decodeRegisterTenantResult,
    encodeGetTenantRegistryNonceParams,
    encodeRegisterTenantParams,
} from "./tenants";
import type {
    AbandonChannelParams,
    RpcChannel,
    RpcChannelIdParams,
    RpcListedChannelState,
    FiberRpcClientOptions,
    GetTenantRegistryNonceParams,
    GetTenantRegistryNonceResult,
    ListChannelsParams,
    NewInvoiceParams,
    NewInvoiceResult,
    OpenChannelWithExternalFundingParams,
    OpenChannelWithExternalFundingResult,
    OpenTenantChannelParams,
    OpenTenantChannelResult,
    RegisterTenantParams,
    RegisterTenantResult,
    RpcInvoice,
    RpcMethod,
    RpcParamsWireByMethod,
    RpcPayment,
    RpcPaymentHashParams,
    RpcResultDecoder,
    RpcSigningStatusResult,
    RpcSubmissionResult,
    SendPaymentParams,
    SettleInvoiceParams,
    SubmitChannelSignatureParams,
    SubmitSignedFundingTxParams,
    SubmitSignedFundingTxResult,
    SubmitWatchtowerSignatureParams,
} from "./rpc.types";
import { encodeRpcChannelIdParams, encodeRpcPaymentHashParams } from "./utils";

// A header value every runtime accepts, so a bad token fails before it is held.
const TOKEN_PATTERN = /^[\x21-\x7e]+$/;

/**
 * Builds the authorization header value of a token, refusing one a header cannot carry.
 * @param token The Biscuit token.
 * @returns The Bearer header value.
 */
function bearerOf(token: unknown): string {
    // The pattern alone would read `null` as the token "null".
    if (typeof token !== "string" || !TOKEN_PATTERN.test(token)) {
        throw new TypeError("token must be printable ASCII without spaces");
    }
    return RPC_BEARER_PREFIX + token;
}

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
            this.headers.authorization = bearerOf(options.token);
        }
        this.fetch = options.fetch ?? this.runtimeFetch();
    }

    /**
     * Replaces the token the next call carries; a refused token leaves the previous one.
     * @param token The Biscuit token.
     */
    setToken(token: string): void {
        this.headers.authorization = bearerOf(token);
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
     * Opens a private channel for the tenant, funded by the user's cells, with the device's public signer material.
     * @param params The channel to open.
     * @returns The final channel id, the unsigned funding transaction and the opening context the node commits to.
     */
    async openTenantChannel(params: OpenTenantChannelParams): Promise<OpenTenantChannelResult> {
        return this.call("open_tenant_channel", encodeOpenTenantChannelParams(params), decodeOpenTenantChannelResult);
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
        await this.call("abandon_channel", encodeRpcChannelIdParams(params), decodeAbandonChannelResult);
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
     * Lists the node's channel ids, reading no other field.
     * @param params The filter, if any.
     * @returns The channel ids.
     */
    async listChannelIds(params: ListChannelsParams = {}): Promise<string[]> {
        return this.call("list_channels", encodeListChannelsParams(params), decodeListChannelIdsResult);
    }

    /**
     * Lists the node's channels' ids and states, taking any state name or flag fiber writes.
     * @param params The filter, if any.
     * @returns The channels' ids and states.
     */
    async listChannelStates(params: ListChannelsParams = {}): Promise<RpcListedChannelState[]> {
        return this.call("list_channels", encodeListChannelsParams(params), decodeListChannelStatesResult);
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
     * @param params The invoice to pay, the fee bound and the trampoline hops.
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
     * Reads a channel's signing status: the request the node waits for the device to sign, if any.
     * @param params The channel's id.
     * @returns The channel's id and its status, still undecoded.
     */
    async getChannelSigningStatus(params: RpcChannelIdParams): Promise<RpcSigningStatusResult> {
        return this.call("get_channel_signing_status", encodeRpcChannelIdParams(params), decodeRpcSigningStatusResult);
    }

    /**
     * Hands the node the device's partial signature for a channel's signing request.
     * @param params The request, its signature and the next signer material.
     * @returns Whether the node applied the signature or had already applied it.
     */
    async submitChannelSignature(params: SubmitChannelSignatureParams): Promise<RpcSubmissionResult> {
        return this.call("submit_channel_signature", encodeSubmitChannelSignatureParams(params), decodeRpcSubmissionResult);
    }

    /**
     * Reads a channel's watchtower signing status.
     * @param params The channel's id.
     * @returns The channel's id and its status, still undecoded.
     */
    async getWatchtowerSigningStatus(params: RpcChannelIdParams): Promise<RpcSigningStatusResult> {
        return this.call("get_watchtower_signing_status", encodeRpcChannelIdParams(params), decodeRpcSigningStatusResult);
    }

    /**
     * Hands the node the device's recoverable signature for a watchtower spend.
     * @param params The request and its 65-byte signature.
     * @returns Whether the node applied the signature or had already applied it.
     */
    async submitWatchtowerSignature(params: SubmitWatchtowerSignatureParams): Promise<RpcSubmissionResult> {
        return this.call("submit_watchtower_signature", encodeSubmitWatchtowerSignatureParams(params), decodeRpcSubmissionResult);
    }

    /**
     * Fetches the nonce a root signer signs to register as a tenant; needs the operator's token.
     * @param params The root signer's public key.
     * @returns The node's id, the key it echoes and the nonce.
     */
    async getTenantRegistryNonce(params: GetTenantRegistryNonceParams): Promise<GetTenantRegistryNonceResult> {
        return this.call("lsp_get_tenant_registry_nonce", encodeGetTenantRegistryNonceParams(params), decodeGetTenantRegistryNonceResult);
    }

    /**
     * Registers a tenant with the root signer's signature over the nonce; needs the operator's token.
     * @param params The root signer's public key, the nonce and the signature.
     * @returns The tenant as registered and its access token.
     */
    async registerTenant(params: RegisterTenantParams): Promise<RegisterTenantResult> {
        return this.call("lsp_register_tenant", encodeRegisterTenantParams(params), decodeRegisterTenantResult);
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
