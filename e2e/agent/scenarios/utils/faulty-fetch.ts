import { OPEN_TENANT_CHANNEL_METHOD } from "../../src/agent.constants";
import type { AgentNodeFetch } from "../../src/agent.types";
import { bareLowerHex, readJsonObject } from "../../src/agent.utils";
import { readJsonRpcRequest } from "../../src/json-rpc";

export type FaultyFetchFault = "rewritten" | "refused";

export type FaultyFetchRequest = {
    at: number;
    url: string;
    method: string | null;
    params: unknown;
    fault: FaultyFetchFault | null;
};

export type FaultyFetchRewrite = (result: unknown, params: unknown) => unknown;

export type FaultyFetchOptions = {
    /**
     * How many matching requests the fault hits before it retires; 1 by default, `Infinity` for every one.
     */
    times?: number;
    when?: (params: unknown) => boolean;
};

type Interceptor = {
    method: string;
    when: (params: unknown) => boolean;
    remaining: number;
    rewrite: FaultyFetchRewrite | null;
};

export { OPEN_TENANT_CHANNEL_METHOD };
export const SUBMIT_CHANNEL_SIGNATURE_METHOD = "submit_channel_signature";
export const SUBMIT_SIGNED_FUNDING_TX_METHOD = "submit_signed_funding_tx";
export const GET_CHANNEL_SIGNING_STATUS_METHOD = "get_channel_signing_status";

export function requestParam(params: unknown, method: string): Record<string, unknown> {
    if (!Array.isArray(params)) throw new Error(`${method}: params must be an array`);
    return readJsonObject((params as unknown[])[0], `${method}.params[0]`);
}

export function channelIdParam(params: unknown, method: string): string {
    const channelId = requestParam(params, method).channel_id;
    if (typeof channelId !== "string") throw new Error(`${method}.channel_id must be a string`);
    return bareLowerHex(channelId);
}

function rewriteAnswer(text: string, rewrite: FaultyFetchRewrite, params: unknown): string | null {
    let answer: unknown;
    try {
        answer = JSON.parse(text);
    } catch {
        return null;
    }
    if (typeof answer !== "object" || answer === null || Array.isArray(answer) || !("result" in answer)) return null;
    return JSON.stringify({ ...answer, result: rewrite(answer.result, params) });
}

export class FaultyFetch {
    readonly requests: FaultyFetchRequest[] = [];

    readonly fetch: AgentNodeFetch = (url, init) => this.send(url, init);

    private interceptors: Interceptor[] = [];

    private sending = 0;

    constructor(private readonly inner: AgentNodeFetch = fetch) {}

    rewriteResult(method: string, rewrite: FaultyFetchRewrite, options: FaultyFetchOptions = {}): void {
        this.intercept(method, rewrite, options);
    }

    refuse(method: string, options: FaultyFetchOptions = {}): void {
        this.intercept(method, null, options);
    }

    clear(): void {
        this.interceptors = [];
    }

    // Refused requests count too, until they throw.
    get inFlight(): number {
        return this.sending;
    }

    sent(method: string): FaultyFetchRequest[] {
        return this.requests.filter((request) => request.method === method && request.fault !== "refused");
    }

    private intercept(method: string, rewrite: FaultyFetchRewrite | null, options: FaultyFetchOptions): void {
        this.interceptors.push({ method, when: options.when ?? (() => true), remaining: options.times ?? 1, rewrite });
    }

    private async send(url: string, init: Parameters<AgentNodeFetch>[1]): ReturnType<AgentNodeFetch> {
        this.sending += 1;
        try {
            return await this.forward(url, init);
        } finally {
            this.sending -= 1;
        }
    }

    private async forward(url: string, init: Parameters<AgentNodeFetch>[1]): ReturnType<AgentNodeFetch> {
        const { method, params } = readJsonRpcRequest(init.body);
        const record: FaultyFetchRequest = { at: Date.now(), url, method, params, fault: null };
        this.requests.push(record);
        const interceptor = this.interceptors.find((entry) => entry.remaining > 0 && entry.method === method && entry.when(params));
        if (interceptor !== undefined && interceptor.rewrite === null) {
            interceptor.remaining -= 1;
            record.fault = "refused";
            throw new Error(`faulty fetch: ${method} refused before it was sent`);
        }
        // The body is read here, so a request counts as in flight until its answer is whole.
        // Called without a receiver, as a browser's fetch requires.
        const send = this.inner;
        const response = await send(url, init);
        const text = await response.text();
        const rewrite = interceptor?.rewrite;
        if (interceptor === undefined || rewrite === undefined || rewrite === null) {
            return { status: response.status, text: () => Promise.resolve(text) };
        }
        // An error answer is handed over as is, the fault left armed for the next request.
        const rewritten = rewriteAnswer(text, rewrite, params);
        if (rewritten !== null) {
            interceptor.remaining -= 1;
            record.fault = "rewritten";
        }
        return { status: response.status, text: () => Promise.resolve(rewritten ?? text) };
    }
}
