import type { FetchInit, FetchResponseLike, IFetchLike } from "../../../src/rpc";
import { FetchMock, rpcErrorAnswer, rpcResultAnswer } from "./fetch.mock";

export type SentCall = { method: string; params: unknown };

export class ScriptedNode {
    readonly mock = new FetchMock();

    readonly fetch: IFetchLike;

    private lastId = 0;

    private readonly hooks = new Map<string, () => void>();

    constructor() {
        this.fetch = async (url: string, init: FetchInit): Promise<FetchResponseLike> => {
            const { method } = JSON.parse(init.body) as { method: string };
            const hook = this.hooks.get(method);
            this.hooks.delete(method);
            hook?.();
            return this.mock.fetch(url, init);
        };
    }

    result(value: unknown): this {
        this.mock.answer(rpcResultAnswer(++this.lastId, value));
        return this;
    }

    error(code: number, message: string): this {
        this.mock.answer(rpcErrorAnswer(++this.lastId, code, message));
        return this;
    }

    reject(cause: unknown): this {
        ++this.lastId;
        this.mock.answer({ rejection: cause });
        return this;
    }

    onCall(method: string, hook: () => void): this {
        this.hooks.set(method, hook);
        return this;
    }

    calls(): SentCall[] {
        return this.mock.requests.map((request) => {
            const { method, params } = JSON.parse(request.init.body) as { method: string; params: unknown[] };
            return { method, params: params[0] };
        });
    }
}
