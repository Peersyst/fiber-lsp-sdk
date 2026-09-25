import type { FetchInit, FetchResponseLike, IFetchLike } from "../../../src/rpc";

export type FetchRequest = { url: string; init: FetchInit; receiver: unknown };

export type FetchAnswer = { status: number; body: string } | { status: number; bodyError: unknown } | { rejection: unknown };

export class FetchMock {
    readonly requests: FetchRequest[] = [];

    readonly fetch: IFetchLike;

    private readonly answers: FetchAnswer[] = [];

    constructor() {
        const { requests, answers } = this;
        // Not an arrow, so the receiver is observable.
        this.fetch = async function (this: unknown, url: string, init: FetchInit): Promise<FetchResponseLike> {
            requests.push({ url, init: structuredClone(init), receiver: this });
            const answer = answers.shift();
            if (!answer) throw new Error("no answer scripted");
            if ("rejection" in answer) throw answer.rejection;
            if ("bodyError" in answer) {
                return { status: answer.status, text: () => Promise.reject(answer.bodyError) };
            }
            return { status: answer.status, text: () => Promise.resolve(answer.body) };
        };
    }

    answer(...answers: FetchAnswer[]): this {
        this.answers.push(...answers);
        return this;
    }

    get last(): FetchRequest {
        const request = this.requests.at(-1);
        if (!request) throw new Error("no request has been sent");
        return request;
    }
}
