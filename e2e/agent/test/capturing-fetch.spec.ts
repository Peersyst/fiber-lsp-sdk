import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { FetchInit, FetchResponseLike, IFetchLike } from "@peersyst/fiber-lsp-sdk";
import { OpenResultCapture } from "../src/capturing-fetch";

const URL = "http://127.0.0.1:8227";

const OPEN_REQUEST: FetchInit = {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: '{"jsonrpc":"2.0","id":7,"method":"open_tenant_channel","params":[{}]}',
};

const LIST_REQUEST: FetchInit = {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: '{"jsonrpc":"2.0","id":8,"method":"list_channels","params":[{}]}',
};

const OPEN_ANSWER =
    '{"jsonrpc":"2.0","id":7,"result":{"channel_id":"0x4056792f61337675c153ab8f10c442fa68a913a18ce6f8beec37a19c23d5aa4d","extra":[1,"0x2"]}}';

function answering(status: number, body: string): { fetch: IFetchLike; sent: FetchInit[]; responses: FetchResponseLike[] } {
    const sent: FetchInit[] = [];
    const responses: FetchResponseLike[] = [];
    const fetch: IFetchLike = async (url, init) => {
        assert.equal(url, URL);
        sent.push(init);
        const response = { status, text: async () => body };
        responses.push(response);
        return response;
    };
    return { fetch, sent, responses };
}

describe("OpenResultCapture", () => {
    it("keeps the raw result of open_tenant_channel and hands the SDK the same status and text", async () => {
        const inner = answering(200, OPEN_ANSWER);
        const capture = new OpenResultCapture(inner.fetch);
        const response = await capture.fetch(URL, OPEN_REQUEST);
        assert.deepEqual(inner.sent, [OPEN_REQUEST]);
        assert.equal(response.status, 200);
        assert.equal(await response.text(), OPEN_ANSWER);
        assert.deepEqual(capture.take(), {
            channel_id: "0x4056792f61337675c153ab8f10c442fa68a913a18ce6f8beec37a19c23d5aa4d",
            extra: [1, "0x2"],
        });
    });

    it("forgets the result once taken", async () => {
        const capture = new OpenResultCapture(answering(200, OPEN_ANSWER).fetch);
        await capture.fetch(URL, OPEN_REQUEST);
        assert.notEqual(capture.take(), null);
        assert.equal(capture.take(), null);
    });

    it("hands any other method's response through untouched, keeping nothing", async () => {
        const inner = answering(200, OPEN_ANSWER);
        const capture = new OpenResultCapture(inner.fetch);
        const response = await capture.fetch(URL, LIST_REQUEST);
        assert.equal(response, inner.responses[0]);
        assert.equal(capture.take(), null);
    });

    for (const [name, body] of [
        ["an error answer", '{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"tenant already has a channel"}}'],
        ["a null result", '{"jsonrpc":"2.0","id":7,"result":null}'],
        ["an array result", '{"jsonrpc":"2.0","id":7,"result":[]}'],
        ["a body that is not JSON", "<html>bad gateway</html>"],
    ] as const) {
        it(`keeps nothing from ${name}, and hands the SDK its text`, async () => {
            const capture = new OpenResultCapture(answering(200, body).fetch);
            const response = await capture.fetch(URL, OPEN_REQUEST);
            assert.equal(await response.text(), body);
            assert.equal(capture.take(), null);
        });
    }

    it("keeps the result of an answer whatever its status, the SDK deciding what a status means", async () => {
        const capture = new OpenResultCapture(answering(502, OPEN_ANSWER).fetch);
        const response = await capture.fetch(URL, OPEN_REQUEST);
        assert.equal(response.status, 502);
        assert.notEqual(capture.take(), null);
    });

    it("hands the SDK a body it could not read as the same failure", async () => {
        const failure = new Error("socket hang up");
        const capture = new OpenResultCapture(async () => ({ status: 200, text: () => Promise.reject(failure) }));
        const response = await capture.fetch(URL, OPEN_REQUEST);
        assert.equal(response.status, 200);
        await assert.rejects(response.text(), (error) => error === failure);
        assert.equal(capture.take(), null);
    });

    it("passes a request that fails as the same failure", async () => {
        const failure = new TypeError("fetch failed");
        const capture = new OpenResultCapture(() => Promise.reject(failure));
        await assert.rejects(capture.fetch(URL, OPEN_REQUEST), (error) => error === failure);
    });
});
