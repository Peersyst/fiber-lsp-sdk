import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { FetchInit, IFetchLike } from "@peersyst/fiber-lsp-sdk";
import { FacadeGate } from "../src/facade-gate";

const URL = "http://127.0.0.1:8227";

const REQUEST: FetchInit = {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: '{"jsonrpc":"2.0","id":1,"method":"list_channels","params":[{}]}',
};

const ANSWER = '{"jsonrpc":"2.0","id":1,"result":{"channels":[]}}';

type Held = { fetch: IFetchLike; sent: FetchInit[]; answer: () => void };

function held(): Held {
    const sent: FetchInit[] = [];
    let answer: () => void = () => undefined;
    const released = new Promise<void>((resolve) => (answer = resolve));
    const fetch: IFetchLike = async (_url, init) => {
        sent.push(init);
        await released;
        return { status: 200, text: async () => ANSWER };
    };
    return { fetch, sent, answer };
}

async function isSettled(promise: Promise<unknown>): Promise<boolean> {
    let settled = false;
    void promise.then(
        () => (settled = true),
        () => (settled = true),
    );
    await new Promise((resolve) => setImmediate(resolve));
    return settled;
}

describe("FacadeGate", () => {
    it("sends while open, handing back the status and the body it read", async () => {
        const sent: FetchInit[] = [];
        const gate = new FacadeGate(async (url, init) => {
            assert.equal(url, URL);
            sent.push(init);
            return { status: 200, text: async () => ANSWER };
        });
        const response = await gate.fetch(URL, REQUEST);
        assert.deepEqual(sent, [REQUEST]);
        assert.equal(response.status, 200);
        assert.equal(await response.text(), ANSWER);
    });

    it("refuses every request once closed, before it reaches the node", async () => {
        const inner = held();
        const gate = new FacadeGate(inner.fetch);
        gate.close();
        await assert.rejects(gate.fetch(URL, REQUEST), { message: "the facade was replaced: its requests no longer reach the node" });
        assert.deepEqual(inner.sent, []);
    });

    it("drains only once the request in flight was answered, its body read", async () => {
        let readBody: () => void = () => undefined;
        const bodyRead = new Promise<void>((resolve) => (readBody = resolve));
        const inner = held();
        const gate = new FacadeGate(async (url, init) => {
            const response = await inner.fetch(url, init);
            return {
                status: response.status,
                text: async () => {
                    await bodyRead;
                    return response.text();
                },
            };
        });
        const request = gate.fetch(URL, REQUEST);
        gate.close();
        const drained = gate.drained();
        assert.equal(await isSettled(drained), false);
        inner.answer();
        assert.equal(await isSettled(drained), false);
        readBody();
        await drained;
        assert.equal(await (await request).text(), ANSWER);
    });

    it("drains one macrotask after the answer, once what follows it in microtasks ran", async () => {
        const inner = held();
        const gate = new FacadeGate(inner.fetch);
        let followed = false;
        const request = gate.fetch(URL, REQUEST).then(async (response) => {
            await response.text();
            for (let step = 0; step < 100; step++) await Promise.resolve();
            followed = true;
        });
        const drained = gate.drained().then(() => followed);
        inner.answer();
        assert.equal(await drained, true);
        await request;
    });

    it("drains a gate with nothing in flight", async () => {
        await new FacadeGate(held().fetch).drained();
    });

    it("hands back a body it could not read as the same failure, the request no longer in flight", async () => {
        const failure = new Error("socket hang up");
        const gate = new FacadeGate(async () => ({ status: 200, text: () => Promise.reject(failure) }));
        const response = await gate.fetch(URL, REQUEST);
        await assert.rejects(response.text(), (error) => error === failure);
        await gate.drained();
    });

    it("passes a request that fails as the same failure, the request no longer in flight", async () => {
        const failure = new TypeError("fetch failed");
        const gate = new FacadeGate(() => Promise.reject(failure));
        await assert.rejects(gate.fetch(URL, REQUEST), (error) => error === failure);
        await gate.drained();
    });
});
