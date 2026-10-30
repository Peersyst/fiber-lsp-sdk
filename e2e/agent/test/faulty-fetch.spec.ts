import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { AgentNodeFetch } from "../src/agent.types";
import { FaultyFetch } from "../scenarios/utils/faulty-fetch";

const URL = "http://127.0.0.1:8227";

type Sent = { url: string; body: string };

function init(body: string): Parameters<AgentNodeFetch>[1] {
    return { method: "POST", headers: { "Content-Type": "application/json" }, body };
}

function nodeAnswering(...bodies: string[]): { fetch: AgentNodeFetch; sent: Sent[] } {
    const sent: Sent[] = [];
    const fetch: AgentNodeFetch = async (url, request) => {
        sent.push({ url, body: request.body });
        const body = bodies.shift();
        if (body === undefined) throw new Error("the node has no answer left");
        return { status: 200, text: async () => body };
    };
    return { fetch, sent };
}

async function answerOf(faults: FaultyFetch, body: string): Promise<string> {
    return (await faults.fetch(URL, init(body))).text();
}

const OPEN = '{"jsonrpc":"2.0","method":"open_tenant_channel","params":[{"funding_amount":"0x1"}],"id":1}';

const SUBMIT_A = '{"jsonrpc":"2.0","method":"submit_channel_signature","params":[{"channel_id":"0xaa"}],"id":1}';

const SUBMIT_B = '{"jsonrpc":"2.0","method":"submit_channel_signature","params":[{"channel_id":"0xbb"}],"id":1}';

const RESULT_ONE = '{"jsonrpc":"2.0","result":{"value":1},"id":1}';

const RESULT_TWO = '{"jsonrpc":"2.0","result":{"value":2},"id":1}';

const RESULT_THREE = '{"jsonrpc":"2.0","result":{"value":3},"id":1}';

const ERROR_ANSWER = '{"jsonrpc":"2.0","error":{"code":-1,"message":"busy"},"id":1}';

const REWRITTEN = { value: "rewritten" };

describe("FaultyFetch", () => {
    it("sends a request no fault matches as it is, and records it", async () => {
        const { fetch, sent } = nodeAnswering(RESULT_ONE);
        const faults = new FaultyFetch(fetch);
        assert.equal(await answerOf(faults, OPEN), RESULT_ONE);
        assert.deepEqual(sent, [{ url: URL, body: OPEN }]);
        assert.deepEqual(
            faults.requests.map(({ url, method, params, fault }) => ({ url, method, params, fault })),
            [{ url: URL, method: "open_tenant_channel", params: [{ funding_amount: "0x1" }], fault: null }],
        );
    });

    it("rewrites the result of the first matching answer alone, handing the rewrite the result and the params", async () => {
        const { fetch } = nodeAnswering(RESULT_ONE, RESULT_TWO);
        const faults = new FaultyFetch(fetch);
        const seen: unknown[] = [];
        faults.rewriteResult("open_tenant_channel", (result, params) => {
            seen.push({ result, params });
            return REWRITTEN;
        });
        assert.deepEqual(JSON.parse(await answerOf(faults, OPEN)), { jsonrpc: "2.0", result: REWRITTEN, id: 1 });
        assert.equal(await answerOf(faults, OPEN), RESULT_TWO);
        assert.deepEqual(seen, [{ result: { value: 1 }, params: [{ funding_amount: "0x1" }] }]);
        assert.deepEqual(
            faults.requests.map(({ fault }) => fault),
            ["rewritten", null],
        );
    });

    it("rewrites as many matching answers as its times", async () => {
        const { fetch } = nodeAnswering(RESULT_ONE, RESULT_TWO, RESULT_THREE);
        const faults = new FaultyFetch(fetch);
        faults.rewriteResult("open_tenant_channel", () => REWRITTEN, { times: 2 });
        for (let index = 0; index < 3; index += 1) await answerOf(faults, OPEN);
        assert.deepEqual(
            faults.requests.map(({ fault }) => fault),
            ["rewritten", "rewritten", null],
        );
    });

    it("hits only the requests its when matches", async () => {
        const { fetch } = nodeAnswering(RESULT_ONE, RESULT_TWO);
        const faults = new FaultyFetch(fetch);
        faults.rewriteResult("submit_channel_signature", () => REWRITTEN, {
            when: (params) => JSON.stringify(params) === '[{"channel_id":"0xbb"}]',
        });
        assert.equal(await answerOf(faults, SUBMIT_A), RESULT_ONE);
        assert.deepEqual(JSON.parse(await answerOf(faults, SUBMIT_B)).result, REWRITTEN);
    });

    it("hands an error answer over as it is, the rewrite left armed for the next answer", async () => {
        const { fetch } = nodeAnswering(ERROR_ANSWER, RESULT_TWO);
        const faults = new FaultyFetch(fetch);
        faults.rewriteResult("open_tenant_channel", () => REWRITTEN);
        assert.equal(await answerOf(faults, OPEN), ERROR_ANSWER);
        assert.deepEqual(JSON.parse(await answerOf(faults, OPEN)).result, REWRITTEN);
        assert.deepEqual(
            faults.requests.map(({ fault }) => fault),
            [null, "rewritten"],
        );
    });

    it("refuses a matching request without sending it, once", async () => {
        const { fetch, sent } = nodeAnswering(RESULT_TWO);
        const faults = new FaultyFetch(fetch);
        faults.refuse("submit_channel_signature");
        await assert.rejects(faults.fetch(URL, init(SUBMIT_A)), {
            message: "faulty fetch: submit_channel_signature refused before it was sent",
        });
        assert.deepEqual(sent, []);
        assert.equal(await answerOf(faults, SUBMIT_B), RESULT_TWO);
        assert.deepEqual(sent, [{ url: URL, body: SUBMIT_B }]);
    });

    it("lists as sent the requests of a method that reached the node, never a refused one", async () => {
        const { fetch } = nodeAnswering(RESULT_ONE, RESULT_TWO);
        const faults = new FaultyFetch(fetch);
        faults.refuse("submit_channel_signature");
        await assert.rejects(faults.fetch(URL, init(SUBMIT_A)));
        await answerOf(faults, SUBMIT_B);
        await answerOf(faults, OPEN);
        assert.deepEqual(
            faults.sent("submit_channel_signature").map(({ params, fault }) => ({ params, fault })),
            [{ params: [{ channel_id: "0xbb" }], fault: null }],
        );
    });

    it("counts a request in flight until its answer is whole", async () => {
        let answer: (body: string) => void = () => undefined;
        const body = new Promise<string>((resolve) => {
            answer = resolve;
        });
        const faults = new FaultyFetch(async () => ({ status: 200, text: () => body }));
        assert.equal(faults.inFlight, 0);
        const pending = faults.fetch(URL, init(OPEN));
        assert.equal(faults.inFlight, 1);
        answer(RESULT_ONE);
        assert.equal(await (await pending).text(), RESULT_ONE);
        assert.equal(faults.inFlight, 0);
    });

    it("stops counting a request whose send throws", async () => {
        const faults = new FaultyFetch(async () => {
            throw new TypeError("fetch failed");
        });
        const pending = faults.fetch(URL, init(OPEN));
        assert.equal(faults.inFlight, 1);
        await assert.rejects(pending, { message: "fetch failed" });
        assert.equal(faults.inFlight, 0);
    });

    it("stops counting a request it refuses", async () => {
        const faults = new FaultyFetch(nodeAnswering().fetch);
        faults.refuse("open_tenant_channel");
        const pending = faults.fetch(URL, init(OPEN));
        await assert.rejects(pending);
        assert.equal(faults.inFlight, 0);
    });

    it("sends every request as it is once cleared", async () => {
        const { fetch, sent } = nodeAnswering(RESULT_ONE, RESULT_TWO);
        const faults = new FaultyFetch(fetch);
        faults.refuse("submit_channel_signature");
        faults.rewriteResult("open_tenant_channel", () => REWRITTEN);
        faults.clear();
        assert.equal(await answerOf(faults, SUBMIT_A), RESULT_ONE);
        assert.equal(await answerOf(faults, OPEN), RESULT_TWO);
        assert.equal(sent.length, 2);
        assert.deepEqual(
            faults.requests.map(({ fault }) => fault),
            [null, null],
        );
    });
});
