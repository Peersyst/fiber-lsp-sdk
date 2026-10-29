import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import type { IncomingHttpHeaders } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import type { TestContext } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { FiberLspSdk } from "@peersyst/fiber-lsp-sdk";
import { Agent } from "../src/agent";
import { AgentRequestError } from "../src/agent.error";
import { MAX_CONTROL_BODY_BYTES, startControlServer } from "../src/control-server";
import type { ControlHandlers } from "../src/control-server";
import { DEVICE_SEED_HEX, DEVICE_TENANT_ID, FakeNode } from "./utils/fake-node";

type ControlResponse = { status: number; headers: IncomingHttpHeaders; body: string };

type Recorded = { opened: unknown[]; authorized: unknown[]; shutdowns: number[]; logged: Record<string, unknown>[] };

function send(base: string, method: string, path: string, body?: string | Buffer): Promise<ControlResponse> {
    return new Promise((resolve, reject) => {
        const request = httpRequest(`${base}${path}`, { method, agent: false }, (response) => {
            const chunks: Buffer[] = [];
            response.on("data", (chunk: Buffer) => chunks.push(chunk));
            response.on("end", () =>
                resolve({ status: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(chunks).toString("utf8") }),
            );
            response.on("error", reject);
        });
        request.on("error", reject);
        request.end(body);
    });
}

function assertResponse(response: ControlResponse, status: number, body: string): void {
    assert.equal(response.status, status);
    assert.equal(response.headers["content-type"], "application/json");
    assert.equal(response.headers.connection, "close");
    assert.equal(response.headers["content-length"], String(Buffer.byteLength(body)));
    assert.equal(response.body, body);
}

function failuresLogged(logged: Record<string, unknown>[]): Record<string, unknown>[] {
    return logged.filter((entry) => entry.kind === "control_request_failed");
}

async function listening(
    t: TestContext,
    statusFile: string,
    handlers: ControlHandlers,
    logged: Record<string, unknown>[],
): Promise<string> {
    const server = await startControlServer({ host: "127.0.0.1", port: 0 }, statusFile, handlers, (kind, fields) =>
        logged.push({ kind, ...fields }),
    );
    t.after(() => new Promise((resolve) => server.close(resolve)));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

async function overStubs(
    t: TestContext,
    answer: (body: unknown) => Promise<unknown>,
): Promise<{ base: string; statusFile: string } & Recorded> {
    const recorded: Recorded = { opened: [], authorized: [], shutdowns: [], logged: [] };
    const statusFile = join(mkdtempSync(join(tmpdir(), "control-")), "status.json");
    const handlers: ControlHandlers = {
        openChannel: (body) => {
            recorded.opened.push(body);
            return answer(body);
        },
        authorize: (body) => {
            recorded.authorized.push(body);
            return answer(body);
        },
        shutdown: () => recorded.shutdowns.push(Date.now()),
    };
    return { base: await listening(t, statusFile, handlers, recorded.logged), statusFile, ...recorded };
}

describe("startControlServer", () => {
    describe("GET /status", () => {
        it("answers 503 while the status file cannot be read, then its exact bytes", async (t) => {
            const server = await overStubs(t, async () => null);
            assert.deepEqual(server.logged, [
                { kind: "control_server_listening", host: "127.0.0.1", port: Number(new URL(server.base).port) },
            ]);
            const missing = await send(server.base, "GET", "/status");
            assert.equal(missing.status, 503);
            assert.deepEqual(JSON.parse(missing.body), {
                error: `status unavailable: ENOENT: no such file or directory, open '${server.statusFile}'`,
            });
            writeFileSync(server.statusFile, '{\n  "tenant_id": "aa"\n}');
            assertResponse(await send(server.base, "GET", "/status"), 200, '{\n  "tenant_id": "aa"\n}');
        });
    });

    for (const [path, handler] of [
        ["/open-channel", "opened"],
        ["/authorize", "authorized"],
    ] as const) {
        describe(`POST ${path}`, () => {
            it("hands the agent the parsed body and answers 200 with its result", async (t) => {
                const server = await overStubs(t, async () => ({ authorized: true }));
                assertResponse(
                    await send(server.base, "POST", path, '{"type":"Invoice","n":[1,2]}'),
                    200,
                    '{"result":{"authorized":true}}',
                );
                assert.deepEqual(server[handler], [{ type: "Invoice", n: [1, 2] }]);
            });

            it("answers a thrown value that is not an Error as 400 with its text, and logs it", async (t) => {
                const server = await overStubs(t, () => Promise.reject("the disk is full"));
                assertResponse(await send(server.base, "POST", path, "{}"), 400, '{"error":"the disk is full"}');
                assert.equal(failuresLogged(server.logged).length, 1);
            });

            it("answers the agent's refusal as 400 with its message", async (t) => {
                const server = await overStubs(t, async () => {
                    throw new AgentRequestError("unknown channel 0x22");
                });
                assertResponse(await send(server.base, "POST", path, "{}"), 400, '{"error":"unknown channel 0x22"}');
                assert.deepEqual(failuresLogged(server.logged), []);
            });

            it("answers any other failure as 400 with its message, as fiber's agent, and logs it", async (t) => {
                const server = await overStubs(t, async () => {
                    throw new Error("the disk is full");
                });
                assertResponse(await send(server.base, "POST", path, "{}"), 400, '{"error":"the disk is full"}');
                const [failure, ...others] = failuresLogged(server.logged);
                assert.deepEqual(others, []);
                assert.equal(failure?.route, `POST ${path}`);
                assert.equal((failure?.error as { message?: unknown } | undefined)?.message, "the disk is full");
            });

            it("answers a body that is not JSON as 400, before the agent", async (t) => {
                const server = await overStubs(t, async () => null);
                const response = await send(server.base, "POST", path, "{");
                assert.equal(response.status, 400);
                assert.match((JSON.parse(response.body) as { error: string }).error, /^malformed JSON: /);
                assert.deepEqual(server[handler], []);
            });

            it("answers an empty body as malformed JSON", async (t) => {
                const server = await overStubs(t, async () => null);
                const response = await send(server.base, "POST", path);
                assert.equal(response.status, 400);
                assert.match((JSON.parse(response.body) as { error: string }).error, /^malformed JSON: /);
            });

            it("reads a body of exactly 1 MiB", async (t) => {
                const server = await overStubs(t, async () => "read");
                const body = `{"pad":"${"a".repeat(MAX_CONTROL_BODY_BYTES - 10)}"}`;
                assert.equal(Buffer.byteLength(body), 1024 * 1024);
                assertResponse(await send(server.base, "POST", path, body), 200, '{"result":"read"}');
                assert.equal(server[handler].length, 1);
            });

            it("refuses a body past 1 MiB as 400, before the agent", async (t) => {
                const server = await overStubs(t, async () => "read");
                const body = `{"pad":"${"a".repeat(MAX_CONTROL_BODY_BYTES - 9)}"}`;
                assertResponse(await send(server.base, "POST", path, body), 400, '{"error":"control request too large"}');
                assert.deepEqual(server[handler], []);
            });
        });
    }

    describe("POST /shutdown", () => {
        it("answers 200 restarting, then shuts the agent down", async (t) => {
            const server = await overStubs(t, async () => null);
            assertResponse(await send(server.base, "POST", "/shutdown"), 200, '{"status":"restarting"}');
            for (let attempt = 0; attempt < 100 && server.shutdowns.length === 0; attempt++) await delay(5);
            assert.equal(server.shutdowns.length, 1);
        });
    });

    describe("anything else", () => {
        for (const [method, path] of [
            ["GET", "/"],
            ["GET", "/open-channel"],
            ["GET", "/authorize"],
            ["GET", "/shutdown"],
            ["POST", "/status"],
            ["GET", "/status/"],
            ["GET", "/status?x=1"],
            ["PUT", "/authorize"],
        ] as const) {
            it(`answers ${method} ${path} as 404`, async (t) => {
                const server = await overStubs(t, async () => null);
                assertResponse(await send(server.base, method, path, method === "GET" ? undefined : "{}"), 404, '{"error":"not found"}');
                assert.deepEqual([server.opened, server.authorized, server.shutdowns], [[], [], []]);
            });
        }
    });

    describe("over the agent", () => {
        it("serves 503 while the agent initializes, holds its requests until it is ready, then serves the status", async (t) => {
            const root = mkdtempSync(join(tmpdir(), "control-agent-"));
            const storeDir = join(root, "store");
            const contractsDir = join(root, "contracts");
            mkdirSync(storeDir);
            mkdirSync(contractsDir);
            writeFileSync(join(storeDir, "master-seed"), Buffer.from(DEVICE_SEED_HEX, "hex"));
            writeFileSync(join(contractsDir, "funding-lock"), "funding-lock");
            writeFileSync(join(contractsDir, "commitment-lock"), "commitment-lock");
            const statusFile = join(root, "status.json");
            const node = new FakeNode();
            let release: () => void = () => undefined;
            const held = new Promise<void>((resolve) => (release = resolve));
            node.beforeAnswer = (method) => (method === "node_info" ? held : Promise.resolve());
            const exits: number[] = [];
            const agent = new Agent(
                {
                    rpcUrl: "http://127.0.0.1:8227",
                    storeDir,
                    statusFile,
                    controlAddr: { host: "127.0.0.1", port: 0 },
                    operatorToken: "operator-token",
                    intervalMs: 60_000,
                    contractsDir,
                },
                {
                    fetch: node.fetch,
                    now: () => 1_800_000_000_000,
                    sleep: (ms) => delay(ms),
                    exit: (code) => exits.push(code),
                    log: () => undefined,
                    createSdk: (masterSeed, options) => new FiberLspSdk(masterSeed, options),
                },
            );
            t.after(() => agent.shutdown());
            const base = await listening(t, statusFile, agent, []);
            const starting = agent.start();
            assert.equal((await send(base, "GET", "/status")).status, 503);
            let answered = false;
            const authorizing = send(
                base,
                "POST",
                "/authorize",
                '{"type":"Watchtower","channel_id":"0x2222222222222222222222222222222222222222222222222222222222222222","destination":{"code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type","args":"0x"},"max_fee":1}',
            ).finally(() => (answered = true));
            await delay(20);
            assert.equal(answered, false);
            release();
            await starting;
            assertResponse(
                await authorizing,
                400,
                '{"error":"unknown channel 0x2222222222222222222222222222222222222222222222222222222222222222"}',
            );
            const status = await send(base, "GET", "/status");
            assert.equal(status.status, 200);
            assert.equal((JSON.parse(status.body) as { tenant_id: unknown }).tenant_id, DEVICE_TENANT_ID);
            assertResponse(await send(base, "POST", "/shutdown"), 200, '{"status":"restarting"}');
            for (let attempt = 0; attempt < 100 && exits.length === 0; attempt++) await delay(5);
            assert.deepEqual(exits, [0]);
        });
    });
});
