import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import type { TestContext } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { FiberLspSdk } from "@peersyst/fiber-lsp-sdk";
import type { FiberLspSdkOptions } from "@peersyst/fiber-lsp-sdk";
import { Agent, INITIALIZE_RETRY_MS, registerAgentTenant } from "../src/agent";
import { AgentRequestError } from "../src/agent.error";
import { messageOf } from "../src/agent.utils";
import type { AgentConfig, AgentState } from "../src/agent.types";
import { readAgentState, writeAgentState } from "../src/agent-store";
import { startControlServer } from "../src/control-server";
import { FileSignerStorage } from "../src/file-storage";
import { agentOperatorClient } from "../src/json-rpc";
import { NonceCapBypassStorage } from "../src/nonce-cap-bypass";
import {
    DEVICE_ROOT_SIGNER,
    DEVICE_SEED_HEX,
    DEVICE_TENANT_ID,
    FakeNode,
    LSP_PUBKEY,
    REGISTRATION_REQUEST_CONSUMED,
    REGISTRATION_SIGNATURE,
    REGISTRATION_SIGNED_AT,
    RETRY_SIGNATURE,
} from "./utils/fake-node";

// 2027-01-15T08:00:00Z: the SDK allocates channel index 1_800_000_000 at this clock.
const NOW_MS = 1_800_000_000_000;

const RPC_URL = "http://127.0.0.1:8227";

const OPERATOR_TOKEN = "operator-token";

// Long enough that only `connect()`'s first tick polls during a test.
const IDLE_INTERVAL_MS = 60_000;

const CHANNEL_ID = "0x4056792f61337675c153ab8f10c442fa68a913a18ce6f8beec37a19c23d5aa4d";

const OTHER_CHANNEL_ID = "0x2222222222222222222222222222222222222222222222222222222222222222";

const PREIMAGE = "0x2222222222222222222222222222222222222222222222222222222222222222";
const CKB_HASH = "0x09dfb3a3fa5af1b3359b6256945af43e31be9f86f3d1b45779cebc09dc609138";
const SHA256_HASH = "0x9f72ea0cf49536e3c66c787f705186df9a4378083753ae9536d65b3ad7fcddc4";

// The contracts folder's two binaries, and the code hashes the SDK's network takes from them.
const FUNDING_LOCK_BINARY = "funding-lock";
const COMMITMENT_LOCK_BINARY = "commitment-lock";
const FUNDING_LOCK_CODE_HASH = "2d7d47f1e1ad9be2160d0ebdc28d6da23bfc2730f9b9c91e61bbb443b4293d38";
const COMMITMENT_LOCK_CODE_HASH = "af7bb4d305dc75bea3327c78eddb742cd646d97e9a7a0ff2e2005a9b178218cc";

const USER_LOCK = {
    code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
    hash_type: "type",
    args: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
};

const LSP_SHUTDOWN_SCRIPT = {
    code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
    hash_type: "type",
    args: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
};

const OPEN_BODY = {
    params: {
        pubkey: LSP_PUBKEY,
        funding_amount: "0x174876e800",
        public: false,
        shutdown_script: USER_LOCK,
        funding_lock_script: USER_LOCK,
    },
};

// The node's answer the SDK accepts for the fake's device at NOW_MS: the LSP's funding and TLC base keys are the curve's 2G and
// 3G, the channel id fiber's of the two TLC base keys, output 0 the funding lock over the musig2 aggregate of the two funding
// keys and capacity the two amounts, each side's reserve 99 CKB over a 20-byte lock.
const OPEN_RESULT = {
    channel_id: CHANNEL_ID,
    unsigned_funding_tx: {
        version: "0x0",
        cell_deps: [
            {
                out_point: { tx_hash: "0xd8ef9125d4bc98b9c3716fcf61110e302098a55222a2e79344a8264352fe7b9d", index: "0x0" },
                dep_type: "dep_group",
            },
        ],
        header_deps: [],
        inputs: [
            {
                since: "0x0",
                previous_output: { tx_hash: "0x89dc569f9eec0e82ca13a353be098d150e9164d79f9c5201079e422a283c8ee4", index: "0x1" },
            },
        ],
        outputs: [
            {
                capacity: "0x19968ceb00",
                lock: { code_hash: `0x${FUNDING_LOCK_CODE_HASH}`, hash_type: "data2", args: "0xc5e37d8dca98263448c6fd4f35b33fb592e320e7" },
                type: null,
            },
        ],
        outputs_data: ["0x"],
        witnesses: ["0x"],
    },
    opening_context: {
        remote_funding_key: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
        remote_settlement_key: "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
        remote_shutdown_script: LSP_SHUTDOWN_SCRIPT,
        commitment_delay_epoch: "0x10000000001",
        commitment_fee_rate: "0x3e8",
        local_amount: "0x174876e800",
        remote_amount: "0x24e160300",
        local_reserved_ckb_amount: "0x24e160300",
        remote_reserved_ckb_amount: "0x24e160300",
    },
};

const INVOICE_BODY = {
    type: "Invoice",
    channel_id: CHANNEL_ID,
    preimage: PREIMAGE,
    terms: {
        payment_hash: CKB_HASH,
        hash_algorithm: "ckb_hash",
        inbound: true,
        amount: 1000000,
        expires_at_ms: 1800003600000,
        min_tlc_expiry_delta_ms: 86400000,
        max_tlc_expiry_ms: 1800604800000,
    },
};

const RELEASE_BODY = { type: "ReleasePreimage", channel_id: CHANNEL_ID, payment_hash: CKB_HASH, preimage: PREIMAGE, target: "Invoice" };

const CLOSE_BODY = {
    type: "Close",
    channel_id: CHANNEL_ID,
    local_script: USER_LOCK,
    remote_script: LSP_SHUTDOWN_SCRIPT,
    local_fee_rate: 1000,
    remote_fee_rate: 0,
};

const WATCHTOWER_BODY = { type: "Watchtower", channel_id: CHANNEL_ID, destination: LSP_SHUTDOWN_SCRIPT, max_fee: 10000 };

// `e2e/lsp` step 27b: node 1's invoice under preimage 0x33..33, 100000 plus a routing fee budget of 500.
const OUTGOING_PREIMAGE = "0x3333333333333333333333333333333333333333333333333333333333333333";
const OUTGOING_HASH = "0xdbddb41b1249f996f6ef6ef69499964db5b200dd8e82360b7de82448e36cc1e4";
const OUTGOING_SHA256_HASH = "0xdeb0e38ced1e41de6f92e70e80c418d2d356afaaa99e26f5939dbc7d3ef4772a";

const PAYMENT_BODY = {
    type: "Payment",
    channel_id: CHANNEL_ID,
    terms: {
        payment_hash: OUTGOING_HASH,
        hash_algorithm: "ckb_hash",
        inbound: false,
        amount: 100500,
        expires_at_ms: 1800003600000,
        min_tlc_expiry_delta_ms: 60000,
        max_tlc_expiry_ms: 1800608400000,
    },
};

const FULFILLMENT_BODY = { type: "Fulfillment", channel_id: CHANNEL_ID, payment_hash: OUTGOING_HASH, preimage: OUTGOING_PREIMAGE };

// The SDK's record keys of the outgoing hash, by its first 20 bytes.
const OUTGOING_INTENT_KEY = "fiber-lsp-sdk:intent:dbddb41b1249f996f6ef6ef69499964db5b200dd";
const OUTGOING_HOLD_INVOICE_KEY = "fiber-lsp-sdk:invoice:dbddb41b1249f996f6ef6ef69499964db5b200dd";

const OUTGOING_INTENT = {
    version: 1,
    paymentHash: "dbddb41b1249f996f6ef6ef69499964db5b200dd8e82360b7de82448e36cc1e4",
    maxShannons: "100500",
    open: true,
    channelIndexes: [],
};

type AgentDirs = { storeDir: string; statusFile: string; contractsDir: string };

type AgentRun = {
    agent: Agent;
    lines: string[];
    sleeps: number[];
    exits: number[];
    built: FiberLspSdkOptions[];
    // Indexes in `built` of the facades disconnected.
    disconnected: number[];
    facades: FiberLspSdk[];
};

type LogEntry = Record<string, unknown>;

function freshDirs(): AgentDirs {
    const root = mkdtempSync(join(tmpdir(), "agent-"));
    const storeDir = join(root, "store");
    const contractsDir = join(root, "contracts");
    mkdirSync(storeDir);
    mkdirSync(contractsDir);
    writeFileSync(join(storeDir, "master-seed"), Buffer.from(DEVICE_SEED_HEX, "hex"));
    writeFileSync(join(contractsDir, "funding-lock"), FUNDING_LOCK_BINARY);
    writeFileSync(join(contractsDir, "commitment-lock"), COMMITMENT_LOCK_BINARY);
    return { storeDir, statusFile: join(root, "status.json"), contractsDir };
}

function configOf(dirs: AgentDirs, intervalMs: number): AgentConfig {
    return {
        rpcUrl: RPC_URL,
        storeDir: dirs.storeDir,
        statusFile: dirs.statusFile,
        controlAddr: null,
        operatorToken: OPERATOR_TOKEN,
        lspNodeId: LSP_PUBKEY,
        intervalMs,
        network: { name: "devnet", contractsDir: dirs.contractsDir },
        nonceCapBypass: false,
    };
}

// Request ids 0x5a.., then 0x5b.., one byte value up per draw: the ones the fake node holds signatures of first.
function requestIds(drawn: number[] = []): (length: number) => Uint8Array {
    let next = 0x5a;
    return (length) => {
        drawn.push(length);
        return new Uint8Array(length).fill(next++);
    };
}

function sdkStore(dirs: AgentDirs): Record<string, string> {
    const path = join(dirs.storeDir, "sdk-store.json");
    return existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as Record<string, string>) : {};
}

function writeSdkEntry(dirs: AgentDirs, key: string, value: unknown): void {
    writeRawSdkEntry(dirs, key, JSON.stringify(value));
}

function writeRawSdkEntry(dirs: AgentDirs, key: string, raw: string): void {
    writeFileSync(join(dirs.storeDir, "sdk-store.json"), JSON.stringify({ ...sdkStore(dirs), [key]: raw }));
}

function runAgent(t: TestContext, config: AgentConfig, node: FakeNode, randomBytes = requestIds()): AgentRun {
    const lines: string[] = [];
    const sleeps: number[] = [];
    const exits: number[] = [];
    const built: FiberLspSdkOptions[] = [];
    const disconnected: number[] = [];
    const facades: FiberLspSdk[] = [];
    const agent = new Agent(config, {
        fetch: node.fetch,
        now: () => NOW_MS,
        randomBytes,
        sleep: async (ms) => {
            sleeps.push(ms);
        },
        exit: (code) => exits.push(code),
        log: (line) => lines.push(line),
        createSdk: (masterSeed, options) => {
            const sdk = new FiberLspSdk(masterSeed, options);
            const position = built.length;
            built.push(options);
            facades.push(sdk);
            const disconnect = sdk.disconnect.bind(sdk);
            sdk.disconnect = () => {
                disconnected.push(position);
                disconnect();
            };
            return sdk;
        },
    });
    t.after(() => agent.shutdown());
    return { agent, lines, sleeps, exits, built, disconnected, facades };
}

async function openedAgent(t: TestContext, dirs: AgentDirs): Promise<AgentRun> {
    const node = new FakeNode();
    node.openAnswer = { result: OPEN_RESULT };
    const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), node);
    await run.agent.start();
    await run.agent.openChannel(OPEN_BODY);
    return run;
}

function entries(run: AgentRun): LogEntry[] {
    return run.lines.map((line) => JSON.parse(line) as LogEntry);
}

function readStatus(dirs: AgentDirs): unknown {
    return JSON.parse(readFileSync(dirs.statusFile, "utf8"));
}

function bytes(hex: string): Uint8Array {
    return Uint8Array.from(Buffer.from(hex.replace(/^0x/, ""), "hex"));
}

async function eventually(what: string, check: () => boolean): Promise<void> {
    for (let attempt = 0; attempt < 400; attempt++) {
        if (check()) return;
        await delay(5);
    }
    assert.fail(`timed out waiting for ${what}`);
}

async function flush(): Promise<void> {
    await new Promise((resolve) => setImmediate(resolve));
}

function bindOtherChannel(dirs: AgentDirs, watchtowerDestination: typeof USER_LOCK | null): void {
    const state = readAgentState(dirs.storeDir);
    writeAgentState(dirs.storeDir, {
        ...state,
        channels: { ...state.channels, [OTHER_CHANNEL_ID]: { localScript: USER_LOCK, remoteScript: LSP_SHUTDOWN_SCRIPT } },
        watchtower:
            watchtowerDestination === null
                ? state.watchtower
                : { type: "Watchtower", channelId: OTHER_CHANNEL_ID, destination: watchtowerDestination, maxFeeShannons: "10000" },
    });
}

async function assertRefused(request: Promise<unknown>, message: string): Promise<void> {
    await assert.rejects(request, (error) => {
        assert.ok(error instanceof AgentRequestError);
        assert.equal(error.message, message);
        return true;
    });
}

describe("Agent", () => {
    describe("start", () => {
        it("registers a cold store once under the operator's token, then calls the node for nothing while idle", async (t) => {
            const dirs = freshDirs();
            const node = new FakeNode();
            const run = runAgent(t, configOf(dirs, 20), node);
            await run.agent.start();
            assert.deepEqual(node.calls.slice(0, 1), [
                {
                    method: "lsp_register_tenant",
                    params: [
                        {
                            root_signer_pubkey: DEVICE_ROOT_SIGNER,
                            request_id: `0x${"5a".repeat(32)}`,
                            signed_at: REGISTRATION_SIGNED_AT,
                            signature: REGISTRATION_SIGNATURE,
                        },
                    ],
                    authorization: `Bearer ${OPERATOR_TOKEN}`,
                },
            ]);
            assert.deepEqual(readAgentState(dirs.storeDir), {
                tenantToken: "tenant-token-1",
                channels: {},
                invoices: {},
                payments: {},
                closes: {},
                watchtower: null,
            });
            assert.deepEqual(readStatus(dirs), {
                tenant_id: DEVICE_TENANT_ID,
                root_signer_pubkey: DEVICE_ROOT_SIGNER,
                tenant_token: "tenant-token-1",
                channel_open_signer_material: { allocated_at_open: true },
                bound_channel_ids: [],
                watchtower_submissions: {},
                revoked_commitments: {},
            });
            // Several ticks of an idle device: the SDK asks nothing that would wake an evicted tenant.
            await delay(100);
            assert.equal(node.calls.length, 1);
        });

        it("builds the facade over the devnet's contracts, the polled interval, nonce reuse allowed and no watchtower", async (t) => {
            const dirs = freshDirs();
            const run = runAgent(t, configOf(dirs, 250), new FakeNode());
            await run.agent.start();
            assert.equal(run.built.length, 1);
            const [options] = run.built;
            assert.ok(options !== undefined);
            assert.deepEqual(options.network, {
                commitmentLock: { codeHash: bytes(COMMITMENT_LOCK_CODE_HASH), hashType: "data2" },
                fundingLock: { codeHash: bytes(FUNDING_LOCK_CODE_HASH), hashType: "data2" },
                invoiceCurrency: "Fibd",
                fundingLockCellDepsCount: 2,
                millisecondsPerEpoch: 2000,
            });
            assert.equal(options.rpcUrl, RPC_URL);
            assert.equal(options.biscuitToken, undefined);
            assert.equal(options.pollIntervalMs, 250);
            assert.equal(options.nonceReuse, "allow");
            assert.equal(options.watchtower, undefined);
            assert.equal(options.now?.(), NOW_MS);
        });

        it("builds the facade over the SDK's testnet preset on testnet, reading no contracts", async (t) => {
            const dirs = freshDirs();
            rmSync(dirs.contractsDir, { recursive: true });
            const run = runAgent(t, { ...configOf(dirs, 250), network: { name: "testnet" } }, new FakeNode());
            await run.agent.start();
            assert.deepEqual(
                run.built.map((options) => options.network),
                ["testnet"],
            );
        });

        it("pins the LSP's key from --lsp-node-id, asking the node for none", async () => {
            const node = new FakeNode();
            const lspNodeId = "02bcbd0e0d811d13363af1e5998f56e74e6aab8a7aa44005e1ce7d696a4d3f10f6";
            const built: FiberLspSdkOptions[] = [];
            // The fake's signatures are to LSP_PUBKEY, so it refuses this registration and the first retry ends the run.
            const agent: Agent = new Agent(
                { ...configOf(freshDirs(), IDLE_INTERVAL_MS), lspNodeId },
                {
                    fetch: node.fetch,
                    now: () => NOW_MS,
                    randomBytes: requestIds(),
                    sleep: async () => agent.shutdown(),
                    exit: () => undefined,
                    log: () => undefined,
                    createSdk: (masterSeed, options) => {
                        built.push(options);
                        return new FiberLspSdk(masterSeed, options);
                    },
                },
            );
            await agent.start();
            assert.deepEqual(built[0]?.lspPubkey, bytes(lspNodeId));
            assert.deepEqual(
                node.calls.map((call) => call.method),
                ["lsp_register_tenant"],
            );
        });

        it("restarts from its store with no operator call, under the same token", async (t) => {
            const dirs = freshDirs();
            const first = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), new FakeNode());
            await first.agent.start();
            first.agent.shutdown();
            const node = new FakeNode();
            const second = runAgent(t, configOf(dirs, 20), node);
            await second.agent.start();
            await delay(100);
            assert.deepEqual(node.calls, []);
            assert.equal(second.built[0]?.biscuitToken, "tenant-token-1");
            assert.equal(readAgentState(dirs.storeDir).tenantToken, "tenant-token-1");
            assert.equal((readStatus(dirs) as { tenant_token: unknown }).tenant_token, "tenant-token-1");
        });

        it("retries the registration every second until it answers, under a fresh request id each time, logging each failure", async (t) => {
            const node = new FakeNode();
            node.registrationFailures = 1;
            const run = runAgent(t, configOf(freshDirs(), IDLE_INTERVAL_MS), node);
            await run.agent.start();
            assert.deepEqual(
                node.callsOf("lsp_register_tenant").map((call) => (call.params as [{ request_id: unknown; signature: unknown }])[0]),
                [
                    {
                        root_signer_pubkey: DEVICE_ROOT_SIGNER,
                        request_id: `0x${"5a".repeat(32)}`,
                        signed_at: REGISTRATION_SIGNED_AT,
                        signature: REGISTRATION_SIGNATURE,
                    },
                    {
                        root_signer_pubkey: DEVICE_ROOT_SIGNER,
                        request_id: `0x${"5b".repeat(32)}`,
                        signed_at: REGISTRATION_SIGNED_AT,
                        signature: RETRY_SIGNATURE,
                    },
                ],
            );
            assert.deepEqual(run.sleeps, [INITIALIZE_RETRY_MS]);
            assert.equal(INITIALIZE_RETRY_MS, 1000);
            const failures = entries(run).filter((entry) => entry.kind === "initialize_failed");
            assert.deepEqual(failures, [{ ts: "2027-01-15T08:00:00.000Z", kind: "initialize_failed", error: "node is starting" }]);
        });

        it("refuses a registration for another tenant, keeping no token, and registers again under a fresh request id", async (t) => {
            const dirs = freshDirs();
            const node = new FakeNode();
            node.foreignRegistrations = 1;
            const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), node);
            await run.agent.start();
            assert.deepEqual(
                node.callsOf("lsp_register_tenant").map((call) => (call.params as [{ request_id: unknown }])[0].request_id),
                [`0x${"5a".repeat(32)}`, `0x${"5b".repeat(32)}`],
            );
            assert.equal(readAgentState(dirs.storeDir).tenantToken, "tenant-token-2");
            assert.deepEqual(
                entries(run)
                    .filter((entry) => entry.kind === "initialize_failed")
                    .map((entry) => entry.error),
                ["lsp_register_tenant: response.result.tenant.tenant_id is not the tenant of the registered root signer"],
            );
        });

        it("logs fiber's refusal of a request id it already consumed and registers again under a fresh one", async (t) => {
            const dirs = freshDirs();
            const node = new FakeNode();
            node.foreignRegistrations = 1;
            const drawn = [0x5a, 0x5a, 0x5b];
            const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), node, (length) => new Uint8Array(length).fill(drawn.shift() ?? 0));
            await run.agent.start();
            assert.deepEqual(
                node.callsOf("lsp_register_tenant").map((call) => (call.params as [{ request_id: unknown }])[0].request_id),
                [`0x${"5a".repeat(32)}`, `0x${"5a".repeat(32)}`, `0x${"5b".repeat(32)}`],
            );
            assert.equal(readAgentState(dirs.storeDir).tenantToken, "tenant-token-2");
            assert.deepEqual(
                entries(run)
                    .filter((entry) => entry.kind === "initialize_failed")
                    .map((entry) => entry.error),
                [
                    "lsp_register_tenant: response.result.tenant.tenant_id is not the tenant of the registered root signer",
                    REGISTRATION_REQUEST_CONSUMED,
                ],
            );
        });

        it("keeps no token from a registration it refused", async () => {
            const dirs = freshDirs();
            const node = new FakeNode();
            node.foreignRegistrations = Number.POSITIVE_INFINITY;
            const stored: AgentState[] = [];
            const agent: Agent = new Agent(configOf(dirs, IDLE_INTERVAL_MS), {
                fetch: node.fetch,
                now: () => NOW_MS,
                randomBytes: requestIds(),
                sleep: async () => {
                    stored.push(readAgentState(dirs.storeDir));
                    agent.shutdown();
                },
                exit: () => undefined,
                log: () => undefined,
                createSdk: (masterSeed, options) => new FiberLspSdk(masterSeed, options),
            });
            await agent.start();
            assert.deepEqual(stored, [{ tenantToken: null, channels: {}, invoices: {}, payments: {}, closes: {}, watchtower: null }]);
        });

        it("hands the SDK its file storage as is while the nonce-cap bypass is off, as by default", async (t) => {
            const run = runAgent(t, configOf(freshDirs(), IDLE_INTERVAL_MS), new FakeNode());
            await run.agent.start();
            assert.ok(run.built[0]?.storage instanceof FileSignerStorage);
        });

        it("hands the SDK its file storage behind the bypass when it is on, reading a channel record's marks as its signed sessions", async (t) => {
            const dirs = freshDirs();
            const record = {
                version: 1,
                signedSessions: { "COMMITMENT:3": "aa".repeat(32) },
                nonceReuse: { "COMMITMENT:3": { sessionCommitment: "cc".repeat(32), message: "bb".repeat(32) } },
            };
            writeSdkEntry(dirs, "fiber-lsp-sdk:channel:7", record);
            const run = runAgent(t, { ...configOf(dirs, IDLE_INTERVAL_MS), nonceCapBypass: true }, new FakeNode());
            await run.agent.start();
            const storage = run.built[0]?.storage;
            assert.ok(storage instanceof NonceCapBypassStorage);
            assert.equal(
                storage.get("fiber-lsp-sdk:channel:7"),
                JSON.stringify({ version: 1, signedSessions: { "COMMITMENT:3": "cc".repeat(32) }, nonceReuse: {} }),
            );
            assert.equal(sdkStore(dirs)["fiber-lsp-sdk:channel:7"], JSON.stringify(record));
        });

        it("refuses an operator token with a space at construction", () => {
            const dirs = freshDirs();
            assert.throws(
                () =>
                    new Agent(
                        { ...configOf(dirs, IDLE_INTERVAL_MS), operatorToken: "a b" },
                        {
                            fetch: new FakeNode().fetch,
                            now: () => NOW_MS,
                            randomBytes: requestIds(),
                            sleep: async () => undefined,
                            exit: () => undefined,
                            log: () => undefined,
                            createSdk: (masterSeed, options) => new FiberLspSdk(masterSeed, options),
                        },
                    ),
                {
                    name: "TypeError",
                    message: "operatorToken must be printable ASCII without spaces",
                },
            );
        });

        it("writes no status without a status file", async (t) => {
            const dirs = freshDirs();
            const run = runAgent(t, { ...configOf(dirs, IDLE_INTERVAL_MS), statusFile: null }, new FakeNode());
            await run.agent.start();
            assert.equal(existsSync(dirs.statusFile), false);
        });
    });

    describe("openChannel", () => {
        it("waits for the initialization", async (t) => {
            const node = new FakeNode();
            node.openAnswer = { result: OPEN_RESULT };
            const run = runAgent(t, configOf(freshDirs(), IDLE_INTERVAL_MS), node);
            let settled = false;
            const opening = run.agent.openChannel(OPEN_BODY).finally(() => (settled = true));
            await flush();
            assert.equal(settled, false);
            assert.deepEqual(node.calls, []);
            await run.agent.start();
            assert.deepEqual(await opening, OPEN_RESULT);
        });

        it("binds the channel the SDK accepted and answers the node's result verbatim", async (t) => {
            const dirs = freshDirs();
            const node = new FakeNode();
            node.openAnswer = { result: OPEN_RESULT };
            const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), node);
            await run.agent.start();
            assert.deepEqual(await run.agent.openChannel(OPEN_BODY), OPEN_RESULT);
            const [call] = node.callsOf("open_channel_with_external_funding");
            assert.equal(call?.authorization, "Bearer tenant-token-1");
            assert.deepEqual(readAgentState(dirs.storeDir).channels, {
                [CHANNEL_ID]: { localScript: USER_LOCK, remoteScript: LSP_SHUTDOWN_SCRIPT },
            });
            assert.deepEqual(readStatus(dirs), {
                tenant_id: DEVICE_TENANT_ID,
                root_signer_pubkey: DEVICE_ROOT_SIGNER,
                tenant_token: "tenant-token-1",
                channel_open_signer_material: null,
                bound_channel_ids: [CHANNEL_ID],
                watchtower_submissions: {},
                revoked_commitments: { [CHANNEL_ID]: [] },
            });
        });

        it("answers the SDK's refusal of the node's answer as a 400 with its code, binding nothing", async (t) => {
            const dirs = freshDirs();
            const node = new FakeNode();
            node.openAnswer = { result: { ...OPEN_RESULT, channel_id: OTHER_CHANNEL_ID } };
            const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), node);
            await run.agent.start();
            await assert.rejects(run.agent.openChannel(OPEN_BODY), (error) => {
                assert.ok(error instanceof AgentRequestError);
                assert.match(error.message, /^opening_rejected: /);
                return true;
            });
            assert.deepEqual(readAgentState(dirs.storeDir).channels, {});
            assert.deepEqual((readStatus(dirs) as { bound_channel_ids: unknown }).bound_channel_ids, []);
        });

        it("answers the node's refusal as a 400 with its JSON-RPC code", async (t) => {
            const node = new FakeNode();
            node.openAnswer = { error: { code: -32000, message: "tenant already has a channel" } };
            const run = runAgent(t, configOf(freshDirs(), IDLE_INTERVAL_MS), node);
            await run.agent.start();
            await assertRefused(run.agent.openChannel(OPEN_BODY), "-32000: tenant already has a channel");
        });

        it("refuses params the SDK cannot honour before asking the node", async (t) => {
            const node = new FakeNode();
            const run = runAgent(t, configOf(freshDirs(), IDLE_INTERVAL_MS), node);
            await run.agent.start();
            await assertRefused(
                run.agent.openChannel({ params: { ...OPEN_BODY.params, public: true } }),
                "params.public must be false: the SDK opens private channels",
            );
            assert.deepEqual(node.callsOf("open_channel_with_external_funding"), []);
        });

        it("binds nothing when the result it kept names another channel than the SDK opened", async (t) => {
            const dirs = freshDirs();
            const node = new FakeNode();
            node.openAnswer = { result: OPEN_RESULT };
            const agent: Agent = new Agent(configOf(dirs, IDLE_INTERVAL_MS), {
                fetch: node.fetch,
                now: () => NOW_MS,
                randomBytes: requestIds(),
                sleep: async () => undefined,
                exit: () => undefined,
                log: () => undefined,
                createSdk: (masterSeed, options) => {
                    const sdk = new FiberLspSdk(masterSeed, options);
                    const prepare = sdk.prepareChannelOpen.bind(sdk);
                    sdk.prepareChannelOpen = async (...args) => ({ ...(await prepare(...args)), channelId: OTHER_CHANNEL_ID });
                    return sdk;
                },
            });
            t.after(() => agent.shutdown());
            await agent.start();
            await assert.rejects(agent.openChannel(OPEN_BODY), (error) => {
                assert.ok(error instanceof Error && !(error instanceof AgentRequestError));
                assert.equal(
                    error.message,
                    `open_channel_with_external_funding's result names channel ${CHANNEL_ID}, the SDK opened ${OTHER_CHANNEL_ID}`,
                );
                return true;
            });
            assert.deepEqual(readAgentState(dirs.storeDir).channels, {});
        });

        it("answers an argument the SDK refuses as a 400 with its message", async (t) => {
            const node = new FakeNode();
            const run = runAgent(t, configOf(freshDirs(), IDLE_INTERVAL_MS), node);
            await run.agent.start();
            await assertRefused(
                run.agent.openChannel({ params: { ...OPEN_BODY.params, funding_amount: "0x24e1602ff" } }),
                "fundedShannons 9899999999 is below the 9900000000 the device's reserve takes over that close script",
            );
            assert.deepEqual(node.callsOf("open_channel_with_external_funding"), []);
        });

        it("answers a plain Error from prepareChannelOpen as a 400 with its message through the control port, logging it", async (t) => {
            const dirs = freshDirs();
            const node = new FakeNode();
            const logged: string[] = [];
            const agent: Agent = new Agent(configOf(dirs, IDLE_INTERVAL_MS), {
                fetch: node.fetch,
                now: () => NOW_MS,
                randomBytes: requestIds(),
                sleep: async () => undefined,
                exit: () => undefined,
                log: () => undefined,
                createSdk: (masterSeed, options) => {
                    const sdk = new FiberLspSdk(masterSeed, options);
                    sdk.prepareChannelOpen = () => Promise.reject(new Error("the store is gone"));
                    return sdk;
                },
            });
            t.after(() => agent.shutdown());
            const server = await startControlServer({ host: "127.0.0.1", port: 0 }, dirs.statusFile, agent, (kind) => logged.push(kind));
            t.after(() => new Promise((resolve) => server.close(resolve)));
            await agent.start();
            const response = await fetch(`http://127.0.0.1:${(server.address() as AddressInfo).port}/open-channel`, {
                method: "POST",
                body: JSON.stringify(OPEN_BODY),
            });
            assert.equal(response.status, 400);
            assert.equal(await response.text(), '{"error":"the store is gone"}');
            assert.deepEqual(
                logged.filter((kind) => kind === "control_request_failed"),
                ["control_request_failed"],
            );
            assert.deepEqual(readAgentState(dirs.storeDir).channels, {});
        });

        it("runs the next request after one it refused", async (t) => {
            const node = new FakeNode();
            node.openAnswer = { result: OPEN_RESULT };
            const run = runAgent(t, configOf(freshDirs(), IDLE_INTERVAL_MS), node);
            await run.agent.start();
            const refused = run.agent.openChannel({ params: { ...OPEN_BODY.params, public: true } });
            const next = run.agent.openChannel(OPEN_BODY);
            await assertRefused(refused, "params.public must be false: the SDK opens private channels");
            assert.deepEqual(await next, OPEN_RESULT);
            assert.equal(node.callsOf("open_channel_with_external_funding").length, 1);
        });

        it("runs one control request at a time, in the order they came", async (t) => {
            const dirs = freshDirs();
            const node = new FakeNode();
            node.openAnswer = { result: OPEN_RESULT };
            let release: () => void = () => undefined;
            const held = new Promise<void>((resolve) => (release = resolve));
            node.beforeAnswer = (method) => (method === "open_channel_with_external_funding" ? held : Promise.resolve());
            const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), node);
            await run.agent.start();
            const opening = run.agent.openChannel(OPEN_BODY);
            // Run alongside the opening, it would find the channel unbound.
            const authorizing = run.agent.authorize(INVOICE_BODY);
            await eventually("the opening", () => node.callsOf("open_channel_with_external_funding").length === 1);
            release();
            assert.deepEqual(await opening, OPEN_RESULT);
            assert.deepEqual(await authorizing, { authorized: true });
        });
    });

    describe("authorize", () => {
        for (const body of [
            { ...INVOICE_BODY, channel_id: OTHER_CHANNEL_ID },
            { ...PAYMENT_BODY, channel_id: OTHER_CHANNEL_ID },
            { ...FULFILLMENT_BODY, channel_id: OTHER_CHANNEL_ID },
            { ...RELEASE_BODY, channel_id: OTHER_CHANNEL_ID },
            { ...CLOSE_BODY, channel_id: OTHER_CHANNEL_ID },
            { ...WATCHTOWER_BODY, channel_id: OTHER_CHANNEL_ID },
        ]) {
            it(`refuses ${body.type} on a channel the agent never bound`, async (t) => {
                const run = await openedAgent(t, freshDirs());
                await assertRefused(run.agent.authorize(body), `unknown channel ${OTHER_CHANNEL_ID}`);
            });
        }

        it("refuses a body it cannot read before waiting for anything", async (t) => {
            const run = runAgent(t, configOf(freshDirs(), IDLE_INTERVAL_MS), new FakeNode());
            await assertRefused(
                run.agent.authorize({ ...INVOICE_BODY, type: "invoice" }),
                "type must be one of Invoice, Payment, Fulfillment, ReleasePreimage, Close, Watchtower",
            );
        });

        it("rewrites the status after each authorization", async (t) => {
            const dirs = freshDirs();
            const run = await openedAgent(t, dirs);
            rmSync(dirs.statusFile);
            assert.deepEqual(await run.agent.authorize(INVOICE_BODY), { authorized: true });
            assert.deepEqual((readStatus(dirs) as { bound_channel_ids: unknown }).bound_channel_ids, [CHANNEL_ID]);
        });

        describe("Invoice", () => {
            it("records each invoice under its payment hash, with its terms", async (t) => {
                const dirs = freshDirs();
                const run = await openedAgent(t, dirs);
                await run.agent.authorize(INVOICE_BODY);
                await run.agent.authorize({
                    ...INVOICE_BODY,
                    terms: { ...INVOICE_BODY.terms, payment_hash: SHA256_HASH, hash_algorithm: "sha256" },
                });
                assert.deepEqual(readAgentState(dirs.storeDir).invoices, {
                    [CKB_HASH]: {
                        type: "Invoice",
                        channelId: CHANNEL_ID,
                        preimage: PREIMAGE,
                        paymentHash: CKB_HASH,
                        hashAlgorithm: "ckb_hash",
                        amountShannons: "1000000",
                        expiresAtMs: "1800003600000",
                        minTlcExpiryDeltaMs: "86400000",
                        maxTlcExpiryMs: "1800604800000",
                    },
                    [SHA256_HASH]: {
                        type: "Invoice",
                        channelId: CHANNEL_ID,
                        preimage: PREIMAGE,
                        paymentHash: SHA256_HASH,
                        hashAlgorithm: "sha256",
                        amountShannons: "1000000",
                        expiresAtMs: "1800003600000",
                        minTlcExpiryDeltaMs: "86400000",
                        maxTlcExpiryMs: "1800604800000",
                    },
                });
            });

            it("answers the same terms again with nothing written, as fiber's CommitmentState::authorize", async (t) => {
                const dirs = freshDirs();
                const run = await openedAgent(t, dirs);
                await run.agent.authorize(INVOICE_BODY);
                const state = readFileSync(join(dirs.storeDir, "agent.json"), "utf8");
                assert.deepEqual(await run.agent.authorize(structuredClone(INVOICE_BODY)), { authorized: true });
                assert.equal(readFileSync(join(dirs.storeDir, "agent.json"), "utf8"), state);
            });

            for (const [name, terms] of [
                ["amount", { amount: 1000001 }],
                ["expires_at_ms", { expires_at_ms: 1800003600001 }],
                ["min_tlc_expiry_delta_ms", { min_tlc_expiry_delta_ms: 86400001 }],
                ["max_tlc_expiry_ms", { max_tlc_expiry_ms: 1800604800001 }],
            ] as const) {
                it(`refuses the hash again under another ${name}, keeping the first`, async (t) => {
                    const dirs = freshDirs();
                    const run = await openedAgent(t, dirs);
                    await run.agent.authorize(INVOICE_BODY);
                    const state = readAgentState(dirs.storeDir);
                    await assertRefused(
                        run.agent.authorize({ ...INVOICE_BODY, terms: { ...INVOICE_BODY.terms, ...terms } }),
                        "payment authorization cannot be replaced",
                    );
                    assert.deepEqual(readAgentState(dirs.storeDir), state);
                });
            }

            it("refuses the hash again on another channel, keeping the first", async (t) => {
                const dirs = freshDirs();
                const first = await openedAgent(t, dirs);
                await first.agent.authorize(INVOICE_BODY);
                first.agent.shutdown();
                bindOtherChannel(dirs, null);
                const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), new FakeNode());
                await run.agent.start();
                await assertRefused(
                    run.agent.authorize({ ...INVOICE_BODY, channel_id: OTHER_CHANNEL_ID }),
                    "payment authorization cannot be replaced",
                );
                assert.equal(readAgentState(dirs.storeDir).invoices[CKB_HASH]?.channelId, CHANNEL_ID);
            });

            for (const [name, patch, message] of [
                ["an outgoing payment", { inbound: false }, "terms.inbound must be true: an Invoice authorizes an incoming payment"],
                ["a preimage of another hash", { payment_hash: SHA256_HASH }, "preimage does not hash to payment_hash under ckb_hash"],
            ] as const) {
                it(`refuses ${name}, recording nothing`, async (t) => {
                    const dirs = freshDirs();
                    const run = await openedAgent(t, dirs);
                    await assertRefused(run.agent.authorize({ ...INVOICE_BODY, terms: { ...INVOICE_BODY.terms, ...patch } }), message);
                    assert.deepEqual(readAgentState(dirs.storeDir).invoices, {});
                });
            }

            it("refuses a hash a Payment authorized, as fiber's CommitmentState::authorize", async (t) => {
                const dirs = freshDirs();
                const run = await openedAgent(t, dirs);
                await run.agent.authorize(PAYMENT_BODY);
                await assertRefused(
                    run.agent.authorize({
                        ...INVOICE_BODY,
                        preimage: OUTGOING_PREIMAGE,
                        terms: { ...INVOICE_BODY.terms, payment_hash: OUTGOING_HASH },
                    }),
                    "payment authorization cannot be replaced",
                );
                assert.deepEqual(readAgentState(dirs.storeDir).invoices, {});
            });
            it("refuses a hash a Payment authorized on another channel, the SDK keeping one debit intent per hash", async (t) => {
                const dirs = freshDirs();
                const first = await openedAgent(t, dirs);
                await first.agent.authorize(PAYMENT_BODY);
                first.agent.shutdown();
                bindOtherChannel(dirs, null);
                const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), new FakeNode());
                await run.agent.start();
                await assertRefused(
                    run.agent.authorize({
                        ...INVOICE_BODY,
                        channel_id: OTHER_CHANNEL_ID,
                        preimage: OUTGOING_PREIMAGE,
                        terms: { ...INVOICE_BODY.terms, payment_hash: OUTGOING_HASH },
                    }),
                    "payment authorization cannot be replaced",
                );
                assert.deepEqual(readAgentState(dirs.storeDir).invoices, {});
            });
        });

        describe("Payment", () => {
            it("records the payment and the SDK's open debit intent, the exact amount its budget", async (t) => {
                const dirs = freshDirs();
                const run = await openedAgent(t, dirs);
                assert.deepEqual(await run.agent.authorize(PAYMENT_BODY), { authorized: true });
                assert.deepEqual(readAgentState(dirs.storeDir).payments, {
                    [OUTGOING_HASH]: {
                        type: "Payment",
                        channelId: CHANNEL_ID,
                        paymentHash: OUTGOING_HASH,
                        hashAlgorithm: "ckb_hash",
                        amountShannons: "100500",
                        expiresAtMs: "1800003600000",
                        minTlcExpiryDeltaMs: "60000",
                        maxTlcExpiryMs: "1800608400000",
                    },
                });
                assert.deepEqual(JSON.parse(sdkStore(dirs)[OUTGOING_INTENT_KEY] ?? "null"), OUTGOING_INTENT);
            });

            it("answers the same terms again with nothing written", async (t) => {
                const dirs = freshDirs();
                const run = await openedAgent(t, dirs);
                await run.agent.authorize(PAYMENT_BODY);
                const state = readFileSync(join(dirs.storeDir, "agent.json"), "utf8");
                const store = sdkStore(dirs);
                assert.deepEqual(await run.agent.authorize(structuredClone(PAYMENT_BODY)), { authorized: true });
                assert.equal(readFileSync(join(dirs.storeDir, "agent.json"), "utf8"), state);
                assert.deepEqual(sdkStore(dirs), store);
            });

            for (const [name, terms] of [
                ["amount", { amount: 100501 }],
                ["hash_algorithm", { hash_algorithm: "sha256" }],
                ["expires_at_ms", { expires_at_ms: 1800003600001 }],
                ["min_tlc_expiry_delta_ms", { min_tlc_expiry_delta_ms: 60001 }],
                ["max_tlc_expiry_ms", { max_tlc_expiry_ms: 1800608400001 }],
            ] as const) {
                it(`refuses the hash again under another ${name}, keeping the first`, async (t) => {
                    const dirs = freshDirs();
                    const run = await openedAgent(t, dirs);
                    await run.agent.authorize(PAYMENT_BODY);
                    const state = readAgentState(dirs.storeDir);
                    await assertRefused(
                        run.agent.authorize({ ...PAYMENT_BODY, terms: { ...PAYMENT_BODY.terms, ...terms } }),
                        "payment authorization cannot be replaced",
                    );
                    assert.deepEqual(readAgentState(dirs.storeDir), state);
                    assert.deepEqual(JSON.parse(sdkStore(dirs)[OUTGOING_INTENT_KEY] ?? "null"), OUTGOING_INTENT);
                });
            }

            it("refuses the hash again on another channel, the SDK keeping one debit intent per hash", async (t) => {
                const dirs = freshDirs();
                const first = await openedAgent(t, dirs);
                await first.agent.authorize(PAYMENT_BODY);
                first.agent.shutdown();
                bindOtherChannel(dirs, null);
                const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), new FakeNode());
                await run.agent.start();
                await assertRefused(
                    run.agent.authorize({ ...PAYMENT_BODY, channel_id: OTHER_CHANNEL_ID }),
                    "payment authorization cannot be replaced",
                );
                assert.equal(readAgentState(dirs.storeDir).payments[OUTGOING_HASH]?.channelId, CHANNEL_ID);
            });

            it("refuses a hash an Invoice authorized", async (t) => {
                const dirs = freshDirs();
                const run = await openedAgent(t, dirs);
                await run.agent.authorize(INVOICE_BODY);
                await assertRefused(
                    run.agent.authorize({ ...PAYMENT_BODY, terms: { ...PAYMENT_BODY.terms, payment_hash: CKB_HASH } }),
                    "payment authorization cannot be replaced",
                );
                assert.deepEqual(readAgentState(dirs.storeDir).payments, {});
            });

            for (const [name, terms, message] of [
                ["an incoming payment", { inbound: true }, "inbound authorization requires authorize_invoice and a matching preimage"],
                ["an amount of 0", { amount: 0 }, "invalid payment amount or expiry bounds"],
            ] as const) {
                it(`refuses ${name}, recording nothing`, async (t) => {
                    const dirs = freshDirs();
                    const run = await openedAgent(t, dirs);
                    await assertRefused(run.agent.authorize({ ...PAYMENT_BODY, terms: { ...PAYMENT_BODY.terms, ...terms } }), message);
                    assert.deepEqual(readAgentState(dirs.storeDir).payments, {});
                    assert.equal(sdkStore(dirs)[OUTGOING_INTENT_KEY], undefined);
                });
            }

            it("refuses the hash of a hold invoice of the device, recording nothing", async (t) => {
                const dirs = freshDirs();
                const run = await openedAgent(t, dirs);
                run.agent.shutdown();
                writeSdkEntry(dirs, OUTGOING_HOLD_INVOICE_KEY, { version: 1, paymentHash: OUTGOING_INTENT.paymentHash });
                const next = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), new FakeNode());
                await next.agent.start();
                await assertRefused(next.agent.authorize(PAYMENT_BODY), `${OUTGOING_HASH} is the hash of a hold invoice of this device`);
                assert.deepEqual(readAgentState(dirs.storeDir).payments, {});
                assert.equal(sdkStore(dirs)[OUTGOING_INTENT_KEY], undefined);
            });

            it("refuses a hash whose bound 20 bytes are a twin hold invoice's, recording nothing", async (t) => {
                const dirs = freshDirs();
                const run = await openedAgent(t, dirs);
                run.agent.shutdown();
                const twin = `${OUTGOING_INTENT.paymentHash.slice(0, 40)}${"00".repeat(12)}`;
                writeSdkEntry(dirs, OUTGOING_HOLD_INVOICE_KEY, { version: 1, paymentHash: twin });
                const next = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), new FakeNode());
                await next.agent.start();
                await assertRefused(
                    next.agent.authorize(PAYMENT_BODY),
                    `the 20 bytes of ${OUTGOING_HASH} a TLC's witness binds are another payment's`,
                );
                assert.deepEqual(readAgentState(dirs.storeDir).payments, {});
                assert.equal(sdkStore(dirs)[OUTGOING_INTENT_KEY], undefined);
            });

            for (const [name, raw] of [
                ["of another budget", JSON.stringify({ ...OUTGOING_INTENT, maxShannons: "100000" })],
                ["closed", JSON.stringify({ ...OUTGOING_INTENT, open: false })],
                ["already charged on a channel", JSON.stringify({ ...OUTGOING_INTENT, channelIndexes: [1800000000] })],
                [
                    "of a twin hash",
                    JSON.stringify({ ...OUTGOING_INTENT, paymentHash: `${OUTGOING_INTENT.paymentHash.slice(0, 40)}${"00".repeat(12)}` }),
                ],
                ["of another version", JSON.stringify({ ...OUTGOING_INTENT, version: 2 })],
                ["whose channel indexes are no array", JSON.stringify({ ...OUTGOING_INTENT, channelIndexes: "" })],
                ["that is no JSON", "{"],
                ["that is no object", "[]"],
            ] as const) {
                it(`refuses a hash the SDK holds a debit intent under, ${name}, leaving it`, async (t) => {
                    const dirs = freshDirs();
                    const run = await openedAgent(t, dirs);
                    run.agent.shutdown();
                    writeRawSdkEntry(dirs, OUTGOING_INTENT_KEY, raw);
                    const next = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), new FakeNode());
                    await next.agent.start();
                    await assertRefused(
                        next.agent.authorize(PAYMENT_BODY),
                        `the SDK already holds a debit intent under the bound hash of ${OUTGOING_HASH}`,
                    );
                    assert.deepEqual(readAgentState(dirs.storeDir).payments, {});
                    assert.equal(sdkStore(dirs)[OUTGOING_INTENT_KEY], raw);
                });
            }

            it("takes the intent a crash left before agent.json recorded the payment as its own", async (t) => {
                const dirs = freshDirs();
                const run = await openedAgent(t, dirs);
                run.agent.shutdown();
                writeSdkEntry(dirs, OUTGOING_INTENT_KEY, OUTGOING_INTENT);
                const next = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), new FakeNode());
                await next.agent.start();
                assert.deepEqual(await next.agent.authorize(PAYMENT_BODY), { authorized: true });
                assert.equal(readAgentState(dirs.storeDir).payments[OUTGOING_HASH]?.amountShannons, "100500");
            });
        });

        describe("Fulfillment", () => {
            it("accepts the preimage of a payment the channel's Payment authorized, recording nothing", async (t) => {
                const dirs = freshDirs();
                const run = await openedAgent(t, dirs);
                await run.agent.authorize(PAYMENT_BODY);
                const state = readFileSync(join(dirs.storeDir, "agent.json"), "utf8");
                const store = sdkStore(dirs);
                assert.deepEqual(await run.agent.authorize(FULFILLMENT_BODY), { authorized: true });
                assert.deepEqual(await run.agent.authorize(FULFILLMENT_BODY), { authorized: true });
                assert.equal(readFileSync(join(dirs.storeDir, "agent.json"), "utf8"), state);
                assert.deepEqual(sdkStore(dirs), store);
            });

            it("checks the preimage under the Payment's algorithm", async (t) => {
                const run = await openedAgent(t, freshDirs());
                await run.agent.authorize({
                    ...PAYMENT_BODY,
                    terms: { ...PAYMENT_BODY.terms, payment_hash: OUTGOING_SHA256_HASH, hash_algorithm: "sha256" },
                });
                assert.deepEqual(await run.agent.authorize({ ...FULFILLMENT_BODY, payment_hash: OUTGOING_SHA256_HASH }), {
                    authorized: true,
                });
            });

            it("accepts the preimage of an invoice the channel's Invoice authorized", async (t) => {
                const run = await openedAgent(t, freshDirs());
                await run.agent.authorize(INVOICE_BODY);
                assert.deepEqual(await run.agent.authorize({ ...FULFILLMENT_BODY, payment_hash: CKB_HASH, preimage: PREIMAGE }), {
                    authorized: true,
                });
            });

            it("refuses a payment nothing authorized", async (t) => {
                const run = await openedAgent(t, freshDirs());
                await assertRefused(run.agent.authorize(FULFILLMENT_BODY), "unknown payment");
            });

            it("refuses a payment another channel's Payment authorized", async (t) => {
                const dirs = freshDirs();
                const first = await openedAgent(t, dirs);
                await first.agent.authorize(PAYMENT_BODY);
                first.agent.shutdown();
                bindOtherChannel(dirs, null);
                const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), new FakeNode());
                await run.agent.start();
                await assertRefused(run.agent.authorize({ ...FULFILLMENT_BODY, channel_id: OTHER_CHANNEL_ID }), "unknown payment");
            });

            it("refuses a preimage that does not hash to the payment hash", async (t) => {
                const run = await openedAgent(t, freshDirs());
                await run.agent.authorize(PAYMENT_BODY);
                await assertRefused(
                    run.agent.authorize({ ...FULFILLMENT_BODY, preimage: PREIMAGE }),
                    "preimage does not match payment hash",
                );
            });

            it("refuses a preimage of the payment hash under the other algorithm", async (t) => {
                const run = await openedAgent(t, freshDirs());
                await run.agent.authorize({ ...PAYMENT_BODY, terms: { ...PAYMENT_BODY.terms, hash_algorithm: "sha256" } });
                await assertRefused(run.agent.authorize(FULFILLMENT_BODY), "preimage does not match payment hash");
            });
        });

        describe("ReleasePreimage", () => {
            it("settles the hold invoice through settle_invoice under the tenant's token", async (t) => {
                const dirs = freshDirs();
                const node = new FakeNode();
                node.openAnswer = { result: OPEN_RESULT };
                const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), node);
                await run.agent.start();
                await run.agent.openChannel(OPEN_BODY);
                await run.agent.authorize(INVOICE_BODY);
                assert.deepEqual(await run.agent.authorize(RELEASE_BODY), { authorized: true });
                assert.deepEqual(node.callsOf("settle_invoice"), [
                    {
                        method: "settle_invoice",
                        params: [{ payment_hash: CKB_HASH, payment_preimage: PREIMAGE }],
                        authorization: "Bearer tenant-token-1",
                    },
                ]);
                assert.deepEqual(node.callsOf("create_preimage"), []);
            });

            it("hands the watchtower the preimage through create_preimage under the tenant's token", async (t) => {
                const node = new FakeNode();
                node.openAnswer = { result: OPEN_RESULT };
                const run = runAgent(t, configOf(freshDirs(), IDLE_INTERVAL_MS), node);
                await run.agent.start();
                await run.agent.openChannel(OPEN_BODY);
                await run.agent.authorize(INVOICE_BODY);
                assert.deepEqual(await run.agent.authorize({ ...RELEASE_BODY, target: "Watchtower" }), { authorized: true });
                assert.deepEqual(node.callsOf("create_preimage"), [
                    {
                        method: "create_preimage",
                        params: [{ payment_hash: CKB_HASH, preimage: PREIMAGE }],
                        authorization: "Bearer tenant-token-1",
                    },
                ]);
                assert.deepEqual(node.callsOf("settle_invoice"), []);
            });

            it("refuses a release no Invoice authorized", async (t) => {
                const run = await openedAgent(t, freshDirs());
                await assertRefused(
                    run.agent.authorize(RELEASE_BODY),
                    `no Invoice authorization for payment hash ${CKB_HASH} on channel ${CHANNEL_ID}`,
                );
            });

            it("refuses a release whose Invoice is another channel's", async (t) => {
                const dirs = freshDirs();
                const first = await openedAgent(t, dirs);
                first.agent.shutdown();
                bindOtherChannel(dirs, null);
                const state = readAgentState(dirs.storeDir);
                writeAgentState(dirs.storeDir, {
                    ...state,
                    invoices: {
                        [CKB_HASH]: {
                            type: "Invoice",
                            channelId: OTHER_CHANNEL_ID,
                            preimage: PREIMAGE,
                            paymentHash: CKB_HASH,
                            hashAlgorithm: "ckb_hash",
                            amountShannons: "1000000",
                            expiresAtMs: "1800003600000",
                            minTlcExpiryDeltaMs: "86400000",
                            maxTlcExpiryMs: "1800604800000",
                        },
                    },
                });
                const node = new FakeNode();
                const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), node);
                await run.agent.start();
                await assertRefused(
                    run.agent.authorize(RELEASE_BODY),
                    `no Invoice authorization for payment hash ${CKB_HASH} on channel ${CHANNEL_ID}`,
                );
                assert.deepEqual(node.callsOf("settle_invoice"), []);
            });

            it("refuses a preimage that does not hash to the payment hash under the Invoice's algorithm", async (t) => {
                const node = new FakeNode();
                node.openAnswer = { result: OPEN_RESULT };
                const run = runAgent(t, configOf(freshDirs(), IDLE_INTERVAL_MS), node);
                await run.agent.start();
                await run.agent.openChannel(OPEN_BODY);
                await run.agent.authorize({
                    ...INVOICE_BODY,
                    terms: { ...INVOICE_BODY.terms, payment_hash: SHA256_HASH, hash_algorithm: "sha256" },
                });
                await assertRefused(
                    run.agent.authorize({
                        ...RELEASE_BODY,
                        payment_hash: SHA256_HASH,
                        preimage: "0x3333333333333333333333333333333333333333333333333333333333333333",
                    }),
                    "preimage does not hash to payment_hash under sha256",
                );
                assert.deepEqual(node.callsOf("settle_invoice"), []);
            });

            it("answers the node's refusal of the release as a 400 with its message", async (t) => {
                const node = new FakeNode();
                node.openAnswer = { result: OPEN_RESULT };
                node.releaseError = "invoice not found";
                const run = runAgent(t, configOf(freshDirs(), IDLE_INTERVAL_MS), node);
                await run.agent.start();
                await run.agent.openChannel(OPEN_BODY);
                await run.agent.authorize(INVOICE_BODY);
                await assertRefused(run.agent.authorize(RELEASE_BODY), "invoice not found");
            });
        });

        describe("Close", () => {
            it("records a close naming the channel's two scripts, whatever the case of their hex", async (t) => {
                const dirs = freshDirs();
                const run = await openedAgent(t, dirs);
                const localScript = { ...USER_LOCK, code_hash: USER_LOCK.code_hash.toUpperCase().replace("0X", "0x") };
                assert.deepEqual(await run.agent.authorize({ ...CLOSE_BODY, local_script: localScript }), { authorized: true });
                assert.deepEqual(readAgentState(dirs.storeDir).closes, {
                    [CHANNEL_ID]: {
                        type: "Close",
                        channelId: CHANNEL_ID,
                        localScript,
                        remoteScript: LSP_SHUTDOWN_SCRIPT,
                        localFeeRate: "1000",
                        remoteFeeRate: "0",
                    },
                });
            });

            it("refuses a local script that is not the lock that funded the channel", async (t) => {
                const run = await openedAgent(t, freshDirs());
                await assertRefused(
                    run.agent.authorize({ ...CLOSE_BODY, local_script: LSP_SHUTDOWN_SCRIPT }),
                    `local_script must be the lock that funded channel ${CHANNEL_ID}`,
                );
            });

            it("refuses a remote script that is not the LSP's shutdown script", async (t) => {
                const run = await openedAgent(t, freshDirs());
                await assertRefused(
                    run.agent.authorize({ ...CLOSE_BODY, remote_script: USER_LOCK }),
                    `remote_script must be the LSP's shutdown script of channel ${CHANNEL_ID}`,
                );
            });
        });

        describe("Watchtower", () => {
            it("records the approval and rebuilds the facade with it over the same store and token", async (t) => {
                const dirs = freshDirs();
                const run = await openedAgent(t, dirs);
                assert.deepEqual(await run.agent.authorize(WATCHTOWER_BODY), { authorized: true });
                assert.deepEqual(readAgentState(dirs.storeDir).watchtower, {
                    type: "Watchtower",
                    channelId: CHANNEL_ID,
                    destination: LSP_SHUTDOWN_SCRIPT,
                    maxFeeShannons: "10000",
                });
                assert.equal(run.built.length, 2);
                assert.deepEqual(run.disconnected, [0]);
                const [before, after] = run.built;
                assert.ok(before !== undefined && after !== undefined);
                assert.deepEqual(after.watchtower, {
                    destination: {
                        codeHash: bytes(LSP_SHUTDOWN_SCRIPT.code_hash),
                        hashType: "type",
                        args: bytes(LSP_SHUTDOWN_SCRIPT.args),
                    },
                    maxFeeShannons: "10000",
                });
                assert.equal(after.storage, before.storage);
                assert.equal(after.biscuitToken, "tenant-token-1");
            });

            it("polls with the rebuilt facade", async (t) => {
                const dirs = freshDirs();
                const node = new FakeNode();
                node.openAnswer = { result: OPEN_RESULT };
                const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), node);
                await run.agent.start();
                await run.agent.openChannel(OPEN_BODY);
                await flush();
                // The idle interval holds the first facade's next tick; the rebuilt one ticks at its connect, on the opened channel.
                const polled = node.callsOf("list_channels").length;
                await run.agent.authorize(WATCHTOWER_BODY);
                await eventually("a poll of the rebuilt facade", () => node.callsOf("list_channels").length > polled);
            });

            it("refuses what the replaced facade still sends, before it reaches the node", async (t) => {
                const node = new FakeNode();
                node.openAnswer = { result: OPEN_RESULT };
                const run = runAgent(t, configOf(freshDirs(), IDLE_INTERVAL_MS), node);
                await run.agent.start();
                await run.agent.openChannel(OPEN_BODY);
                await run.agent.authorize(WATCHTOWER_BODY);
                const [replaced] = run.facades;
                assert.ok(replaced !== undefined);
                const calls = node.calls.length;
                await assert.rejects(replaced.listChannels(), (error) => {
                    assert.ok(error instanceof Error && error.cause instanceof Error);
                    assert.equal(error.cause.message, "the facade was replaced: its requests no longer reach the node");
                    return true;
                });
                assert.equal(node.calls.length, calls);
            });

            it("builds the new facade only once the replaced one's request in flight was answered", async (t) => {
                const node = new FakeNode();
                node.openAnswer = { result: OPEN_RESULT };
                const run = runAgent(t, configOf(freshDirs(), IDLE_INTERVAL_MS), node);
                await run.agent.start();
                await run.agent.openChannel(OPEN_BODY);
                let answer: () => void = () => undefined;
                const answered = new Promise<void>((resolve) => (answer = resolve));
                node.beforeAnswer = (method) => (method === "list_channels" ? answered : Promise.resolve());
                const [replaced] = run.facades;
                assert.ok(replaced !== undefined);
                const order: string[] = [];
                const inFlight = replaced.listChannels().then(() => order.push("request answered"));
                await eventually("the request in flight", () => node.callsOf("list_channels").length === 1);
                let authorized = false;
                const authorizing = run.agent.authorize(WATCHTOWER_BODY).finally(() => (authorized = true));
                await delay(20);
                assert.equal(run.built.length, 1);
                assert.deepEqual(run.disconnected, [0]);
                assert.equal(authorized, false);
                const built = run.built.length;
                answer();
                await inFlight;
                order.push(`facades built: ${run.built.length - built}`);
                assert.deepEqual(await authorizing, { authorized: true });
                assert.deepEqual(order, ["request answered", "facades built: 0"]);
                assert.equal(run.built.length, 2);
            });

            it("runs a facade over the old approval when agent.json cannot be written, and answers the failure", async (t) => {
                const dirs = freshDirs();
                const node = new FakeNode();
                node.openAnswer = { result: OPEN_RESULT };
                const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), node);
                await run.agent.start();
                await run.agent.openChannel(OPEN_BODY);
                await flush();
                // A folder in its place: the rename that writes agent.json fails.
                rmSync(join(dirs.storeDir, "agent.json"));
                mkdirSync(join(dirs.storeDir, "agent.json"));
                const polled = node.callsOf("list_channels").length;
                await assert.rejects(run.agent.authorize(WATCHTOWER_BODY), (error) => {
                    assert.ok(error instanceof Error && !(error instanceof AgentRequestError));
                    assert.match(error.message, /agent\.json/);
                    return true;
                });
                assert.equal(run.built.length, 3);
                assert.equal(run.built[1]?.watchtower?.maxFeeShannons, "10000");
                assert.equal(run.built[2]?.watchtower, undefined);
                assert.deepEqual(run.disconnected, [0]);
                await eventually("a poll of the facade over the old approval", () => node.callsOf("list_channels").length > polled);
            });

            it("runs a facade over the old approval when the new one cannot be built, agent.json keeping it", async (t) => {
                const dirs = freshDirs();
                const node = new FakeNode();
                node.openAnswer = { result: OPEN_RESULT };
                const built: FiberLspSdkOptions[] = [];
                const agent: Agent = new Agent(configOf(dirs, IDLE_INTERVAL_MS), {
                    fetch: node.fetch,
                    now: () => NOW_MS,
                    randomBytes: requestIds(),
                    sleep: async () => undefined,
                    exit: () => undefined,
                    log: () => undefined,
                    createSdk: (masterSeed, options) => {
                        built.push(options);
                        if (built.length === 3) throw new RangeError("watchtower.maxFeeShannons is refused");
                        return new FiberLspSdk(masterSeed, options);
                    },
                });
                t.after(() => agent.shutdown());
                await agent.start();
                await agent.openChannel(OPEN_BODY);
                await agent.authorize(WATCHTOWER_BODY);
                await flush();
                const polled = node.callsOf("list_channels").length;
                await assertRefused(agent.authorize({ ...WATCHTOWER_BODY, max_fee: 20000 }), "watchtower.maxFeeShannons is refused");
                assert.equal(readAgentState(dirs.storeDir).watchtower?.maxFeeShannons, "10000");
                assert.deepEqual(
                    built.map((options) => options.watchtower?.maxFeeShannons),
                    [undefined, "10000", "20000", "10000"],
                );
                await eventually("a poll of the facade over the old approval", () => node.callsOf("list_channels").length > polled);
            });

            it("keeps the approval across a restart, the facade built with it", async (t) => {
                const dirs = freshDirs();
                const first = await openedAgent(t, dirs);
                await first.agent.authorize(WATCHTOWER_BODY);
                first.agent.shutdown();
                const second = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), new FakeNode());
                await second.agent.start();
                assert.equal(second.built.length, 1);
                assert.deepEqual(second.built[0]?.watchtower, {
                    destination: {
                        codeHash: bytes(LSP_SHUTDOWN_SCRIPT.code_hash),
                        hashType: "type",
                        args: bytes(LSP_SHUTDOWN_SCRIPT.args),
                    },
                    maxFeeShannons: "10000",
                });
            });

            it("replaces the approval of the same channel", async (t) => {
                const dirs = freshDirs();
                const run = await openedAgent(t, dirs);
                await run.agent.authorize(WATCHTOWER_BODY);
                assert.deepEqual(await run.agent.authorize({ ...WATCHTOWER_BODY, destination: USER_LOCK, max_fee: 20000 }), {
                    authorized: true,
                });
                assert.equal(readAgentState(dirs.storeDir).watchtower?.maxFeeShannons, "20000");
                assert.equal(run.built[2]?.watchtower?.maxFeeShannons, "20000");
            });

            for (const [name, patch] of [
                ["destination", { destination: LSP_SHUTDOWN_SCRIPT }],
                ["fee cap", { destination: USER_LOCK, max_fee: 10001 }],
            ] as const) {
                it(`refuses another channel's approval with another ${name}: the SDK takes one`, async (t) => {
                    const dirs = freshDirs();
                    const first = await openedAgent(t, dirs);
                    first.agent.shutdown();
                    bindOtherChannel(dirs, USER_LOCK);
                    const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), new FakeNode());
                    await run.agent.start();
                    await assertRefused(
                        run.agent.authorize({ ...WATCHTOWER_BODY, ...patch }),
                        `channel ${OTHER_CHANNEL_ID} approved another watchtower destination or fee cap, and the SDK takes one approval`,
                    );
                    assert.equal(readAgentState(dirs.storeDir).watchtower?.channelId, OTHER_CHANNEL_ID);
                    assert.equal(run.built.length, 1);
                });
            }

            it("takes another channel's approval with the same destination and fee cap", async (t) => {
                const dirs = freshDirs();
                const first = await openedAgent(t, dirs);
                first.agent.shutdown();
                bindOtherChannel(dirs, USER_LOCK);
                const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), new FakeNode());
                await run.agent.start();
                assert.deepEqual(await run.agent.authorize({ ...WATCHTOWER_BODY, destination: USER_LOCK }), { authorized: true });
                assert.equal(readAgentState(dirs.storeDir).watchtower?.channelId, CHANNEL_ID);
            });
        });
    });

    describe("the status", () => {
        it("logs and skips a write whose evidence cannot be read, the agent running on", async (t) => {
            const dirs = freshDirs();
            const first = await openedAgent(t, dirs);
            first.agent.shutdown();
            bindOtherChannel(dirs, null);
            rmSync(dirs.statusFile);
            const run = runAgent(t, configOf(dirs, IDLE_INTERVAL_MS), new FakeNode());
            await run.agent.start();
            assert.equal(existsSync(dirs.statusFile), false);
            const [failure] = entries(run).filter((entry) => entry.kind === "status_write_failed");
            assert.equal((failure?.error as { code?: unknown } | undefined)?.code, "unknown_channel");
            assert.deepEqual(await run.agent.authorize(INVOICE_BODY), { authorized: true });
        });

        it("logs every SDK event as one line and rewrites the status on it", async (t) => {
            const dirs = freshDirs();
            const node = new FakeNode();
            node.openAnswer = { result: OPEN_RESULT };
            const run = runAgent(t, configOf(dirs, 20), node);
            await run.agent.start();
            // A channel watched, so the channel step lists the node's channels.
            await run.agent.openChannel(OPEN_BODY);
            rmSync(dirs.statusFile);
            node.listChannelsFails = true;
            const isListingError = (entry: LogEntry): boolean =>
                entry.kind === "sdk_event" &&
                /list_channels is down/.test(String((entry.error as { message?: unknown } | undefined)?.message));
            await eventually("an error event", () => entries(run).some(isListingError));
            const event = entries(run).find(isListingError);
            assert.equal(event?.ts, "2027-01-15T08:00:00.000Z");
            assert.equal(event?.type, "ERROR");
            const error = event?.error as { name: unknown; code: unknown; message: unknown; cause: { message: unknown } };
            assert.equal(error.name, "SdkError");
            assert.equal(error.code, "poll_failed");
            assert.match(String(error.message), /list_channels is down/);
            assert.equal(error.cause.message, "list_channels is down");
            await eventually("the status", () => existsSync(dirs.statusFile));
        });
    });

    describe("shutdown", () => {
        it("stops polling and exits with 0", async (t) => {
            const run = runAgent(t, configOf(freshDirs(), IDLE_INTERVAL_MS), new FakeNode());
            await run.agent.start();
            run.agent.shutdown();
            assert.deepEqual(run.disconnected, [0]);
            assert.deepEqual(run.exits, [0]);
        });

        it("ends the retries of an initialization that never succeeded", async () => {
            const node = new FakeNode();
            node.registrationFailures = Number.POSITIVE_INFINITY;
            const exits: number[] = [];
            const agent: Agent = new Agent(configOf(freshDirs(), IDLE_INTERVAL_MS), {
                fetch: node.fetch,
                now: () => NOW_MS,
                randomBytes: requestIds(),
                sleep: async () => agent.shutdown(),
                exit: (code) => exits.push(code),
                log: () => undefined,
                createSdk: (masterSeed, options) => new FiberLspSdk(masterSeed, options),
            });
            await agent.start();
            assert.equal(node.callsOf("lsp_register_tenant").length, 1);
            assert.deepEqual(exits, [0]);
        });
    });
});

describe("registerAgentTenant", () => {
    function deviceOf(dirs: AgentDirs): FiberLspSdk {
        return new FiberLspSdk(Buffer.from(DEVICE_SEED_HEX, "hex"), {
            network: "testnet",
            storage: new FileSignerStorage(join(dirs.storeDir, "sdk-store.json")),
            rpcUrl: RPC_URL,
            lspPubkey: Buffer.from(LSP_PUBKEY, "hex"),
            now: () => NOW_MS,
        });
    }

    it("signs a fresh 32-byte request id at the clock's time and registers it under the operator's token", async () => {
        const node = new FakeNode();
        const drawn: number[] = [];
        const tenant = await registerAgentTenant(deviceOf(freshDirs()), agentOperatorClient(RPC_URL, node.fetch, OPERATOR_TOKEN), {
            now: () => NOW_MS,
            randomBytes: requestIds(drawn),
        });
        assert.deepEqual(tenant, { tenantId: DEVICE_TENANT_ID, accessToken: "tenant-token-1" });
        assert.deepEqual(drawn, [32]);
        assert.deepEqual(node.calls, [
            {
                method: "lsp_register_tenant",
                params: [
                    {
                        root_signer_pubkey: DEVICE_ROOT_SIGNER,
                        request_id: `0x${"5a".repeat(32)}`,
                        signed_at: REGISTRATION_SIGNED_AT,
                        signature: REGISTRATION_SIGNATURE,
                    },
                ],
                authorization: `Bearer ${OPERATOR_TOKEN}`,
            },
        ]);
    });

    it("draws a new request id on every call", async () => {
        const node = new FakeNode();
        const sdk = deviceOf(freshDirs());
        const operator = agentOperatorClient(RPC_URL, node.fetch, OPERATOR_TOKEN);
        const effects = { now: () => NOW_MS, randomBytes: requestIds() };
        await registerAgentTenant(sdk, operator, effects);
        await registerAgentTenant(sdk, operator, effects);
        assert.deepEqual(
            node.calls.map((call) => (call.params as [{ request_id: unknown; signature: unknown }])[0]),
            [
                {
                    root_signer_pubkey: DEVICE_ROOT_SIGNER,
                    request_id: `0x${"5a".repeat(32)}`,
                    signed_at: REGISTRATION_SIGNED_AT,
                    signature: REGISTRATION_SIGNATURE,
                },
                {
                    root_signer_pubkey: DEVICE_ROOT_SIGNER,
                    request_id: `0x${"5b".repeat(32)}`,
                    signed_at: REGISTRATION_SIGNED_AT,
                    signature: RETRY_SIGNATURE,
                },
            ],
        );
    });

    it("refuses an answer that registers another tenant", async () => {
        const node = new FakeNode();
        node.foreignRegistrations = 1;
        await assert.rejects(
            registerAgentTenant(deviceOf(freshDirs()), agentOperatorClient(RPC_URL, node.fetch, OPERATOR_TOKEN), {
                now: () => NOW_MS,
                randomBytes: requestIds(),
            }),
            {
                name: "RpcResponseError",
                path: "response.result.tenant.tenant_id",
                reason: "is not the tenant of the registered root signer",
            },
        );
    });

    it("hands the registration the facade signed to the operator and returns what it answers", async () => {
        const received: unknown[] = [];
        const tenant = await registerAgentTenant(
            deviceOf(freshDirs()),
            {
                registerTenant: async (registration) => {
                    received.push(registration);
                    return { tenantId: DEVICE_TENANT_ID, accessToken: "stub-token" };
                },
            },
            { now: () => NOW_MS, randomBytes: requestIds() },
        );
        assert.deepEqual(tenant, { tenantId: DEVICE_TENANT_ID, accessToken: "stub-token" });
        assert.deepEqual(received, [
            {
                rootSignerPubkey: new Uint8Array(Buffer.from(DEVICE_ROOT_SIGNER, "hex")),
                requestId: new Uint8Array(32).fill(0x5a),
                signedAtMs: BigInt(NOW_MS),
                signature: new Uint8Array(Buffer.from(REGISTRATION_SIGNATURE, "hex")),
                tenantId: DEVICE_TENANT_ID,
            },
        ]);
    });

    it("reads the clock afresh for every registration", async () => {
        const received: { requestId: Uint8Array; signedAtMs: bigint }[] = [];
        const operator = {
            registerTenant: async (registration: { requestId: Uint8Array; signedAtMs: bigint }) => {
                received.push(registration);
                return { tenantId: DEVICE_TENANT_ID, accessToken: "stub-token" };
            },
        };
        const sdk = deviceOf(freshDirs());
        let n = 0;
        const effects = { now: () => NOW_MS + n++, randomBytes: requestIds() };
        await registerAgentTenant(sdk, operator, effects);
        await registerAgentTenant(sdk, operator, effects);
        assert.deepEqual(
            received.map((registration) => [registration.signedAtMs, registration.requestId]),
            [
                [BigInt(NOW_MS), new Uint8Array(32).fill(0x5a)],
                [BigInt(NOW_MS + 1), new Uint8Array(32).fill(0x5b)],
            ],
        );
    });
});

describe("messageOf", () => {
    it("reads an error's message, and writes anything else thrown as a string", () => {
        assert.deepEqual([new TypeError("bad input"), "plain", 7, null, undefined].map(messageOf), [
            "bad input",
            "plain",
            "7",
            "null",
            "undefined",
        ]);
    });
});
