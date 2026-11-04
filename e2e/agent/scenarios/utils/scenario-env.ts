import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { SdkNetwork } from "@peersyst/fiber-lsp-sdk";
import { AGENT_NETWORK_NAMES, MAX_TIMER_DELAY_MS } from "../../src/agent.constants";
import type { AgentNetworkName } from "../../src/agent.types";
import { isAgentNetworkName } from "../../src/config";
import { devnetNetwork } from "../../src/devnet-network";

const DEVNET_ENVIRONMENT_FILE = join("tests", "bruno", "environments", "test.bru");

const DEVNET_CONTRACTS_DIR = join("tests", "deploy", "contracts");

const BRU_VARS_BLOCK = /^vars\s*\{\n([\s\S]*?)\n\}/m;

const BRU_VAR_LINE = /^\s*([A-Za-z0-9_]+):\s*(.*?)\s*$/;

const ENV_FILE_LINE = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/;

const POSITIVE_INTEGER = /^[1-9][0-9]*$/;

// fiber#1701 force-closes a channel whose revocation nonce ledger stays unbalanced past PEER_CHANNEL_RESPONSE_TIMEOUT, on the
// next CHECK_CHANNELS_INTERVAL: 30 s and 3 s in the devnet's debug build (d8dd6d28 `fiber/channel.rs:155,6787-6793`,
// `fiber/network.rs:249-251`). A release build keeps the timeout and ticks every 60 s (`fiber/network.rs:252-253`).
const DEBUG_PEER_CHANNEL_RESPONSE_TIMEOUT_MS = 30_000;
const DEBUG_CHECK_CHANNELS_INTERVAL_MS = 3_000;

// As fiber's hosted e2e funds a tenant channel (`lsp-remote-signer-watchtower-preimage`, step 04). Node 2 auto-accepts a public
// channel with as much of its own, the outbound liquidity.
const DEVNET_CHANNEL_SHANNONS = "50000000000";

// An opening waits on the funding tx's confirmation and fiber's channel-ready exchange: minutes on a loaded devnet.
const DEVNET_OPENING_TIMEOUT_MS = 5 * 60_000;

// Gossip runs every second on the devnet, but an announcement waits on the funding tx's confirmations first.
const DEVNET_GRAPH_TIMEOUT_MS = 3 * 60_000;

// Four confirmations of blocks some 10 s apart, behind whatever else the shared pool holds.
const TESTNET_OPENING_TIMEOUT_MS = 10 * 60_000;

// Gossip maintenance runs every 60 s, fiber's default outside its tests.
const TESTNET_GRAPH_TIMEOUT_MS = 10 * 60_000;

// How far inside fiber#1701's timeout `backgrounded-round` comes back, for the rest of the round to land before it.
export const INSIDE_WINDOW_SLACK_MS = 9_000;

// How far past the watchdog's latest check `backgrounded-round` comes back to find the channel closed.
export const PAST_WINDOW_SLACK_MS = 12_000;

// How far past the watchdog's latest check `served-third-session` looks at the channel, still ready.
export const STILL_READY_SLACK_MS = 3_000;

// The widest a scenario waits past the watchdog's latest check: `outbound-payment`'s force close.
export const FORCE_CLOSE_SLACK_MS = 27_000;

// The currency of the SDK's testnet preset, which it does not export.
const TESTNET_INVOICE_CURRENCY = "Fibt";

export type ScenarioChain = {
    network: AgentNetworkName;
    peerChannelResponseTimeoutMs: number;
    checkChannelsIntervalMs: number;
    tenantChannelShannons: string;
    publicChannelShannons: string;
    openingTimeoutMs: number;
    graphTimeoutMs: number;
    invoiceCurrency: string;
};

export type ScenarioEnv = {
    ckbRpcUrl: string;
    node1RpcUrl: string;
    /**
     * Node 2 is the LSP.
     */
    node2RpcUrl: string;
    node3RpcUrl: string;
    node1Addr: string;
    node2Addr: string;
    node3Addr: string;
    node1Pubkey: string;
    node2Pubkey: string;
    node3Pubkey: string;
    operatorToken: string;
    /**
     * Owns the cells of node 1's `default_funding_lock_script`, which funds the device's channels.
     */
    fundingPrivkey: string;
    sdkNetwork: SdkNetwork;
    chain: ScenarioChain;
};

type ScenarioVarReader = (name: string) => string;

function isSet(value: string | undefined): value is string {
    return value !== undefined && value !== "";
}

function readBruVars(text: string, path: string): Map<string, string> {
    const block = BRU_VARS_BLOCK.exec(text);
    if (block === null || block[1] === undefined) throw new Error(`${path} has no vars block`);
    const vars = new Map<string, string>();
    for (const line of block[1].split("\n")) {
        const match = BRU_VAR_LINE.exec(line);
        if (match?.[1] !== undefined && match[2] !== undefined) vars.set(match[1], match[2]);
    }
    return vars;
}

function readEnvFileVars(text: string, path: string): Map<string, string> {
    const vars = new Map<string, string>();
    for (const [index, raw] of text.split("\n").entries()) {
        const line = raw.trim();
        if (line === "" || line.startsWith("#")) continue;
        const match = ENV_FILE_LINE.exec(line);
        if (match?.[1] === undefined || match[2] === undefined) throw new Error(`${path}:${index + 1} is not KEY=value`);
        // The value is taken verbatim, so a space after `=` or a quote would end up in it.
        if (/^\s/.test(match[2])) throw new Error(`${path}:${index + 1} is not KEY=value: whitespace follows the =`);
        if (/^["']/.test(match[2])) throw new Error(`${path}:${index + 1} is not KEY=value: its value is quoted`);
        if (match[2].includes("#")) {
            throw new Error(`${path}:${index + 1} is not KEY=value: a # starts only a whole-line comment`);
        }
        if (vars.has(match[1])) throw new Error(`${path} sets ${match[1]} twice`);
        vars.set(match[1], match[2]);
    }
    return vars;
}

function varReader(vars: Map<string, string>, path: string): ScenarioVarReader {
    return (name) => {
        const value = vars.get(name);
        if (value === undefined || value === "") throw new Error(`${path} does not set ${name}`);
        return value;
    };
}

function readPositiveInteger(read: ScenarioVarReader, name: string, path: string): string {
    const value = read(name);
    if (!POSITIVE_INTEGER.test(value)) throw new Error(`${path}'s ${name} must be a positive integer, got ${JSON.stringify(value)}`);
    return value;
}

// The pair's every derived wait must fit a timer, and the inside margin must stay positive.
function readWatchdogPair(
    read: ScenarioVarReader,
    path: string,
): Pick<ScenarioChain, "peerChannelResponseTimeoutMs" | "checkChannelsIntervalMs"> {
    const timeout = Number(readPositiveInteger(read, "PEER_CHANNEL_RESPONSE_TIMEOUT_MS", path));
    const interval = Number(readPositiveInteger(read, "CHECK_CHANNELS_INTERVAL_MS", path));
    if (timeout <= INSIDE_WINDOW_SLACK_MS) {
        throw new Error(`${path}'s PEER_CHANNEL_RESPONSE_TIMEOUT_MS must be above ${INSIDE_WINDOW_SLACK_MS}`);
    }
    if (timeout + interval + FORCE_CLOSE_SLACK_MS > MAX_TIMER_DELAY_MS) {
        throw new Error(
            `${path}'s PEER_CHANNEL_RESPONSE_TIMEOUT_MS and CHECK_CHANNELS_INTERVAL_MS add up past ${MAX_TIMER_DELAY_MS - FORCE_CLOSE_SLACK_MS}`,
        );
    }
    return { peerChannelResponseTimeoutMs: timeout, checkChannelsIntervalMs: interval };
}

function readNodeVars(read: ScenarioVarReader): Omit<ScenarioEnv, "sdkNetwork" | "chain"> {
    return {
        ckbRpcUrl: read("CKB_RPC_URL"),
        node1RpcUrl: read("NODE1_RPC_URL"),
        node2RpcUrl: read("NODE2_RPC_URL"),
        node3RpcUrl: read("NODE3_RPC_URL"),
        node1Addr: read("NODE1_ADDR"),
        node2Addr: read("NODE2_ADDR"),
        node3Addr: read("NODE3_ADDR"),
        node1Pubkey: read("NODE1_PUBKEY"),
        node2Pubkey: read("NODE2_PUBKEY"),
        node3Pubkey: read("NODE3_PUBKEY"),
        operatorToken: read("LSP_OPERATOR_TOKEN"),
        fundingPrivkey: read("LSP_REMOTE_SIGNER_FUNDING_PRIVKEY"),
    };
}

function readScenarioNetwork(value: string | undefined): AgentNetworkName {
    if (!isSet(value)) return "devnet";
    if (!isAgentNetworkName(value)) {
        throw new Error(`FIBER_E2E_NETWORK must be ${AGENT_NETWORK_NAMES.join(" or ")}, got ${JSON.stringify(value)}`);
    }
    return value;
}

function readDevnetEnv(env: NodeJS.ProcessEnv): ScenarioEnv {
    if (isSet(env.FIBER_E2E_ENV_FILE)) throw new Error("FIBER_E2E_ENV_FILE is read on testnet alone, the devnet's environment is test.bru");
    const checkout = env.FIBER_CHECKOUT;
    if (!isSet(checkout)) throw new Error("FIBER_CHECKOUT must name the fiber checkout the devnet runs from");
    const path = join(checkout, DEVNET_ENVIRONMENT_FILE);
    const read = varReader(readBruVars(readFileSync(path, "utf8"), path), path);
    const network = devnetNetwork(join(checkout, DEVNET_CONTRACTS_DIR));
    return {
        ...readNodeVars(read),
        sdkNetwork: network,
        chain: {
            network: "devnet",
            peerChannelResponseTimeoutMs: DEBUG_PEER_CHANNEL_RESPONSE_TIMEOUT_MS,
            checkChannelsIntervalMs: DEBUG_CHECK_CHANNELS_INTERVAL_MS,
            tenantChannelShannons: DEVNET_CHANNEL_SHANNONS,
            publicChannelShannons: DEVNET_CHANNEL_SHANNONS,
            openingTimeoutMs: DEVNET_OPENING_TIMEOUT_MS,
            graphTimeoutMs: DEVNET_GRAPH_TIMEOUT_MS,
            invoiceCurrency: network.invoiceCurrency,
        },
    };
}

function readTestnetEnv(env: NodeJS.ProcessEnv): ScenarioEnv {
    if (isSet(env.FIBER_CHECKOUT)) throw new Error("FIBER_CHECKOUT is read on the devnet alone, testnet runs on the SDK's preset");
    const path = env.FIBER_E2E_ENV_FILE;
    if (!isSet(path)) throw new Error("FIBER_E2E_ENV_FILE must name the testnet's environment file");
    const read = varReader(readEnvFileVars(readFileSync(path, "utf8"), path), path);
    return {
        ...readNodeVars(read),
        sdkNetwork: "testnet",
        chain: {
            network: "testnet",
            ...readWatchdogPair(read, path),
            tenantChannelShannons: readPositiveInteger(read, "TENANT_CHANNEL_SHANNONS", path),
            publicChannelShannons: readPositiveInteger(read, "PUBLIC_CHANNEL_SHANNONS", path),
            openingTimeoutMs: TESTNET_OPENING_TIMEOUT_MS,
            graphTimeoutMs: TESTNET_GRAPH_TIMEOUT_MS,
            invoiceCurrency: TESTNET_INVOICE_CURRENCY,
        },
    };
}

export function readScenarioEnv(env: NodeJS.ProcessEnv = process.env): ScenarioEnv {
    return readScenarioNetwork(env.FIBER_E2E_NETWORK) === "devnet" ? readDevnetEnv(env) : readTestnetEnv(env);
}

// The latest fiber#1701 force-closes a channel after its ledger unbalances: past the timeout, on the next check.
export function watchdogLatestMs(chain: ScenarioChain): number {
    return chain.peerChannelResponseTimeoutMs + chain.checkChannelsIntervalMs;
}
