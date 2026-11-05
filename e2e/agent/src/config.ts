import { resolve } from "node:path";
import { AGENT_NETWORK_NAMES, MAX_TIMER_DELAY_MS } from "./agent.constants";
import type { AgentConfig, AgentControlAddr, AgentNetwork, AgentNetworkName } from "./agent.types";

type AgentFlag =
    | "rpc"
    | "ws-rpc"
    | "store"
    | "operator-token"
    | "lsp-node-id"
    | "status-file"
    | "control-addr"
    | "interval-ms"
    | "network"
    | "contracts-dir"
    | "ckb-rpc"
    | "nonce-cap-bypass";

// Fiber's agent reads these from the environment too; `--contracts-dir` and `--ckb-rpc` it does not. `--interval-ms`,
// `--network` and `--nonce-cap-bypass` are this agent's alone. `--ws-rpc` is taken and left: fiber's agent subscribes there,
// this one polls.
const FLAG_ENV_VARS: Readonly<Record<AgentFlag, string | null>> = {
    rpc: "FIBER_LSP_SDK_AGENT_RPC",
    "ws-rpc": "FIBER_LSP_SDK_AGENT_WS_RPC",
    store: "FIBER_LSP_SDK_AGENT_STORE",
    "operator-token": "FIBER_LSP_SDK_AGENT_OPERATOR_TOKEN",
    "lsp-node-id": "FIBER_LSP_SDK_AGENT_LSP_NODE_ID",
    "status-file": "FIBER_LSP_SDK_AGENT_STATUS_FILE",
    "control-addr": "FIBER_LSP_SDK_AGENT_CONTROL_ADDR",
    "interval-ms": "FIBER_LSP_SDK_AGENT_INTERVAL_MS",
    network: "FIBER_LSP_SDK_AGENT_NETWORK",
    "contracts-dir": null,
    "ckb-rpc": null,
    "nonce-cap-bypass": "FIBER_LSP_SDK_AGENT_NONCE_CAP_BYPASS",
};

const SWITCH_FLAGS: readonly AgentFlag[] = ["nonce-cap-bypass"];

const SWITCH_VALUES: Readonly<Record<string, boolean>> = { true: true, "1": true, false: false, "0": false };

const DEFAULT_INTERVAL_MS = 200;

const DEFAULT_AGENT_NETWORK: AgentNetworkName = "devnet";

const DEFAULT_CONTRACTS_DIR = "../deploy/contracts";

const MAX_PORT = 65_535;

const DECIMAL_PATTERN = /^[0-9]+$/;

// A compressed secp256k1 point, as fiber's agent reads it: `0x` optional.
const NODE_ID_PATTERN = /^(?:0x)?(?:02|03)[0-9a-fA-F]{64}$/;

/**
 * Tells whether a string names one of the agent's flags.
 * @param name The name after `--`.
 * @returns Whether it is a flag.
 */
function isAgentFlag(name: string): name is AgentFlag {
    return Object.hasOwn(FLAG_ENV_VARS, name);
}

/**
 * Reads the command line into the value of each flag.
 * @param argv The arguments after the program.
 * @returns The value of each flag given.
 */
function readFlags(argv: readonly string[]): Map<AgentFlag, string> {
    const flags = new Map<AgentFlag, string>();
    for (let index = 0; index < argv.length; index++) {
        const argument = argv[index] ?? "";
        if (!argument.startsWith("--")) throw new Error(`unexpected argument ${JSON.stringify(argument)}`);
        const separator = argument.indexOf("=");
        const name = separator === -1 ? argument.slice(2) : argument.slice(2, separator);
        if (!isAgentFlag(name)) throw new Error(`unknown flag --${name}`);
        if (flags.has(name)) throw new Error(`--${name} is given more than once`);
        if (SWITCH_FLAGS.includes(name)) {
            if (separator !== -1) throw new Error(`--${name} takes no value`);
            flags.set(name, "true");
            continue;
        }
        let value: string | undefined;
        if (separator !== -1) {
            value = argument.slice(separator + 1);
        } else {
            value = argv[index + 1];
            if (value !== undefined && value.startsWith("--")) value = undefined;
            index++;
        }
        if (value === undefined || value === "") throw new Error(`--${name} requires a value`);
        flags.set(name, value);
    }
    return flags;
}

/**
 * Reads a decimal integer within bounds.
 * @param name The flag it came from, for the refusal.
 * @param value The text.
 * @param min The lowest value allowed.
 * @param max The highest value allowed.
 * @returns The integer.
 */
function readInteger(name: string, value: string, min: number, max: number): number {
    const integer = DECIMAL_PATTERN.test(value) ? Number(value) : Number.NaN;
    if (!(integer >= min && integer <= max))
        throw new Error(`--${name} must be an integer between ${min} and ${max}, got ${JSON.stringify(value)}`);
    return integer;
}

/**
 * Reads the LSP's node id, a compressed public key with or without `0x`.
 * @param value The text.
 * @returns The id, bare lowercase hex.
 */
function readNodeId(value: string): string {
    if (!NODE_ID_PATTERN.test(value)) {
        throw new Error(`--lsp-node-id must be a 33-byte compressed public key in hex, got ${JSON.stringify(value)}`);
    }
    return value.slice(value.length - 66).toLowerCase();
}

/**
 * Reads a switch: on when given as a flag, else as its environment variable says.
 * @param value The setting's value, `"true"` when the flag was given.
 * @param name The switch, for the refusal.
 * @returns Whether it is on.
 */
function readSwitch(value: string | null, name: AgentFlag): boolean {
    if (value === null) return false;
    const on = Object.hasOwn(SWITCH_VALUES, value) ? SWITCH_VALUES[value] : undefined;
    if (on === undefined)
        throw new Error(`${FLAG_ENV_VARS[name] ?? `--${name}`} must be true, false, 1 or 0, got ${JSON.stringify(value)}`);
    return on;
}

/**
 * Tells whether a string names one of the networks the agent runs on.
 * @param value The text.
 * @returns Whether it is a network.
 */
export function isAgentNetworkName(value: string): value is AgentNetworkName {
    return AGENT_NETWORK_NAMES.some((name) => name === value);
}

/**
 * Reads the network: the devnet with its contracts folder, or testnet on the SDK's preset.
 * @param value The setting's value, `null` when neither its flag nor its variable gives one.
 * @param contractsDir The contracts folder given, `null` when none was.
 * @returns The network.
 */
function readNetwork(value: string | null, contractsDir: string | null): AgentNetwork {
    const name = value ?? DEFAULT_AGENT_NETWORK;
    if (!isAgentNetworkName(name)) {
        throw new Error(`--network must be ${AGENT_NETWORK_NAMES.join(" or ")}, got ${JSON.stringify(name)}`);
    }
    if (name === "devnet") return { name, contractsDir: resolve(contractsDir ?? DEFAULT_CONTRACTS_DIR) };
    if (contractsDir !== null) throw new Error(`--contracts-dir is the devnet's alone: ${name}'s contracts are the SDK's preset`);
    return { name };
}

/**
 * Reads a `host:port` address, an IPv6 host in brackets.
 * @param value The text.
 * @returns The address.
 */
function readControlAddr(value: string): AgentControlAddr {
    const separator = value.lastIndexOf(":");
    if (separator === -1) throw new Error(`--control-addr must be host:port, got ${JSON.stringify(value)}`);
    let host = value.slice(0, separator);
    if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
    if (host === "") throw new Error(`--control-addr must name a host, got ${JSON.stringify(value)}`);
    return { host, port: readInteger("control-addr", value.slice(separator + 1), 0, MAX_PORT) };
}

type AgentEnv = Readonly<Record<string, string | undefined>>;

/**
 * Reads one setting: its flag, else its environment variable, an empty one counting as unset.
 * @param flags The flags given.
 * @param env The environment.
 * @param name The setting.
 * @returns Its value, or `null` when neither gives one.
 */
function readSetting(flags: ReadonlyMap<AgentFlag, string>, env: AgentEnv, name: AgentFlag): string | null {
    const flag = flags.get(name);
    if (flag !== undefined) return flag;
    const variable = FLAG_ENV_VARS[name];
    const value = variable === null ? undefined : env[variable];
    return value === undefined || value === "" ? null : value;
}

/**
 * Reads a setting the agent cannot run without.
 * @param flags The flags given.
 * @param env The environment.
 * @param name The setting.
 * @returns Its value.
 */
function readRequiredSetting(flags: ReadonlyMap<AgentFlag, string>, env: AgentEnv, name: AgentFlag): string {
    const value = readSetting(flags, env, name);
    if (value === null) throw new Error(`--${name} (or ${FLAG_ENV_VARS[name] ?? "its variable"}) is required`);
    return value;
}

/**
 * Reads the agent's configuration as fiber's agent does: each flag, else its environment variable, else its default.
 * @param argv The arguments after the program, `--flag value` or `--flag=value`.
 * @param env The environment.
 * @returns The configuration.
 */
export function parseAgentConfig(argv: readonly string[], env: AgentEnv): AgentConfig {
    const flags = readFlags(argv);
    const rpc = readRequiredSetting(flags, env, "rpc");
    const storeDir = readRequiredSetting(flags, env, "store");
    const operatorToken = readRequiredSetting(flags, env, "operator-token");
    const lspNodeId = readNodeId(readRequiredSetting(flags, env, "lsp-node-id"));
    const statusFile = readSetting(flags, env, "status-file");
    const controlAddr = readSetting(flags, env, "control-addr");
    if (controlAddr !== null && statusFile === null) throw new Error("--control-addr requires --status-file");
    const intervalMs = readSetting(flags, env, "interval-ms");
    return {
        rpcUrl: rpc.startsWith("http://") || rpc.startsWith("https://") ? rpc : `http://${rpc}`,
        storeDir,
        statusFile,
        controlAddr: controlAddr === null ? null : readControlAddr(controlAddr),
        operatorToken,
        lspNodeId,
        intervalMs: intervalMs === null ? DEFAULT_INTERVAL_MS : readInteger("interval-ms", intervalMs, 1, MAX_TIMER_DELAY_MS),
        network: readNetwork(readSetting(flags, env, "network"), readSetting(flags, env, "contracts-dir")),
        nonceCapBypass: readSwitch(readSetting(flags, env, "nonce-cap-bypass"), "nonce-cap-bypass"),
    };
}
