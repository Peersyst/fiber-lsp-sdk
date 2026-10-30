import { resolve } from "node:path";
import type { AgentConfig, AgentControlAddr } from "./agent.types";

type AgentFlag = "rpc" | "store" | "operator-token" | "status-file" | "control-addr" | "interval-ms" | "contracts-dir" | "ckb-rpc";

// Fiber's agent reads these from the environment too; `--contracts-dir` and `--ckb-rpc` it does not.
const FLAG_ENV_VARS: Readonly<Record<AgentFlag, string | null>> = {
    rpc: "FIBER_LSP_SDK_AGENT_RPC",
    store: "FIBER_LSP_SDK_AGENT_STORE",
    "operator-token": "FIBER_LSP_SDK_AGENT_OPERATOR_TOKEN",
    "status-file": "FIBER_LSP_SDK_AGENT_STATUS_FILE",
    "control-addr": "FIBER_LSP_SDK_AGENT_CONTROL_ADDR",
    "interval-ms": "FIBER_LSP_SDK_AGENT_INTERVAL_MS",
    "contracts-dir": null,
    "ckb-rpc": null,
};

const DEFAULT_INTERVAL_MS = 200;

const DEFAULT_CONTRACTS_DIR = "../deploy/contracts";

// The SDK's poll interval is a timer delay: at least 1 ms and within a signed 32-bit integer.
const MAX_INTERVAL_MS = 2 ** 31 - 1;

const MAX_PORT = 65_535;

const DECIMAL_PATTERN = /^[0-9]+$/;

/**
 * Tells whether a string names one of the agent's flags.
 * @param name The name after `--`.
 * @returns Whether it is a flag.
 */
function isAgentFlag(name: string): name is AgentFlag {
    return Object.hasOwn(FLAG_ENV_VARS, name);
}

/**
 * Reads the command line into the value of each flag, refusing an unknown flag, a repeated one or one without a value.
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
        intervalMs: intervalMs === null ? DEFAULT_INTERVAL_MS : readInteger("interval-ms", intervalMs, 1, MAX_INTERVAL_MS),
        contractsDir: resolve(readSetting(flags, env, "contracts-dir") ?? DEFAULT_CONTRACTS_DIR),
    };
}
