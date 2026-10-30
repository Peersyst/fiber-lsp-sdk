import { setTimeout as sleep } from "node:timers/promises";
import { FiberLspSdk } from "@peersyst/fiber-lsp-sdk";
import { Agent } from "./agent";
import type { AgentConfig, AgentEffects } from "./agent.types";
import { agentLogger } from "./agent-log";
import { messageOf } from "./agent.utils";
import { parseAgentConfig } from "./config";
import { startControlServer } from "./control-server";

/**
 * Writes a fatal error to stderr and exits.
 * @param error What failed.
 * @param code The exit code.
 */
function fail(error: unknown, code: number): never {
    process.stderr.write(`fiber-lsp-sdk-agent: ${messageOf(error)}\n`);
    process.exit(code);
}

/**
 * Runs the agent: the configuration, the control server when it has an address, then the agent until a signal or a shutdown.
 */
async function main(): Promise<void> {
    let config: AgentConfig;
    try {
        config = parseAgentConfig(process.argv.slice(2), process.env);
    } catch (error) {
        fail(error, 2);
    }
    const effects: AgentEffects = {
        fetch,
        now: Date.now,
        sleep: (ms) => sleep(ms),
        exit: (code) => process.exit(code),
        log: (line) => process.stdout.write(`${line}\n`),
        createSdk: (masterSeed, options) => new FiberLspSdk(masterSeed, options),
    };
    const agent = new Agent(config, effects);
    process.once("SIGINT", () => agent.shutdown());
    process.once("SIGTERM", () => agent.shutdown());
    if (config.controlAddr !== null && config.statusFile !== null) {
        await startControlServer(config.controlAddr, config.statusFile, agent, agentLogger(effects.now, effects.log));
    }
    await agent.start();
}

main().catch((error: unknown) => fail(error, 1));
