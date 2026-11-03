import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { SdkNetworkConfig } from "@peersyst/fiber-lsp-sdk";
import { devnetNetwork } from "../../src/devnet-network";

const ENVIRONMENT_FILE = join("tests", "bruno", "environments", "test.bru");

const CONTRACTS_DIR = join("tests", "deploy", "contracts");

const BRU_VARS_BLOCK = /^vars\s*\{\n([\s\S]*?)\n\}/m;

const BRU_VAR_LINE = /^\s*([A-Za-z0-9_]+):\s*(.*?)\s*$/;

export type DevnetEnv = {
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
    network: SdkNetworkConfig;
};

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

function requireVar(vars: Map<string, string>, name: string, path: string): string {
    const value = vars.get(name);
    if (value === undefined || value === "") throw new Error(`${path} does not set ${name}`);
    return value;
}

export function readDevnetEnv(env: NodeJS.ProcessEnv = process.env): DevnetEnv {
    const checkout = env.FIBER_CHECKOUT;
    if (checkout === undefined || checkout === "") throw new Error("FIBER_CHECKOUT must name the fiber checkout the devnet runs from");
    const path = join(checkout, ENVIRONMENT_FILE);
    const vars = readBruVars(readFileSync(path, "utf8"), path);
    const read = (name: string): string => requireVar(vars, name, path);
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
        network: devnetNetwork(join(checkout, CONTRACTS_DIR)),
    };
}
