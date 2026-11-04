import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { readScenarioEnv } from "../scenarios/utils/scenario-env";
import type { ScenarioEnv } from "../scenarios/utils/scenario-env";

type Vars = readonly (readonly [string, string])[];

const NODE_VARS: Vars = [
    ["CKB_RPC_URL", "http://127.0.0.1:8114"],
    ["NODE1_RPC_URL", "http://127.0.0.1:21714"],
    ["NODE2_RPC_URL", "http://127.0.0.1:21715"],
    ["NODE3_RPC_URL", "http://127.0.0.1:21716"],
    ["NODE1_ADDR", "/ip4/127.0.0.1/tcp/8344/p2p/QmNode1"],
    ["NODE2_ADDR", "/ip4/127.0.0.1/tcp/8345/p2p/QmNode2"],
    ["NODE3_ADDR", "/ip4/127.0.0.1/tcp/8346/p2p/QmNode3"],
    ["NODE1_PUBKEY", "0291a6576bd5a94bd74b27080a48340875338fff9f6d6361fe6b8db8d0d1912fcc"],
    ["NODE2_PUBKEY", "02bcbd0e0d811d13363af1e5998f56e74e6aab8a7aa44005e1ce7d696a4d3f10f6"],
    ["NODE3_PUBKEY", "03fd3a6cd3ec6ba8a4b0d0e0d3d50a0be9a5c4b1a0f8bf0ed0b8a3d21f2c91d1a2"],
    ["LSP_OPERATOR_TOKEN", "En0KEwoRb3BlcmF0b3I"],
    ["LSP_REMOTE_SIGNER_FUNDING_PRIVKEY", "0xd00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc"],
];

const CHAIN_VARS: Vars = [
    ["PEER_CHANNEL_RESPONSE_TIMEOUT_MS", "30000"],
    ["CHECK_CHANNELS_INTERVAL_MS", "60000"],
    ["TENANT_CHANNEL_SHANNONS", "20000000000"],
    ["PUBLIC_CHANNEL_SHANNONS", "50000000000"],
];

const TESTNET_VARS: Vars = [...NODE_VARS, ...CHAIN_VARS];

const MILLISECOND_VARS = ["PEER_CHANNEL_RESPONSE_TIMEOUT_MS", "CHECK_CHANNELS_INTERVAL_MS"] as const;

const SHANNON_VARS = ["TENANT_CHANNEL_SHANNONS", "PUBLIC_CHANNEL_SHANNONS"] as const;

const NODE_ENV = {
    ckbRpcUrl: "http://127.0.0.1:8114",
    node1RpcUrl: "http://127.0.0.1:21714",
    node2RpcUrl: "http://127.0.0.1:21715",
    node3RpcUrl: "http://127.0.0.1:21716",
    node1Addr: "/ip4/127.0.0.1/tcp/8344/p2p/QmNode1",
    node2Addr: "/ip4/127.0.0.1/tcp/8345/p2p/QmNode2",
    node3Addr: "/ip4/127.0.0.1/tcp/8346/p2p/QmNode3",
    node1Pubkey: "0291a6576bd5a94bd74b27080a48340875338fff9f6d6361fe6b8db8d0d1912fcc",
    node2Pubkey: "02bcbd0e0d811d13363af1e5998f56e74e6aab8a7aa44005e1ce7d696a4d3f10f6",
    node3Pubkey: "03fd3a6cd3ec6ba8a4b0d0e0d3d50a0be9a5c4b1a0f8bf0ed0b8a3d21f2c91d1a2",
    operatorToken: "En0KEwoRb3BlcmF0b3I",
    fundingPrivkey: "0xd00c06bfd800d27397002dca6fb0993d5ba6399b4238b2f29ee9deb97593d2bc",
};

const TESTNET_ENV: ScenarioEnv = {
    ...NODE_ENV,
    sdkNetwork: "testnet",
    chain: {
        network: "testnet",
        peerChannelResponseTimeoutMs: 30_000,
        checkChannelsIntervalMs: 60_000,
        tenantChannelShannons: "20000000000",
        publicChannelShannons: "50000000000",
        openingTimeoutMs: 600_000,
        graphTimeoutMs: 600_000,
        invoiceCurrency: "Fibt",
    },
};

function hex(bytes: Uint8Array): string {
    return `0x${Buffer.from(bytes).toString("hex")}`;
}

function checkout(vars: Vars): string {
    const dir = mkdtempSync(join(tmpdir(), "agent-checkout-"));
    const environments = join(dir, "tests", "bruno", "environments");
    const contracts = join(dir, "tests", "deploy", "contracts");
    mkdirSync(environments, { recursive: true });
    mkdirSync(contracts, { recursive: true });
    const lines = vars.map(([name, value]) => `  ${name}: ${value}`).join("\n");
    writeFileSync(join(environments, "test.bru"), `vars {\n${lines}\n}\n`);
    writeFileSync(join(contracts, "funding-lock"), new Uint8Array([0x61, 0x62, 0x63]));
    writeFileSync(join(contracts, "commitment-lock"), new Uint8Array());
    return dir;
}

function bruFile(dir: string): string {
    return join(dir, "tests", "bruno", "environments", "test.bru");
}

function envFile(text: string): string {
    const path = join(mkdtempSync(join(tmpdir(), "agent-testnet-")), "testnet.env");
    writeFileSync(path, text);
    return path;
}

function envFileOf(vars: Vars): string {
    return envFile(vars.map(([name, value]) => `${name}=${value}\n`).join(""));
}

function readTestnet(path: string): ScenarioEnv {
    return readScenarioEnv({ FIBER_E2E_NETWORK: "testnet", FIBER_E2E_ENV_FILE: path });
}

function withVar(name: string, value: string): Vars {
    return TESTNET_VARS.map(([other, current]) => [other, other === name ? value : current] as const);
}

describe("readScenarioEnv on the devnet", () => {
    it("reads every var of test.bru, the network from the checkout's contracts, and the debug build's chain", () => {
        const env = readScenarioEnv({ FIBER_CHECKOUT: checkout(NODE_VARS) });
        if (typeof env.sdkNetwork === "string") assert.fail(`the devnet's network is the preset ${env.sdkNetwork}`);
        assert.deepEqual(
            {
                ...env,
                sdkNetwork: {
                    ...env.sdkNetwork,
                    commitmentLock: { ...env.sdkNetwork.commitmentLock, codeHash: hex(env.sdkNetwork.commitmentLock.codeHash) },
                    fundingLock: { ...env.sdkNetwork.fundingLock, codeHash: hex(env.sdkNetwork.fundingLock.codeHash) },
                },
            },
            {
                ...NODE_ENV,
                sdkNetwork: {
                    commitmentLock: { codeHash: "0x44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e", hashType: "data2" },
                    fundingLock: { codeHash: "0x521c604cc09b814b0a9106305395def35d0211b9996a3e0f326ae4d671bd8fc2", hashType: "data2" },
                    invoiceCurrency: "Fibd",
                    fundingLockCellDepsCount: 2,
                    millisecondsPerEpoch: 2000,
                },
                chain: {
                    network: "devnet",
                    peerChannelResponseTimeoutMs: 30_000,
                    checkChannelsIntervalMs: 3_000,
                    tenantChannelShannons: "50000000000",
                    publicChannelShannons: "50000000000",
                    openingTimeoutMs: 300_000,
                    graphTimeoutMs: 180_000,
                    invoiceCurrency: "Fibd",
                },
            },
        );
    });

    for (const [name, network] of [
        ["absent", {}],
        ["empty", { FIBER_E2E_NETWORK: "" }],
        ["devnet", { FIBER_E2E_NETWORK: "devnet" }],
    ] as const) {
        it(`reads the devnet with FIBER_E2E_NETWORK ${name}`, () => {
            assert.equal(readScenarioEnv({ ...network, FIBER_CHECKOUT: checkout(NODE_VARS) }).chain.network, "devnet");
        });
    }

    it("takes an empty FIBER_E2E_ENV_FILE for unset", () => {
        assert.equal(readScenarioEnv({ FIBER_CHECKOUT: checkout(NODE_VARS), FIBER_E2E_ENV_FILE: "" }).chain.network, "devnet");
    });

    for (const [name] of NODE_VARS) {
        it(`refuses a test.bru without ${name}`, () => {
            const dir = checkout(NODE_VARS.filter(([other]) => other !== name));
            assert.throws(() => readScenarioEnv({ FIBER_CHECKOUT: dir }), { message: `${bruFile(dir)} does not set ${name}` });
        });

        it(`refuses a test.bru whose ${name} is empty`, () => {
            const dir = checkout(NODE_VARS.map(([other, value]) => [other, other === name ? "" : value] as const));
            assert.throws(() => readScenarioEnv({ FIBER_CHECKOUT: dir }), { message: `${bruFile(dir)} does not set ${name}` });
        });
    }

    it("refuses a test.bru without a vars block", () => {
        const dir = checkout(NODE_VARS);
        writeFileSync(bruFile(dir), "meta {\n  name: test\n}\n");
        assert.throws(() => readScenarioEnv({ FIBER_CHECKOUT: dir }), { message: `${bruFile(dir)} has no vars block` });
    });

    for (const [name, env] of [
        ["absent", {}],
        ["empty", { FIBER_CHECKOUT: "" }],
    ] as const) {
        it(`refuses FIBER_CHECKOUT ${name}`, () => {
            assert.throws(() => readScenarioEnv(env), { message: "FIBER_CHECKOUT must name the fiber checkout the devnet runs from" });
        });
    }

    it("refuses FIBER_E2E_ENV_FILE", () => {
        assert.throws(() => readScenarioEnv({ FIBER_CHECKOUT: checkout(NODE_VARS), FIBER_E2E_ENV_FILE: envFileOf(TESTNET_VARS) }), {
            message: "FIBER_E2E_ENV_FILE is read on testnet alone, the devnet's environment is test.bru",
        });
    });
});

describe("readScenarioEnv's network", () => {
    for (const value of ["mainnet", "Testnet", "DEVNET", " testnet", "testnet "]) {
        it(`refuses FIBER_E2E_NETWORK ${JSON.stringify(value)}`, () => {
            assert.throws(() => readScenarioEnv({ FIBER_E2E_NETWORK: value, FIBER_CHECKOUT: checkout(NODE_VARS) }), {
                message: `FIBER_E2E_NETWORK must be devnet or testnet, got ${JSON.stringify(value)}`,
            });
        });
    }
});

describe("readScenarioEnv on testnet", () => {
    it("reads every key of the environment file, on the SDK's testnet preset", () => {
        assert.deepEqual(readTestnet(envFileOf(TESTNET_VARS)), TESTNET_ENV);
    });

    it("skips blank lines and comments, ignores keys it does not read, and keeps an = inside a value", () => {
        const path = envFile(
            [
                "# the testnet's LSP",
                "#x",
                "",
                "LSP_SDK_AGENT_URL=http://127.0.0.1:21917",
                "   ",
                ...TESTNET_VARS.map(([name, value]) => (name === "LSP_OPERATOR_TOKEN" ? `${name}=${value}==` : `${name}=${value}`)),
                "  # trailing",
            ].join("\r\n"),
        );
        assert.deepEqual(readTestnet(path), { ...TESTNET_ENV, operatorToken: "En0KEwoRb3BlcmF0b3I==" });
    });

    for (const [name, env] of [
        ["absent", { FIBER_E2E_NETWORK: "testnet" }],
        ["empty", { FIBER_E2E_NETWORK: "testnet", FIBER_E2E_ENV_FILE: "" }],
    ] as const) {
        it(`refuses FIBER_E2E_ENV_FILE ${name}`, () => {
            assert.throws(() => readScenarioEnv(env), { message: "FIBER_E2E_ENV_FILE must name the testnet's environment file" });
        });
    }

    it("refuses FIBER_CHECKOUT", () => {
        const env = { FIBER_E2E_NETWORK: "testnet", FIBER_E2E_ENV_FILE: envFileOf(TESTNET_VARS), FIBER_CHECKOUT: checkout(NODE_VARS) };
        assert.throws(() => readScenarioEnv(env), {
            message: "FIBER_CHECKOUT is read on the devnet alone, testnet runs on the SDK's preset",
        });
    });

    it("takes an empty FIBER_CHECKOUT for unset", () => {
        const env = { FIBER_E2E_NETWORK: "testnet", FIBER_E2E_ENV_FILE: envFileOf(TESTNET_VARS), FIBER_CHECKOUT: "" };
        assert.deepEqual(readScenarioEnv(env), TESTNET_ENV);
    });

    for (const [name] of TESTNET_VARS) {
        it(`refuses an environment file without ${name}`, () => {
            const path = envFileOf(TESTNET_VARS.filter(([other]) => other !== name));
            assert.throws(() => readTestnet(path), { message: `${path} does not set ${name}` });
        });

        it(`refuses an environment file whose ${name} is empty`, () => {
            const path = envFileOf(withVar(name, ""));
            assert.throws(() => readTestnet(path), { message: `${path} does not set ${name}` });
        });
    }

    for (const name of [...MILLISECOND_VARS, ...SHANNON_VARS]) {
        for (const value of ["0", "-1", "+1", "1.5", "01", "1e3", "0x10", "1 2", "one"]) {
            it(`refuses ${name} ${JSON.stringify(value)}`, () => {
                const path = envFileOf(withVar(name, value));
                assert.throws(() => readTestnet(path), {
                    message: `${path}'s ${name} must be a positive integer, got ${JSON.stringify(value)}`,
                });
            });
        }
    }

    function withPair(timeout: string, interval: string): string {
        return envFileOf(
            TESTNET_VARS.map(([name, value]) => [
                name,
                name === "PEER_CHANNEL_RESPONSE_TIMEOUT_MS" ? timeout : name === "CHECK_CHANNELS_INTERVAL_MS" ? interval : value,
            ]),
        );
    }

    function pairOf(path: string): [number, number] {
        const { chain } = readTestnet(path);
        return [chain.peerChannelResponseTimeoutMs, chain.checkChannelsIntervalMs];
    }

    it("takes 1 for the check interval and each amount", () => {
        const path = envFileOf(
            TESTNET_VARS.map(([name, value]) =>
                ["CHECK_CHANNELS_INTERVAL_MS", "TENANT_CHANNEL_SHANNONS", "PUBLIC_CHANNEL_SHANNONS"].includes(name)
                    ? [name, "1"]
                    : [name, value],
            ),
        );
        assert.deepEqual(readTestnet(path).chain, {
            ...TESTNET_ENV.chain,
            checkChannelsIntervalMs: 1,
            tenantChannelShannons: "1",
            publicChannelShannons: "1",
        });
    });

    it("takes a peer response timeout just above backgrounded-round's inside margin", () => {
        assert.deepEqual(pairOf(withPair("9001", "60000")), [9001, 60000]);
    });

    it("refuses a peer response timeout at backgrounded-round's inside margin", () => {
        const path = withPair("9000", "60000");
        assert.throws(() => readTestnet(path), { message: `${path}'s PEER_CHANNEL_RESPONSE_TIMEOUT_MS must be above 9000` });
    });

    // 2^31 - 1 less the widest slack, 27 s: the longest a timer can wait past the watchdog's latest check.
    for (const [name, timeout, interval] of [
        ["the interval", "30000", "2147426647"],
        ["the timeout", "2147456646", "1"],
    ] as const) {
        it(`takes a pair whose sum reaches what a timer waits, by ${name}`, () => {
            assert.deepEqual(pairOf(withPair(timeout, interval)), [Number(timeout), Number(interval)]);
        });
    }

    for (const [name, timeout, interval] of [
        ["the interval", "30000", "2147426648"],
        ["the timeout", "2147456647", "1"],
        ["an interval past the safe integers", "30000", "9007199254740993"],
    ] as const) {
        it(`refuses a pair whose sum passes what a timer waits, by ${name}`, () => {
            const path = withPair(timeout, interval);
            assert.throws(() => readTestnet(path), {
                message: `${path}'s PEER_CHANNEL_RESPONSE_TIMEOUT_MS and CHECK_CHANNELS_INTERVAL_MS add up past 2147456647`,
            });
        });
    }

    for (const name of SHANNON_VARS) {
        it(`takes ${name} past the largest safe integer, as a string`, () => {
            const chain = readTestnet(envFileOf(withVar(name, "340282366920938463463374607431768211455"))).chain;
            assert.equal(
                name === "TENANT_CHANNEL_SHANNONS" ? chain.tenantChannelShannons : chain.publicChannelShannons,
                "340282366920938463463374607431768211455",
            );
        });
    }

    for (const line of [
        "NODE1_RPC_URL",
        "NODE1_RPC_URL =http://127.0.0.1:21714",
        "export NODE1_RPC_URL=http://127.0.0.1:21714",
        "1NODE=x",
        "=x",
    ]) {
        it(`refuses the line ${JSON.stringify(line)}`, () => {
            const path = envFile(`# the testnet's LSP\n${TESTNET_VARS.map(([name, value]) => `${name}=${value}`).join("\n")}\n${line}\n`);
            assert.throws(() => readTestnet(path), { message: `${path}:${TESTNET_VARS.length + 2} is not KEY=value` });
        });
    }

    for (const [name, value, problem] of [
        ["a leading space", " 02bcbd0e0d811d13363af1e5998f56e74e6aab8a7aa44005e1ce7d696a4d3f10f6", "whitespace follows the ="],
        ["a leading tab", "\t02bcbd0e0d811d13363af1e5998f56e74e6aab8a7aa44005e1ce7d696a4d3f10f6", "whitespace follows the ="],
        ["double quotes", '"02bcbd0e0d811d13363af1e5998f56e74e6aab8a7aa44005e1ce7d696a4d3f10f6"', "its value is quoted"],
        ["single quotes", "'02bcbd0e0d811d13363af1e5998f56e74e6aab8a7aa44005e1ce7d696a4d3f10f6'", "its value is quoted"],
    ] as const) {
        it(`refuses a value with ${name}, naming the line and not the value`, () => {
            const path = envFileOf(withVar("NODE2_PUBKEY", value));
            const line = TESTNET_VARS.findIndex(([key]) => key === "NODE2_PUBKEY") + 1;
            assert.throws(() => readTestnet(path), { message: `${path}:${line} is not KEY=value: ${problem}` });
        });
    }

    it("refuses a # inside a value, naming the line and not the value", () => {
        const path = envFileOf(withVar("LSP_OPERATOR_TOKEN", "En0KEwoRb3#BlcmF0b3I"));
        const line = TESTNET_VARS.findIndex(([key]) => key === "LSP_OPERATOR_TOKEN") + 1;
        assert.throws(() => readTestnet(path), { message: `${path}:${line} is not KEY=value: a # starts only a whole-line comment` });
    });

    it("refuses a key set twice", () => {
        const path = envFileOf([...TESTNET_VARS, ["NODE1_RPC_URL", "http://127.0.0.1:21714"]]);
        assert.throws(() => readTestnet(path), { message: `${path} sets NODE1_RPC_URL twice` });
    });
});
