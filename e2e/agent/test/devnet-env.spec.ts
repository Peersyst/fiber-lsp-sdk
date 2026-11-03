import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { readDevnetEnv } from "../scenarios/utils/devnet-env";

const VARS: readonly (readonly [string, string])[] = [
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

function hex(bytes: Uint8Array): string {
    return `0x${Buffer.from(bytes).toString("hex")}`;
}

function checkout(vars: readonly (readonly [string, string])[]): string {
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

function environmentFile(dir: string): string {
    return join(dir, "tests", "bruno", "environments", "test.bru");
}

describe("readDevnetEnv", () => {
    it("reads every var of test.bru, and the network from the checkout's contracts", () => {
        const env = readDevnetEnv({ FIBER_CHECKOUT: checkout(VARS) });
        assert.deepEqual(
            {
                ...env,
                network: {
                    ...env.network,
                    commitmentLock: { ...env.network.commitmentLock, codeHash: hex(env.network.commitmentLock.codeHash) },
                    fundingLock: { ...env.network.fundingLock, codeHash: hex(env.network.fundingLock.codeHash) },
                },
            },
            {
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
                network: {
                    commitmentLock: { codeHash: "0x44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e", hashType: "data2" },
                    fundingLock: { codeHash: "0x521c604cc09b814b0a9106305395def35d0211b9996a3e0f326ae4d671bd8fc2", hashType: "data2" },
                    invoiceCurrency: "Fibd",
                    fundingLockCellDepsCount: 2,
                    millisecondsPerEpoch: 2000,
                },
            },
        );
    });

    for (const [name] of VARS) {
        it(`refuses a test.bru without ${name}`, () => {
            const dir = checkout(VARS.filter(([other]) => other !== name));
            assert.throws(() => readDevnetEnv({ FIBER_CHECKOUT: dir }), { message: `${environmentFile(dir)} does not set ${name}` });
        });

        it(`refuses a test.bru whose ${name} is empty`, () => {
            const dir = checkout(VARS.map(([other, value]) => [other, other === name ? "" : value] as const));
            assert.throws(() => readDevnetEnv({ FIBER_CHECKOUT: dir }), { message: `${environmentFile(dir)} does not set ${name}` });
        });
    }

    it("refuses a test.bru without a vars block", () => {
        const dir = checkout(VARS);
        writeFileSync(environmentFile(dir), "meta {\n  name: test\n}\n");
        assert.throws(() => readDevnetEnv({ FIBER_CHECKOUT: dir }), { message: `${environmentFile(dir)} has no vars block` });
    });

    for (const [name, env] of [
        ["absent", {}],
        ["empty", { FIBER_CHECKOUT: "" }],
    ] as const) {
        it(`refuses FIBER_CHECKOUT ${name}`, () => {
            assert.throws(() => readDevnetEnv(env), { message: "FIBER_CHECKOUT must name the fiber checkout the devnet runs from" });
        });
    }
});
