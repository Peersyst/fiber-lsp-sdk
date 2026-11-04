import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { describe, it } from "node:test";
import type { ScriptJson } from "../src/agent.types";
import { sighashAllLock, signSighashAllInputs } from "../src/sighash-signer";
import { TESTNET_TX } from "./utils/ckb-testnet-tx";

const CLI = join(__dirname, "..", "src", "sign-tx.js");

const PRIVATE_KEY = "0x1111111111111111111111111111111111111111111111111111111111111111";

// Nothing listens there, so resolving an input's lock fails without the network.
const CLOSED_RPC = "http://127.0.0.1:9";

type Run = { status: number | null; stdout: string; stderr: string };

function run(env: Record<string, string>, stdin: string): Run {
    const result = spawnSync(process.execPath, [CLI], { env: { PATH: process.env.PATH ?? "", ...env }, input: stdin, encoding: "utf8" });
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

const UNSIGNED = JSON.stringify({ ...TESTNET_TX, witnesses: [] });

const OTHER_LOCK: ScriptJson = {
    code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
    hash_type: "type",
    args: "0x8e0e0590f4a1b5d38e19f9bd58e9e3d0ae6ad9c6",
};

// The CLI blocks no event loop of this process, so the server here answers it while it runs.
function runAsync(env: Record<string, string>, stdin: string): Promise<Run> {
    return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [CLI], { env: { PATH: process.env.PATH ?? "", ...env } });
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString()));
        child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
        child.on("error", reject);
        child.on("close", (status) => resolve({ status, stdout, stderr }));
        child.stdin.end(stdin);
    });
}

// A CKB RPC whose live cells are the vector's inputs: the first under the key's lock, the second under another.
async function liveCellRpc(keyLock: ScriptJson): Promise<{ url: string; methods: string[]; close: () => Promise<void> }> {
    const methods: string[] = [];
    const server = createServer((request, response) => {
        let body = "";
        request.on("data", (chunk: Buffer) => (body += chunk.toString()));
        request.on("end", () => {
            const call = JSON.parse(body) as { method: string; params: [{ tx_hash: string }, boolean] };
            methods.push(call.method);
            const lock = call.params[0].tx_hash === TESTNET_TX.inputs[0]?.previous_output.tx_hash ? keyLock : OTHER_LOCK;
            const result = { cell: { output: { capacity: "0x174876e800", lock, type: null }, data: null }, status: "live" };
            response.end(JSON.stringify({ jsonrpc: "2.0", result, id: 1 }));
        });
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    return { url: `http://127.0.0.1:${port}`, methods, close: () => new Promise((resolve) => server.close(() => resolve())) };
}

describe("sign-tx", () => {
    it("writes the tx with the key's input signed, and nothing on stderr", async () => {
        const keyLock = sighashAllLock(PRIVATE_KEY);
        const rpc = await liveCellRpc(keyLock);
        try {
            const result = await runAsync({ CKB_SIGNER_PRIVATE_KEY: PRIVATE_KEY, CKB_RPC_URL: rpc.url }, UNSIGNED);
            const unsigned = { ...TESTNET_TX, witnesses: [] };
            const expected = await signSighashAllInputs(unsigned, PRIVATE_KEY, async (outPoint) =>
                outPoint.tx_hash === TESTNET_TX.inputs[0]?.previous_output.tx_hash ? keyLock : OTHER_LOCK,
            );
            assert.deepEqual(result, { status: 0, stdout: `${JSON.stringify(expected)}\n`, stderr: "" });
            assert.deepEqual(rpc.methods, ["get_live_cell", "get_live_cell"]);
        } finally {
            await rpc.close();
        }
    });

    for (const [name, env, variable] of [
        ["without the key", { CKB_RPC_URL: CLOSED_RPC }, "CKB_SIGNER_PRIVATE_KEY"],
        ["with an empty key", { CKB_SIGNER_PRIVATE_KEY: "", CKB_RPC_URL: CLOSED_RPC }, "CKB_SIGNER_PRIVATE_KEY"],
        ["without the CKB RPC", { CKB_SIGNER_PRIVATE_KEY: PRIVATE_KEY }, "CKB_RPC_URL"],
        ["with an empty CKB RPC", { CKB_SIGNER_PRIVATE_KEY: PRIVATE_KEY, CKB_RPC_URL: "" }, "CKB_RPC_URL"],
    ] as const) {
        it(`exits 1 ${name}`, () => {
            assert.deepEqual(run(env, UNSIGNED), { status: 1, stdout: "", stderr: `sign-tx: ${variable} must be set\n` });
        });
    }

    it("exits 1 on stdin that is not JSON", () => {
        assert.deepEqual(run({ CKB_SIGNER_PRIVATE_KEY: PRIVATE_KEY, CKB_RPC_URL: CLOSED_RPC }, "not json"), {
            status: 1,
            stdout: "",
            stderr: "sign-tx: stdin is not JSON\n",
        });
    });

    it("exits 1 on JSON that is not a tx", () => {
        assert.deepEqual(run({ CKB_SIGNER_PRIVATE_KEY: PRIVATE_KEY, CKB_RPC_URL: CLOSED_RPC }, "[]"), {
            status: 1,
            stdout: "",
            stderr: "sign-tx: tx must be an object\n",
        });
    });

    it("exits 1 on a malformed key, and writes no part of it", () => {
        const key = `${PRIVATE_KEY}ff`;
        const result = run({ CKB_SIGNER_PRIVATE_KEY: key, CKB_RPC_URL: CLOSED_RPC }, UNSIGNED);
        assert.deepEqual(result, { status: 1, stdout: "", stderr: "sign-tx: the private key must be 32 bytes of 0x hex\n" });
    });

    it("exits 1 when no input's lock can be read, and never writes the key", () => {
        const result = run({ CKB_SIGNER_PRIVATE_KEY: PRIVATE_KEY, CKB_RPC_URL: CLOSED_RPC }, UNSIGNED);
        assert.equal(result.status, 1);
        assert.equal(result.stdout, "");
        assert.match(result.stderr, /^sign-tx: get_live_cell: no answer from http:\/\/127\.0\.0\.1:9: .+\n$/);
        assert.equal(result.stderr.includes(PRIVATE_KEY.slice(2)), false);
    });
});
