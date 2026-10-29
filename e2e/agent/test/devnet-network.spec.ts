import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { devnetNetwork } from "../src/devnet-network";

function hex(bytes: Uint8Array): string {
    return `0x${Buffer.from(bytes).toString("hex")}`;
}

function contractsDir(fundingLock: Uint8Array, commitmentLock: Uint8Array): string {
    const dir = mkdtempSync(join(tmpdir(), "agent-contracts-"));
    writeFileSync(join(dir, "funding-lock"), fundingLock);
    writeFileSync(join(dir, "commitment-lock"), commitmentLock);
    return dir;
}

describe("devnetNetwork", () => {
    it("runs each lock by the data2 hash of its binary, with the debug build's epoch and the devnet's currency", () => {
        const network = devnetNetwork(contractsDir(new Uint8Array([0x61, 0x62, 0x63]), new Uint8Array()));
        assert.deepEqual(
            {
                ...network,
                commitmentLock: { ...network.commitmentLock, codeHash: hex(network.commitmentLock.codeHash) },
                fundingLock: { ...network.fundingLock, codeHash: hex(network.fundingLock.codeHash) },
            },
            {
                commitmentLock: { codeHash: "0x44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e", hashType: "data2" },
                fundingLock: { codeHash: "0x521c604cc09b814b0a9106305395def35d0211b9996a3e0f326ae4d671bd8fc2", hashType: "data2" },
                invoiceCurrency: "Fibd",
                fundingLockCellDepsCount: 2,
                millisecondsPerEpoch: 2000,
            },
        );
    });

    it("refuses a contracts folder without the funding lock", () => {
        const dir = mkdtempSync(join(tmpdir(), "agent-contracts-"));
        writeFileSync(join(dir, "commitment-lock"), new Uint8Array());
        assert.throws(() => devnetNetwork(dir), { code: "ENOENT" });
    });

    it("refuses a contracts folder without the commitment lock", () => {
        const dir = mkdtempSync(join(tmpdir(), "agent-contracts-"));
        writeFileSync(join(dir, "funding-lock"), new Uint8Array());
        assert.throws(() => devnetNetwork(dir), { code: "ENOENT" });
    });
});
