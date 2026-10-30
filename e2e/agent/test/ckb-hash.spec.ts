import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ckbBlake2b } from "../src/ckb-hash";

function hex(bytes: Uint8Array): string {
    return `0x${Buffer.from(bytes).toString("hex")}`;
}

describe("ckbBlake2b", () => {
    it("hashes nothing to CKB's empty hash", () => {
        assert.equal(hex(ckbBlake2b(new Uint8Array())), "0x44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e");
    });

    it("hashes a few bytes under the ckb-default-hash personalisation", () => {
        assert.equal(
            hex(ckbBlake2b(new Uint8Array([0x61, 0x62, 0x63]))),
            "0x521c604cc09b814b0a9106305395def35d0211b9996a3e0f326ae4d671bd8fc2",
        );
    });
});
