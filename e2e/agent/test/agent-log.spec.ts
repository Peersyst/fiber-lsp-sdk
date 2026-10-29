import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { SdkError } from "@peersyst/fiber-lsp-sdk";
import { agentLogLine, agentLogger } from "../src/agent-log";

const NOW_MS = 1_800_000_000_000;

const TIMESTAMP = "2027-01-15T08:00:00.000Z";

describe("agentLogLine", () => {
    it("writes one JSON object: the time, the kind, then the fields", () => {
        assert.equal(
            agentLogLine(NOW_MS, "initialize_failed", { error: "node is starting" }),
            `{"ts":"${TIMESTAMP}","kind":"initialize_failed","error":"node is starting"}`,
        );
    });

    it("writes a bigint as its decimal string and bytes as lowercase hex, however deep", () => {
        const line = agentLogLine(NOW_MS, "probe", { amount: 18446744073709551615n, nested: { key: new Uint8Array([0x0a, 0xff]) } });
        assert.equal(line, `{"ts":"${TIMESTAMP}","kind":"probe","amount":"18446744073709551615","nested":{"key":"0aff"}}`);
    });

    it("writes an SDK error event with its code, its message and its cause", () => {
        const cause = new Error("list_channels is down");
        const event = { type: "ERROR", error: new SdkError("poll_failed", "a poll of the node failed: list_channels is down", { cause }) };
        assert.deepEqual(JSON.parse(agentLogLine(NOW_MS, "sdk_event", event)), {
            ts: TIMESTAMP,
            kind: "sdk_event",
            type: "ERROR",
            error: {
                name: "SdkError",
                message: "a poll of the node failed: list_channels is down",
                code: "poll_failed",
                cause: { name: "Error", message: "list_channels is down" },
            },
        });
    });

    it("writes a refused signing event in full", () => {
        const event = {
            type: "SIGNING",
            channelId: "0x4056792f61337675c153ab8f10c442fa68a913a18ce6f8beec37a19c23d5aa4d",
            requestId: "0x1",
            transition: "CompleteReceivedCommitment",
            outcome: "refused",
            error: { code: "nonce_reuse", message: "the slot already served two sessions" },
            deadlineMs: 1_800_000_600_000,
        };
        assert.deepEqual(JSON.parse(agentLogLine(NOW_MS, "sdk_event", event)), { ts: TIMESTAMP, kind: "sdk_event", ...event });
    });
});

describe("agentLogger", () => {
    it("stamps each entry with the clock and writes it as one line", () => {
        const lines: string[] = [];
        let now = NOW_MS;
        const log = agentLogger(
            () => now,
            (line) => lines.push(line),
        );
        log("first", {});
        now += 1;
        log("second", { n: 2 });
        assert.deepEqual(lines, [`{"ts":"${TIMESTAMP}","kind":"first"}`, `{"ts":"2027-01-15T08:00:00.001Z","kind":"second","n":2}`]);
    });
});
