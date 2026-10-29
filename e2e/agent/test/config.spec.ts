import assert from "node:assert/strict";
import { resolve } from "node:path";
import { describe, it } from "node:test";
import { parseAgentConfig } from "../src/config";

const REQUIRED = ["--rpc", "127.0.0.1:21714", "--store", "/tmp/agent-store", "--operator-token", "operator"];

const NO_ENV = {};

describe("parseAgentConfig", () => {
    it("fills every default when only the required flags are given", () => {
        assert.deepEqual(parseAgentConfig(REQUIRED, NO_ENV), {
            rpcUrl: "http://127.0.0.1:21714",
            storeDir: "/tmp/agent-store",
            statusFile: null,
            controlAddr: null,
            operatorToken: "operator",
            intervalMs: 200,
            contractsDir: resolve("../deploy/contracts"),
        });
    });

    it("reads every flag, in both spellings", () => {
        const argv = [
            "--rpc=http://127.0.0.1:21714",
            "--store",
            "/tmp/agent-store",
            "--operator-token=operator",
            "--status-file",
            "/tmp/status.json",
            "--control-addr=127.0.0.1:21799",
            "--interval-ms",
            "50",
            "--contracts-dir=/opt/contracts",
            "--ckb-rpc",
            "http://127.0.0.1:8114",
        ];
        assert.deepEqual(parseAgentConfig(argv, NO_ENV), {
            rpcUrl: "http://127.0.0.1:21714",
            storeDir: "/tmp/agent-store",
            statusFile: "/tmp/status.json",
            controlAddr: { host: "127.0.0.1", port: 21799 },
            operatorToken: "operator",
            intervalMs: 50,
            contractsDir: "/opt/contracts",
        });
    });

    it("reads every setting fiber's agent reads from the environment", () => {
        const env = {
            FIBER_LSP_SDK_AGENT_RPC: "127.0.0.1:21714",
            FIBER_LSP_SDK_AGENT_STORE: "/tmp/agent-store",
            FIBER_LSP_SDK_AGENT_OPERATOR_TOKEN: "operator",
            FIBER_LSP_SDK_AGENT_STATUS_FILE: "/tmp/status.json",
            FIBER_LSP_SDK_AGENT_CONTROL_ADDR: "127.0.0.1:21799",
            FIBER_LSP_SDK_AGENT_INTERVAL_MS: "50",
        };
        assert.deepEqual(parseAgentConfig([], env), {
            rpcUrl: "http://127.0.0.1:21714",
            storeDir: "/tmp/agent-store",
            statusFile: "/tmp/status.json",
            controlAddr: { host: "127.0.0.1", port: 21799 },
            operatorToken: "operator",
            intervalMs: 50,
            contractsDir: resolve("../deploy/contracts"),
        });
    });

    it("prefers each flag over its environment variable", () => {
        const env = {
            FIBER_LSP_SDK_AGENT_RPC: "127.0.0.1:1",
            FIBER_LSP_SDK_AGENT_STORE: "/env/store",
            FIBER_LSP_SDK_AGENT_OPERATOR_TOKEN: "env-operator",
            FIBER_LSP_SDK_AGENT_STATUS_FILE: "/env/status.json",
            FIBER_LSP_SDK_AGENT_CONTROL_ADDR: "127.0.0.1:2",
            FIBER_LSP_SDK_AGENT_INTERVAL_MS: "3",
        };
        const argv = [...REQUIRED, "--status-file", "/tmp/status.json", "--control-addr", "127.0.0.1:21799", "--interval-ms", "50"];
        assert.deepEqual(parseAgentConfig(argv, env), {
            rpcUrl: "http://127.0.0.1:21714",
            storeDir: "/tmp/agent-store",
            statusFile: "/tmp/status.json",
            controlAddr: { host: "127.0.0.1", port: 21799 },
            operatorToken: "operator",
            intervalMs: 50,
            contractsDir: resolve("../deploy/contracts"),
        });
    });

    it("takes an empty environment variable as unset", () => {
        const env = { FIBER_LSP_SDK_AGENT_STATUS_FILE: "", FIBER_LSP_SDK_AGENT_CONTROL_ADDR: "", FIBER_LSP_SDK_AGENT_INTERVAL_MS: "" };
        const config = parseAgentConfig(REQUIRED, env);
        assert.equal(config.statusFile, null);
        assert.equal(config.controlAddr, null);
        assert.equal(config.intervalMs, 200);
    });

    it("keeps an http or https scheme and prepends http to a bare address", () => {
        const rpcUrl = (rpc: string) => parseAgentConfig(["--rpc", rpc, "--store", "/s", "--operator-token", "t"], NO_ENV).rpcUrl;
        assert.equal(rpcUrl("http://node:8227"), "http://node:8227");
        assert.equal(rpcUrl("https://node:8227"), "https://node:8227");
        assert.equal(rpcUrl("node:8227"), "http://node:8227");
    });

    it("resolves a relative contracts dir against the working directory", () => {
        assert.equal(parseAgentConfig([...REQUIRED, "--contracts-dir", "contracts"], NO_ENV).contractsDir, resolve("contracts"));
    });

    it("ignores --ckb-rpc, which it still accepts", () => {
        assert.deepEqual(parseAgentConfig([...REQUIRED, "--ckb-rpc=http://127.0.0.1:8114"], NO_ENV), parseAgentConfig(REQUIRED, NO_ENV));
    });

    it("refuses an absent --rpc", () => {
        assert.throws(() => parseAgentConfig(["--store", "/s", "--operator-token", "t"], NO_ENV), {
            message: "--rpc (or FIBER_LSP_SDK_AGENT_RPC) is required",
        });
    });

    it("refuses an absent --store", () => {
        assert.throws(() => parseAgentConfig(["--rpc", "node:1", "--operator-token", "t"], NO_ENV), {
            message: "--store (or FIBER_LSP_SDK_AGENT_STORE) is required",
        });
    });

    it("refuses an absent --operator-token", () => {
        assert.throws(() => parseAgentConfig(["--rpc", "node:1", "--store", "/s"], NO_ENV), {
            message: "--operator-token (or FIBER_LSP_SDK_AGENT_OPERATOR_TOKEN) is required",
        });
    });

    it("refuses an unknown flag, --once included", () => {
        assert.throws(() => parseAgentConfig([...REQUIRED, "--verbose"], NO_ENV), { message: "unknown flag --verbose" });
        assert.throws(() => parseAgentConfig([...REQUIRED, "--once"], NO_ENV), { message: "unknown flag --once" });
        assert.throws(() => parseAgentConfig([...REQUIRED, "--rpc-url=x"], NO_ENV), { message: "unknown flag --rpc-url" });
    });

    it("refuses an argument that is not a flag", () => {
        assert.throws(() => parseAgentConfig([...REQUIRED, "extra"], NO_ENV), { message: 'unexpected argument "extra"' });
        assert.throws(() => parseAgentConfig([...REQUIRED, "-v"], NO_ENV), { message: 'unexpected argument "-v"' });
    });

    it("refuses a flag given twice", () => {
        assert.throws(() => parseAgentConfig([...REQUIRED, "--rpc=node:2"], NO_ENV), { message: "--rpc is given more than once" });
    });

    it("refuses a flag without its value", () => {
        assert.throws(() => parseAgentConfig([...REQUIRED, "--status-file"], NO_ENV), { message: "--status-file requires a value" });
        assert.throws(() => parseAgentConfig(["--rpc", "--store", "/s", "--operator-token", "t"], NO_ENV), {
            message: "--rpc requires a value",
        });
        assert.throws(() => parseAgentConfig([...REQUIRED, "--status-file="], NO_ENV), { message: "--status-file requires a value" });
    });

    it("refuses --control-addr without --status-file, from a flag or from the environment", () => {
        assert.throws(() => parseAgentConfig([...REQUIRED, "--control-addr", "127.0.0.1:21799"], NO_ENV), {
            message: "--control-addr requires --status-file",
        });
        assert.throws(() => parseAgentConfig(REQUIRED, { FIBER_LSP_SDK_AGENT_CONTROL_ADDR: "127.0.0.1:21799" }), {
            message: "--control-addr requires --status-file",
        });
    });

    describe("--control-addr", () => {
        const controlAddr = (value: string) =>
            parseAgentConfig([...REQUIRED, "--status-file", "/tmp/status.json", "--control-addr", value], NO_ENV).controlAddr;

        it("reads the port from 0 to 65535", () => {
            assert.deepEqual(controlAddr("127.0.0.1:0"), { host: "127.0.0.1", port: 0 });
            assert.deepEqual(controlAddr("localhost:65535"), { host: "localhost", port: 65535 });
        });

        it("reads an IPv6 host without its brackets", () => {
            assert.deepEqual(controlAddr("[::1]:21799"), { host: "::1", port: 21799 });
        });

        it("refuses an address without a port", () => {
            assert.throws(() => controlAddr("127.0.0.1"), { message: '--control-addr must be host:port, got "127.0.0.1"' });
        });

        it("refuses an address without a host", () => {
            assert.throws(() => controlAddr(":21799"), { message: '--control-addr must name a host, got ":21799"' });
            assert.throws(() => controlAddr("[]:21799"), { message: '--control-addr must name a host, got "[]:21799"' });
        });

        it("refuses a port above 65535", () => {
            assert.throws(() => controlAddr("127.0.0.1:65536"), {
                message: '--control-addr must be an integer between 0 and 65535, got "65536"',
            });
        });

        it("refuses a port that is not a decimal integer", () => {
            for (const port of ["", "-1", "8x", "0x50", "1.5", " 80"]) {
                assert.throws(() => controlAddr(`127.0.0.1:${port}`), {
                    message: `--control-addr must be an integer between 0 and 65535, got ${JSON.stringify(port)}`,
                });
            }
        });
    });

    describe("--interval-ms", () => {
        const intervalMs = (value: string) => parseAgentConfig([...REQUIRED, `--interval-ms=${value}`], NO_ENV).intervalMs;

        it("reads an interval from 1 to 2147483647", () => {
            assert.equal(intervalMs("1"), 1);
            assert.equal(intervalMs("2147483647"), 2147483647);
        });

        it("refuses 0 and anything above 2147483647", () => {
            for (const value of ["0", "2147483648"]) {
                assert.throws(() => intervalMs(value), {
                    message: `--interval-ms must be an integer between 1 and 2147483647, got ${JSON.stringify(value)}`,
                });
            }
        });

        it("refuses an interval that is not a decimal integer", () => {
            for (const value of ["-1", "1.5", "1e3", "0x10", "ten", " 5"]) {
                assert.throws(() => intervalMs(value), {
                    message: `--interval-ms must be an integer between 1 and 2147483647, got ${JSON.stringify(value)}`,
                });
            }
        });

        it("refuses a malformed interval from the environment", () => {
            assert.throws(() => parseAgentConfig(REQUIRED, { FIBER_LSP_SDK_AGENT_INTERVAL_MS: "fast" }), {
                message: '--interval-ms must be an integer between 1 and 2147483647, got "fast"',
            });
        });
    });
});
