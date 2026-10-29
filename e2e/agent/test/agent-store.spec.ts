import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import type { AgentState } from "../src/agent.types";
import { loadOrCreateMasterSeed, readAgentState, writeAgentState } from "../src/agent-store";

const CHANNEL = "0x1111111111111111111111111111111111111111111111111111111111111111";

const PAYMENT_HASH = "0x09dfb3a3e2e8e0e8a0a3d2e3b1d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f89138";

const STATE: AgentState = {
    tenantToken: "tenant-token",
    lspPubkey: "02b7ca5d4b3a7e8e5e47d16d9b0d4a8e3f1c2b3a4d5e6f708192a3b4c5d6e7f809",
    channels: {
        [CHANNEL]: {
            localScript: {
                code_hash: "0x9BD7E06F3ECF4BE0F2FCD2188B23F1B9FCC88E5D4B65A8637B17723BBDA3CCE8",
                hash_type: "type",
                args: "0xaabb",
            },
            remoteScript: {
                code_hash: "0x2222222222222222222222222222222222222222222222222222222222222222",
                hash_type: "data2",
                args: "0x",
            },
        },
    },
    invoices: {
        [PAYMENT_HASH]: {
            type: "Invoice",
            channelId: CHANNEL,
            preimage: "0x2222222222222222222222222222222222222222222222222222222222222222",
            paymentHash: PAYMENT_HASH,
            hashAlgorithm: "sha256",
        },
    },
    closes: {
        [CHANNEL]: {
            type: "Close",
            channelId: CHANNEL,
            localScript: {
                code_hash: "0x3333333333333333333333333333333333333333333333333333333333333333",
                hash_type: "data",
                args: "0x01",
            },
            remoteScript: {
                code_hash: "0x4444444444444444444444444444444444444444444444444444444444444444",
                hash_type: "data1",
                args: "0x02",
            },
            localFeeRate: "1000",
            remoteFeeRate: "0",
        },
    },
    watchtower: {
        type: "Watchtower",
        channelId: CHANNEL,
        destination: { code_hash: "0x5555555555555555555555555555555555555555555555555555555555555555", hash_type: "type", args: "0x03" },
        maxFeeShannons: "100000000",
    },
};

type JsonObject = Record<string, unknown>;

function freshDir(): string {
    return mkdtempSync(join(tmpdir(), "agent-store-"));
}

function at(value: unknown, ...keys: string[]): JsonObject {
    let current = value;
    for (const key of keys) {
        assert.ok(typeof current === "object" && current !== null);
        current = (current as JsonObject)[key];
    }
    assert.ok(typeof current === "object" && current !== null);
    return current as JsonObject;
}

function storeWith(mutate: (state: JsonObject) => void): string {
    const dir = freshDir();
    const state = structuredClone(STATE) as unknown as JsonObject;
    mutate(state);
    writeFileSync(join(dir, "agent.json"), JSON.stringify(state));
    return dir;
}

function assertRefused(mutate: (state: JsonObject) => void, message: string): void {
    const dir = storeWith(mutate);
    assert.throws(() => readAgentState(dir), { message: `agent.json: ${message}` });
}

const SCRIPT_CODE_HASH = "must be 32 bytes of 0x-prefixed hex";
const SCRIPT_HASH_TYPE = 'must be one of "data", "type", "data1", "data2"';
const SCRIPT_ARGS = "must be whole bytes of 0x-prefixed hex";
const HASH256 = "must be 32 bytes of 0x-prefixed lowercase hex";
const FEE_RATE = "must be a decimal integer string";

function scriptRefusals(path: string[], label: string): void {
    describe(label, () => {
        it("refuses it absent", () =>
            assertRefused((state) => delete at(state, ...path.slice(0, -1))[path.at(-1) ?? ""], `${label} is missing`));
        it("refuses it not an object", () =>
            assertRefused((state) => (at(state, ...path.slice(0, -1))[path.at(-1) ?? ""] = "0x"), `${label} must be an object`));
        it("refuses an unknown field", () =>
            assertRefused((state) => (at(state, ...path).extra = 1), `${label}.extra is not a known field`));
        for (const field of ["code_hash", "hash_type", "args"]) {
            it(`refuses ${field} absent`, () => assertRefused((state) => delete at(state, ...path)[field], `${label}.${field} is missing`));
        }
        it("refuses a code_hash of 31 bytes", () =>
            assertRefused((state) => (at(state, ...path).code_hash = `0x${"55".repeat(31)}`), `${label}.code_hash ${SCRIPT_CODE_HASH}`));
        it("refuses a code_hash of 33 bytes", () =>
            assertRefused((state) => (at(state, ...path).code_hash = `0x${"55".repeat(33)}`), `${label}.code_hash ${SCRIPT_CODE_HASH}`));
        it("refuses a code_hash without 0x", () =>
            assertRefused((state) => (at(state, ...path).code_hash = "55".repeat(32)), `${label}.code_hash ${SCRIPT_CODE_HASH}`));
        it("refuses a hash_type fiber does not write", () =>
            assertRefused((state) => (at(state, ...path).hash_type = "Data2"), `${label}.hash_type ${SCRIPT_HASH_TYPE}`));
        it("refuses args of an odd length", () =>
            assertRefused((state) => (at(state, ...path).args = "0xabc"), `${label}.args ${SCRIPT_ARGS}`));
        it("refuses args without 0x", () => assertRefused((state) => (at(state, ...path).args = "ab"), `${label}.args ${SCRIPT_ARGS}`));
        it("refuses args that are not hex", () =>
            assertRefused((state) => (at(state, ...path).args = "0xzz"), `${label}.args ${SCRIPT_ARGS}`));
    });
}

function hash256Refusals(path: string[], field: string, label: string): void {
    describe(label, () => {
        it("refuses it absent", () => assertRefused((state) => delete at(state, ...path)[field], `${label} is missing`));
        for (const [name, value] of [
            ["uppercase", `0x${"AB".repeat(32)}`],
            ["without 0x", "ab".repeat(32)],
            ["of 31 bytes", `0x${"ab".repeat(31)}`],
            ["of 33 bytes", `0x${"ab".repeat(33)}`],
            ["a number", 1],
        ] as const) {
            it(`refuses it ${name}`, () => assertRefused((state) => (at(state, ...path)[field] = value), `${label} ${HASH256}`));
        }
    });
}

describe("loadOrCreateMasterSeed", () => {
    it("creates 32 random bytes, owner-readable only, in a store it creates", () => {
        const dir = join(freshDir(), "nested", "store");
        const seed = loadOrCreateMasterSeed(dir);
        assert.equal(seed.length, 32);
        const path = join(dir, "master-seed");
        assert.deepEqual(new Uint8Array(readFileSync(path)), seed);
        assert.equal(statSync(path).mode & 0o777, 0o600);
        assert.equal(existsSync(`${path}.tmp`), false);
    });

    it("reads back the same seed on every later run", () => {
        const dir = freshDir();
        const seed = loadOrCreateMasterSeed(dir);
        assert.deepEqual(loadOrCreateMasterSeed(dir), seed);
    });

    it("draws a different seed for another store", () => {
        assert.notDeepEqual(loadOrCreateMasterSeed(freshDir()), loadOrCreateMasterSeed(freshDir()));
    });

    it("reads a seed the store already holds as it is", () => {
        const dir = freshDir();
        const bytes = new Uint8Array(32).map((_, index) => index);
        writeFileSync(join(dir, "master-seed"), bytes);
        assert.deepEqual(loadOrCreateMasterSeed(dir), bytes);
    });

    for (const length of [0, 31, 33]) {
        it(`refuses a seed file of ${length} bytes and leaves it as it was`, () => {
            const dir = freshDir();
            const path = join(dir, "master-seed");
            writeFileSync(path, new Uint8Array(length).fill(7));
            assert.throws(() => loadOrCreateMasterSeed(dir), { message: `${path} must hold 32 bytes, found ${length}` });
            assert.equal(readFileSync(path).length, length);
        });
    }
});

describe("writeAgentState and readAgentState", () => {
    it("read an empty state when the file does not exist", () => {
        assert.deepEqual(readAgentState(join(freshDir(), "absent")), {
            tenantToken: null,
            lspPubkey: null,
            channels: {},
            invoices: {},
            closes: {},
            watchtower: null,
        });
    });

    it("round-trip a full state through a store they create, owner-readable only", () => {
        const dir = join(freshDir(), "store");
        writeAgentState(dir, STATE);
        assert.deepEqual(readAgentState(dir), STATE);
        assert.equal(statSync(join(dir, "agent.json")).mode & 0o777, 0o600);
        assert.equal(existsSync(join(dir, "agent.json.tmp")), false);
    });

    it("round-trip the state of an agent not registered yet", () => {
        const dir = freshDir();
        const empty: AgentState = { tenantToken: null, lspPubkey: null, channels: {}, invoices: {}, closes: {}, watchtower: null };
        writeAgentState(dir, empty);
        assert.deepEqual(readAgentState(dir), empty);
    });

    it("replace the previous state", () => {
        const dir = freshDir();
        writeAgentState(dir, STATE);
        writeAgentState(dir, { ...STATE, tenantToken: "rotated" });
        assert.equal(readAgentState(dir).tenantToken, "rotated");
    });
});

describe("readAgentState refuses a malformed agent.json", () => {
    it("refuses a file that is not JSON", () => {
        const dir = freshDir();
        writeFileSync(join(dir, "agent.json"), "{");
        assert.throws(() => readAgentState(dir), { message: "agent.json is not JSON" });
    });

    it("refuses a file that is not an object", () => {
        const dir = freshDir();
        writeFileSync(join(dir, "agent.json"), "[]");
        assert.throws(() => readAgentState(dir), { message: "agent.json: state must be an object" });
    });

    it("refuses an unknown top-level field", () => {
        assertRefused((state) => (state.version = 1), "state.version is not a known field");
    });

    for (const field of ["tenantToken", "lspPubkey", "channels", "invoices", "closes", "watchtower"]) {
        it(`refuses ${field} absent`, () => assertRefused((state) => delete state[field], `state.${field} is missing`));
    }

    describe("state.tenantToken", () => {
        it("refuses an empty token", () =>
            assertRefused((state) => (state.tenantToken = ""), "state.tenantToken must be a non-empty string or null"));
        it("refuses a number", () =>
            assertRefused((state) => (state.tenantToken = 1), "state.tenantToken must be a non-empty string or null"));
    });

    describe("state.lspPubkey", () => {
        const problem = "must be 33 bytes of lowercase hex without 0x, or null";
        for (const [name, value] of [
            ["with 0x", `0x${"02".repeat(33)}`],
            ["uppercase", "0".repeat(64) + "AB"],
            ["of 32 bytes", "02".repeat(32)],
            ["of 34 bytes", "02".repeat(34)],
            ["a number", 2],
        ] as const) {
            it(`refuses it ${name}`, () => assertRefused((state) => (state.lspPubkey = value), `state.lspPubkey ${problem}`));
        }
    });

    describe("state.channels", () => {
        it("refuses an array", () => assertRefused((state) => (state.channels = []), "state.channels must be an object"));
        it("refuses null", () => assertRefused((state) => (state.channels = null), "state.channels must be an object"));
        it("refuses an uppercase key", () =>
            assertRefused(
                (state) => (state.channels = { [`0x${"AA".repeat(32)}`]: at(state, "channels", CHANNEL) }),
                `state.channels["0x${"AA".repeat(32)}"] must be keyed by 32 bytes of 0x-prefixed lowercase hex`,
            ));
        it("refuses a key of 31 bytes", () =>
            assertRefused(
                (state) => (state.channels = { [`0x${"11".repeat(31)}`]: at(state, "channels", CHANNEL) }),
                `state.channels["0x${"11".repeat(31)}"] must be keyed by 32 bytes of 0x-prefixed lowercase hex`,
            ));
        it("refuses an entry that is not an object", () =>
            assertRefused((state) => (at(state, "channels")[CHANNEL] = "x"), `state.channels["${CHANNEL}"] must be an object`));
        it("refuses an unknown field", () =>
            assertRefused(
                (state) => (at(state, "channels", CHANNEL).extra = 1),
                `state.channels["${CHANNEL}"].extra is not a known field`,
            ));
    });
    scriptRefusals(["channels", CHANNEL, "localScript"], `state.channels["${CHANNEL}"].localScript`);
    scriptRefusals(["channels", CHANNEL, "remoteScript"], `state.channels["${CHANNEL}"].remoteScript`);

    describe("state.invoices", () => {
        const invoice = `state.invoices["${PAYMENT_HASH}"]`;
        it("refuses an entry that is not an object", () =>
            assertRefused((state) => (at(state, "invoices")[PAYMENT_HASH] = 1), `${invoice} must be an object`));
        it("refuses an unknown field", () =>
            assertRefused((state) => (at(state, "invoices", PAYMENT_HASH).terms = {}), `${invoice}.terms is not a known field`));
        it("refuses type absent", () =>
            assertRefused((state) => delete at(state, "invoices", PAYMENT_HASH).type, `${invoice}.type is missing`));
        it("refuses another type", () =>
            assertRefused((state) => (at(state, "invoices", PAYMENT_HASH).type = "Close"), `${invoice}.type must be one of "Invoice"`));
        it("refuses hashAlgorithm absent", () =>
            assertRefused((state) => delete at(state, "invoices", PAYMENT_HASH).hashAlgorithm, `${invoice}.hashAlgorithm is missing`));
        it("refuses a hashAlgorithm fiber does not name", () =>
            assertRefused(
                (state) => (at(state, "invoices", PAYMENT_HASH).hashAlgorithm = "CkbHash"),
                `${invoice}.hashAlgorithm must be one of "ckb_hash", "sha256"`,
            ));
        it("reads the ckb_hash algorithm", () => {
            const dir = storeWith((state) => (at(state, "invoices", PAYMENT_HASH).hashAlgorithm = "ckb_hash"));
            assert.equal(readAgentState(dir).invoices[PAYMENT_HASH]?.hashAlgorithm, "ckb_hash");
        });
        it("refuses an invoice filed under another payment hash", () =>
            assertRefused(
                (state) => (at(state, "invoices", PAYMENT_HASH).paymentHash = CHANNEL),
                `${invoice}.paymentHash must be the key it is filed under`,
            ));
    });
    for (const field of ["channelId", "preimage", "paymentHash"]) {
        hash256Refusals(["invoices", PAYMENT_HASH], field, `state.invoices["${PAYMENT_HASH}"].${field}`);
    }

    describe("state.closes", () => {
        const close = `state.closes["${CHANNEL}"]`;
        it("refuses an entry that is not an object", () =>
            assertRefused((state) => (at(state, "closes")[CHANNEL] = []), `${close} must be an object`));
        it("refuses an unknown field", () =>
            assertRefused((state) => (at(state, "closes", CHANNEL).extra = 1), `${close}.extra is not a known field`));
        it("refuses type absent", () => assertRefused((state) => delete at(state, "closes", CHANNEL).type, `${close}.type is missing`));
        it("refuses another type", () =>
            assertRefused((state) => (at(state, "closes", CHANNEL).type = "Invoice"), `${close}.type must be one of "Close"`));
        it("refuses a close filed under another channel", () =>
            assertRefused(
                (state) => (at(state, "closes", CHANNEL).channelId = PAYMENT_HASH),
                `${close}.channelId must be the key it is filed under`,
            ));
        for (const field of ["localFeeRate", "remoteFeeRate"]) {
            it(`refuses ${field} absent`, () =>
                assertRefused((state) => delete at(state, "closes", CHANNEL)[field], `${close}.${field} is missing`));
            for (const [name, value] of [
                ["with a leading zero", "01000"],
                ["in hex", "0x3e8"],
                ["negative", "-1"],
                ["empty", ""],
                ["a number", 1000],
            ] as const) {
                it(`refuses ${field} ${name}`, () =>
                    assertRefused((state) => (at(state, "closes", CHANNEL)[field] = value), `${close}.${field} ${FEE_RATE}`));
            }
        }
    });
    hash256Refusals(["closes", CHANNEL], "channelId", `state.closes["${CHANNEL}"].channelId`);
    scriptRefusals(["closes", CHANNEL, "localScript"], `state.closes["${CHANNEL}"].localScript`);
    scriptRefusals(["closes", CHANNEL, "remoteScript"], `state.closes["${CHANNEL}"].remoteScript`);

    describe("state.watchtower", () => {
        it("refuses an array", () => assertRefused((state) => (state.watchtower = []), "state.watchtower must be an object"));
        it("refuses an unknown field", () =>
            assertRefused((state) => (at(state, "watchtower").extra = 1), "state.watchtower.extra is not a known field"));
        it("refuses type absent", () => assertRefused((state) => delete at(state, "watchtower").type, "state.watchtower.type is missing"));
        it("refuses another type", () =>
            assertRefused((state) => (at(state, "watchtower").type = "watchtower"), 'state.watchtower.type must be one of "Watchtower"'));
        it("refuses maxFeeShannons absent", () =>
            assertRefused((state) => delete at(state, "watchtower").maxFeeShannons, "state.watchtower.maxFeeShannons is missing"));
        for (const [name, value] of [
            ["with a leading zero", "0100"],
            ["in hex", "0x64"],
            ["negative", "-1"],
            ["empty", ""],
            ["a number", 100],
        ] as const) {
            it(`refuses maxFeeShannons ${name}`, () =>
                assertRefused(
                    (state) => (at(state, "watchtower").maxFeeShannons = value),
                    "state.watchtower.maxFeeShannons must be a decimal integer string",
                ));
        }
        it("reads a maxFeeShannons of 0", () => {
            const dir = storeWith((state) => (at(state, "watchtower").maxFeeShannons = "0"));
            assert.equal(readAgentState(dir).watchtower?.maxFeeShannons, "0");
        });
    });
    hash256Refusals(["watchtower"], "channelId", "state.watchtower.channelId");
    scriptRefusals(["watchtower", "destination"], "state.watchtower.destination");
});
