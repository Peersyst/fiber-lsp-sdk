import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { AgentRequestError } from "../src/agent.error";
import { readOpenChannelRequest, sameScriptJson } from "../src/open-params";

const LSP_PUBKEY = "0291a6576bd5a94bd74a2b3f7aa6ba3e7c2ccf3e6d5c8a1f3b9e2d4c6a8b0f1e2d";

// 04-open-external-signer-channel.bru, its variables filled: the default funding lock and the agent's open marker.
const SUITE_BODY = {
    params: {
        pubkey: LSP_PUBKEY,
        public: false,
        funding_amount: "0xba43b7400",
        commitment_fee_rate: "0x3e8",
        commitment_delay_epoch: "0x10000000001",
        shutdown_script: {
            code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
            hash_type: "type",
            args: "0x75178f34549c5fe9cd1a0c57aebd01e7ddf9249e",
        },
        funding_lock_script: {
            code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
            hash_type: "type",
            args: "0x75178f34549c5fe9cd1a0c57aebd01e7ddf9249e",
        },
        external_channel_signer: { allocated_at_open: true },
    },
};

function withParams(patch: Record<string, unknown>): { params: Record<string, unknown> } {
    const params: Record<string, unknown> = { ...structuredClone(SUITE_BODY.params), ...patch };
    for (const [key, value] of Object.entries(patch)) if (value === undefined) delete params[key];
    return { params };
}

function withScript(patch: Record<string, unknown>): Record<string, unknown> {
    const script: Record<string, unknown> = { ...structuredClone(SUITE_BODY.params.funding_lock_script), ...patch };
    for (const [key, value] of Object.entries(patch)) if (value === undefined) delete script[key];
    return script;
}

function refuses(body: unknown, field: string): void {
    assert.throws(
        () => readOpenChannelRequest(body, LSP_PUBKEY),
        (error: unknown) => error instanceof AgentRequestError && error.message.includes(field),
    );
}

function refusesWith(body: unknown, message: string): void {
    assert.throws(
        () => readOpenChannelRequest(body, LSP_PUBKEY),
        (error: unknown) => error instanceof AgentRequestError && error.message === message,
    );
}

const CELL_DEP = { out_point: { tx_hash: `0x${"ab".repeat(32)}`, index: "0x0" }, dep_type: "dep_group" };

describe("readOpenChannelRequest", () => {
    it("reads the suite's body into prepareChannelOpen's arguments", () => {
        assert.deepEqual(readOpenChannelRequest(SUITE_BODY, LSP_PUBKEY), {
            amountShannons: "50000000000",
            userLock: {
                codeHash: Uint8Array.from(Buffer.from("9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", "hex")),
                hashType: "type",
                args: Uint8Array.from(Buffer.from("75178f34549c5fe9cd1a0c57aebd01e7ddf9249e", "hex")),
            },
            userLockCellDeps: undefined,
            userLockJson: {
                code_hash: "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
                hash_type: "type",
                args: "0x75178f34549c5fe9cd1a0c57aebd01e7ddf9249e",
            },
        });
    });

    it("keeps the lock as sent, case included", () => {
        const lock = withScript({ args: "0x75178F34549C5FE9CD1A0C57AEBD01E7DDF9249E" });
        const opened = readOpenChannelRequest(withParams({ funding_lock_script: lock, shutdown_script: lock }), LSP_PUBKEY);
        assert.equal(opened.userLockJson.args, "0x75178F34549C5FE9CD1A0C57AEBD01E7DDF9249E");
    });

    it("ignores keys beside params, as fiber's agent does", () => {
        assert.equal(readOpenChannelRequest({ ...SUITE_BODY, extra: 1 }, LSP_PUBKEY).amountShannons, "50000000000");
    });

    it("refuses a body that is not an object", () => {
        refusesWith(null, "body must be an object");
        refusesWith([SUITE_BODY], "body must be an object");
        refusesWith("{}", "body must be an object");
        refusesWith(1, "body must be an object");
    });

    it("refuses absent or non-object params", () => {
        refusesWith({}, "params must be an object");
        refusesWith({ params: null }, "params must be an object");
        refusesWith({ params: [] }, "params must be an object");
        refusesWith({ params: "{}" }, "params must be an object");
        refusesWith({ params: true }, "params must be an object");
    });

    describe("pubkey", () => {
        it("accepts the LSP's node id in any case, with or without 0x on either side", () => {
            assert.doesNotThrow(() => readOpenChannelRequest(withParams({ pubkey: `0x${LSP_PUBKEY.toUpperCase()}` }), LSP_PUBKEY));
            assert.doesNotThrow(() => readOpenChannelRequest(withParams({ pubkey: LSP_PUBKEY }), `0x${LSP_PUBKEY}`));
        });

        it("refuses an absent, non-string or other pubkey", () => {
            refuses(withParams({ pubkey: undefined }), "params.pubkey");
            refuses(withParams({ pubkey: 2 }), "params.pubkey");
            refuses(withParams({ pubkey: `${LSP_PUBKEY.slice(0, -1)}e` }), "params.pubkey");
            refuses(withParams({ pubkey: `03${LSP_PUBKEY.slice(2)}` }), "params.pubkey");
        });
    });

    describe("public", () => {
        it("accepts it absent or null, as serde reads None", () => {
            assert.doesNotThrow(() => readOpenChannelRequest(withParams({ public: undefined }), LSP_PUBKEY));
            assert.doesNotThrow(() => readOpenChannelRequest(withParams({ public: null }), LSP_PUBKEY));
        });

        it("refuses anything but false", () => {
            refuses(withParams({ public: true }), "params.public");
            refuses(withParams({ public: "false" }), "params.public");
            refuses(withParams({ public: 0 }), "params.public");
        });
    });

    describe("funding_amount", () => {
        it("reads the u128 bounds", () => {
            assert.equal(readOpenChannelRequest(withParams({ funding_amount: "0x0" }), LSP_PUBKEY).amountShannons, "0");
            assert.equal(
                readOpenChannelRequest(withParams({ funding_amount: `0x${"f".repeat(32)}` }), LSP_PUBKEY).amountShannons,
                "340282366920938463463374607431768211455",
            );
            assert.equal(readOpenChannelRequest(withParams({ funding_amount: "0xBA43B7400" }), LSP_PUBKEY).amountShannons, "50000000000");
        });

        it("refuses one past u128", () => {
            refuses(withParams({ funding_amount: `0x1${"0".repeat(32)}` }), "params.funding_amount");
        });

        it("refuses an absent or malformed amount", () => {
            refuses(withParams({ funding_amount: undefined }), "params.funding_amount");
            refuses(withParams({ funding_amount: null }), "params.funding_amount");
            refuses(withParams({ funding_amount: 50000000000 }), "params.funding_amount");
            refuses(withParams({ funding_amount: "ba43b7400" }), "params.funding_amount");
            refuses(withParams({ funding_amount: "0x" }), "params.funding_amount");
            refuses(withParams({ funding_amount: "0x0ba43b7400" }), "params.funding_amount");
            refuses(withParams({ funding_amount: "0xba43b740g" }), "params.funding_amount");
            refuses(withParams({ funding_amount: "50000000000" }), "params.funding_amount");
        });
    });

    for (const field of ["shutdown_script", "funding_lock_script"]) {
        describe(field, () => {
            it("refuses it absent, null or not an object", () => {
                refusesWith(withParams({ [field]: undefined }), `params.${field} must be an object`);
                refusesWith(withParams({ [field]: null }), `params.${field} must be an object`);
                refusesWith(withParams({ [field]: "0x" }), `params.${field} must be an object`);
                refusesWith(withParams({ [field]: [] }), `params.${field} must be an object`);
            });

            it("refuses a malformed code_hash", () => {
                refuses(withParams({ [field]: withScript({ code_hash: undefined }) }), `params.${field}.code_hash`);
                refuses(withParams({ [field]: withScript({ code_hash: `0x${"9b".repeat(31)}` }) }), `params.${field}.code_hash`);
                refuses(withParams({ [field]: withScript({ code_hash: `0x${"9b".repeat(33)}` }) }), `params.${field}.code_hash`);
                refuses(withParams({ [field]: withScript({ code_hash: "9b".repeat(32) }) }), `params.${field}.code_hash`);
                refuses(withParams({ [field]: withScript({ code_hash: `0x${"zz".repeat(32)}` }) }), `params.${field}.code_hash`);
            });

            it("refuses a hash_type the SDK does not sign for, its spelling exact", () => {
                refuses(withParams({ [field]: withScript({ hash_type: undefined }) }), `params.${field}.hash_type`);
                refuses(withParams({ [field]: withScript({ hash_type: "Type" }) }), `params.${field}.hash_type`);
                refuses(withParams({ [field]: withScript({ hash_type: "data3" }) }), `params.${field}.hash_type`);
                refuses(withParams({ [field]: withScript({ hash_type: 1 }) }), `params.${field}.hash_type`);
            });

            it("refuses malformed args", () => {
                refuses(withParams({ [field]: withScript({ args: undefined }) }), `params.${field}.args`);
                refuses(withParams({ [field]: withScript({ args: "0x751" }) }), `params.${field}.args`);
                refuses(withParams({ [field]: withScript({ args: "75178f34" }) }), `params.${field}.args`);
                refuses(withParams({ [field]: withScript({ args: "0x7g" }) }), `params.${field}.args`);
            });

            it("refuses a key CKB's script does not have", () => {
                refuses(withParams({ [field]: withScript({ extra: "0x" }) }), `params.${field}.extra`);
            });
        });
    }

    it("reads every hash type the SDK signs for, and empty args", () => {
        for (const hashType of ["data", "type", "data1", "data2"]) {
            const lock = withScript({ hash_type: hashType, args: "0x" });
            const opened = readOpenChannelRequest(withParams({ shutdown_script: lock, funding_lock_script: lock }), LSP_PUBKEY);
            assert.equal(opened.userLock.hashType, hashType);
            assert.deepEqual(opened.userLock.args, new Uint8Array(0));
        }
    });

    describe("the two scripts", () => {
        it("accepts them equal up to the case of their hex", () => {
            const upper = withScript({ code_hash: SUITE_BODY.params.funding_lock_script.code_hash.toUpperCase().replace("0X", "0x") });
            assert.doesNotThrow(() => readOpenChannelRequest(withParams({ shutdown_script: upper }), LSP_PUBKEY));
        });

        it("refuses a shutdown script other than the funding lock, field by field", () => {
            refuses(withParams({ shutdown_script: withScript({ code_hash: `0x${"00".repeat(32)}` }) }), "params.shutdown_script must be");
            refuses(withParams({ shutdown_script: withScript({ hash_type: "data1" }) }), "params.shutdown_script must be");
            refuses(
                withParams({ shutdown_script: withScript({ args: "0x75178f34549c5fe9cd1a0c57aebd01e7ddf9249f" }) }),
                "params.shutdown_script must be",
            );
            refuses(withParams({ shutdown_script: withScript({ args: "0x" }) }), "params.shutdown_script must be");
        });
    });

    describe("commitment_fee_rate", () => {
        it("accepts it absent or null", () => {
            assert.doesNotThrow(() => readOpenChannelRequest(withParams({ commitment_fee_rate: undefined }), LSP_PUBKEY));
            assert.doesNotThrow(() => readOpenChannelRequest(withParams({ commitment_fee_rate: null }), LSP_PUBKEY));
        });

        it("accepts 0x3e8 in either case", () => {
            assert.doesNotThrow(() => readOpenChannelRequest(withParams({ commitment_fee_rate: "0x3E8" }), LSP_PUBKEY));
        });

        it("refuses any rate but 0x3e8", () => {
            const other = "params.commitment_fee_rate must be 0x3e8, the rate the SDK opens with";
            refusesWith(withParams({ commitment_fee_rate: "0x3e9" }), other);
            refusesWith(withParams({ commitment_fee_rate: "0x3e7" }), other);
            refusesWith(withParams({ commitment_fee_rate: "0x0" }), other);
        });

        it("refuses a rate that is not a u64 in fiber's hex", () => {
            const malformed = "params.commitment_fee_rate must be a 0x hex uint up to 0xffffffffffffffff";
            refusesWith(withParams({ commitment_fee_rate: "0x03e8" }), malformed);
            refusesWith(withParams({ commitment_fee_rate: "3e8" }), malformed);
            refusesWith(withParams({ commitment_fee_rate: "0x3eg" }), malformed);
            refusesWith(withParams({ commitment_fee_rate: 1000 }), malformed);
            refusesWith(withParams({ commitment_fee_rate: `0x1${"0".repeat(16)}` }), malformed);
        });
    });

    describe("commitment_delay_epoch", () => {
        it("accepts it absent or null", () => {
            assert.doesNotThrow(() => readOpenChannelRequest(withParams({ commitment_delay_epoch: undefined }), LSP_PUBKEY));
            assert.doesNotThrow(() => readOpenChannelRequest(withParams({ commitment_delay_epoch: null }), LSP_PUBKEY));
        });

        it("accepts 0x10000000001 by value", () => {
            assert.doesNotThrow(() => readOpenChannelRequest(withParams({ commitment_delay_epoch: "0x10000000001" }), LSP_PUBKEY));
        });

        it("refuses any delay but 0x10000000001", () => {
            const other = "params.commitment_delay_epoch must be 0x10000000001, the delay the SDK opens with";
            refusesWith(withParams({ commitment_delay_epoch: "0x10000000002" }), other);
            refusesWith(withParams({ commitment_delay_epoch: "0x10000000000" }), other);
            refusesWith(withParams({ commitment_delay_epoch: "0x1" }), other);
        });

        it("refuses a delay that is not a u64 in fiber's hex", () => {
            const malformed = "params.commitment_delay_epoch must be a 0x hex uint up to 0xffffffffffffffff";
            refusesWith(withParams({ commitment_delay_epoch: "0x010000000001" }), malformed);
            refusesWith(withParams({ commitment_delay_epoch: "10000000001" }), malformed);
            refusesWith(withParams({ commitment_delay_epoch: 0x10000000001 }), malformed);
            refusesWith(withParams({ commitment_delay_epoch: `0x1${"0".repeat(16)}` }), malformed);
        });
    });

    describe("the optionals the SDK does not open with", () => {
        const sent: Record<string, unknown> = {
            funding_udt_type_script: SUITE_BODY.params.funding_lock_script,
            funding_fee_rate: "0x3e8",
            tlc_expiry_delta: "0xdbba00",
            tlc_min_value: "0x0",
            tlc_fee_proportional_millionths: "0x3e8",
            max_tlc_value_in_flight: "0xba43b7400",
            max_tlc_number_in_flight: "0x7d",
        };
        for (const [field, value] of Object.entries(sent)) {
            it(`refuses ${field} present, and accepts it null`, () => {
                refuses(withParams({ [field]: value }), `params.${field}`);
                assert.doesNotThrow(() => readOpenChannelRequest(withParams({ [field]: null }), LSP_PUBKEY));
            });
        }
    });

    it("ignores a key fiber's params do not have, as serde does", () => {
        assert.deepEqual(
            readOpenChannelRequest(withParams({ funding_amount_shannons: "0x1", Public: true }), LSP_PUBKEY),
            readOpenChannelRequest(SUITE_BODY, LSP_PUBKEY),
        );
    });

    it("ignores external_channel_signer, whatever it holds, and its absence", () => {
        assert.doesNotThrow(() => readOpenChannelRequest(withParams({ external_channel_signer: undefined }), LSP_PUBKEY));
        assert.doesNotThrow(() => readOpenChannelRequest(withParams({ external_channel_signer: "anything" }), LSP_PUBKEY));
    });

    describe("funding_lock_script_cell_deps", () => {
        it("reads them into the SDK's cell deps", () => {
            const deps = [CELL_DEP, { out_point: { tx_hash: `0x${"CD".repeat(32)}`, index: "0xffffffff" }, dep_type: "code" }];
            assert.deepEqual(readOpenChannelRequest(withParams({ funding_lock_script_cell_deps: deps }), LSP_PUBKEY).userLockCellDeps, [
                { outPoint: { txHash: new Uint8Array(32).fill(0xab), index: 0 }, depType: "dep_group" },
                { outPoint: { txHash: new Uint8Array(32).fill(0xcd), index: 0xffffffff }, depType: "code" },
            ]);
        });

        it("reads them absent or null as none, and empty as empty", () => {
            assert.equal(
                readOpenChannelRequest(withParams({ funding_lock_script_cell_deps: null }), LSP_PUBKEY).userLockCellDeps,
                undefined,
            );
            assert.deepEqual(readOpenChannelRequest(withParams({ funding_lock_script_cell_deps: [] }), LSP_PUBKEY).userLockCellDeps, []);
        });

        it("refuses a non-array or a non-object entry", () => {
            refusesWith(withParams({ funding_lock_script_cell_deps: CELL_DEP }), "params.funding_lock_script_cell_deps must be an array");
            refusesWith(withParams({ funding_lock_script_cell_deps: ["0x"] }), "params.funding_lock_script_cell_deps[0] must be an object");
            refusesWith(withParams({ funding_lock_script_cell_deps: [null] }), "params.funding_lock_script_cell_deps[0] must be an object");
            refusesWith(withParams({ funding_lock_script_cell_deps: [[]] }), "params.funding_lock_script_cell_deps[0] must be an object");
        });

        it("refuses an absent or malformed out_point", () => {
            const at = "params.funding_lock_script_cell_deps[0].out_point";
            refusesWith(withParams({ funding_lock_script_cell_deps: [{ dep_type: "code" }] }), `${at} must be an object`);
            refusesWith(withParams({ funding_lock_script_cell_deps: [{ ...CELL_DEP, out_point: "0x" }] }), `${at} must be an object`);
            refuses(withParams({ funding_lock_script_cell_deps: [{ ...CELL_DEP, out_point: { index: "0x0" } }] }), `${at}.tx_hash`);
            refuses(
                withParams({
                    funding_lock_script_cell_deps: [{ ...CELL_DEP, out_point: { tx_hash: `0x${"ab".repeat(31)}`, index: "0x0" } }],
                }),
                `${at}.tx_hash`,
            );
            refuses(
                withParams({ funding_lock_script_cell_deps: [{ ...CELL_DEP, out_point: { tx_hash: CELL_DEP.out_point.tx_hash } }] }),
                `${at}.index`,
            );
            refuses(
                withParams({ funding_lock_script_cell_deps: [{ ...CELL_DEP, out_point: { ...CELL_DEP.out_point, index: 0 } }] }),
                `${at}.index`,
            );
            refuses(
                withParams({ funding_lock_script_cell_deps: [{ ...CELL_DEP, out_point: { ...CELL_DEP.out_point, index: "0x01" } }] }),
                `${at}.index`,
            );
            refuses(
                withParams({
                    funding_lock_script_cell_deps: [{ ...CELL_DEP, out_point: { ...CELL_DEP.out_point, index: "0x100000000" } }],
                }),
                `${at}.index`,
            );
            refuses(
                withParams({ funding_lock_script_cell_deps: [{ ...CELL_DEP, out_point: { ...CELL_DEP.out_point, extra: 1 } }] }),
                `${at}.extra`,
            );
        });

        it("refuses an absent or misspelt dep_type, and an unknown key", () => {
            const at = "params.funding_lock_script_cell_deps[0]";
            refuses(withParams({ funding_lock_script_cell_deps: [{ out_point: CELL_DEP.out_point }] }), `${at}.dep_type`);
            refuses(withParams({ funding_lock_script_cell_deps: [{ ...CELL_DEP, dep_type: "DepGroup" }] }), `${at}.dep_type`);
            refuses(withParams({ funding_lock_script_cell_deps: [{ ...CELL_DEP, dep_type: "Code" }] }), `${at}.dep_type`);
            refuses(withParams({ funding_lock_script_cell_deps: [{ ...CELL_DEP, extra: 1 }] }), `${at}.extra`);
        });
    });
});

describe("sameScriptJson", () => {
    it("compares each field, ignoring the case of the hex", () => {
        const lock = SUITE_BODY.params.funding_lock_script;
        assert.equal(sameScriptJson(lock, { ...lock, args: lock.args.toUpperCase().replace("0X", "0x") }), true);
        assert.equal(sameScriptJson(lock, { ...lock, code_hash: `0x${"00".repeat(32)}` }), false);
        assert.equal(sameScriptJson(lock, { ...lock, hash_type: "data" }), false);
        assert.equal(sameScriptJson(lock, { ...lock, args: "0x" }), false);
    });
});
