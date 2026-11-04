import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { AgentNodeFetch, ScriptJson } from "../src/agent.types";
import { ckbBlake2b } from "../src/ckb-hash";
import { ckbTxHash, moleculeWitnessArgs, readWitnessArgs } from "../src/ckb-tx";
import type { CkbOutPointJson } from "../src/ckb-json";
import type { CkbTxJson } from "../src/ckb-tx";
import {
    liveCellLockResolver,
    sighashAllLock,
    sighashAllMessage,
    signSighashAllInputs,
    SIGHASH_ALL_LOCK_CODE_HASH,
} from "../src/sighash-signer";
import {
    TESTNET_CODE_DEPS_TX,
    TESTNET_GROUP_TX,
    TESTNET_GROUP_TX_HASH,
    TESTNET_INPUT_LOCK_ARGS,
    TESTNET_TX,
    TESTNET_TYPED_TX,
} from "./utils/ckb-testnet-tx";

const PRIVATE_KEY = "0x1111111111111111111111111111111111111111111111111111111111111111";

const KEY_LOCK: ScriptJson = {
    code_hash: SIGHASH_ALL_LOCK_CODE_HASH,
    hash_type: "type",
    args: "0xf949a9cc83edefcd580eb3f0f3bae187c4d008db",
};

const OTHER_LOCK: ScriptJson = {
    code_hash: SIGHASH_ALL_LOCK_CODE_HASH,
    hash_type: "type",
    args: "0x8e0e0590f4a1b5d38e19f9bd58e9e3d0ae6ad9c6",
};

// The curve's order, past whose half an s is high.
const CURVE_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

// The key's RFC 6979 signature of this tx's first input has a high s: the signer must write its low twin.
const HIGH_S_TX: CkbTxJson = { ...TESTNET_TX, witnesses: ["0x", "0x", "0x00"] };
const HIGH_S_RAW = 0xc171c5bbfcb728d8a7031ad51a67a8a54556bcb95630b88a8f4fd5c6724b476an;
const HIGH_S_WITNESS =
    "0x550000001000000055000000550000004100000055978b531fc16a41be80036d384161e3638df48cd97245153f250989654fb8af3e8e3a440348d72758fce52ae59857597558202d5917e7b1308288c65deaf9d700";

// The key's signature of TESTNET_TX with its first input under the key's lock and no witness: the second input's lock and
// witness are outside the message.
const FIRST_INPUT_WITNESS =
    "0x5500000010000000550000005500000041000000ad6d895eb7b942152096021ff1eb917bb2219d233cc1da1f96947fc592d538b55caba7d8d492a6d16b08624f9f4466a1c831ab772d157c751cd549d0a7cd5e5e00";

const BOTH_INPUTS_WITNESS =
    "0x5500000010000000550000005500000041000000a30f6a9865c31848b6efa29e08d082eb7d232493004e29f661a079d3fb99604119b7eb13a111d9770ea2f1ebad7b24c8f288342a9f83061d3bbd42fc08f672ce01";

const EXTRA_WITNESS_SIGNED =
    "0x5500000010000000550000005500000041000000d5d2514bafb050259fc2d8aad42c752879ef678d9aa71ad58650eac33c090bd6135de2b886309dce3ac9351f282f9886a053ca6d1101081fb07eecf6736efbc601";

const UNSIGNED: CkbTxJson = { ...TESTNET_TX, witnesses: [] };

function locksBy(first: ScriptJson, second: ScriptJson): (outPoint: CkbOutPointJson) => Promise<ScriptJson> {
    return async (outPoint) => (outPoint.tx_hash === TESTNET_TX.inputs[0]?.previous_output.tx_hash ? first : second);
}

function signatureOf(witness: string): Uint8Array {
    const lock = readWitnessArgs(hexToBytes(witness.slice(2)), "w").lock;
    if (lock === null) assert.fail("the witness has no lock");
    return lock;
}

// A second path to the signer's: recovers the key from the signature and hashes it to the lock args.
function recoveredArgs(signature: Uint8Array, message: Uint8Array): string {
    const recovered = new Uint8Array([signature[64] ?? 0, ...signature.subarray(0, 64)]);
    return `0x${bytesToHex(ckbBlake2b(secp256k1.recoverPublicKey(recovered, message, { prehash: false })).subarray(0, 20))}`;
}

describe("sighashAllMessage", () => {
    for (const index of [0, 1]) {
        it(`is the message testnet accepted the signature of input ${index} over`, () => {
            const witness = TESTNET_TX.witnesses[index] ?? "";
            assert.equal(recoveredArgs(signatureOf(witness), sighashAllMessage(TESTNET_TX, [index])), TESTNET_INPUT_LOCK_ARGS[index]);
        });
    }

    it("is the message testnet accepted each of four one-input groups over, under locks run by type, data, data1 and data2", () => {
        for (const index of [0, 1, 2, 3]) {
            const witness = TESTNET_CODE_DEPS_TX.witnesses[index] ?? "";
            assert.equal(recoveredArgs(signatureOf(witness), sighashAllMessage(TESTNET_CODE_DEPS_TX, [index])), TESTNET_INPUT_LOCK_ARGS[0]);
        }
    });

    it("is the message testnet accepted a group over in a tx with a since and a typed output", () => {
        const witness = TESTNET_TYPED_TX.witnesses[0] ?? "";
        assert.equal(recoveredArgs(signatureOf(witness), sighashAllMessage(TESTNET_TYPED_TX, [0, 1])), TESTNET_INPUT_LOCK_ARGS[0]);
    });

    it("covers the witnesses of a group's inputs past a gap, and not the one in the gap", () => {
        const [input] = TESTNET_TX.inputs;
        if (input === undefined) assert.fail("the vector has inputs");
        const three: CkbTxJson = {
            ...TESTNET_TX,
            inputs: [...TESTNET_TX.inputs, { ...input, since: "0x1" }],
            witnesses: ["0x", "0x", "0x"],
        };
        const plain = bytesToHex(sighashAllMessage(three, [0, 2]));
        assert.equal(bytesToHex(sighashAllMessage({ ...three, witnesses: ["0x", "0xab", "0x"] }, [0, 2])), plain);
        assert.notEqual(bytesToHex(sighashAllMessage({ ...three, witnesses: ["0x", "0x", "0xab"] }, [0, 2])), plain);
    });

    it("is the message testnet accepted one signature of a two-input group over", () => {
        assert.equal(bytesToHex(ckbTxHash(TESTNET_GROUP_TX)), TESTNET_GROUP_TX_HASH.slice(2));
        const witness = TESTNET_GROUP_TX.witnesses[0] ?? "";
        assert.equal(recoveredArgs(signatureOf(witness), sighashAllMessage(TESTNET_GROUP_TX, [0, 1])), TESTNET_INPUT_LOCK_ARGS[0]);
    });

    it("leaves out a group input with no witness, as the lock stops there, but covers an empty one", () => {
        const absent = bytesToHex(sighashAllMessage(UNSIGNED, [0, 1]));
        assert.equal(bytesToHex(sighashAllMessage({ ...UNSIGNED, witnesses: ["0x"] }, [0, 1])), absent);
        assert.equal(absent, bytesToHex(sighashAllMessage(UNSIGNED, [0])));
        assert.notEqual(bytesToHex(sighashAllMessage({ ...UNSIGNED, witnesses: ["0x", "0x"] }, [0, 1])), absent);
    });

    it("covers the group's other witnesses and those past the inputs", () => {
        const alone = bytesToHex(sighashAllMessage(UNSIGNED, [0]));
        assert.notEqual(bytesToHex(sighashAllMessage({ ...UNSIGNED, witnesses: ["0x", "0xab"] }, [0, 1])), alone);
        assert.notEqual(bytesToHex(sighashAllMessage({ ...UNSIGNED, witnesses: ["0x", "0x", "0xab"] }, [0])), alone);
        assert.equal(bytesToHex(sighashAllMessage({ ...UNSIGNED, witnesses: ["0x", "0xab"] }, [0])), alone);
    });

    it("refuses an empty group", () => {
        assert.throws(() => sighashAllMessage(UNSIGNED, []), { message: "a sighash group holds one input at least" });
    });
});

describe("sighashAllLock", () => {
    it("is the default lock over the blake160 of the key's compressed public key", () => {
        assert.deepEqual(sighashAllLock(PRIVATE_KEY), KEY_LOCK);
    });
});

describe("signSighashAllInputs", () => {
    it("signs the input under the key's lock in its own witness, as testnet would check it", async () => {
        const signed = await signSighashAllInputs(UNSIGNED, PRIVATE_KEY, locksBy(KEY_LOCK, OTHER_LOCK));
        assert.deepEqual(signed, { ...UNSIGNED, witnesses: [FIRST_INPUT_WITNESS] });
        assert.equal(recoveredArgs(signatureOf(FIRST_INPUT_WITNESS), sighashAllMessage(UNSIGNED, [0])), KEY_LOCK.args);
    });

    it("signs a group of two inputs once, in the first one's witness, and gives the second an empty one", async () => {
        const signed = await signSighashAllInputs(UNSIGNED, PRIVATE_KEY, locksBy(KEY_LOCK, KEY_LOCK));
        assert.deepEqual(signed.witnesses, [BOTH_INPUTS_WITNESS, "0x"]);
        assert.equal(recoveredArgs(signatureOf(BOTH_INPUTS_WITNESS), sighashAllMessage(signed, [0, 1])), KEY_LOCK.args);
    });

    it("pads the witnesses up to a group that starts past them", async () => {
        const signed = await signSighashAllInputs(UNSIGNED, PRIVATE_KEY, locksBy(OTHER_LOCK, KEY_LOCK));
        assert.deepEqual(signed.witnesses, ["0x", FIRST_INPUT_WITNESS]);
    });

    it("keeps the witnesses past the inputs, and signs them", async () => {
        const tx = { ...UNSIGNED, witnesses: ["0x", "0x", "0xabcd"] };
        const signed = await signSighashAllInputs(tx, PRIVATE_KEY, locksBy(KEY_LOCK, OTHER_LOCK));
        assert.deepEqual(signed.witnesses, [EXTRA_WITNESS_SIGNED, "0x", "0xabcd"]);
        assert.equal(recoveredArgs(signatureOf(EXTRA_WITNESS_SIGNED), sighashAllMessage(tx, [0])), KEY_LOCK.args);
    });

    it("keeps the type fields of the witness it signs", async () => {
        const witness = `0x${bytesToHex(moleculeWitnessArgs({ lock: null, inputType: new Uint8Array([0xab]), outputType: new Uint8Array([0xcd]) }))}`;
        const tx = { ...UNSIGNED, witnesses: [witness] };
        const signed = await signSighashAllInputs(tx, PRIVATE_KEY, locksBy(KEY_LOCK, OTHER_LOCK));
        const read = readWitnessArgs(hexToBytes((signed.witnesses[0] ?? "").slice(2)), "w");
        assert.deepEqual(
            { inputType: read.inputType, outputType: read.outputType },
            { inputType: new Uint8Array([0xab]), outputType: new Uint8Array([0xcd]) },
        );
        assert.ok(read.lock !== null);
        assert.equal(recoveredArgs(read.lock, sighashAllMessage(tx, [0])), KEY_LOCK.args);
    });

    it("refuses a tx with no input under the key's lock", async () => {
        await assert.rejects(signSighashAllInputs(UNSIGNED, PRIVATE_KEY, locksBy(OTHER_LOCK, OTHER_LOCK)), {
            message: `no input of the transaction is locked by ${KEY_LOCK.args}'s default lock`,
        });
    });

    for (const [name, lock] of [
        ["another code hash", { ...KEY_LOCK, code_hash: "0x6c67887fe201ee0c7853f1682c0b77c0e6214044c156c7558269390a8afa6d7c" }],
        ["another hash type", { ...KEY_LOCK, hash_type: "data" }],
        ["other args", OTHER_LOCK],
    ] as const) {
        it(`signs no input under a lock with ${name}`, async () => {
            await assert.rejects(signSighashAllInputs(UNSIGNED, PRIVATE_KEY, locksBy(lock, OTHER_LOCK)), {
                message: /^no input of the transaction/,
            });
        });
    }

    it("matches the key's lock whatever the case of its hex", async () => {
        const upper = {
            ...KEY_LOCK,
            code_hash: KEY_LOCK.code_hash.toUpperCase().replace("0X", "0x"),
            args: KEY_LOCK.args.toUpperCase().replace("0X", "0x"),
        };
        assert.deepEqual((await signSighashAllInputs(UNSIGNED, PRIVATE_KEY, locksBy(upper, OTHER_LOCK))).witnesses, [FIRST_INPUT_WITNESS]);
    });

    it("writes the low s of a signature RFC 6979 gives high", async () => {
        const signed = await signSighashAllInputs(HIGH_S_TX, PRIVATE_KEY, locksBy(KEY_LOCK, OTHER_LOCK));
        assert.deepEqual(signed.witnesses, [HIGH_S_WITNESS, "0x", "0x00"]);
        const s = BigInt(`0x${bytesToHex(signatureOf(HIGH_S_WITNESS).subarray(32, 64))}`);
        assert.ok(HIGH_S_RAW > CURVE_ORDER / 2n, "the vector's raw s is high");
        assert.equal(s, CURVE_ORDER - HIGH_S_RAW);
        assert.equal(recoveredArgs(signatureOf(HIGH_S_WITNESS), sighashAllMessage(HIGH_S_TX, [0])), KEY_LOCK.args);
    });

    it("takes the private key in uppercase hex as the same key", async () => {
        const lower = `0x${"ab".repeat(32)}`;
        const upper = `0x${"AB".repeat(32)}`;
        const lock = sighashAllLock(lower);
        assert.deepEqual(sighashAllLock(upper), lock);
        const signed = await signSighashAllInputs(UNSIGNED, upper, locksBy(lock, OTHER_LOCK));
        assert.deepEqual(signed, await signSighashAllInputs(UNSIGNED, lower, locksBy(lock, OTHER_LOCK)));
    });

    it("refuses a first witness that is not a WitnessArgs", async () => {
        await assert.rejects(signSighashAllInputs({ ...UNSIGNED, witnesses: ["0xabcd"] }, PRIVATE_KEY, locksBy(KEY_LOCK, OTHER_LOCK)), {
            message: "witnesses[0] is not a WitnessArgs",
        });
    });

    for (const key of [PRIVATE_KEY.slice(2), `${PRIVATE_KEY}11`, PRIVATE_KEY.slice(0, -2), `0x${"zz".repeat(32)}`, ""]) {
        it(`refuses the private key ${JSON.stringify(key)}`, async () => {
            await assert.rejects(signSighashAllInputs(UNSIGNED, key, locksBy(KEY_LOCK, OTHER_LOCK)), {
                message: "the private key must be 32 bytes of 0x hex",
            });
        });
    }

    for (const key of [`0x${"00".repeat(32)}`, "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"]) {
        it(`refuses the private key ${key}, outside the curve's scalars`, async () => {
            await assert.rejects(signSighashAllInputs(UNSIGNED, key, locksBy(KEY_LOCK, OTHER_LOCK)), {
                message: "the private key is not a valid secp256k1 secret key",
            });
        });
    }
});

describe("liveCellLockResolver", () => {
    const URL = "https://ckb.example/";
    const OUT_POINT: CkbOutPointJson = { tx_hash: "0xa87cffdc2ebdb9bfe82b0ae1ecc51f47ace9bf5ef0ee90668cdb261f580dd61f", index: "0x0" };

    function answering(result: unknown): { fetch: AgentNodeFetch; bodies: string[] } {
        const bodies: string[] = [];
        const fetch: AgentNodeFetch = async (url, init) => {
            assert.equal(url, URL);
            bodies.push(init.body);
            return { status: 200, text: async () => JSON.stringify({ jsonrpc: "2.0", result, id: 1 }) };
        };
        return { fetch, bodies };
    }

    it("reads the lock of a live cell", async () => {
        const { fetch, bodies } = answering({
            cell: { output: { capacity: "0x746a528800", lock: KEY_LOCK, type: null }, data: null },
            status: "live",
        });
        assert.deepEqual(await liveCellLockResolver(URL, fetch)(OUT_POINT), KEY_LOCK);
        assert.deepEqual(
            bodies.map((body) => JSON.parse(body) as unknown),
            [{ jsonrpc: "2.0", method: "get_live_cell", params: [OUT_POINT, false], id: 1 }],
        );
    });

    for (const status of ["dead", "unknown", undefined]) {
        it(`refuses a cell whose status is ${JSON.stringify(status)}`, async () => {
            const { fetch } = answering({ cell: null, status });
            await assert.rejects(liveCellLockResolver(URL, fetch)(OUT_POINT), {
                message: `get_live_cell ${OUT_POINT.tx_hash}:0x0 is ${JSON.stringify(status)}, not live`,
            });
        });
    }

    for (const [name, result, field] of [
        ["no result", null, ""],
        ["a live status with no cell", { status: "live", cell: null }, ".cell"],
        ["a live cell with no output", { status: "live", cell: { data: null } }, ".cell.output"],
    ] as const) {
        it(`refuses ${name}`, async () => {
            const { fetch } = answering(result);
            await assert.rejects(liveCellLockResolver(URL, fetch)(OUT_POINT), {
                message: `get_live_cell ${OUT_POINT.tx_hash}:0x0${field} must be an object`,
            });
        });
    }

    it("refuses a live cell with no lock script", async () => {
        const { fetch } = answering({ cell: { output: { capacity: "0x1", lock: null, type: null } }, status: "live" });
        await assert.rejects(liveCellLockResolver(URL, fetch)(OUT_POINT), {
            message: `get_live_cell ${OUT_POINT.tx_hash}:0x0.cell.output.lock must be an object`,
        });
    });
});
