import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { AgentRequestError } from "../src/agent.error";
import { readCkbBytes, readCkbCellDep, readCkbHash, readCkbOutPoint, readCkbQuantity } from "../src/ckb-json";

const HASH = "0xa87cffdc2ebdb9bfe82b0ae1ecc51f47ace9bf5ef0ee90668cdb261f580dd61f";

function refuses(read: () => unknown, message: string): void {
    assert.throws(read, (error: unknown) => error instanceof AgentRequestError && error.message === message);
}

describe("readCkbQuantity", () => {
    for (const value of ["0x0", "0x1", "0xff"]) {
        it(`reads ${value}`, () => {
            assert.equal(readCkbQuantity(value, 0xffn, "q"), value);
        });
    }

    it("refuses one past its bound", () => {
        refuses(() => readCkbQuantity("0x100", 0xffn, "q"), "q is out of range");
    });

    for (const value of ["0x", "0x00", "0x01", "0xA", "0", " 0x0", "0x0 ", 0, null]) {
        it(`refuses ${JSON.stringify(value)}`, () => {
            refuses(() => readCkbQuantity(value, 0xffn, "q"), "q must be a hex integer");
        });
    }
});

describe("readCkbBytes", () => {
    for (const value of ["0x", "0xab", "0xABcd"]) {
        it(`reads ${value}`, () => {
            assert.equal(readCkbBytes(value, "b"), value);
        });
    }

    for (const value of ["0xa", "ab", "0xzz", "0x ", 1, null]) {
        it(`refuses ${JSON.stringify(value)}`, () => {
            refuses(() => readCkbBytes(value, "b"), "b must be 0x hex bytes");
        });
    }
});

describe("readCkbHash", () => {
    it("reads 32 bytes of hex in either case", () => {
        assert.equal(readCkbHash(HASH, "h"), HASH);
        assert.equal(readCkbHash(`0x${HASH.slice(2).toUpperCase()}`, "h"), `0x${HASH.slice(2).toUpperCase()}`);
    });

    for (const value of [HASH.slice(2), `${HASH}00`, HASH.slice(0, -2), `0x${"zz".repeat(32)}`, 1]) {
        it(`refuses ${JSON.stringify(value)}`, () => {
            refuses(() => readCkbHash(value, "h"), "h must be 32 bytes of 0x hex");
        });
    }
});

describe("readCkbOutPoint", () => {
    it("reads an out point up to the largest index", () => {
        assert.deepEqual(readCkbOutPoint({ tx_hash: HASH, index: "0xffffffff" }, "p"), { tx_hash: HASH, index: "0xffffffff" });
    });

    it("refuses an index past u32", () => {
        refuses(() => readCkbOutPoint({ tx_hash: HASH, index: "0x100000000" }, "p"), "p.index is out of range");
    });

    it("refuses an absent index or tx_hash, and a field it does not have", () => {
        refuses(() => readCkbOutPoint({ tx_hash: HASH }, "p"), "p.index must be a hex integer");
        refuses(() => readCkbOutPoint({ index: "0x0" }, "p"), "p.tx_hash must be 32 bytes of 0x hex");
        refuses(() => readCkbOutPoint({ tx_hash: HASH, index: "0x0", extra: 1 }, "p"), "p.extra is not a known field");
    });
});

describe("readCkbCellDep", () => {
    for (const depType of ["code", "dep_group"] as const) {
        it(`reads a ${depType} dep`, () => {
            const dep = { out_point: { tx_hash: HASH, index: "0x1" }, dep_type: depType };
            assert.deepEqual(readCkbCellDep(dep, "d"), dep);
        });
    }

    for (const depType of [undefined, "Code", "depGroup", "data"]) {
        it(`refuses dep_type ${JSON.stringify(depType)}`, () => {
            refuses(
                () => readCkbCellDep({ out_point: { tx_hash: HASH, index: "0x1" }, dep_type: depType }, "d"),
                "d.dep_type must be code or dep_group",
            );
        });
    }

    it("refuses an absent out_point and a field it does not have", () => {
        refuses(() => readCkbCellDep({ dep_type: "code" }, "d"), "d.out_point must be an object");
        refuses(
            () => readCkbCellDep({ out_point: { tx_hash: HASH, index: "0x1" }, dep_type: "code", extra: 1 }, "d"),
            "d.extra is not a known field",
        );
    });
});
