import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { AgentRequestError } from "../src/agent.error";
import { readExactJsonObject, readJsonList } from "../src/agent.utils";

function refuses(read: () => unknown, message: string): void {
    assert.throws(read, (error: unknown) => error instanceof AgentRequestError && error.message === message);
}

describe("readExactJsonObject", () => {
    it("reads an object with some or all of its keys", () => {
        assert.deepEqual(readExactJsonObject({ a: 1 }, ["a", "b"], "o"), { a: 1 });
        assert.deepEqual(readExactJsonObject({ a: 1, b: 2 }, ["a", "b"], "o"), { a: 1, b: 2 });
    });

    it("refuses a key outside them", () => {
        refuses(() => readExactJsonObject({ a: 1, c: 3 }, ["a", "b"], "o"), "o.c is not a known field");
    });

    for (const value of [null, [], "o", 1]) {
        it(`refuses ${JSON.stringify(value)}`, () => {
            refuses(() => readExactJsonObject(value, ["a"], "o"), "o must be an object");
        });
    }
});

describe("readJsonList", () => {
    it("reads each item where it sits", () => {
        const seen: string[] = [];
        const read = (item: unknown, at: string): string => {
            seen.push(at);
            return String(item);
        };
        assert.deepEqual(readJsonList(["x", "y"], "l", read), ["x", "y"]);
        assert.deepEqual(seen, ["l[0]", "l[1]"]);
    });

    for (const value of [null, {}, "l"]) {
        it(`refuses ${JSON.stringify(value)}`, () => {
            refuses(() => readJsonList(value, "l", String), "l must be an array");
        });
    }
});
