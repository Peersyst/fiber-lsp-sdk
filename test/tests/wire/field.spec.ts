import type { Field } from "../../../src/wire";
import {
    decodeBoolean,
    decodeEnum,
    decodeMapped,
    decodeNonEmptyString,
    decodeString,
    decodeUnsignedInteger,
    malformed,
    readArray,
    readObject,
    readPair,
    requireObject,
} from "../../../src/wire";
import { refusal } from "../../utils/refusal";

function field(value: unknown, path = "root"): Field {
    return { value, path };
}

describe("malformed", () => {
    it("refuses with the field's path and the reason", () => {
        const error = refusal(() => malformed(field(1, "a.b[2]"), "must be bytes"));
        expect(error.path).toBe("a.b[2]");
        expect(error.reason).toBe("must be bytes");
        expect(error.message).toBe("a.b[2] must be bytes");
    });
});

describe("requireObject", () => {
    it("returns a plain object as is", () => {
        const value = { a: 1 };
        expect(requireObject(field(value))).toBe(value);
    });

    it.each([null, [], "x", 1, true, undefined])("refuses %p", (value) => {
        expect(refusal(() => requireObject(field(value))).message).toBe("root must be an object");
    });
});

describe("readObject", () => {
    it("reads each member as a field with a dotted path", () => {
        const at = readObject<{ a: number; b: string }>(field({ a: 1 }));
        expect(at("a")).toEqual({ value: 1, path: "root.a" });
        expect(at("b")).toEqual({ value: undefined, path: "root.b" });
    });

    it("refuses what is not an object before any member is read", () => {
        expect(refusal(() => readObject(field([]))).path).toBe("root");
    });
});

describe("readArray", () => {
    it("reads each item as a field with an indexed path", () => {
        expect(readArray(field(["x", 2]))).toEqual([
            { value: "x", path: "root[0]" },
            { value: 2, path: "root[1]" },
        ]);
        expect(readArray(field([]))).toEqual([]);
    });

    it("holds the array to an exact length when one is given", () => {
        expect(readArray(field([1, 2]), 2)).toHaveLength(2);
        expect(refusal(() => readArray(field([1]), 2)).message).toBe("root must have exactly 2 items");
        expect(refusal(() => readArray(field([1, 2, 3]), 2)).message).toBe("root must have exactly 2 items");
        expect(refusal(() => readArray(field([]), 1)).message).toBe("root must have exactly 1 items");
    });

    it.each([{}, null, "ab", 2, undefined])("refuses %p", (value) => {
        expect(refusal(() => readArray(field(value))).message).toBe("root must be an array");
    });
});

describe("readPair", () => {
    it("reads exactly two items", () => {
        expect(readPair(field(["a", "b"]))).toEqual([
            { value: "a", path: "root[0]" },
            { value: "b", path: "root[1]" },
        ]);
        expect(refusal(() => readPair(field(["a"]))).message).toBe("root must have exactly 2 items");
        expect(refusal(() => readPair(field(["a", "b", "c"]))).message).toBe("root must have exactly 2 items");
    });
});

describe("decodeBoolean", () => {
    it("reads both booleans", () => {
        expect(decodeBoolean(field(true))).toBe(true);
        expect(decodeBoolean(field(false))).toBe(false);
    });

    it.each(["true", 1, 0, null, undefined, {}])("refuses %p", (value) => {
        expect(refusal(() => decodeBoolean(field(value))).message).toBe("root must be a boolean");
    });
});

describe("decodeString", () => {
    it("reads any string, empty included", () => {
        expect(decodeString(field(""))).toBe("");
        expect(decodeString(field("x"))).toBe("x");
    });

    it.each([1, null, undefined, ["x"]])("refuses %p", (value) => {
        expect(refusal(() => decodeString(field(value))).message).toBe("root must be a string");
    });
});

describe("decodeNonEmptyString", () => {
    it("reads a string with at least one character", () => {
        expect(decodeNonEmptyString(field("x"))).toBe("x");
    });

    it.each(["", 1, null, undefined])("refuses %p", (value) => {
        expect(refusal(() => decodeNonEmptyString(field(value))).message).toBe("root must be a non-empty string");
    });
});

describe("decodeEnum", () => {
    const VALUES = ["offered", "received"] as const;

    it("reads a member of the set", () => {
        expect(decodeEnum(field("received"), VALUES)).toBe("received");
    });

    it.each(["Offered", "sent", "", 1, null, undefined, ["offered"]])("refuses %p, naming the set and not the value", (value) => {
        expect(refusal(() => decodeEnum(field(value), VALUES)).message).toBe("root must be one of offered, received");
    });
});

describe("decodeMapped", () => {
    const SPELLINGS = { ckb_hash: "ckb-hash", sha256: "sha256" } as const;

    it("reads a wire spelling and returns the SDK's", () => {
        expect(decodeMapped(field("ckb_hash"), SPELLINGS)).toBe("ckb-hash");
        expect(decodeMapped(field("sha256"), SPELLINGS)).toBe("sha256");
    });

    it.each(["ckb-hash", "CKB_HASH", "constructor", "toString", "__proto__", "hasOwnProperty", 1, undefined])("refuses %p", (value) => {
        expect(refusal(() => decodeMapped(field(value), SPELLINGS)).message).toBe("root must be one of ckb_hash, sha256");
    });
});

describe("decodeUnsignedInteger", () => {
    it("reads an integer within the bound", () => {
        expect(decodeUnsignedInteger(field(0), 5)).toBe(0);
        expect(decodeUnsignedInteger(field(5), 5)).toBe(5);
        expect(decodeUnsignedInteger(field(Number.MAX_SAFE_INTEGER), Number.MAX_SAFE_INTEGER)).toBe(Number.MAX_SAFE_INTEGER);
    });

    it.each([6, -1, 1.5, "1", NaN, Infinity, null, undefined, 2 ** 53])("refuses %p", (value) => {
        expect(refusal(() => decodeUnsignedInteger(field(value), 5)).message).toBe("root must be an integer between 0 and 5");
    });
});
