import { assertRequestId, decodeChannelId, decodeRequestId, isRequestId } from "../../../../src/protocol/utils";
import { WireError } from "../../../../src/wire";

const FIELD = { path: "root" };
const CHANNEL_ID = `0x${"1f".repeat(32)}`;

describe("isRequestId", () => {
    it("accepts 1 to 64 printable ASCII characters", () => {
        expect(isRequestId("1")).toBe(true);
        expect(isRequestId("0x2a")).toBe(true);
        expect(isRequestId("a".repeat(64))).toBe(true);
        expect(isRequestId(" ~")).toBe(true);
    });

    it.each([
        ["empty", ""],
        ["65 characters", "a".repeat(65)],
        ["a character outside ASCII", "req-é"],
        ["64 characters that are more than 64 bytes", "é".repeat(64)],
        ["a surrogate pair", "req-\u{1f511}"],
        ["a control character", "req\n1"],
        ["the NUL character", "req\x001"],
        ["DEL, the one control character above the printable range", "req\x7f"],
        ["a number", 1],
        ["null", null],
        ["undefined", undefined],
        ["an array", ["1"]],
    ])("refuses %s", (_, value) => {
        expect(isRequestId(value)).toBe(false);
    });
});

describe("assertRequestId", () => {
    it("accepts an id the wire carries", () => {
        expect(() => assertRequestId("a")).not.toThrow();
        expect(() => assertRequestId("a".repeat(64))).not.toThrow();
    });

    it.each(["", "a".repeat(65), "req-é"])("rejects %p, which is a device bug and not a refusal", (requestId) => {
        expect(() => assertRequestId(requestId)).toThrow(TypeError);
        expect(() => assertRequestId(requestId)).toThrow("requestId must be a string of 1 to 64 printable ASCII characters");
    });
});

describe("decodeRequestId", () => {
    it("keeps the id as the opaque string it is", () => {
        expect(decodeRequestId({ ...FIELD, value: "req 1" })).toBe("req 1");
    });

    it.each(["", "a".repeat(65), "req-é", "req\n1", 7, undefined])("refuses %p", (value) => {
        expect(() => decodeRequestId({ ...FIELD, value })).toThrow(WireError);
        expect(() => decodeRequestId({ ...FIELD, value })).toThrow("root must be a string of 1 to 64 printable ASCII characters");
    });
});

describe("decodeChannelId", () => {
    it("keeps the wire string of a 32-byte hash", () => {
        expect(decodeChannelId({ ...FIELD, value: CHANNEL_ID })).toBe(CHANNEL_ID);
    });

    it.each([`0x${"1f".repeat(31)}`, `0x${"1f".repeat(33)}`, `0x${"1F".repeat(32)}`, "1f".repeat(32), "", undefined, 1])(
        "refuses %p",
        (value) => {
            expect(() => decodeChannelId({ ...FIELD, value })).toThrow("root must be 32 bytes of 0x-prefixed lowercase hex");
        },
    );
});
