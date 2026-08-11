import { compareBytes } from "../../../../src/common/utils/bytes.utils";

describe("compareBytes", () => {
    it("orders lexicographically", () => {
        expect(compareBytes(Uint8Array.of(0x01), Uint8Array.of(0x02))).toBeLessThan(0);
        expect(compareBytes(Uint8Array.of(0x02), Uint8Array.of(0x01))).toBeGreaterThan(0);
        expect(compareBytes(Uint8Array.of(0x01, 0xff), Uint8Array.of(0x02, 0x00))).toBeLessThan(0);
        expect(compareBytes(Uint8Array.of(0x01), Uint8Array.of(0x01))).toBe(0);
    });

    it("orders a strict prefix first", () => {
        expect(compareBytes(Uint8Array.of(0x01), Uint8Array.of(0x01, 0x00))).toBeLessThan(0);
        expect(compareBytes(Uint8Array.of(0x01, 0x00), Uint8Array.of(0x01))).toBeGreaterThan(0);
    });
});
