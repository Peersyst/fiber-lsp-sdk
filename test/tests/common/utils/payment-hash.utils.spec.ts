import { hexToBytes } from "@noble/hashes/utils.js";
import { truncatePaymentHash } from "../../../../src/common";

describe("truncatePaymentHash", () => {
    it("keeps the first 20 bytes, the ones a settlement witness entry binds", () => {
        const hash = hexToBytes("6844f645bb03ff9d1c9c48ee5e9e971be09bf34a3612c81b20c2a5a1bff2a6b6");
        expect(truncatePaymentHash(hash)).toEqual(hexToBytes("6844f645bb03ff9d1c9c48ee5e9e971be09bf34a"));
    });

    it("hands back a copy, so the caller's hash stays its own", () => {
        const hash = new Uint8Array(32).fill(7);
        truncatePaymentHash(hash).fill(0);
        expect(hash).toEqual(new Uint8Array(32).fill(7));
    });
});
