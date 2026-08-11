import { blake2b } from "@noble/hashes/blake2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { blake160, ckbBlake2b } from "../../../../src/common/utils/ckb-hash.utils";

const DATA = utf8ToBytes("data");
const SALT = utf8ToBytes("salt");

describe("ckbBlake2b", () => {
    it("matches CKB's digest of the empty input", () => {
        expect(bytesToHex(ckbBlake2b(new Uint8Array(0)))).toBe("44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e");
    });

    it("returns 32 bytes", () => {
        expect(ckbBlake2b(DATA)).toHaveLength(32);
    });

    it("hashes chunks as one concatenated input", () => {
        expect(bytesToHex(ckbBlake2b(SALT, DATA))).toBe(bytesToHex(ckbBlake2b(concatBytes(SALT, DATA))));
    });

    it("depends on the order of the chunks", () => {
        expect(bytesToHex(ckbBlake2b(SALT, DATA))).not.toBe(bytesToHex(ckbBlake2b(DATA, SALT)));
    });

    it("applies the CKB personalization", () => {
        expect(bytesToHex(ckbBlake2b(DATA))).not.toBe(bytesToHex(blake2b(DATA, { dkLen: 32 })));
    });

    it("does not mutate its input", () => {
        const input = Uint8Array.from(DATA);
        ckbBlake2b(input);
        expect(bytesToHex(input)).toBe(bytesToHex(DATA));
    });
});

describe("blake160", () => {
    it("is the first 20 bytes of the CKB blake2b-256 digest", () => {
        const data = Uint8Array.of(0xde, 0xad, 0xbe, 0xef);
        expect(blake160(data)).toHaveLength(20);
        expect(bytesToHex(blake160(data))).toBe(bytesToHex(ckbBlake2b(data).slice(0, 20)));
    });

    it("hashes multiple chunks as one input", () => {
        expect(bytesToHex(blake160(Uint8Array.of(0xde, 0xad), Uint8Array.of(0xbe, 0xef)))).toBe(
            bytesToHex(blake160(Uint8Array.of(0xde, 0xad, 0xbe, 0xef))),
        );
    });
});
