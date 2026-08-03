import { blake2b } from "@noble/hashes/blake2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { DIGEST_LENGTH } from "../../../../src/derivation/derivation.constants.js";
import { blake2bHashWithSalt, ckbBlake2b } from "../../../../src/derivation/utils/ckb-hash.utils.js";

const DATA = utf8ToBytes("data");
const SALT = utf8ToBytes("salt");

describe("ckbBlake2b", () => {
    it("matches CKB's digest of the empty input", () => {
        expect(bytesToHex(ckbBlake2b(new Uint8Array(0)))).toBe("44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e");
    });

    it("returns 32 bytes", () => {
        expect(ckbBlake2b(DATA)).toHaveLength(DIGEST_LENGTH);
    });

    it("hashes chunks as one concatenated input", () => {
        expect(bytesToHex(ckbBlake2b(SALT, DATA))).toBe(bytesToHex(ckbBlake2b(concatBytes(SALT, DATA))));
    });

    it("depends on the order of the chunks", () => {
        expect(bytesToHex(ckbBlake2b(SALT, DATA))).not.toBe(bytesToHex(ckbBlake2b(DATA, SALT)));
    });

    it("applies the CKB personalization", () => {
        expect(bytesToHex(ckbBlake2b(DATA))).not.toBe(bytesToHex(blake2b(DATA, { dkLen: DIGEST_LENGTH })));
    });

    it("does not mutate its input", () => {
        const input = Uint8Array.from(DATA);
        ckbBlake2b(input);
        expect(bytesToHex(input)).toBe(bytesToHex(DATA));
    });
});

describe("blake2bHashWithSalt", () => {
    it("hashes the salt before the data", () => {
        expect(bytesToHex(blake2bHashWithSalt(DATA, SALT))).toBe(bytesToHex(ckbBlake2b(SALT, DATA)));
    });

    it("is not the same as hashing the data before the salt", () => {
        expect(bytesToHex(blake2bHashWithSalt(DATA, SALT))).not.toBe(bytesToHex(ckbBlake2b(DATA, SALT)));
    });
});
