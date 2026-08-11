import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { ckbBlake2b } from "../../../../src/common/utils/ckb-hash.utils";
import { blake2bHashWithSalt } from "../../../../src/derivation/utils/ckb-hash.utils";

const DATA = utf8ToBytes("data");
const SALT = utf8ToBytes("salt");

describe("blake2bHashWithSalt", () => {
    it("hashes the salt before the data", () => {
        expect(bytesToHex(blake2bHashWithSalt(DATA, SALT))).toBe(bytesToHex(ckbBlake2b(SALT, DATA)));
    });

    it("is not the same as hashing the data before the salt", () => {
        expect(bytesToHex(blake2bHashWithSalt(DATA, SALT))).not.toBe(bytesToHex(ckbBlake2b(DATA, SALT)));
    });
});
