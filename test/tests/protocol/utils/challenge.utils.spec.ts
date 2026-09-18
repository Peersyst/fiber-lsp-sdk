import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { ckbBlake2b } from "../../../../src/common";
import { CHALLENGE_LENGTH, SESSION_CHALLENGE_LABEL, sessionChallengeDigest } from "../../../../src/protocol";

const CHALLENGE = new Uint8Array(CHALLENGE_LENGTH).fill(0x5c);

describe("sessionChallengeDigest", () => {
    it("hashes the label ahead of the challenge, CKB style", () => {
        expect(bytesToHex(sessionChallengeDigest(CHALLENGE))).toBe(bytesToHex(ckbBlake2b(utf8ToBytes(SESSION_CHALLENGE_LABEL), CHALLENGE)));
    });

    // The bridge computes this exact digest to verify the signed challenge: a change here is a protocol change.
    it("is pinned", () => {
        expect(bytesToHex(sessionChallengeDigest(CHALLENGE))).toBe("ab23c4c15cb8c8b73908510d3153a703d94e511fd2dc5cba27bf4e711ddf5f44");
    });

    it("is neither the bare challenge nor its plain hash", () => {
        const digest = bytesToHex(sessionChallengeDigest(CHALLENGE));
        expect(digest).not.toBe(bytesToHex(CHALLENGE));
        expect(digest).not.toBe(bytesToHex(ckbBlake2b(CHALLENGE)));
    });

    it("is distinct per challenge", () => {
        const other = Uint8Array.from(CHALLENGE).fill(0x5d, 0, 1);
        expect(bytesToHex(sessionChallengeDigest(other))).not.toBe(bytesToHex(sessionChallengeDigest(CHALLENGE)));
    });

    it.each([0, CHALLENGE_LENGTH - 1, CHALLENGE_LENGTH + 1])("rejects a challenge of %i bytes", (length) => {
        expect(() => sessionChallengeDigest(new Uint8Array(length))).toThrow(TypeError);
    });
});
