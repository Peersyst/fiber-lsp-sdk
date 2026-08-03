import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { MAX_COMMITMENT_NUMBER } from "../../../src/derivation/derivation.constants.js";
import {
    deriveChannelKeys,
    derivePrivateKey,
    derivePublicKey,
    deriveTlcKey,
    getCommitmentPoint,
    getCommitmentSecret,
    getTweakByCommitmentPoint,
    pubkeyOf,
    tweakPrivkey,
} from "../../../src/derivation/fiber-scheme.js";
import { ckbBlake2b } from "../../../src/derivation/utils/ckb-hash.utils.js";

const CURVE_ORDER = secp256k1.Point.Fn.ORDER;
const CHANNEL_SEED = new Uint8Array(32).fill(0x42);
const keys = deriveChannelKeys(CHANNEL_SEED);
const COMMITMENT_NUMBERS = [0, 1, 2, 5, 1000, 65535, MAX_COMMITMENT_NUMBER];

describe("deriveChannelKeys", () => {
    it("derives four distinct 32-byte secrets", () => {
        const secrets = [keys.fundingKey, keys.tlcBaseKey, keys.musig2BaseNonce, keys.commitmentSeed];
        for (const secret of secrets) expect(secret).toHaveLength(32);
        expect(new Set(secrets.map(bytesToHex)).size).toBe(4);
    });

    it("is deterministic", () => {
        expect(bytesToHex(deriveChannelKeys(CHANNEL_SEED).fundingKey)).toBe(bytesToHex(keys.fundingKey));
    });

    it("derives different keys from different seeds", () => {
        const other = deriveChannelKeys(new Uint8Array(32).fill(0x43));
        expect(bytesToHex(other.fundingKey)).not.toBe(bytesToHex(keys.fundingKey));
    });

    it("does not mutate the seed", () => {
        const seed = new Uint8Array(32).fill(0x42);
        deriveChannelKeys(seed);
        expect(bytesToHex(seed)).toBe(bytesToHex(CHANNEL_SEED));
    });

    it.each([31, 33])("rejects a %i-byte seed", (length) => {
        expect(() => deriveChannelKeys(new Uint8Array(length))).toThrow(TypeError);
    });
});

describe("pubkeyOf", () => {
    it("returns a compressed point", () => {
        const pubkey = pubkeyOf(keys.fundingKey);
        expect(pubkey).toHaveLength(33);
        expect([0x02, 0x03]).toContain(pubkey[0]);
    });

    it("rejects a secret key of the wrong length", () => {
        expect(() => pubkeyOf(new Uint8Array(31))).toThrow(TypeError);
    });

    it("rejects the zero secret key", () => {
        expect(() => pubkeyOf(new Uint8Array(32))).toThrow();
    });

    it("rejects a secret key at the curve order", () => {
        expect(() => pubkeyOf(numberToBytesBE(CURVE_ORDER, 32))).toThrow();
    });
});

describe("tweakPrivkey", () => {
    it("adds the scalar to the key modulo the curve order", () => {
        const secretKey = numberToBytesBE(7n, 32);
        const scalar = numberToBytesBE(11n, 32);
        expect(bytesToHex(tweakPrivkey(secretKey, scalar))).toBe(bytesToHex(numberToBytesBE(18n, 32)));
    });

    it("returns the key unchanged when the scalar is zero", () => {
        expect(bytesToHex(tweakPrivkey(keys.fundingKey, new Uint8Array(32)))).toBe(bytesToHex(keys.fundingKey));
    });

    it("is symmetric in its two operands", () => {
        expect(bytesToHex(tweakPrivkey(keys.fundingKey, keys.tlcBaseKey))).toBe(bytesToHex(tweakPrivkey(keys.tlcBaseKey, keys.fundingKey)));
    });

    it("reduces a scalar at the curve order", () => {
        expect(bytesToHex(tweakPrivkey(keys.fundingKey, numberToBytesBE(CURVE_ORDER, 32)))).toBe(bytesToHex(keys.fundingKey));
    });

    it("refuses a tweak that cancels the key", () => {
        const secretKey = numberToBytesBE(1n, 32);
        const scalar = numberToBytesBE(CURVE_ORDER - 1n, 32);
        expect(() => tweakPrivkey(secretKey, scalar)).toThrow("tweak produced a zero private key");
    });

    it.each([31, 33])("rejects a %i-byte operand", (length) => {
        expect(() => tweakPrivkey(new Uint8Array(length), new Uint8Array(32))).toThrow(TypeError);
        expect(() => tweakPrivkey(new Uint8Array(32), new Uint8Array(length))).toThrow(TypeError);
    });
});

describe("getTweakByCommitmentPoint", () => {
    it("hashes the compressed point", () => {
        const point = getCommitmentPoint(keys.commitmentSeed, 0);
        expect(bytesToHex(getTweakByCommitmentPoint(point))).toBe(bytesToHex(ckbBlake2b(point)));
    });

    it("rejects anything but a 33-byte point", () => {
        expect(() => getTweakByCommitmentPoint(new Uint8Array(32))).toThrow(TypeError);
    });

    // fiber serialises compressed: hashing the uncompressed form of the same point
    // would produce a different tweak, and therefore different keys, silently.
    it("rejects the uncompressed serialisation of a valid point", () => {
        const uncompressed = secp256k1.Point.fromBytes(getCommitmentPoint(keys.commitmentSeed, 0)).toBytes(false);
        expect(uncompressed).toHaveLength(65);
        expect(() => getTweakByCommitmentPoint(uncompressed)).toThrow(TypeError);
    });
});

describe("derivePrivateKey and derivePublicKey", () => {
    it.each(COMMITMENT_NUMBERS)("agree on the derived key for commitment %i", (commitmentNumber) => {
        const point = getCommitmentPoint(keys.commitmentSeed, commitmentNumber);
        const fromSecret = pubkeyOf(derivePrivateKey(keys.tlcBaseKey, point));
        const fromPublic = derivePublicKey(pubkeyOf(keys.tlcBaseKey), point);
        expect(bytesToHex(fromSecret)).toBe(bytesToHex(fromPublic));
    });

    it("derives a different key per commitment point", () => {
        const first = derivePrivateKey(keys.tlcBaseKey, getCommitmentPoint(keys.commitmentSeed, 0));
        const second = derivePrivateKey(keys.tlcBaseKey, getCommitmentPoint(keys.commitmentSeed, 1));
        expect(bytesToHex(first)).not.toBe(bytesToHex(second));
    });

    it("rejects a base public key that is not a compressed point", () => {
        expect(() => derivePublicKey(new Uint8Array(32), getCommitmentPoint(keys.commitmentSeed, 0))).toThrow(TypeError);
    });

    it("rejects a base public key that is not on the curve", () => {
        const offCurve = new Uint8Array(33);
        offCurve[0] = 0x02;
        expect(() => derivePublicKey(offCurve, getCommitmentPoint(keys.commitmentSeed, 0))).toThrow();
    });

    it("rejects a commitment point that is not 33 bytes", () => {
        expect(() => derivePrivateKey(keys.tlcBaseKey, new Uint8Array(32))).toThrow(TypeError);
        expect(() => derivePublicKey(pubkeyOf(keys.tlcBaseKey), new Uint8Array(32))).toThrow(TypeError);
    });

    // The public counterpart of "refuses a tweak that cancels the key": the derived
    // point is the identity, which is not a public key. Both paths must refuse, or
    // node and device would disagree on what happened.
    it("refuses a base public key that the tweak cancels", () => {
        const point = getCommitmentPoint(keys.commitmentSeed, 0);
        const tweak = bytesToNumberBE(getTweakByCommitmentPoint(point)) % CURVE_ORDER;
        const cancelling = secp256k1.Point.BASE.multiply(CURVE_ORDER - tweak).toBytes(true);
        expect(() => derivePublicKey(cancelling, point)).toThrow();
    });
});

describe("getCommitmentSecret", () => {
    it("returns the seed itself for commitment 0", () => {
        expect(bytesToHex(getCommitmentSecret(keys.commitmentSeed, 0))).toBe(bytesToHex(keys.commitmentSeed));
    });

    it("returns a copy the caller can mutate safely", () => {
        const channelKeys = deriveChannelKeys(CHANNEL_SEED);
        const secret = getCommitmentSecret(channelKeys.commitmentSeed, 0);
        secret[0] = (secret[0] ?? 0) ^ 0xff;
        expect(bytesToHex(channelKeys.commitmentSeed)).toBe(bytesToHex(keys.commitmentSeed));
    });

    it("is distinct for every commitment number in a range", () => {
        const secrets = new Set<string>();
        for (let commitmentNumber = 0; commitmentNumber <= 64; commitmentNumber++) {
            secrets.add(bytesToHex(getCommitmentSecret(keys.commitmentSeed, commitmentNumber)));
        }
        expect(secrets.size).toBe(65);
    });

    it("accepts the highest commitment number of the 48-bit chain", () => {
        expect(getCommitmentSecret(keys.commitmentSeed, MAX_COMMITMENT_NUMBER)).toHaveLength(32);
    });

    it.each([-1, 1.5, 2 ** 48, Number.MAX_SAFE_INTEGER, NaN])("rejects the out-of-range commitment number %p", (commitmentNumber) => {
        expect(() => getCommitmentSecret(keys.commitmentSeed, commitmentNumber)).toThrow(RangeError);
    });

    it("does not mutate the seed", () => {
        const seed = Uint8Array.from(keys.commitmentSeed);
        getCommitmentSecret(seed, 12345);
        expect(bytesToHex(seed)).toBe(bytesToHex(keys.commitmentSeed));
    });

    // The chain walks bits high to low, so a secret already reached at index I is the
    // starting state for every index that only adds bits below I's lowest set one.
    // This is what lets the counterparty store the revealed secrets in 48 values, and
    // the reason Lightning counts commitment numbers downwards.
    it("reaches a later secret from an earlier one when the extra bits are lower", () => {
        const reached = 0b110000;
        const lowerBits = 0b001011;
        expect(bytesToHex(getCommitmentSecret(getCommitmentSecret(keys.commitmentSeed, reached), lowerBits))).toBe(
            bytesToHex(getCommitmentSecret(keys.commitmentSeed, reached | lowerBits)),
        );
    });

    // A caller may hand over a view into a larger buffer; reading `.buffer` instead of
    // copying would silently hash the wrong 32 bytes.
    it("accepts a seed that is a view into a larger buffer", () => {
        const backing = new Uint8Array(64).fill(0xaa);
        backing.set(keys.commitmentSeed, 32);
        expect(bytesToHex(getCommitmentSecret(backing.subarray(32), 12345))).toBe(
            bytesToHex(getCommitmentSecret(keys.commitmentSeed, 12345)),
        );
    });
});

describe("getCommitmentPoint", () => {
    it("is the public key of the commitment secret", () => {
        expect(bytesToHex(getCommitmentPoint(keys.commitmentSeed, 7))).toBe(
            bytesToHex(pubkeyOf(getCommitmentSecret(keys.commitmentSeed, 7))),
        );
    });
});

describe("deriveTlcKey", () => {
    it("tweaks the TLC base key by the commitment point", () => {
        const point = getCommitmentPoint(keys.commitmentSeed, 3);
        expect(bytesToHex(deriveTlcKey(keys, 3))).toBe(bytesToHex(derivePrivateKey(keys.tlcBaseKey, point)));
    });

    it("is distinct per commitment number", () => {
        const derived = new Set(COMMITMENT_NUMBERS.map((n) => bytesToHex(deriveTlcKey(keys, n))));
        expect(derived.size).toBe(COMMITMENT_NUMBERS.length);
    });

    it("rejects an out-of-range commitment number", () => {
        expect(() => deriveTlcKey(keys, 2 ** 48)).toThrow(RangeError);
    });
});

describe("fiber scheme outputs", () => {
    // The compatibility contract with upstream, pinned by hand and deliberately
    // redundant with the interop vectors: those live in a generated file, so a change
    // made on both sides at once would regenerate them green. The domain separators
    // are inside these hashes, so "fixing" one lands here. Not a snapshot to update.
    it("derives the pinned channel keys", () => {
        expect(bytesToHex(keys.fundingKey)).toBe("c0449fe2045920ba83ab6e805b6b4c63173cafbd50b8c1f58ce8a5ef69ed8226");
        expect(bytesToHex(keys.tlcBaseKey)).toBe("96043d26cb586b8d307daad24a88c28b2c85e9fba3d30889d1fe35d5a2c4f858");
        expect(bytesToHex(keys.musig2BaseNonce)).toBe("3a672ccb70ee09558e596fcc742111b0553ca700fb49de9661b467367e4365c2");
        expect(bytesToHex(keys.commitmentSeed)).toBe("ea50050bcd68bd32e986203848b9bbe89c4c613e8889a74712f1dce2aacb7805");
    });

    // 1000 walks six set bits; the maximum walks all 48, so a chain one bit short
    // cannot reproduce it.
    it("derives the pinned commitment secrets", () => {
        expect(bytesToHex(getCommitmentSecret(keys.commitmentSeed, 1000))).toBe(
            "1f05d13bb89cba571f576e023a8a80a5af68702881b63a26a0fa8a175ab4facf",
        );
        expect(bytesToHex(getCommitmentSecret(keys.commitmentSeed, MAX_COMMITMENT_NUMBER))).toBe(
            "b6fda97ecc511bc56a81301deda74409e55e5fe96321bbadb5a45afd748bae2a",
        );
    });

    it("derives the pinned commitment point", () => {
        expect(bytesToHex(getCommitmentPoint(keys.commitmentSeed, 1000))).toBe(
            "03456642ec552736db40cf03d2f4cce79a7ae63082d79a868b22d645733c72ff2e",
        );
    });

    it("derives the pinned TLC key", () => {
        expect(bytesToHex(deriveTlcKey(keys, 1000))).toBe("4df377b8d29ac56a3a54a919d3ab4b252ec6798ec824983e53aec61667282d13");
    });
});
