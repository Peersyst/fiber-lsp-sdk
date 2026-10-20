import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE, equalBytes } from "@noble/curves/utils.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { Session, keyAggExport, keyAggregate, nonceAggregate, nonceGen } from "@scure/btc-signer/musig2.js";
import { NONCE_CONTEXTS } from "../../../src/derivation/derivation.constants";
import type { NonceContext } from "../../../src/derivation/derivation.types";
import { deriveChannelSeed, deriveNonceSeed } from "../../../src/derivation/device-scheme";
import { deriveChannelKeys, getCommitmentPoint, pubkeyOf } from "../../../src/derivation/fiber-scheme";
import {
    aggregatePartialSignatures,
    aggregatePublicNonces,
    getBasePublicKeys,
    getChannelCommitmentPoint,
    getPublicNonce,
    partialSign,
    verifyPeerPartialSignature,
} from "../../../src/signer/musig2-engine";
import type { CosignSession, PartialSignRequest } from "../../../src/signer/signer.types";

const MASTER_SEED = new Uint8Array(32).fill(0x24);
const channelKeys = deriveChannelKeys(deriveChannelSeed(MASTER_SEED, 0));
const localPubkey = pubkeyOf(channelKeys.fundingKey);

const PEER_SECRET_KEY = new Uint8Array(32).fill(0x77);
const peerPubkey = pubkeyOf(PEER_SECRET_KEY);
const PEER_NONCE_RAND = new Uint8Array(32).fill(0x07);
const MESSAGE = new Uint8Array(32).fill(0xab);

// Regenerated per use: scure zeroes a secret nonce buffer once it signs.
function peerNonces() {
    return nonceGen(peerPubkey, PEER_SECRET_KEY, undefined, undefined, undefined, PEER_NONCE_RAND);
}

const localPubNonce = getPublicNonce(channelKeys, 0, "COMMITMENT");
const aggregatedNonce = nonceAggregate([localPubNonce, peerNonces().public]);

const REQUEST: PartialSignRequest = {
    orderedPublicKeys: [localPubkey, peerPubkey],
    aggregatedNonce,
    message: MESSAGE,
    commitmentNumber: 0,
    context: "COMMITMENT",
};

describe("getBasePublicKeys", () => {
    it("returns the compressed public halves of the base keys", () => {
        const basePublicKeys = getBasePublicKeys(channelKeys);
        expect(basePublicKeys.fundingPubkey).toHaveLength(33);
        expect(basePublicKeys.tlcBasePubkey).toHaveLength(33);
        expect(bytesToHex(basePublicKeys.fundingPubkey)).toBe(bytesToHex(pubkeyOf(channelKeys.fundingKey)));
        expect(bytesToHex(basePublicKeys.tlcBasePubkey)).toBe(bytesToHex(pubkeyOf(channelKeys.tlcBaseKey)));
    });

    it("is deterministic", () => {
        expect(bytesToHex(getBasePublicKeys(channelKeys).fundingPubkey)).toBe(bytesToHex(getBasePublicKeys(channelKeys).fundingPubkey));
    });

    it("rejects channel keys with malformed secrets", () => {
        expect(() => getBasePublicKeys({ ...channelKeys, fundingKey: new Uint8Array(31) })).toThrow(TypeError);
        expect(() => getBasePublicKeys({ ...channelKeys, tlcBaseKey: new Uint8Array(31) })).toThrow(TypeError);
    });
});

describe("getChannelCommitmentPoint", () => {
    it.each([0, 1, 1000])("matches the derivation of commitment number %i", (commitmentNumber) => {
        expect(bytesToHex(getChannelCommitmentPoint(channelKeys, commitmentNumber))).toBe(
            bytesToHex(getCommitmentPoint(channelKeys.commitmentSeed, commitmentNumber)),
        );
    });

    it.each([-1, 2 ** 48])("rejects the commitment number %p", (commitmentNumber) => {
        expect(() => getChannelCommitmentPoint(channelKeys, commitmentNumber)).toThrow(RangeError);
    });

    it("rejects channel keys with a malformed commitment seed", () => {
        expect(() => getChannelCommitmentPoint({ ...channelKeys, commitmentSeed: new Uint8Array(31) }, 0)).toThrow(TypeError);
    });
});

describe("getPublicNonce", () => {
    it("returns a deterministic 66-byte public nonce", () => {
        expect(getPublicNonce(channelKeys, 0, "COMMITMENT")).toHaveLength(66);
        expect(bytesToHex(getPublicNonce(channelKeys, 0, "COMMITMENT"))).toBe(bytesToHex(getPublicNonce(channelKeys, 0, "COMMITMENT")));
    });

    // A device restored from the mnemonic must republish the exact nonces of its open slots.
    it("is byte-identical from freshly re-derived channel keys", () => {
        const restoredKeys = deriveChannelKeys(deriveChannelSeed(Uint8Array.from(MASTER_SEED), 0));
        expect(bytesToHex(getPublicNonce(restoredKeys, 5, "REVOKE"))).toBe(bytesToHex(getPublicNonce(channelKeys, 5, "REVOKE")));
    });

    it("is distinct per context", () => {
        const nonces = new Set(NONCE_CONTEXTS.map((context) => bytesToHex(getPublicNonce(channelKeys, 4, context))));
        expect(nonces.size).toBe(NONCE_CONTEXTS.length);
    });

    it("is distinct per commitment number", () => {
        const nonces = new Set([0, 1, 2, 1000].map((n) => bytesToHex(getPublicNonce(channelKeys, n, "COMMITMENT"))));
        expect(nonces.size).toBe(4);
    });

    it("is distinct per channel", () => {
        const otherChannel = deriveChannelKeys(deriveChannelSeed(MASTER_SEED, 1));
        expect(bytesToHex(getPublicNonce(otherChannel, 0, "COMMITMENT"))).not.toBe(
            bytesToHex(getPublicNonce(channelKeys, 0, "COMMITMENT")),
        );
    });

    it.each([-1, 2 ** 48])("rejects the commitment number %p", (commitmentNumber) => {
        expect(() => getPublicNonce(channelKeys, commitmentNumber, "COMMITMENT")).toThrow(RangeError);
    });

    it("rejects an unknown context", () => {
        expect(() => getPublicNonce(channelKeys, 0, "SETTLE" as unknown as NonceContext)).toThrow(TypeError);
    });

    it("rejects channel keys with malformed secrets", () => {
        expect(() => getPublicNonce({ ...channelKeys, musig2BaseNonce: new Uint8Array(31) }, 0, "COMMITMENT")).toThrow(TypeError);
        expect(() => getPublicNonce({ ...channelKeys, fundingKey: new Uint8Array(31) }, 0, "COMMITMENT")).toThrow(TypeError);
    });
});

describe("partialSign", () => {
    it("returns a 32-byte partial signature, byte-identical across identical requests", () => {
        const first = partialSign(channelKeys, REQUEST);
        expect(first).toHaveLength(32);
        // The idempotent re-delivery contract: a re-sent request gets the same response.
        expect(bytesToHex(partialSign(channelKeys, REQUEST))).toBe(bytesToHex(first));
    });

    // Verifying against the nonce getPublicNonce published proves both entry points regenerate one and the same nonce.
    it("verifies under the published public nonce with the device at index 0", () => {
        const partial = partialSign(channelKeys, REQUEST);
        const session = new Session(aggregatedNonce, [localPubkey, peerPubkey], MESSAGE);
        expect(session.partialSigVerify(partial, [localPubNonce, peerNonces().public], 0)).toBe(true);
    });

    it("verifies with the device at index 1", () => {
        const partial = partialSign(channelKeys, { ...REQUEST, orderedPublicKeys: [peerPubkey, localPubkey] });
        const session = new Session(aggregatedNonce, [peerPubkey, localPubkey], MESSAGE);
        expect(session.partialSigVerify(partial, [peerNonces().public, localPubNonce], 1)).toBe(true);
    });

    // KeyAgg([A, B]) != KeyAgg([B, A]): the engine must sign for exactly the order the node sent.
    it("is sensitive to the key order", () => {
        const roleOrdered = partialSign(channelKeys, REQUEST);
        const swapped = partialSign(channelKeys, { ...REQUEST, orderedPublicKeys: [peerPubkey, localPubkey] });
        expect(bytesToHex(swapped)).not.toBe(bytesToHex(roleOrdered));
    });

    it("aggregates with the peer half into a valid schnorr signature", () => {
        const partial = partialSign(channelKeys, REQUEST);
        const session = new Session(aggregatedNonce, [localPubkey, peerPubkey], MESSAGE);
        const peerPartial = session.sign(peerNonces().secret, PEER_SECRET_KEY);
        const finalSignature = session.partialSigAgg([partial, peerPartial]);
        expect(schnorr.verify(finalSignature, MESSAGE, keyAggExport(keyAggregate([localPubkey, peerPubkey])))).toBe(true);
    });

    it("is distinct per message, commitment number and context", () => {
        const partials = new Set(
            [
                partialSign(channelKeys, REQUEST),
                partialSign(channelKeys, { ...REQUEST, message: new Uint8Array(32).fill(0xac) }),
                partialSign(channelKeys, { ...REQUEST, commitmentNumber: 1 }),
                partialSign(channelKeys, { ...REQUEST, context: "REVOKE" }),
            ].map(bytesToHex),
        );
        expect(partials.size).toBe(4);
    });

    it.each([
        ["a missing key list", { ...REQUEST, orderedPublicKeys: undefined as unknown as Uint8Array[] }, TypeError],
        ["a key list that is not an array", { ...REQUEST, orderedPublicKeys: localPubkey as unknown as Uint8Array[] }, TypeError],
        ["a single public key", { ...REQUEST, orderedPublicKeys: [localPubkey] }, TypeError],
        [
            "three public keys",
            { ...REQUEST, orderedPublicKeys: [localPubkey, peerPubkey, pubkeyOf(new Uint8Array(32).fill(3))] },
            TypeError,
        ],
        ["a 32-byte public key", { ...REQUEST, orderedPublicKeys: [localPubkey, new Uint8Array(32)] }, TypeError],
        ["a 34-byte public key", { ...REQUEST, orderedPublicKeys: [localPubkey, new Uint8Array(34)] }, TypeError],
        ["duplicate public keys", { ...REQUEST, orderedPublicKeys: [localPubkey, localPubkey] }, TypeError],
        [
            "a key list missing the funding pubkey",
            { ...REQUEST, orderedPublicKeys: [peerPubkey, pubkeyOf(new Uint8Array(32).fill(3))] },
            TypeError,
        ],
        ["a 65-byte aggregated nonce", { ...REQUEST, aggregatedNonce: new Uint8Array(65) }, TypeError],
        ["a 67-byte aggregated nonce", { ...REQUEST, aggregatedNonce: new Uint8Array(67) }, TypeError],
        ["a 31-byte message", { ...REQUEST, message: new Uint8Array(31) }, TypeError],
        ["a 33-byte message", { ...REQUEST, message: new Uint8Array(33) }, TypeError],
        ["a negative commitment number", { ...REQUEST, commitmentNumber: -1 }, RangeError],
        ["an out-of-range commitment number", { ...REQUEST, commitmentNumber: 2 ** 48 }, RangeError],
        ["an unknown context", { ...REQUEST, context: "SETTLE" as unknown as NonceContext }, TypeError],
    ])("rejects %s", (_, request, expected) => {
        expect(() => partialSign(channelKeys, request)).toThrow(expected);
    });

    it("rejects channel keys with malformed secrets", () => {
        expect(() => partialSign({ ...channelKeys, fundingKey: new Uint8Array(31) }, REQUEST)).toThrow(TypeError);
        expect(() => partialSign({ ...channelKeys, musig2BaseNonce: new Uint8Array(31) }, REQUEST)).toThrow(TypeError);
    });

    // The engine cannot see whether the aggregate holds its nonce: the same secret nonce answers a second challenge, and three
    // recover the funding key (docs/signing.md), so the policy's claim on a slot covers the whole session.
    it("resigns a slot under a foreign aggregated nonce, reusing the slot's secret nonce across two sessions", () => {
        const otherSlotNonce = getPublicNonce(channelKeys, 1, "COMMITMENT");
        const foreignAggregate = nonceAggregate([otherSlotNonce, peerNonces().public]);
        const partial = partialSign(channelKeys, { ...REQUEST, aggregatedNonce: foreignAggregate });
        expect(partial).toHaveLength(32);
        expect(bytesToHex(partial)).not.toBe(bytesToHex(partialSign(channelKeys, REQUEST)));
        const session = new Session(foreignAggregate, [localPubkey, peerPubkey], MESSAGE);
        expect(session.partialSigVerify(partial, [otherSlotNonce, peerNonces().public], 0)).toBe(false);
    });

    // A well-lengthed but invalid aggregated nonce propagates whatever scure throws.
    it("rejects 66 bytes that are not an aggregated nonce", () => {
        expect(() => partialSign(channelKeys, { ...REQUEST, aggregatedNonce: new Uint8Array(66).fill(1) })).toThrow();
    });

    it("never echoes secret material in error messages", () => {
        const failingCalls = [
            () => partialSign(channelKeys, { ...REQUEST, orderedPublicKeys: [peerPubkey, pubkeyOf(new Uint8Array(32).fill(3))] }),
            () => partialSign(channelKeys, { ...REQUEST, commitmentNumber: -1 }),
            () => partialSign(channelKeys, { ...REQUEST, context: "SETTLE" as unknown as NonceContext }),
            () => partialSign(channelKeys, { ...REQUEST, aggregatedNonce: new Uint8Array(66).fill(1) }),
        ];
        const fundingKeyHex = bytesToHex(channelKeys.fundingKey);
        const nonceSeedHex = bytesToHex(deriveNonceSeed(channelKeys, 0, "COMMITMENT"));
        for (const call of failingCalls) {
            let message = "";
            try {
                call();
            } catch (error) {
                message = error instanceof Error ? error.message : String(error);
            }
            expect(message).not.toBe("");
            expect(message).not.toContain(fundingKeyHex);
            expect(message).not.toContain(nonceSeedHex);
        }
    });
});

describe("engine v1 outputs", () => {
    // The idempotent re-delivery contract, pinned: a dependency bump that changes these breaks every in-flight
    // signing round (published nonce vs regenerated nonce), so a failure here is investigated, never repinned.
    it("derives the pinned public nonce for slot (0, COMMITMENT)", () => {
        expect(bytesToHex(localPubNonce)).toBe(
            "02b9f91ff99a01a17ac43bec3d56a2e6195b8954638005530e8ee3e927c64585300370fec92548d2441c52b04fc5bd8d26055ab8efe99e3241d080c777cf3af408e5",
        );
    });

    it("produces the pinned partial signature for the literal request", () => {
        expect(bytesToHex(partialSign(channelKeys, REQUEST))).toBe("37c8b87b10ff19ff826227383ed478f0fe69624d03180f57b519784edadb8887");
    });
});

// The peer's half of REQUEST, signed by the peer itself.
function peerPartialSignature(session: { orderedPublicKeys: Uint8Array[]; aggregatedNonce: Uint8Array; message: Uint8Array }) {
    return new Session(session.aggregatedNonce, session.orderedPublicKeys, session.message).sign(peerNonces().secret, PEER_SECRET_KEY);
}

const COSIGN: CosignSession = {
    orderedPublicKeys: [localPubkey, peerPubkey],
    aggregatedNonce,
    message: MESSAGE,
    devicePublicNonce: localPubNonce,
    peerPublicNonce: peerNonces().public,
};

describe("aggregatePublicNonces", () => {
    it("sums the two nonces into the aggregate the session signs under, in either order", () => {
        expect(bytesToHex(aggregatePublicNonces(localPubNonce, peerNonces().public))).toBe(bytesToHex(aggregatedNonce));
        expect(bytesToHex(aggregatePublicNonces(peerNonces().public, localPubNonce))).toBe(bytesToHex(aggregatedNonce));
    });

    it("tells apart a nonce the device did not publish for the slot", () => {
        const otherSlot = getPublicNonce(channelKeys, 1, "COMMITMENT");
        expect(bytesToHex(aggregatePublicNonces(otherSlot, peerNonces().public))).not.toBe(bytesToHex(aggregatedNonce));
    });

    it.each([
        ["a 65-byte device nonce", new Uint8Array(65), peerNonces().public],
        ["a 67-byte device nonce", new Uint8Array(67), peerNonces().public],
        ["a 65-byte peer nonce", localPubNonce, new Uint8Array(65)],
        ["a peer nonce that is not bytes", localPubNonce, "02" as unknown as Uint8Array],
    ])("rejects %s", (_, device, peer) => {
        expect(() => aggregatePublicNonces(device, peer)).toThrow(TypeError);
    });
});

describe("verifyPeerPartialSignature", () => {
    it("accepts the peer's half with the device first in the key list", () => {
        expect(verifyPeerPartialSignature(channelKeys, COSIGN, peerPartialSignature(COSIGN))).toBe(true);
    });

    it("accepts the peer's half with the peer first, its nonce placed by its key's position", () => {
        const swapped = { ...COSIGN, orderedPublicKeys: [peerPubkey, localPubkey] };
        expect(verifyPeerPartialSignature(channelKeys, swapped, peerPartialSignature(swapped))).toBe(true);
    });

    it("refuses the peer's half of another message", () => {
        const other = peerPartialSignature({ ...COSIGN, message: new Uint8Array(32).fill(0xac) });
        expect(verifyPeerPartialSignature(channelKeys, COSIGN, other)).toBe(false);
    });

    it("refuses the peer's half under another key order", () => {
        const swapped = peerPartialSignature({ ...COSIGN, orderedPublicKeys: [peerPubkey, localPubkey] });
        expect(verifyPeerPartialSignature(channelKeys, COSIGN, swapped)).toBe(false);
    });

    it("refuses the device's own half passed off as the peer's", () => {
        expect(verifyPeerPartialSignature(channelKeys, COSIGN, partialSign(channelKeys, REQUEST))).toBe(false);
    });

    it("refuses a half signed under nonces that do not sum to the aggregated nonce", () => {
        const otherPeerNonce = nonceGen(peerPubkey, PEER_SECRET_KEY, undefined, undefined, undefined, new Uint8Array(32).fill(0x08)).public;
        expect(verifyPeerPartialSignature(channelKeys, { ...COSIGN, peerPublicNonce: otherPeerNonce }, peerPartialSignature(COSIGN))).toBe(
            false,
        );
        const otherDeviceNonce = getPublicNonce(channelKeys, 1, "COMMITMENT");
        expect(
            verifyPeerPartialSignature(channelKeys, { ...COSIGN, devicePublicNonce: otherDeviceNonce }, peerPartialSignature(COSIGN)),
        ).toBe(false);
    });

    it("refuses a half one off the right scalar, and the zero scalar", () => {
        const half = peerPartialSignature(COSIGN);
        const offByOne = secp256k1.Point.Fn.toBytes(secp256k1.Point.Fn.add(bytesToNumberBE(half), 1n));
        expect(verifyPeerPartialSignature(channelKeys, COSIGN, offByOne)).toBe(false);
        expect(verifyPeerPartialSignature(channelKeys, COSIGN, new Uint8Array(32))).toBe(false);
    });

    it.each([
        ["a key list without the funding key", { ...COSIGN, orderedPublicKeys: [peerPubkey, pubkeyOf(new Uint8Array(32).fill(3))] }],
        ["a single key", { ...COSIGN, orderedPublicKeys: [localPubkey] }],
        ["duplicate keys", { ...COSIGN, orderedPublicKeys: [localPubkey, localPubkey] }],
        ["a 65-byte aggregated nonce", { ...COSIGN, aggregatedNonce: new Uint8Array(65) }],
        ["a 31-byte message", { ...COSIGN, message: new Uint8Array(31) }],
        ["a 65-byte device nonce", { ...COSIGN, devicePublicNonce: new Uint8Array(65) }],
        ["a 67-byte peer nonce", { ...COSIGN, peerPublicNonce: new Uint8Array(67) }],
    ])("rejects %s", (_, session) => {
        expect(() => verifyPeerPartialSignature(channelKeys, session, peerPartialSignature(COSIGN))).toThrow(TypeError);
    });

    it.each([31, 33])("rejects a %i-byte partial signature", (length) => {
        expect(() => verifyPeerPartialSignature(channelKeys, COSIGN, new Uint8Array(length))).toThrow(TypeError);
    });
});

describe("aggregatePartialSignatures", () => {
    const aggregateKey = keyAggExport(keyAggregate([localPubkey, peerPubkey]));

    it("aggregates both halves into the schnorr signature the 2-of-2 key accepts, in either order", () => {
        const own = partialSign(channelKeys, REQUEST);
        const peer = peerPartialSignature(REQUEST);
        const signature = aggregatePartialSignatures(REQUEST, [peer, own]);
        expect(signature).toHaveLength(64);
        expect(schnorr.verify(signature, MESSAGE, aggregateKey)).toBe(true);
        expect(bytesToHex(aggregatePartialSignatures(REQUEST, [own, peer]))).toBe(bytesToHex(signature));
    });

    it("refuses halves that do not aggregate into a valid signature", () => {
        const own = partialSign(channelKeys, REQUEST);
        const foreign = peerPartialSignature({ ...REQUEST, message: new Uint8Array(32).fill(0xac) });
        expect(() => aggregatePartialSignatures(REQUEST, [foreign, own])).toThrow(TypeError);
        expect(() => aggregatePartialSignatures(REQUEST, [own, own])).toThrow(TypeError);
    });

    it.each([
        ["one partial signature", [new Uint8Array(32)]],
        ["three partial signatures", [new Uint8Array(32), new Uint8Array(32), new Uint8Array(32)]],
        ["a 31-byte partial signature", [new Uint8Array(32), new Uint8Array(31)]],
        ["a list that is not an array", new Uint8Array(64) as unknown as Uint8Array[]],
    ])("rejects %s", (_, partials) => {
        expect(() => aggregatePartialSignatures(REQUEST, partials)).toThrow(TypeError);
    });

    it.each([
        ["a single key", { ...REQUEST, orderedPublicKeys: [localPubkey] }],
        ["duplicate keys", { ...REQUEST, orderedPublicKeys: [localPubkey, localPubkey] }],
        ["a 65-byte aggregated nonce", { ...REQUEST, aggregatedNonce: new Uint8Array(65) }],
        ["a 33-byte message", { ...REQUEST, message: new Uint8Array(33) }],
    ])("rejects a session with %s", (_, session) => {
        const halves = [partialSign(channelKeys, REQUEST), peerPartialSignature(REQUEST)];
        expect(() => aggregatePartialSignatures(session, halves)).toThrow(TypeError);
    });
});

// BIP-327 signs `s = σ·(k1 + b·k2) + e·a·g·d` over the slot's two secret nonces `k1`, `k2` and the funding key `d`, with
// `σ` the sign R's parity gives the nonces, `g` the one Q's parity gives the key, and everything else public: the node
// computes `b`, `R`, `e` from what it sent. Under a deterministic nonce every session on one slot is one more linear
// equation in the same three unknowns, which is why the policy serves a slot at most two sessions (docs/signing.md).
describe("three sessions over one slot", () => {
    const { Fn } = secp256k1.Point;
    const keyList = [localPubkey, peerPubkey];
    const messages = [0xa1, 0xa2, 0xa3].map((byte) => new Uint8Array(32).fill(byte));

    function taggedScalar(tag: string, ...parts: Uint8Array[]): bigint {
        return Fn.create(bytesToNumberBE(schnorr.utils.taggedHash(tag, ...parts)));
    }

    // The equation a node reads off one partial signature: its coefficients on k1, k2 and d.
    function equationOf(message: Uint8Array): { k1: bigint; k2: bigint; d: bigint; s: bigint } {
        const Q = keyAggregate(keyList).aggPublicKey;
        const qBytes = Q.toBytes(true).subarray(1);
        const b = taggedScalar("MuSig/noncecoef", aggregatedNonce, qBytes, message);
        const R1 = secp256k1.Point.fromBytes(aggregatedNonce.subarray(0, 33));
        const R2 = secp256k1.Point.fromBytes(aggregatedNonce.subarray(33));
        const R = R1.add(R2.multiply(b));
        const e = taggedScalar("BIP0340/challenge", R.toBytes(true).subarray(1), qBytes, message);
        const list = schnorr.utils.taggedHash("KeyAgg list", ...keyList);
        // BIP-327 gives the second distinct key of the list the coefficient 1; the device is first here.
        const a = taggedScalar("KeyAgg coefficient", list, localPubkey);
        const g = Q.toAffine().y % 2n === 0n ? 1n : Fn.neg(1n);
        const sigma = R.toAffine().y % 2n === 0n ? 1n : Fn.neg(1n);
        const s = bytesToNumberBE(partialSign(channelKeys, { ...REQUEST, message }));
        return { k1: sigma, k2: Fn.mul(sigma, b), d: Fn.mul(Fn.mul(e, a), g), s };
    }

    function det3(rows: { k1: bigint; k2: bigint; d: bigint }[]): bigint {
        const [r0, r1, r2] = rows as [(typeof rows)[0], (typeof rows)[0], (typeof rows)[0]];
        const minor = (p: bigint, q: bigint, r: bigint, t: bigint) => Fn.sub(Fn.mul(p, t), Fn.mul(q, r));
        return Fn.add(
            Fn.sub(Fn.mul(r0.k1, minor(r1.k2, r1.d, r2.k2, r2.d)), Fn.mul(r0.k2, minor(r1.k1, r1.d, r2.k1, r2.d))),
            Fn.mul(r0.d, minor(r1.k1, r1.k2, r2.k1, r2.k2)),
        );
    }

    it("reads the equations right: they hold at the device's own nonces and key", () => {
        const nonceSecret = nonceGen(
            localPubkey,
            channelKeys.fundingKey,
            undefined,
            undefined,
            undefined,
            deriveNonceSeed(channelKeys, 0, "COMMITMENT"),
        ).secret;
        const k1 = bytesToNumberBE(nonceSecret.subarray(0, 32));
        const k2 = bytesToNumberBE(nonceSecret.subarray(32, 64));
        const d = bytesToNumberBE(channelKeys.fundingKey);
        for (const message of messages) {
            const { k1: c1, k2: c2, d: c3, s } = equationOf(message);
            expect(Fn.add(Fn.add(Fn.mul(c1, k1), Fn.mul(c2, k2)), Fn.mul(c3, d))).toBe(s);
        }
    });

    it("leaves the key free under two sessions: every candidate key has nonces that answer both", () => {
        const [first, second] = messages.slice(0, 2).map(equationOf) as [ReturnType<typeof equationOf>, ReturnType<typeof equationOf>];
        // Nonzero, so for any d the two equations fix k1 and k2: nothing in them singles out the funding key.
        const nonceDeterminant = Fn.sub(Fn.mul(first.k1, second.k2), Fn.mul(first.k2, second.k1));
        expect(nonceDeterminant).not.toBe(0n);
        const wrongKey = bytesToNumberBE(new Uint8Array(32).fill(0x09));
        const rhs1 = Fn.sub(first.s, Fn.mul(first.d, wrongKey));
        const rhs2 = Fn.sub(second.s, Fn.mul(second.d, wrongKey));
        const inverse = Fn.inv(nonceDeterminant);
        const k1 = Fn.mul(Fn.sub(Fn.mul(rhs1, second.k2), Fn.mul(first.k2, rhs2)), inverse);
        const k2 = Fn.mul(Fn.sub(Fn.mul(first.k1, rhs2), Fn.mul(rhs1, second.k1)), inverse);
        for (const row of [first, second]) {
            expect(Fn.add(Fn.add(Fn.mul(row.k1, k1), Fn.mul(row.k2, k2)), Fn.mul(row.d, wrongKey))).toBe(row.s);
        }
    });

    it("recovers the funding key from a third session's partial signature", () => {
        const rows = messages.map(equationOf);
        const determinant = det3(rows);
        expect(determinant).not.toBe(0n);
        // Cramer's rule for d: the determinant with the d column replaced by the partial signatures.
        const withS = rows.map((row) => ({ k1: row.k1, k2: row.k2, d: row.s }));
        const recovered = Fn.mul(det3(withS), Fn.inv(determinant));
        const recoveredKey = Fn.toBytes(recovered);
        expect(bytesToHex(recoveredKey)).toBe(bytesToHex(channelKeys.fundingKey));
        expect(equalBytes(pubkeyOf(recoveredKey), localPubkey)).toBe(true);
    });
});
