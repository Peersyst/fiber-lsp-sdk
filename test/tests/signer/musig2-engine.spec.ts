import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { Session, keyAggExport, keyAggregate, nonceAggregate, nonceGen } from "@scure/btc-signer/musig2.js";
import { NONCE_CONTEXTS } from "../../../src/derivation/derivation.constants";
import type { NonceContext } from "../../../src/derivation/derivation.types";
import { deriveChannelSeed, deriveNonceSeed } from "../../../src/derivation/device-scheme";
import { deriveChannelKeys, getCommitmentPoint, pubkeyOf } from "../../../src/derivation/fiber-scheme";
import { getBasePublicKeys, getChannelCommitmentPoint, getPublicNonce, partialSign } from "../../../src/signer/musig2-engine";
import type { PartialSignRequest } from "../../../src/signer/signer.types";

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
                partialSign(channelKeys, { ...REQUEST, context: "CLOSE" }),
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

    // The engine cannot tell whether the aggregate includes the nonce it published, so it signs regardless, and the result is
    // both unusable to the node and dangerous to the device: same slot and same message as REQUEST means the same secret nonce,
    // now answering a second challenge. Three of these recover the funding key (docs/signing.md), which is why the claim the
    // policy layer holds on a slot has to cover the whole session and not just the message.
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
