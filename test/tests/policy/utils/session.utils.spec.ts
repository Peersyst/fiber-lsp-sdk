import { hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelKeys } from "../../../../src/derivation";
import type { SignSession } from "../../../../src/policy";
import { assertSignSession, buildSessionCommitment } from "../../../../src/policy/utils";
import { loadInteropVectors } from "../../../utils/interop-vectors";

const vectors = loadInteropVectors();
const KEYS = deriveChannelKeys(hexToBytes(vectors.sdk_scheme.channel.seed));
const LOCAL_PUBKEY = hexToBytes(vectors.sdk_scheme.channel.channel_keys.funding_pubkey);
const REMOTE_PUBKEY = hexToBytes(vectors.digest.remote.funding_pubkey);
const OTHER_PUBKEY = hexToBytes(vectors.fiber_scheme.channel_keys.funding_pubkey);
const AGGREGATED_NONCE = hexToBytes("02".repeat(33) + "03".repeat(33));
const MESSAGE = hexToBytes("5723e5072abb4f1c6a1fe86dc188129fd9a3dbc82537c3c0601effe741fe6fca");

function session(overrides: Partial<SignSession> = {}): SignSession {
    return { orderedPublicKeys: [LOCAL_PUBKEY, REMOTE_PUBKEY], aggregatedNonce: AGGREGATED_NONCE, message: MESSAGE, ...overrides };
}

describe("buildSessionCommitment", () => {
    // Stored format: a changed commitment reopens every slot already served, so this is never repinned.
    it("pins the v1 commitment of a session", () => {
        expect(buildSessionCommitment(session())).toBe("a53e6cd816bb9b553393cd6873df581552619d884c7a1880f37e36bb4af2137f");
    });

    it("is deterministic", () => {
        expect(buildSessionCommitment(session())).toBe(buildSessionCommitment(session()));
    });

    it.each([
        ["the key order", session({ orderedPublicKeys: [REMOTE_PUBKEY, LOCAL_PUBKEY] })],
        ["a key", session({ orderedPublicKeys: [LOCAL_PUBKEY, OTHER_PUBKEY] })],
        ["the aggregated nonce", session({ aggregatedNonce: hexToBytes("02".repeat(33) + "04".repeat(33)) })],
        ["the message", session({ message: hexToBytes("00".repeat(31) + "01") })],
    ])("changes when %s changes", (_, other) => {
        expect(buildSessionCommitment(other)).not.toBe(buildSessionCommitment(session()));
    });

    it.each([
        ["one public key", session({ orderedPublicKeys: [LOCAL_PUBKEY] })],
        ["three public keys", session({ orderedPublicKeys: [LOCAL_PUBKEY, REMOTE_PUBKEY, OTHER_PUBKEY] })],
        ["public keys that are not an array", session({ orderedPublicKeys: LOCAL_PUBKEY as unknown as Uint8Array[] })],
        ["a 32-byte public key", session({ orderedPublicKeys: [LOCAL_PUBKEY.slice(1), REMOTE_PUBKEY] })],
        ["a public key that is not bytes", session({ orderedPublicKeys: [LOCAL_PUBKEY, "02".repeat(33) as unknown as Uint8Array] })],
        ["two identical public keys", session({ orderedPublicKeys: [LOCAL_PUBKEY, LOCAL_PUBKEY] })],
        ["a 65-byte aggregated nonce", session({ aggregatedNonce: AGGREGATED_NONCE.slice(1) })],
        ["a 31-byte message", session({ message: MESSAGE.slice(1) })],
    ])("refuses to commit to a session with %s", (_, malformed) => {
        expect(() => buildSessionCommitment(malformed)).toThrow(TypeError);
    });
});

describe("assertSignSession", () => {
    it.each([
        ["first", session()],
        ["second", session({ orderedPublicKeys: [REMOTE_PUBKEY, LOCAL_PUBKEY] })],
    ])("accepts a session with the channel funding key %s", (_, accepted) => {
        expect(() => assertSignSession(KEYS, accepted)).not.toThrow();
    });

    it("rejects a session without the channel funding key", () => {
        expect(() => assertSignSession(KEYS, session({ orderedPublicKeys: [REMOTE_PUBKEY, OTHER_PUBKEY] }))).toThrow(
            new TypeError("session.orderedPublicKeys must include the channel funding public key"),
        );
    });

    it("rejects a malformed session before looking at the keys", () => {
        expect(() => assertSignSession(KEYS, session({ message: MESSAGE.slice(1) }))).toThrow(TypeError);
    });

    it("never names a secret in its refusals", () => {
        try {
            assertSignSession(KEYS, session({ orderedPublicKeys: [REMOTE_PUBKEY, OTHER_PUBKEY] }));
            throw new Error("expected a refusal");
        } catch (error) {
            expect((error as Error).message).not.toContain(vectors.sdk_scheme.channel.channel_keys.funding_key);
        }
    });
});
