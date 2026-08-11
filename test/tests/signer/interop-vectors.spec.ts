import { writeFileSync } from "node:fs";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { Session, nonceAggregate } from "@scure/btc-signer/musig2.js";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation/fiber-scheme";
import { getPublicNonce, partialSign } from "../../../src/signer/musig2-engine";
import { loadInteropVectors } from "../../utils/interop-vectors";

// The jest half of the musig interop loop: the engine's partial signature verifies against the vector inputs fiber's
// own musig2 crate generated. Full aggregation against this remote is impossible in TS (fiber's Rust SecNonceBuilder
// omits the public key scure's nonceGen requires, so the remote secret nonce cannot be regenerated here); the Rust
// half, `verify-ts`, verifies and aggregates this same signature under fiber's exact crate.
describe("musig interop vectors", () => {
    const vectors = loadInteropVectors();
    const keys = deriveChannelKeys(hexToBytes(vectors.fiber_scheme.channel_seed));
    const localPubkey = pubkeyOf(keys.fundingKey);
    const remotePubkey = hexToBytes(vectors.musig.remote_pubkey);
    const remotePubNonce = hexToBytes(vectors.musig.remote_pubnonce);
    const message = hexToBytes(vectors.musig.message);

    // The canonical slot of the interop loop, (0, COMMITMENT); local first, matching the harness's AggNonce::sum.
    const localPubNonce = getPublicNonce(keys, 0, "COMMITMENT");
    const aggregatedNonce = nonceAggregate([localPubNonce, remotePubNonce]);
    const partialSignature = partialSign(keys, {
        orderedPublicKeys: [localPubkey, remotePubkey],
        aggregatedNonce,
        message,
        commitmentNumber: 0,
        context: "COMMITMENT",
    });

    it("signs with the funding key of the fiber-scheme vectors", () => {
        expect(bytesToHex(localPubkey)).toBe(vectors.fiber_scheme.channel_keys.funding_pubkey);
    });

    it("produces a partial signature the vector session verifies", () => {
        const session = new Session(aggregatedNonce, [localPubkey, remotePubkey], message);
        expect(session.partialSigVerify(partialSignature, [localPubNonce, remotePubNonce], 0)).toBe(true);
    });

    // The Rust half's input, written only when asked so `pnpm test` stays side-effect free. See interop/README.md.
    const tsOutPath = process.env.INTEROP_TS_OUT;
    if (tsOutPath) {
        it("emits the partial signature the rust half verifies", () => {
            const tsOutput = { local_pubnonce: bytesToHex(localPubNonce), partial_signature: bytesToHex(partialSignature) };
            writeFileSync(tsOutPath, `${JSON.stringify(tsOutput, null, 2)}\n`);
        });
    }
});
