import { writeFileSync } from "node:fs";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { Session, nonceAggregate } from "@scure/btc-signer/musig2.js";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation/fiber-scheme";
import type { ChannelSigningRequest } from "../../../src/protocol";
import { decodeChannelSigningStatus } from "../../../src/protocol";
import type { DispatchOutcome } from "../../../src/signer";
import { computeSigningMessage, getPublicNonce, partialSign } from "../../../src/signer";
import { loadInteropVectors } from "../../utils/interop-vectors";
import { openSigningChannel, signingDeviceKeys } from "../../utils/signing-channel";
import type { SigningCaseVector } from "../../utils/signing-vectors";
import { loadSigningVectors, signingStatusField } from "../../utils/signing-vectors";

// The jest half of the musig loop; `verify-ts` aggregates it under fiber's crate. Aggregating here is impossible: fiber's
// `SecNonceBuilder` omits the public key scure's `nonceGen` takes, so the remote secret nonce cannot be regenerated.
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

    // The Rust half's input, written only when asked so `pnpm test` stays side-effect free (interop/README.md).
    const tsOutPath = process.env.INTEROP_TS_OUT;
    if (tsOutPath) {
        it("emits the partial signature the rust half verifies", () => {
            const tsOutput = { local_pubnonce: bytesToHex(localPubNonce), partial_signature: bytesToHex(partialSignature) };
            writeFileSync(tsOutPath, `${JSON.stringify(tsOutput, null, 2)}\n`);
        });
    }
});

// The jest half of the signing loop: what the device answers each request of `signing.json`, which `verify-signing`
// verifies under fiber's musig2 crate and aggregates with the peer's half.
describe("signing interop vectors", () => {
    const vectors = loadSigningVectors();
    const keys = signingDeviceKeys(vectors);

    type DeviceHalf = { name: string; public_nonce: string; partial_signature: string };

    function requestOf(kase: SigningCaseVector): ChannelSigningRequest {
        const status = decodeChannelSigningStatus(signingStatusField(kase));
        if (status.kind !== "required") throw new Error(`${kase.name} asks for no signature`);
        return status;
    }

    function signedOf(outcome: DispatchOutcome): Extract<DispatchOutcome, { kind: "signed" }> {
        if (outcome.kind !== "signed") throw new Error(`expected a signature, got ${JSON.stringify(outcome)}`);
        return outcome;
    }

    // Through the dispatch on a channel at the state before the case; the announcement, which the dispatch refuses, through the engine.
    async function deviceHalfOf(kase: SigningCaseVector): Promise<DeviceHalf> {
        const request = requestOf(kase);
        const publicNonce = bytesToHex(getPublicNonce(keys, request.slot.commitmentNumber, request.slot.context));
        if (kase.transition === "SignChannelAnnouncement") {
            const signature = partialSign(keys, {
                orderedPublicKeys: request.keyAggregation,
                aggregatedNonce: request.aggNonce,
                message: hexToBytes(kase.expected.message),
                commitmentNumber: request.slot.commitmentNumber,
                context: request.slot.context,
            });
            return { name: kase.name, public_nonce: publicNonce, partial_signature: bytesToHex(signature) };
        }
        const { dispatch, channelId } = await openSigningChannel(vectors, kase);
        const signed = signedOf(await dispatch.handle(channelId, signingStatusField(kase)));
        return { name: kase.name, public_nonce: publicNonce, partial_signature: bytesToHex(signed.partialSignature) };
    }

    it("signs with the funding key the vectors name for the device", () => {
        expect(bytesToHex(pubkeyOf(keys.fundingKey))).toBe(vectors.device.funding_pubkey);
    });

    // The announcement is refused before its message is computed.
    const signedCases = vectors.cases.filter((kase) => kase.transition !== "SignChannelAnnouncement");

    it.each(signedCases.map((kase) => [kase.name, kase] as const))("computes the message of %s as fiber does", (_, kase) => {
        const { content } = requestOf(kase);
        expect(bytesToHex(computeSigningMessage(content))).toBe(kase.expected.message);
    });

    it.each(vectors.cases.map((kase) => [kase.name, kase] as const))("answers %s with the device half fiber expects", async (_, kase) => {
        const half = await deviceHalfOf(kase);
        expect(half.public_nonce).toBe(kase.expected.public_nonce);
        expect(half.partial_signature).toBe(kase.expected.partial_signature);
    });

    // The Rust half's input, every case once. See interop/README.md.
    const signingOutPath = process.env.INTEROP_SIGNING_OUT;
    if (signingOutPath) {
        it("emits the device half of every case for the rust half", async () => {
            const cases: DeviceHalf[] = [];
            for (const kase of vectors.cases) cases.push(await deviceHalfOf(kase));
            writeFileSync(signingOutPath, `${JSON.stringify({ cases }, null, 2)}\n`);
        });
    }
});
