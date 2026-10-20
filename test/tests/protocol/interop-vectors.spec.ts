import { hexToBytes } from "@noble/hashes/utils.js";
import { ProtocolError, decodeChannelSigningStatus } from "../../../src/protocol";
import { refusal } from "../../utils/refusal";
import { loadSigningVectors, signingStatusField, signingVariantOf } from "../../utils/signing-vectors";

const vectors = loadSigningVectors();

const STATUS_PATH = "response.result.status";

const HEADER = "must have the header byte 0x00: no parity flag, no tweak";

// Fiber's verdict is musig2's `from_bytes`, which reads any context it can rebuild; the SDK reads only the one fiber writes for
// a channel, two untweaked keys, so it refuses three variants fiber accepts.
const VARIANTS: [name: string, fiberAccepts: boolean, path: string, reason: string][] = [
    ["key_agg_ctx with the parity header bit", true, "content.key_agg_ctx", HEADER],
    ["key_agg_ctx with the tweak header bit and no tweak", false, "content.key_agg_ctx", HEADER],
    ["key_agg_ctx with the tweak header bit and its tweak", true, "content.key_agg_ctx", "must be 71 bytes"],
    ["key_agg_ctx with a count of 3 and three keys", true, "content.key_agg_ctx", "must be 71 bytes"],
    ["key_agg_ctx with a count of 3 and two keys", false, "content.key_agg_ctx", "must count exactly 2 keys"],
    ["key_agg_ctx with an off-curve key", false, "content.key_agg_ctx", "must have a second key on the curve"],
    ["agg_nonce of 65 bytes", false, "content.agg_nonce", "must be 66 bytes of 0x-prefixed lowercase hex"],
];

describe("the signing vectors", () => {
    it.each(vectors.cases.map((entry) => [entry.name, entry] as const))("decodes the %s case as its transition", (_name, entry) => {
        const status = decodeChannelSigningStatus(signingStatusField(entry));
        if (status.kind !== "required") throw new Error("the case carries no request");
        expect(status.transition).toBe(entry.transition);
        const funding = { device: vectors.device.funding_pubkey, peer: vectors.peer.funding_pubkey };
        expect(status.keyAggregation).toEqual(entry.expected.key_order.map((role) => hexToBytes(funding[role])));
    });

    it("covers every variant the vectors carry", () => {
        expect(VARIANTS.map(([name]) => name).sort()).toEqual(vectors.variants.map((variant) => variant.name).sort());
    });

    it.each(VARIANTS)("refuses the variant %s (fiber accepts it: %p)", (name, fiberAccepts, path, reason) => {
        const variant = signingVariantOf(vectors, name);
        expect(variant.verdict.accepted).toBe(fiberAccepts);
        const error = refusal(() => decodeChannelSigningStatus(signingStatusField(variant)));
        expect(error).toBeInstanceOf(ProtocolError);
        expect({ path: error.path, reason: error.reason }).toEqual({ path: `${STATUS_PATH}.${path}`, reason });
    });
});
