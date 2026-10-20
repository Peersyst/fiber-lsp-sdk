import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { CHANNEL_SIGNING_TRANSITIONS } from "../../../../src/protocol";
import { SIGNING_KEY_ORDERS } from "../../../../src/signer/signer.constants";
import { orderFundingPubkeys, readPeerFundingPubkey } from "../../../../src/signer/utils/key-order.utils";

// Two pairs, one per side of the sort: the vectors' keys put the peer first, so the device-first sort needs keys of its own.
const LOW = hexToBytes("026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638");
const HIGH = hexToBytes("02e42662b93a36b0817ec942512688ce880d300f3d48309ac79953cfd402c10ff5");
// LOW's x under the odd prefix, which sorts it above HIGH: the prefix byte is compared first.
const ODD_LOW = hexToBytes("036372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638");
const OTHER = hexToBytes("032559e1b167552782cab5be4294260d51edfc36aef4ca7cc165b3b21b15e98e21");

function hexPair(pair: [Uint8Array, Uint8Array]): [string, string] {
    return [bytesToHex(pair[0]), bytesToHex(pair[1])];
}

describe("SIGNING_KEY_ORDERS", () => {
    // Fiber's `get_musig2_agg_context` takes `[local, remote]` for the revocation it receives and `[remote, local]` for the one it sends.
    it("names an order for every transition: ascending but for the two revocations", () => {
        expect(SIGNING_KEY_ORDERS).toEqual({
            SendCommitmentSigned: "ascending",
            CompleteReceivedCommitment: "ascending",
            SendRevokeAndAck: "peer-first",
            CompleteReceivedRevokeAndAck: "device-first",
            SendClosingSigned: "ascending",
            SignChannelAnnouncement: "ascending",
        });
        expect(Object.keys(SIGNING_KEY_ORDERS).sort()).toEqual([...CHANNEL_SIGNING_TRANSITIONS].sort());
    });
});

describe("orderFundingPubkeys", () => {
    const ascending = CHANNEL_SIGNING_TRANSITIONS.filter((transition) => SIGNING_KEY_ORDERS[transition] === "ascending");

    it.each(ascending)("sorts the keys for %s, whichever side sorts first", (transition) => {
        expect(hexPair(orderFundingPubkeys(transition, LOW, HIGH))).toEqual(hexPair([LOW, HIGH]));
        expect(hexPair(orderFundingPubkeys(transition, HIGH, LOW))).toEqual(hexPair([LOW, HIGH]));
    });

    it("sorts by the compressed bytes, the prefix byte first", () => {
        expect(hexPair(orderFundingPubkeys("SendCommitmentSigned", ODD_LOW, HIGH))).toEqual(hexPair([HIGH, ODD_LOW]));
    });

    it("puts the peer first for SendRevokeAndAck, whichever side sorts first", () => {
        expect(hexPair(orderFundingPubkeys("SendRevokeAndAck", LOW, HIGH))).toEqual(hexPair([HIGH, LOW]));
        expect(hexPair(orderFundingPubkeys("SendRevokeAndAck", HIGH, LOW))).toEqual(hexPair([LOW, HIGH]));
    });

    it("puts the device first for CompleteReceivedRevokeAndAck, whichever side sorts first", () => {
        expect(hexPair(orderFundingPubkeys("CompleteReceivedRevokeAndAck", LOW, HIGH))).toEqual(hexPair([LOW, HIGH]));
        expect(hexPair(orderFundingPubkeys("CompleteReceivedRevokeAndAck", HIGH, LOW))).toEqual(hexPair([HIGH, LOW]));
    });
});

describe("readPeerFundingPubkey", () => {
    // Each transition with the device sorting first and last: the order fiber aggregates, and the reverse of it.
    const cases = CHANNEL_SIGNING_TRANSITIONS.flatMap((transition) =>
        [
            { device: LOW, peer: HIGH },
            { device: HIGH, peer: LOW },
        ].map((keys) => ({ transition, ...keys, expected: orderFundingPubkeys(transition, keys.device, keys.peer) })),
    );

    it.each(cases)("reads the peer's key out of the order $transition aggregates", ({ transition, device, peer, expected }) => {
        expect(bytesToHex(readPeerFundingPubkey(transition, expected, device))).toBe(bytesToHex(peer));
    });

    it.each(cases)("refuses the reverse of the order $transition aggregates", ({ transition, device, expected }) => {
        expect(() => readPeerFundingPubkey(transition, [expected[1], expected[0]], device)).toThrow(
            new TypeError(`the key aggregation is not in the ${SIGNING_KEY_ORDERS[transition]} order ${transition} aggregates under`),
        );
    });

    it.each(CHANNEL_SIGNING_TRANSITIONS)("refuses a key aggregation of %s without the device's key, in either order", (transition) => {
        const refusal = new TypeError("the key aggregation does not include the channel's funding key");
        expect(() => readPeerFundingPubkey(transition, [LOW, OTHER], HIGH)).toThrow(refusal);
        expect(() => readPeerFundingPubkey(transition, [OTHER, LOW], HIGH)).toThrow(refusal);
    });
});
