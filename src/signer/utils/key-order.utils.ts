import { equalBytes } from "@noble/curves/utils.js";
import { compareBytes } from "../../common";
import type { ChannelSigningTransition } from "../../protocol";
import { SIGNING_KEY_ORDERS } from "../signer.constants";

/**
 * Orders the two funding keys the way fiber aggregates them for a transition.
 * @param transition The request's transition.
 * @param devicePubkey The device's funding public key.
 * @param peerPubkey The peer's funding public key.
 * @returns The two keys in aggregation order.
 */
export function orderFundingPubkeys(
    transition: ChannelSigningTransition,
    devicePubkey: Uint8Array,
    peerPubkey: Uint8Array,
): [Uint8Array, Uint8Array] {
    switch (SIGNING_KEY_ORDERS[transition]) {
        // Fiber's `should_local_go_first_in_musig2`: the device first when its key sorts first.
        case "ascending":
            return compareBytes(devicePubkey, peerPubkey) <= 0 ? [devicePubkey, peerPubkey] : [peerPubkey, devicePubkey];
        case "peer-first":
            return [peerPubkey, devicePubkey];
        case "device-first":
            return [devicePubkey, peerPubkey];
    }
}

/**
 * Reads the peer's funding key out of a key aggregation, holding it to the transition's order.
 * @param transition The request's transition.
 * @param keyAggregation The two keys as the request aggregated them.
 * @param devicePubkey The device's funding public key.
 * @returns The peer's funding public key.
 */
export function readPeerFundingPubkey(
    transition: ChannelSigningTransition,
    keyAggregation: [Uint8Array, Uint8Array],
    devicePubkey: Uint8Array,
): Uint8Array {
    const [first, second] = keyAggregation;
    const peerPubkey = equalBytes(first, devicePubkey) ? second : equalBytes(second, devicePubkey) ? first : null;
    if (peerPubkey === null) throw new TypeError("the key aggregation does not include the channel's funding key");
    const [expectedFirst] = orderFundingPubkeys(transition, devicePubkey, peerPubkey);
    if (!equalBytes(first, expectedFirst)) {
        throw new TypeError(`the key aggregation is not in the ${SIGNING_KEY_ORDERS[transition]} order ${transition} aggregates under`);
    }
    return peerPubkey;
}
