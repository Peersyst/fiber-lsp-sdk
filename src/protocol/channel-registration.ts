import { COMPRESSED_POINT_LENGTH, assertBytes } from "../common";
import { SECRET_KEY_LENGTH } from "../derivation";
import type { Field } from "../wire";
import { encodeHexBytes, readObject } from "../wire";
import type { ChannelRegisteredWire, ChannelRegistration, InboundFrame, RegisterChannelWire } from "./protocol.types";
import { assertRequestId, decodeChannelId, decodeRequestId } from "./utils";

/**
 * Writes a `register_channel` frame: the base public keys and the delegated settlement key, nothing derived by number.
 * @param requestId Id the device correlates the acknowledgement by.
 * @param registration The channel's registration payload.
 * @returns The wire object.
 */
export function encodeRegisterChannel(requestId: string, registration: ChannelRegistration): RegisterChannelWire {
    assertRequestId(requestId);
    assertBytes("fundingPubkey", registration.fundingPubkey, COMPRESSED_POINT_LENGTH);
    assertBytes("tlcBasePubkey", registration.tlcBasePubkey, COMPRESSED_POINT_LENGTH);
    assertBytes("localSettlementKey", registration.localSettlementKey, SECRET_KEY_LENGTH);
    return {
        type: "register_channel",
        request_id: requestId,
        funding_pubkey: encodeHexBytes(registration.fundingPubkey),
        tlc_base_pubkey: encodeHexBytes(registration.tlcBasePubkey),
        local_settlement_key: encodeHexBytes(registration.localSettlementKey),
    };
}

/**
 * Reads a `channel_registered` frame: the node naming the channel it will open with the registered keys.
 * @param field The frame, already known to be a registration acknowledgement.
 * @returns The acknowledgement.
 */
export function decodeChannelRegistered(field: Field): Extract<InboundFrame, { type: "channel_registered" }> {
    const at = readObject<ChannelRegisteredWire>(field);
    return { type: "channel_registered", requestId: decodeRequestId(at("request_id")), channelId: decodeChannelId(at("channel_id")) };
}
