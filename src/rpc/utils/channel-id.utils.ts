import { HASH256_LENGTH } from "../../common";
import { assertWireHexBytes } from "../../wire";
import type { RpcChannelIdParams, RpcChannelIdParamsWire } from "../rpc.types";

/**
 * Writes the params of a method that names a channel and nothing else.
 * @param params The channel.
 * @returns The wire params.
 */
export function encodeRpcChannelIdParams(params: RpcChannelIdParams): RpcChannelIdParamsWire {
    assertWireHexBytes("channelId", params.channelId, HASH256_LENGTH);
    return { channel_id: params.channelId };
}
