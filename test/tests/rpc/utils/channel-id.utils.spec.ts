import { encodeRpcChannelIdParams } from "../../../../src/rpc";
import { toRpcChannelIdParams } from "../../../utils/rpc-typed";
import { loadRpcVectors } from "../../../utils/rpc-vectors";

const vectors = loadRpcVectors();

const CHANNEL_ID = `0x${"11".repeat(32)}`;

const CASES = (["abandon_channel", "get_channel_signing_status", "get_watchtower_signing_status"] as const).flatMap((method) =>
    vectors.methods[method].params.map((entry) => [method, entry.name, entry] as const),
);

describe("encodeRpcChannelIdParams", () => {
    it("writes the channel id as it is, and nothing else", () => {
        const wire = encodeRpcChannelIdParams({ channelId: CHANNEL_ID });
        expect(wire).toEqual({ channel_id: CHANNEL_ID });
        expect(Object.keys(wire)).toEqual(["channel_id"]);
    });

    it.each(CASES)("writes the %s / %s case as fiber's serde does", (_, __, entry) => {
        expect(encodeRpcChannelIdParams(toRpcChannelIdParams(entry.values))).toEqual(entry.json);
    });

    it.each([
        ["a bare channel id", "11".repeat(32)],
        ["an uppercase channel id", `0x${"AA".repeat(32)}`],
        ["a channel id of 31 bytes", `0x${"11".repeat(31)}`],
        ["a channel id of 33 bytes", `0x${"11".repeat(33)}`],
        ["a padded channel id", `${CHANNEL_ID} `],
        ["a missing channel id", undefined],
        ["a channel id given as null", null],
    ])("refuses %s", (_, channelId) => {
        expect(() => encodeRpcChannelIdParams({ channelId: channelId as string })).toThrow(
            new TypeError("channelId must be 32 bytes of 0x-prefixed lowercase hex"),
        );
    });
});
