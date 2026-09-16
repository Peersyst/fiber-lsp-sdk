import { hexToBytes } from "@noble/hashes/utils.js";
import { decodeChannelRegistered, encodeRegisterChannel } from "../../../src/protocol/channel-registration";
import { refusal } from "../../utils/refusal";
import { withField } from "../../utils/with-field";

const REQUEST_ID = "reg-1";
const CHANNEL_ID = `0x${"1f".repeat(32)}`;
const REGISTRATION = {
    fundingPubkey: hexToBytes(`02${"ab".repeat(32)}`),
    tlcBasePubkey: hexToBytes(`03${"cd".repeat(32)}`),
    localSettlementKey: hexToBytes("ef".repeat(32)),
};
const ACKNOWLEDGEMENT = { type: "channel_registered", request_id: REQUEST_ID, channel_id: CHANNEL_ID };

describe("encodeRegisterChannel", () => {
    it("writes the base public keys and the delegated settlement key, and nothing derived by number", () => {
        expect(encodeRegisterChannel(REQUEST_ID, REGISTRATION)).toEqual({
            type: "register_channel",
            request_id: REQUEST_ID,
            funding_pubkey: `0x02${"ab".repeat(32)}`,
            tlc_base_pubkey: `0x03${"cd".repeat(32)}`,
            local_settlement_key: `0x${"ef".repeat(32)}`,
        });
    });

    it("rejects a request id outside the wire bound", () => {
        expect(() => encodeRegisterChannel("", REGISTRATION)).toThrow(TypeError);
        expect(() => encodeRegisterChannel("a".repeat(65), REGISTRATION)).toThrow(TypeError);
    });

    it("rejects a key of the wrong wire size", () => {
        expect(() => encodeRegisterChannel(REQUEST_ID, { ...REGISTRATION, fundingPubkey: REGISTRATION.fundingPubkey.slice(1) })).toThrow(
            TypeError,
        );
        expect(() => encodeRegisterChannel(REQUEST_ID, { ...REGISTRATION, tlcBasePubkey: REGISTRATION.localSettlementKey })).toThrow(
            TypeError,
        );
        expect(() => encodeRegisterChannel(REQUEST_ID, { ...REGISTRATION, localSettlementKey: REGISTRATION.fundingPubkey })).toThrow(
            TypeError,
        );
    });
});

describe("decodeChannelRegistered", () => {
    it("reads the id the node gave the channel", () => {
        expect(decodeChannelRegistered({ value: ACKNOWLEDGEMENT, path: "channel_registered" })).toEqual({
            type: "channel_registered",
            requestId: REQUEST_ID,
            channelId: CHANNEL_ID,
        });
    });

    it.each([
        ["request_id", undefined],
        ["request_id", ""],
        ["request_id", 1],
        ["request_id", "a".repeat(65)],
        ["request_id", "req-é"],
        ["channel_id", undefined],
        ["channel_id", `0x${"1f".repeat(31)}`],
        ["channel_id", "1f".repeat(32)],
    ])("refuses %s = %p", (path, value) => {
        const error = refusal(() =>
            decodeChannelRegistered({ value: withField(ACKNOWLEDGEMENT, path, value), path: "channel_registered" }),
        );
        expect(error.path).toBe(`channel_registered.${path}`);
    });
});
