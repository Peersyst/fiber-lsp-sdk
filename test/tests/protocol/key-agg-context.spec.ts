import { hexToBytes } from "@noble/hashes/utils.js";
import { decodeKeyAggContext } from "../../../src/protocol/key-agg-context";
import { refusal } from "../../utils/refusal";

const PEER_KEY = "026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638";
const DEVICE_KEY = "02e42662b93a36b0817ec942512688ce880d300f3d48309ac79953cfd402c10ff5";
// A valid encoding whose x has no y on the curve, the one fiber's variant decodes to "invalid point byte representation".
const OFF_CURVE_KEY = "022068854bacc49665230d0813b9b3d055d1cb42a62b10b53d633c952e99f665b2";
const THIRD_KEY = "02b1621ddb5fcb68f70c5897d779ab3572857cf356329e6f0f3bee8745548ff9c1";
const TWEAK = "4140a663980cc0397275f1155eb073a91c1f13b97ef5c2177855aaf1bc55b3a2";
const COUNT_2 = "00000002";
const PATH = "content.key_agg_ctx";

const LENGTH = "must be 71 bytes";
const HEADER = "must have the header byte 0x00: no parity flag, no tweak";
const COUNT = "must count exactly 2 keys";

function decode(value: unknown): [Uint8Array, Uint8Array] {
    return decodeKeyAggContext({ value, path: PATH });
}

function reasonOf(value: unknown): string {
    const error = refusal(() => decode(value));
    expect(error.path).toBe(PATH);
    return error.reason;
}

describe("decodeKeyAggContext", () => {
    it("reads the two keys in the order they were aggregated", () => {
        expect(decode(`0x00${COUNT_2}${PEER_KEY}${DEVICE_KEY}`)).toEqual([hexToBytes(PEER_KEY), hexToBytes(DEVICE_KEY)]);
        expect(decode(`0x00${COUNT_2}${DEVICE_KEY}${PEER_KEY}`)).toEqual([hexToBytes(DEVICE_KEY), hexToBytes(PEER_KEY)]);
    });

    it.each([
        ["one byte short", `0x00${COUNT_2}${PEER_KEY}${DEVICE_KEY.slice(0, -2)}`],
        ["one byte over", `0x00${COUNT_2}${PEER_KEY}${DEVICE_KEY}00`],
        ["the header alone", "0x00"],
        ["empty", "0x"],
        ["a tweak with its tweak, as fiber accepts", `0x02${TWEAK}${COUNT_2}${PEER_KEY}${DEVICE_KEY}`],
        ["three keys counted three, as fiber accepts", `0x0000000003${PEER_KEY}${DEVICE_KEY}${THIRD_KEY}`],
    ])("refuses a length other than 71 bytes: %s", (_name, value) => {
        expect(reasonOf(value)).toBe(LENGTH);
    });

    it.each([
        ["the parity bit, which fiber accepts", "01"],
        ["the tweak bit with no tweak", "02"],
        ["both bits", "03"],
        ["a bit fiber does not define", "80"],
    ])("refuses a header other than 0x00: %s", (_name, header) => {
        expect(reasonOf(`0x${header}${COUNT_2}${PEER_KEY}${DEVICE_KEY}`)).toBe(HEADER);
    });

    it.each([
        ["zero", "00000000"],
        ["one", "00000001"],
        ["three", "00000003"],
        ["two in the high byte, a little-endian reading", "02000000"],
        ["two plus 2^8", "00000102"],
    ])("refuses a count other than 2: %s", (_name, count) => {
        expect(reasonOf(`0x00${count}${PEER_KEY}${DEVICE_KEY}`)).toBe(COUNT);
    });

    it.each([
        ["off the curve", OFF_CURVE_KEY],
        ["with an uncompressed prefix", `04${PEER_KEY.slice(2)}`],
        ["with a zero prefix", `00${PEER_KEY.slice(2)}`],
        ["all zero, the infinity sentinel", "00".repeat(33)],
    ])("refuses a key that is no compressed point: %s", (_name, key) => {
        expect(reasonOf(`0x00${COUNT_2}${key}${DEVICE_KEY}`)).toBe("must have a first key on the curve");
        expect(reasonOf(`0x00${COUNT_2}${PEER_KEY}${key}`)).toBe("must have a second key on the curve");
    });

    it("refuses the same key twice, which a funding lock of two parties never aggregates", () => {
        expect(reasonOf(`0x00${COUNT_2}${PEER_KEY}${PEER_KEY}`)).toBe("must aggregate two distinct keys");
    });

    it.each([
        ["without the 0x prefix", `00${COUNT_2}${PEER_KEY}${DEVICE_KEY}`],
        ["in uppercase", `0x00${COUNT_2}${PEER_KEY.toUpperCase()}${DEVICE_KEY}`],
        ["with an odd digit count", `0x00${COUNT_2}${PEER_KEY}${DEVICE_KEY}0`],
        ["as bytes", hexToBytes(`00${COUNT_2}${PEER_KEY}${DEVICE_KEY}`)],
        ["absent", undefined],
        ["null", null],
    ])("refuses a value that is not 0x-prefixed lowercase hex: %s", (_name, value) => {
        expect(reasonOf(value)).toBe("must be whole bytes of 0x-prefixed lowercase hex");
    });
});
