import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelSeed } from "../../../src/derivation/device-scheme";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation/fiber-scheme";
import { computeChannelAnnouncementDigest } from "../../../src/digest/channel-announcement";
import type { ChannelAnnouncementInput } from "../../../src/digest/digest.types";

const MASTER_SEED = new Uint8Array(32).fill(0x24);
const channelKeys = deriveChannelKeys(deriveChannelSeed(MASTER_SEED, 0));

const remoteFundingPubkey = pubkeyOf(new Uint8Array(32).fill(0x33));
const NODE_ONE = pubkeyOf(new Uint8Array(32).fill(0x44));
const NODE_TWO = pubkeyOf(new Uint8Array(32).fill(0x99));

const BASE_INPUT: ChannelAnnouncementInput = {
    chainHash: new Uint8Array(32).fill(0xc4),
    fundingOutPoint: { txHash: new Uint8Array(32).fill(0xf0), index: 0 },
    nodeIds: [NODE_ONE, NODE_TWO],
    remoteFundingPubkey,
    capacityShannons: 80_500_000_000n,
    udtTypeScript: null,
};

const baseDigest = bytesToHex(computeChannelAnnouncementDigest(channelKeys, BASE_INPUT));

function digestOf(overrides: Partial<ChannelAnnouncementInput>): string {
    return bytesToHex(computeChannelAnnouncementDigest(channelKeys, { ...BASE_INPUT, ...overrides }));
}

describe("computeChannelAnnouncementDigest", () => {
    it("returns a deterministic 32-byte digest", () => {
        expect(computeChannelAnnouncementDigest(channelKeys, BASE_INPUT)).toHaveLength(32);
        expect(digestOf({})).toBe(baseDigest);
    });

    // The announcement sorts the node ids itself, so the caller's order must not matter.
    it("is invariant to the node id order", () => {
        expect(digestOf({ nodeIds: [NODE_TWO, NODE_ONE] })).toBe(baseDigest);
    });

    it.each<[keyof ChannelAnnouncementInput, Partial<ChannelAnnouncementInput>]>([
        ["chainHash", { chainHash: new Uint8Array(32).fill(0xc5) }],
        ["fundingOutPoint", { fundingOutPoint: { txHash: new Uint8Array(32).fill(0xf1), index: 0 } }],
        ["nodeIds", { nodeIds: [NODE_ONE, pubkeyOf(new Uint8Array(32).fill(0x9a))] }],
        ["remoteFundingPubkey", { remoteFundingPubkey: pubkeyOf(new Uint8Array(32).fill(0x34)) }],
        ["capacityShannons", { capacityShannons: 80_500_000_001n }],
        ["udtTypeScript", { udtTypeScript: { codeHash: hexToBytes("aa".repeat(32)), hashType: "type", args: new Uint8Array(0) } }],
    ])("commits to %s", (_, overrides) => {
        expect(digestOf(overrides)).not.toBe(baseDigest);
    });

    it("refuses malformed inputs, one field at a time", () => {
        expect(() => digestOf({ chainHash: new Uint8Array(31) })).toThrow(TypeError);
        expect(() => digestOf({ nodeIds: [new Uint8Array(32), NODE_TWO] })).toThrow(TypeError);
        expect(() => digestOf({ nodeIds: [NODE_ONE, new Uint8Array(34)] })).toThrow(TypeError);
        expect(() => digestOf({ remoteFundingPubkey: new Uint8Array(32) })).toThrow(TypeError);
        expect(() => digestOf({ capacityShannons: 1n << 128n })).toThrow(RangeError);
        expect(() => digestOf({ fundingOutPoint: { txHash: new Uint8Array(32), index: 2 ** 32 } })).toThrow(RangeError);
    });
});
