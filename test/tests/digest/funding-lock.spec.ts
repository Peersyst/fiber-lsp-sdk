import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { blake160 } from "../../../src/common/utils/ckb-hash.utils";
import { fundingLockArgs, tenantChannelId } from "../../../src/digest/funding-lock";
import { aggregateXOnlyPubkey } from "../../../src/digest/utils/digest.utils";

// The keys of the signing vectors' channel, and the values the funding lock case of the vectors pins for them.
const DEVICE_FUNDING_PUBKEY = hexToBytes("02e42662b93a36b0817ec942512688ce880d300f3d48309ac79953cfd402c10ff5");
const PEER_FUNDING_PUBKEY = hexToBytes("026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638");
const DEVICE_TLC_BASE_PUBKEY = hexToBytes("035de18a9013ba6eb918a415764d99945683f18d3f9fa4c881ed92423124de0849");
const PEER_TLC_BASE_PUBKEY = hexToBytes("032559e1b167552782cab5be4294260d51edfc36aef4ca7cc165b3b21b15e98e21");
const FUNDING_LOCK_ARGS = "d28355e59077c4ac7d755f5f63c5a3e4d154e9dd";
const CHANNEL_ID = "0xba90612b1c7b672e5dea40d64e0b352ec7dc8b7f652c9a84d4b82f7ec1488c2a";

// One malformed key per row; the name in each message is the parameter's.
function malformedKeys(name: string): [string, unknown, TypeError][] {
    return [
        ["absent", undefined, new TypeError(`${name} must be a Uint8Array`)],
        ["in hex", "02e42662b93a36b0817ec942512688ce880d300f3d48309ac79953cfd402c10ff5", new TypeError(`${name} must be a Uint8Array`)],
        ["of 32 bytes", DEVICE_FUNDING_PUBKEY.subarray(1), new TypeError(`${name} must be 33 bytes, got 32`)],
        ["of 34 bytes", Uint8Array.of(...DEVICE_FUNDING_PUBKEY, 0x00), new TypeError(`${name} must be 33 bytes, got 34`)],
        [
            "with an uncompressed prefix",
            Uint8Array.of(0x04, ...DEVICE_FUNDING_PUBKEY.subarray(1)),
            new TypeError(`${name} must be a compressed point on secp256k1`),
        ],
        [
            "with an x off the curve",
            Uint8Array.of(0x02, ...new Uint8Array(32)),
            new TypeError(`${name} must be a compressed point on secp256k1`),
        ],
    ];
}

describe("fundingLockArgs", () => {
    it("derives the args the vectors pin, 20 bytes", () => {
        const args = fundingLockArgs(DEVICE_FUNDING_PUBKEY, PEER_FUNDING_PUBKEY);
        expect(args).toHaveLength(20);
        expect(bytesToHex(args)).toBe(FUNDING_LOCK_ARGS);
    });

    it("derives the same args whichever party's key comes first", () => {
        expect(bytesToHex(fundingLockArgs(PEER_FUNDING_PUBKEY, DEVICE_FUNDING_PUBKEY))).toBe(FUNDING_LOCK_ARGS);
    });

    // The peer's key sorts first here, so the aggregate in the order the device's key is given in is another lock.
    it("aggregates the keys sorted, not in the order given", () => {
        expect(bytesToHex(blake160(aggregateXOnlyPubkey([DEVICE_FUNDING_PUBKEY, PEER_FUNDING_PUBKEY])))).not.toBe(FUNDING_LOCK_ARGS);
        expect(bytesToHex(blake160(aggregateXOnlyPubkey([PEER_FUNDING_PUBKEY, DEVICE_FUNDING_PUBKEY])))).toBe(FUNDING_LOCK_ARGS);
    });

    it.each(malformedKeys("fundingPubkeyA"))("refuses fundingPubkeyA %s", (_, key, error) => {
        expect(() => fundingLockArgs(key as Uint8Array, PEER_FUNDING_PUBKEY)).toThrow(error);
    });

    it.each(malformedKeys("fundingPubkeyB"))("refuses fundingPubkeyB %s", (_, key, error) => {
        expect(() => fundingLockArgs(DEVICE_FUNDING_PUBKEY, key as Uint8Array)).toThrow(error);
    });

    it("refuses the same key twice", () => {
        expect(() => fundingLockArgs(DEVICE_FUNDING_PUBKEY, Uint8Array.from(DEVICE_FUNDING_PUBKEY))).toThrow(
            new TypeError("fundingPubkeyA and fundingPubkeyB must be two distinct public keys"),
        );
    });
});

describe("tenantChannelId", () => {
    it("derives the id the vectors pin, as fiber's JSON writes it", () => {
        expect(tenantChannelId(DEVICE_TLC_BASE_PUBKEY, PEER_TLC_BASE_PUBKEY)).toBe(CHANNEL_ID);
    });

    it("derives the same id from the other end of the channel", () => {
        expect(tenantChannelId(PEER_TLC_BASE_PUBKEY, DEVICE_TLC_BASE_PUBKEY)).toBe(CHANNEL_ID);
    });

    it.each(malformedKeys("localTlcBasePubkey"))("refuses localTlcBasePubkey %s", (_, key, error) => {
        expect(() => tenantChannelId(key as Uint8Array, PEER_TLC_BASE_PUBKEY)).toThrow(error);
    });

    it.each(malformedKeys("remoteSettlementKey"))("refuses remoteSettlementKey %s", (_, key, error) => {
        expect(() => tenantChannelId(DEVICE_TLC_BASE_PUBKEY, key as Uint8Array)).toThrow(error);
    });

    it("refuses the device's own key as the peer's", () => {
        expect(() => tenantChannelId(DEVICE_TLC_BASE_PUBKEY, Uint8Array.from(DEVICE_TLC_BASE_PUBKEY))).toThrow(
            new TypeError("localTlcBasePubkey and remoteSettlementKey must be two distinct public keys"),
        );
    });
});
