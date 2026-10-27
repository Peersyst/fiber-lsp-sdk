import { bytesToHex } from "@noble/hashes/utils.js";
import { MAX_CHANNEL_INDEX, MAX_COMMITMENT_NUMBER, MAX_INVOICE_INDEX, NONCE_CONTEXTS } from "../../../src/derivation/derivation.constants";
import type { NonceContext } from "../../../src/derivation/derivation.types";
import {
    deriveChannelSeed,
    deriveHoldInvoicePreimage,
    deriveNonceSeed,
    deriveWalletIdentityKey,
} from "../../../src/derivation/device-scheme";
import { deriveChannelKeys } from "../../../src/derivation/fiber-scheme";

const MASTER_SEED = new Uint8Array(32).fill(0x24);
const OTHER_MASTER_SEED = new Uint8Array(32).fill(0x25);
const channelKeys = deriveChannelKeys(deriveChannelSeed(MASTER_SEED, 0));

describe("deriveWalletIdentityKey", () => {
    it("returns a deterministic 32-byte key", () => {
        expect(deriveWalletIdentityKey(MASTER_SEED)).toHaveLength(32);
        expect(bytesToHex(deriveWalletIdentityKey(MASTER_SEED))).toBe(bytesToHex(deriveWalletIdentityKey(MASTER_SEED)));
    });

    it("is bound to the master seed", () => {
        expect(bytesToHex(deriveWalletIdentityKey(MASTER_SEED))).not.toBe(bytesToHex(deriveWalletIdentityKey(OTHER_MASTER_SEED)));
    });

    // Two devices restored from one mnemonic are one wallet.
    it("is a function of the master seed alone", () => {
        const restored = Uint8Array.from(MASTER_SEED);
        expect(bytesToHex(deriveWalletIdentityKey(restored))).toBe(bytesToHex(deriveWalletIdentityKey(MASTER_SEED)));
    });

    it("is not the seed of any channel", () => {
        expect(bytesToHex(deriveWalletIdentityKey(MASTER_SEED))).not.toBe(bytesToHex(deriveChannelSeed(MASTER_SEED, 0)));
    });

    it.each([31, 33])("rejects a %i-byte master seed", (length) => {
        expect(() => deriveWalletIdentityKey(new Uint8Array(length))).toThrow(TypeError);
    });
});

describe("deriveChannelSeed", () => {
    it("is deterministic", () => {
        expect(bytesToHex(deriveChannelSeed(MASTER_SEED, 7))).toBe(bytesToHex(deriveChannelSeed(MASTER_SEED, 7)));
    });

    it("is distinct for every channel index in a range", () => {
        const seeds = new Set<string>();
        for (let channelIndex = 0; channelIndex <= 100; channelIndex++) {
            seeds.add(bytesToHex(deriveChannelSeed(MASTER_SEED, channelIndex)));
        }
        expect(seeds.size).toBe(101);
    });

    it("is bound to the master seed", () => {
        expect(bytesToHex(deriveChannelSeed(MASTER_SEED, 0))).not.toBe(bytesToHex(deriveChannelSeed(OTHER_MASTER_SEED, 0)));
    });

    it("accepts the highest exactly representable index", () => {
        expect(deriveChannelSeed(MASTER_SEED, MAX_CHANNEL_INDEX)).toHaveLength(32);
    });

    it.each([-1, 1.5, MAX_CHANNEL_INDEX + 1, NaN, Infinity])("rejects the channel index %p", (channelIndex) => {
        expect(() => deriveChannelSeed(MASTER_SEED, channelIndex)).toThrow(RangeError);
    });

    it("rejects a master seed of the wrong length", () => {
        expect(() => deriveChannelSeed(new Uint8Array(16), 0)).toThrow(TypeError);
    });
});

describe("deriveHoldInvoicePreimage", () => {
    it("is deterministic", () => {
        expect(bytesToHex(deriveHoldInvoicePreimage(MASTER_SEED, 7))).toBe(bytesToHex(deriveHoldInvoicePreimage(MASTER_SEED, 7)));
    });

    it("is distinct for every invoice index in a range", () => {
        const preimages = new Set<string>();
        for (let invoiceIndex = 0; invoiceIndex <= 100; invoiceIndex++) {
            preimages.add(bytesToHex(deriveHoldInvoicePreimage(MASTER_SEED, invoiceIndex)));
        }
        expect(preimages.size).toBe(101);
    });

    it("is bound to the master seed", () => {
        expect(bytesToHex(deriveHoldInvoicePreimage(MASTER_SEED, 0))).not.toBe(bytesToHex(deriveHoldInvoicePreimage(OTHER_MASTER_SEED, 0)));
    });

    it("is not the seed of the channel of the same index", () => {
        expect(bytesToHex(deriveHoldInvoicePreimage(MASTER_SEED, 0))).not.toBe(bytesToHex(deriveChannelSeed(MASTER_SEED, 0)));
    });

    it("accepts the highest exactly representable index", () => {
        expect(MAX_INVOICE_INDEX).toBe(Number.MAX_SAFE_INTEGER);
        expect(deriveHoldInvoicePreimage(MASTER_SEED, MAX_INVOICE_INDEX)).toHaveLength(32);
    });

    it.each([-1, 1.5, MAX_INVOICE_INDEX + 1, NaN, Infinity, undefined])("rejects the invoice index %p", (invoiceIndex) => {
        expect(() => deriveHoldInvoicePreimage(MASTER_SEED, invoiceIndex as number)).toThrow(
            new RangeError(`invoiceIndex must be an integer between 0 and ${MAX_INVOICE_INDEX}, got ${invoiceIndex}`),
        );
    });

    it.each([31, 33])("rejects a %i-byte master seed", (length) => {
        expect(() => deriveHoldInvoicePreimage(new Uint8Array(length), 0)).toThrow(
            new TypeError(`masterSeed must be 32 bytes, got ${length}`),
        );
    });

    it("rejects an absent master seed", () => {
        expect(() => deriveHoldInvoicePreimage(undefined as unknown as Uint8Array, 0)).toThrow(
            new TypeError("masterSeed must be a Uint8Array"),
        );
    });
});

describe("deriveNonceSeed", () => {
    it("returns a deterministic 32-byte seed", () => {
        expect(deriveNonceSeed(channelKeys, 0, "COMMITMENT")).toHaveLength(32);
        expect(bytesToHex(deriveNonceSeed(channelKeys, 0, "COMMITMENT"))).toBe(bytesToHex(deriveNonceSeed(channelKeys, 0, "COMMITMENT")));
    });

    it("is distinct per context", () => {
        const seeds = new Set(NONCE_CONTEXTS.map((context) => bytesToHex(deriveNonceSeed(channelKeys, 4, context))));
        expect(seeds.size).toBe(NONCE_CONTEXTS.length);
    });

    it("is distinct per commitment number", () => {
        const seeds = new Set([0, 1, 2, 1000, MAX_COMMITMENT_NUMBER].map((n) => bytesToHex(deriveNonceSeed(channelKeys, n, "COMMITMENT"))));
        expect(seeds.size).toBe(5);
    });

    it("is distinct per channel", () => {
        const otherChannel = deriveChannelKeys(deriveChannelSeed(MASTER_SEED, 1));
        expect(bytesToHex(deriveNonceSeed(otherChannel, 0, "COMMITMENT"))).not.toBe(
            bytesToHex(deriveNonceSeed(channelKeys, 0, "COMMITMENT")),
        );
    });

    it("rejects an out-of-range commitment number", () => {
        expect(() => deriveNonceSeed(channelKeys, 2 ** 48, "COMMITMENT")).toThrow(RangeError);
    });

    // A close signs in the commitment slot, as fiber does.
    it.each(["SETTLE", "CLOSE"])("rejects the unknown context %s", (context) => {
        const unknownContext = context as unknown as NonceContext;
        expect(() => deriveNonceSeed(channelKeys, 0, unknownContext)).toThrow(
            new TypeError("context must be one of COMMITMENT, REVOKE, ANNOUNCEMENT"),
        );
    });

    // It validates nothing itself: the guards of what it composes do.
    it("rejects channel keys with malformed secrets", () => {
        expect(() => deriveNonceSeed({ ...channelKeys, commitmentSeed: new Uint8Array(31) }, 0, "COMMITMENT")).toThrow(TypeError);
        expect(() => deriveNonceSeed({ ...channelKeys, musig2BaseNonce: new Uint8Array(31) }, 0, "COMMITMENT")).toThrow(TypeError);
    });
});

describe("scheme v1 outputs", () => {
    // The recoverability contract: changing these strands existing channels, so a change needs a new scheme version.
    it("derives the pinned wallet identity key", () => {
        expect(bytesToHex(deriveWalletIdentityKey(MASTER_SEED))).toBe("fe11dd3161e80f6e20a43106d2b0853ec87d613c87ab0c87f41584c31f091ed1");
    });

    it("derives the pinned channel seeds", () => {
        expect(bytesToHex(deriveChannelSeed(MASTER_SEED, 0))).toBe("c457d413e86ae061a58581a01fd42ecdef1398cc1e39ecd06e0656e8a5a7037f");
        expect(bytesToHex(deriveChannelSeed(MASTER_SEED, MAX_CHANNEL_INDEX))).toBe(
            "30a8f54cdacc5ce91ab352639f846146e403e1568e1dd427f26affa76e8e182e",
        );
    });

    it("derives the pinned hold invoice preimages", () => {
        expect(bytesToHex(deriveHoldInvoicePreimage(MASTER_SEED, 0))).toBe(
            "a6b4115ac71b6ef546f367b8c787b0fd2b12ae68e28c6ba5226ba31d0c7a9fdb",
        );
        expect(bytesToHex(deriveHoldInvoicePreimage(MASTER_SEED, MAX_INVOICE_INDEX))).toBe(
            "97789786d535e8c1711ed07d498a9bb68ff8e158d392b8d8ea160b929dacce79",
        );
    });

    it("derives the pinned nonce seed", () => {
        expect(bytesToHex(deriveNonceSeed(channelKeys, 0, "COMMITMENT"))).toBe(
            "c5d7b4a3d7a2e57d1c58c96e0f01463ccb927a991cb2820a87011718f43c51f5",
        );
    });
});
