import { bytesToHex } from "@noble/hashes/utils.js";
import { HDKey } from "@scure/bip32";
import { BIP39_SEED_LENGTH, MAX_ACCOUNT_INDEX } from "../../../src/derivation/derivation.constants";
import { deriveChannelSeed, deriveWalletIdentityKey } from "../../../src/derivation/device-scheme";
import { deriveChannelKeys } from "../../../src/derivation/fiber-scheme";
import { deriveMasterSeed } from "../../../src/derivation/master-seed";

const BIP39_SEED = new Uint8Array(BIP39_SEED_LENGTH).fill(0x11);
const OTHER_BIP39_SEED = new Uint8Array(BIP39_SEED_LENGTH).fill(0x12);

function keyAtPathHex(path: string): string {
    const { privateKey } = HDKey.fromMasterSeed(BIP39_SEED).derive(path);
    if (privateKey === null) throw new Error(`no private key at ${path}`);
    return bytesToHex(privateKey);
}

describe("deriveMasterSeed", () => {
    it("returns a deterministic 32-byte seed", () => {
        expect(deriveMasterSeed(BIP39_SEED)).toHaveLength(32);
        expect(bytesToHex(deriveMasterSeed(BIP39_SEED))).toBe(bytesToHex(deriveMasterSeed(BIP39_SEED)));
    });

    it("defaults to account 0", () => {
        expect(bytesToHex(deriveMasterSeed(BIP39_SEED))).toBe(bytesToHex(deriveMasterSeed(BIP39_SEED, 0)));
    });

    it("is bound to the BIP39 seed", () => {
        expect(bytesToHex(deriveMasterSeed(BIP39_SEED))).not.toBe(bytesToHex(deriveMasterSeed(OTHER_BIP39_SEED)));
    });

    it("is distinct for every account index in a range", () => {
        const seeds = new Set<string>();
        for (let accountIndex = 0; accountIndex <= 20; accountIndex++) {
            seeds.add(bytesToHex(deriveMasterSeed(BIP39_SEED, accountIndex)));
        }
        expect(seeds.size).toBe(21);
    });

    it("accepts the highest hardened account index", () => {
        expect(deriveMasterSeed(BIP39_SEED, MAX_ACCOUNT_INDEX)).toHaveLength(32);
    });

    it("does not mutate its input", () => {
        const seed = Uint8Array.from(BIP39_SEED);
        deriveMasterSeed(seed, 3);
        expect(bytesToHex(seed)).toBe(bytesToHex(BIP39_SEED));
    });

    it("feeds the rest of the scheme", () => {
        const masterSeed = deriveMasterSeed(BIP39_SEED);
        expect(deriveWalletIdentityKey(masterSeed)).toHaveLength(32);
        expect(deriveChannelKeys(deriveChannelSeed(masterSeed, 0)).fundingKey).toHaveLength(32);
    });

    // The whole point of purpose 1017: a wallet spending on-chain from BIP44/49/84 can
    // never hand the same private key to both trees, whatever account it derives.
    it("cannot collide with the on-chain purposes a wallet spends from", () => {
        const onChain = [44, 49, 84].flatMap((purpose) => [
            keyAtPathHex(`m/${purpose}'/309'/0'`),
            keyAtPathHex(`m/${purpose}'/309'/0'/0/0`),
            keyAtPathHex(`m/${purpose}'/309'/0'/0'/0'`),
        ]);
        expect(onChain).not.toContain(bytesToHex(deriveMasterSeed(BIP39_SEED)));
    });

    it.each([0, 32, 63, 65])("rejects a %i-byte BIP39 seed", (length) => {
        expect(() => deriveMasterSeed(new Uint8Array(length))).toThrow(TypeError);
    });

    it("rejects a value that is not a byte array", () => {
        expect(() => deriveMasterSeed("11".repeat(64) as unknown as Uint8Array)).toThrow(TypeError);
    });

    it.each([-1, 1.5, MAX_ACCOUNT_INDEX + 1, NaN, Infinity])("rejects the account index %p", (accountIndex) => {
        expect(() => deriveMasterSeed(BIP39_SEED, accountIndex)).toThrow(RangeError);
    });
});

describe("scheme v1 outputs", () => {
    // The recoverability contract at its root, pinned independently of the interop
    // vectors: these bytes are the path itself, so a changed level lands here first.
    it("derives the pinned master seeds", () => {
        expect(bytesToHex(deriveMasterSeed(BIP39_SEED))).toBe("164dee70ea1d82df63d5f84ec2f876d400e1bfd61d14e37d11cd300fa2ffa2fd");
        expect(bytesToHex(deriveMasterSeed(BIP39_SEED, 7))).toBe("7605118f63c347c0624933b0d14d3cf290c95d9a57a3044f368a22a10c021d96");
        expect(bytesToHex(deriveMasterSeed(BIP39_SEED, MAX_ACCOUNT_INDEX))).toBe(
            "229ff24b06b71ae2e15862cfc776c0799cb5563be259668a44bdc64bc4f8a8c9",
        );
    });
});
