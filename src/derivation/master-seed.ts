import { HDKey } from "@scure/bip32";
import { assertBytes, assertUnsignedInteger } from "../common";
import {
    BIP39_SEED_LENGTH,
    MASTER_SEED_COIN_TYPE,
    MASTER_SEED_LENGTH,
    MASTER_SEED_PURPOSE,
    MAX_ACCOUNT_INDEX,
} from "./derivation.constants";

/**
 * Derives the master seed the SDK is constructed with, over a hardened BIP32 path of its own.
 * @param bip39Seed The 64-byte seed the host expanded the mnemonic into.
 * @param accountIndex Index of the account level of the path, up to `MAX_ACCOUNT_INDEX`.
 * @returns The 32-byte master seed.
 */
export function deriveMasterSeed(bip39Seed: Uint8Array, accountIndex = 0): Uint8Array {
    assertBytes("bip39Seed", bip39Seed, BIP39_SEED_LENGTH);
    assertUnsignedInteger("accountIndex", accountIndex, MAX_ACCOUNT_INDEX);

    const path = `m/${MASTER_SEED_PURPOSE}'/${MASTER_SEED_COIN_TYPE}'/${accountIndex}'`;
    const { privateKey } = HDKey.fromMasterSeed(bip39Seed).derive(path);
    assertBytes("derived master seed", privateKey, MASTER_SEED_LENGTH);
    return privateKey;
}
