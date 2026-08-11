/**
 * Port of fiber's channel key derivation (`crates/fiber-types/src/channel.rs` @ `b71a61c3`): keep the interop vectors green.
 */
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE, numberToBytesBE } from "@noble/curves/utils.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { COMPRESSED_POINT_LENGTH, assertBytes, assertUnsignedInteger } from "../common";
import { CHANNEL_SEED_LENGTH, MAX_COMMITMENT_NUMBER, SECRET_KEY_LENGTH } from "./derivation.constants";
import type { FiberChannelKeys } from "./derivation.types";
import { blake2bHashWithSalt, ckbBlake2b } from "./utils";

const CURVE_ORDER = secp256k1.Point.Fn.ORDER;

/**
 * Derives the compressed public key of a secret key.
 * @param secretKey The 32-byte secret key.
 * @returns The 33-byte compressed public key.
 */
export function pubkeyOf(secretKey: Uint8Array): Uint8Array {
    assertBytes("secretKey", secretKey, SECRET_KEY_LENGTH);
    return secp256k1.getPublicKey(secretKey, true);
}

/**
 * Port of fiber's `Privkey::tweak`: `(scalar + secretKey) mod n`.
 * @param secretKey The 32-byte secret key to tweak.
 * @param scalar The 32-byte scalar to add.
 * @returns The tweaked 32-byte secret key.
 */
export function tweakPrivkey(secretKey: Uint8Array, scalar: Uint8Array): Uint8Array {
    assertBytes("secretKey", secretKey, SECRET_KEY_LENGTH);
    assertBytes("scalar", scalar, SECRET_KEY_LENGTH);
    const tweaked = (bytesToNumberBE(scalar) + bytesToNumberBE(secretKey)) % CURVE_ORDER;
    if (tweaked === 0n) {
        throw new Error("tweak produced a zero private key");
    }
    return numberToBytesBE(tweaked, SECRET_KEY_LENGTH);
}

/**
 * Derives the tweak a commitment point applies to a base key.
 * @param commitmentPoint The 33-byte compressed commitment point.
 * @returns The 32-byte tweak.
 */
export function getTweakByCommitmentPoint(commitmentPoint: Uint8Array): Uint8Array {
    assertBytes("commitmentPoint", commitmentPoint, COMPRESSED_POINT_LENGTH);
    return ckbBlake2b(commitmentPoint);
}

/**
 * Port of fiber's `derive_private_key`.
 * @param secretKey The 32-byte base secret key.
 * @param commitmentPoint The 33-byte compressed commitment point.
 * @returns The derived 32-byte secret key.
 */
export function derivePrivateKey(secretKey: Uint8Array, commitmentPoint: Uint8Array): Uint8Array {
    return tweakPrivkey(secretKey, getTweakByCommitmentPoint(commitmentPoint));
}

/**
 * Port of fiber's `try_derive_public_key`, the pubkey-only path for keys the device does not hold.
 * @param basePublicKey The 33-byte compressed base public key.
 * @param commitmentPoint The 33-byte compressed commitment point.
 * @returns The derived 33-byte compressed public key.
 */
export function derivePublicKey(basePublicKey: Uint8Array, commitmentPoint: Uint8Array): Uint8Array {
    assertBytes("basePublicKey", basePublicKey, COMPRESSED_POINT_LENGTH);
    const tweak = bytesToNumberBE(getTweakByCommitmentPoint(commitmentPoint)) % CURVE_ORDER;
    const point = secp256k1.Point.fromBytes(basePublicKey).add(secp256k1.Point.BASE.multiply(tweak));
    return point.toBytes(true);
}

/**
 * Port of fiber's `get_commitment_secret`, a BOLT3-style 48-bit flip-and-hash chain.
 * @param commitmentSeed The 32-byte root of the chain, the secret of commitment number 0.
 * @param commitmentNumber The commitment number, up to `MAX_COMMITMENT_NUMBER`.
 * @returns A fresh 32-byte secret the caller may mutate.
 */
export function getCommitmentSecret(commitmentSeed: Uint8Array, commitmentNumber: number): Uint8Array {
    assertBytes("commitmentSeed", commitmentSeed, SECRET_KEY_LENGTH);
    assertUnsignedInteger("commitmentNumber", commitmentNumber, MAX_COMMITMENT_NUMBER);

    const bits = BigInt(commitmentNumber);
    const secret = Uint8Array.from(commitmentSeed);
    // Indexing a Uint8Array types as `number | undefined` under `noUncheckedIndexedAccess`.
    const view = new DataView(secret.buffer);
    for (let bitpos = 47; bitpos >= 0; bitpos--) {
        if ((bits & (1n << BigInt(bitpos))) === 0n) continue;
        const index = bitpos >> 3;
        view.setUint8(index, view.getUint8(index) ^ (1 << (bitpos & 7)));
        secret.set(ckbBlake2b(secret));
    }
    return secret;
}

/**
 * Derives the commitment point of a commitment number: the public key of its secret.
 * @param commitmentSeed The 32-byte root of the commitment secret chain.
 * @param commitmentNumber The commitment number, up to `MAX_COMMITMENT_NUMBER`.
 * @returns The 33-byte compressed commitment point.
 */
export function getCommitmentPoint(commitmentSeed: Uint8Array, commitmentNumber: number): Uint8Array {
    return pubkeyOf(getCommitmentSecret(commitmentSeed, commitmentNumber));
}

/**
 * Port of fiber's `InMemorySigner::generate_from_seed`, keeping the upstream "musig nocne" spelling.
 * @param channelSeed The 32-byte channel seed.
 * @returns The channel's four secrets.
 */
export function deriveChannelKeys(channelSeed: Uint8Array): FiberChannelKeys {
    assertBytes("channelSeed", channelSeed, CHANNEL_SEED_LENGTH);

    const seed = ckbBlake2b(channelSeed);
    const commitmentSeed = ckbBlake2b(seed, utf8ToBytes("commitment seed"));
    const fundingKey = blake2bHashWithSalt(seed, utf8ToBytes("funding key"));
    const tlcBaseKey = blake2bHashWithSalt(fundingKey, utf8ToBytes("HTLC base key"));
    const musig2BaseNonce = blake2bHashWithSalt(tlcBaseKey, utf8ToBytes("musig nocne"));

    return { fundingKey, tlcBaseKey, musig2BaseNonce, commitmentSeed };
}

/**
 * Port of fiber's `derive_tlc_key`: the per-commitment settlement material.
 * @param keys The channel's four secrets.
 * @param commitmentNumber The commitment number, up to `MAX_COMMITMENT_NUMBER`.
 * @returns The derived 32-byte TLC secret key.
 */
export function deriveTlcKey(keys: FiberChannelKeys, commitmentNumber: number): Uint8Array {
    return derivePrivateKey(keys.tlcBaseKey, getCommitmentPoint(keys.commitmentSeed, commitmentNumber));
}
