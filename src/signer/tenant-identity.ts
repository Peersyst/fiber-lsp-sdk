import { secp256k1 } from "@noble/curves/secp256k1.js";
import { equalBytes } from "@noble/curves/utils.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import {
    COMPACT_ECDSA_SIGNATURE_LENGTH,
    COMPRESSED_POINT_LENGTH,
    HASH256_LENGTH,
    assertBytes,
    assertCompressedPoint,
    ckbBlake2b,
    isPlainObject,
} from "../common";
import { blake2bHashWithSalt, deriveWalletIdentityKey, pubkeyOf } from "../derivation";
import type { GetTenantRegistryNonceResult, RegisterTenantParams } from "../rpc";
import { TENANT_ID_DOMAIN, TENANT_REGISTRY_PROTOCOL } from "./signer.constants";

const TENANT_REGISTRY_PREFIX = utf8ToBytes(TENANT_REGISTRY_PROTOCOL);

const TENANT_ID_SALT = utf8ToBytes(TENANT_ID_DOMAIN);

/**
 * Builds the bytes fiber's `TenantRegistryPayload::canonical_bytes` writes for a registry nonce.
 * @param challenge The result of `lsp_get_tenant_registry_nonce`.
 * @returns The protocol prefix, the LSP's node id, the root signer and the nonce, concatenated.
 */
export function buildTenantRegistryPayload(challenge: GetTenantRegistryNonceResult): Uint8Array {
    if (!isPlainObject(challenge)) throw new TypeError("challenge must be an object");
    assertCompressedPoint("challenge.lspNodeId", challenge.lspNodeId);
    assertCompressedPoint("challenge.rootSignerPubkey", challenge.rootSignerPubkey);
    assertBytes("challenge.nonce", challenge.nonce, HASH256_LENGTH);
    return concatBytes(TENANT_REGISTRY_PREFIX, challenge.lspNodeId, challenge.rootSignerPubkey, challenge.nonce);
}

/**
 * Computes fiber's `TenantRegistryPayload::digest`, `blake2b_hash_with_salt` with an empty salt.
 * @param challenge The result of `lsp_get_tenant_registry_nonce`.
 * @returns The 32-byte digest of the registry payload.
 */
export function computeTenantRegistryDigest(challenge: GetTenantRegistryNonceResult): Uint8Array {
    return ckbBlake2b(buildTenantRegistryPayload(challenge));
}

export class TenantIdentity {
    readonly #secretKey: Uint8Array;

    readonly #publicKey: Uint8Array;

    readonly #tenantId: string;

    /**
     * Derives the RootSigner from the master seed's wallet identity key.
     * @param masterSeed The master seed.
     */
    constructor(masterSeed: Uint8Array) {
        this.#secretKey = deriveWalletIdentityKey(masterSeed);
        this.#publicKey = pubkeyOf(this.#secretKey);
        this.#tenantId = bytesToHex(blake2bHashWithSalt(this.#publicKey, TENANT_ID_SALT));
    }

    /**
     * The RootSigner's public key, the one the LSP issues registry nonces to.
     * @returns A copy of the 33-byte compressed key.
     */
    get publicKey(): Uint8Array {
        return this.#publicKey.slice();
    }

    /**
     * The tenant id fiber's `TenantId::from_root_signer_pubkey` derives from the RootSigner.
     * @returns The 64-character lowercase hex id.
     */
    get tenantId(): string {
        return this.#tenantId;
    }

    /**
     * Signs a registry nonce issued to this RootSigner, refusing one issued to another key.
     * @param challenge The result of `lsp_get_tenant_registry_nonce`.
     * @returns The params of `lsp_register_tenant`, with the 64-byte compact ECDSA signature over the registry digest.
     */
    signRegistration(challenge: GetTenantRegistryNonceResult): RegisterTenantParams {
        if (!isPlainObject(challenge)) throw new TypeError("challenge must be an object");
        assertBytes("challenge.rootSignerPubkey", challenge.rootSignerPubkey, COMPRESSED_POINT_LENGTH);
        // Fiber's `begin_registration` (`fiber-lsp-sdk/src/session.rs:184-191`) refuses it too.
        if (!equalBytes(challenge.rootSignerPubkey, this.#publicKey)) {
            throw new TypeError(
                "challenge.rootSignerPubkey must be this identity's public key: the nonce was issued to another RootSigner",
            );
        }
        const digest = computeTenantRegistryDigest(challenge);
        // As rust-secp256k1's `sign_ecdsa`: no prehash, RFC 6979 without extra entropy, low-S, compact.
        const signature = secp256k1.sign(digest, this.#secretKey, { prehash: false, lowS: true, extraEntropy: false, format: "compact" });
        assertBytes("signature", signature, COMPACT_ECDSA_SIGNATURE_LENGTH);
        return { rootSignerPubkey: this.#publicKey.slice(), nonce: Uint8Array.from(challenge.nonce), signature };
    }
}
