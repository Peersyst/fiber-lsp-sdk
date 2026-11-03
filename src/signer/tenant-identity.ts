import { secp256k1 } from "@noble/curves/secp256k1.js";
import { numberToBytesBE } from "@noble/curves/utils.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import {
    COMPACT_ECDSA_SIGNATURE_LENGTH,
    HASH256_LENGTH,
    UINT64_LENGTH,
    UINT64_MAX,
    assertBytes,
    assertCompressedPoint,
    assertUnsignedBigInt,
    ckbBlake2b,
    isPlainObject,
} from "../common";
import { blake2bHashWithSalt, deriveWalletIdentityKey, pubkeyOf } from "../derivation";
import type { RegisterTenantParams } from "../rpc";
import { TENANT_ID_DOMAIN, TENANT_REGISTRY_PROTOCOL } from "./signer.constants";
import type { TenantRegistryPayload } from "./signer.types";

const TENANT_REGISTRY_PREFIX = utf8ToBytes(TENANT_REGISTRY_PROTOCOL);

const TENANT_ID_SALT = utf8ToBytes(TENANT_ID_DOMAIN);

/**
 * Builds the bytes fiber's `TenantRegistryPayload::canonical_bytes` writes, the signing time as a big-endian u64.
 * @param payload The LSP's node id, the root signer, the request id and the signing time.
 * @returns The protocol prefix and the four fields, concatenated.
 */
export function buildTenantRegistryPayload(payload: TenantRegistryPayload): Uint8Array {
    if (!isPlainObject(payload)) throw new TypeError("payload must be an object");
    const { lspNodeId, rootSignerPubkey, requestId, signedAtMs } = payload;
    assertCompressedPoint("lspNodeId", lspNodeId);
    assertCompressedPoint("rootSignerPubkey", rootSignerPubkey);
    assertBytes("requestId", requestId, HASH256_LENGTH);
    assertUnsignedBigInt("signedAtMs", signedAtMs, UINT64_MAX);
    return concatBytes(TENANT_REGISTRY_PREFIX, lspNodeId, rootSignerPubkey, requestId, numberToBytesBE(signedAtMs, UINT64_LENGTH));
}

/**
 * Computes fiber's `TenantRegistryPayload::digest`, `blake2b_hash_with_salt` with an empty salt.
 * @param payload The LSP's node id, the root signer, the request id and the signing time.
 * @returns The 32-byte digest of the registry payload.
 */
export function computeTenantRegistryDigest(payload: TenantRegistryPayload): Uint8Array {
    return ckbBlake2b(buildTenantRegistryPayload(payload));
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
     * The RootSigner's public key, which a registration names and the tenant id derives from.
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
     * Signs the registry payload of this RootSigner, as fiber's `begin_registration` does, for the LSP and request given.
     * @param request The LSP's node id, the request id and the signing time in Unix milliseconds.
     * @returns The params of `lsp_register_tenant`, with the 64-byte compact ECDSA signature over the registry digest.
     */
    signRegistration(request: Omit<TenantRegistryPayload, "rootSignerPubkey">): RegisterTenantParams {
        if (!isPlainObject(request)) throw new TypeError("request must be an object");
        const { lspNodeId, requestId, signedAtMs } = request;
        // Checked before the copy, which would read a number or a string as a length; the payload checks the rest.
        assertBytes("requestId", requestId, HASH256_LENGTH);
        const payload = { lspNodeId, rootSignerPubkey: this.#publicKey, requestId: new Uint8Array(requestId), signedAtMs };
        const digest = computeTenantRegistryDigest(payload);
        // As rust-secp256k1's `sign_ecdsa`: no prehash, RFC 6979 without extra entropy, low-S, compact.
        const signature = secp256k1.sign(digest, this.#secretKey, { prehash: false, lowS: true, extraEntropy: false, format: "compact" });
        assertBytes("signature", signature, COMPACT_ECDSA_SIGNATURE_LENGTH);
        return {
            rootSignerPubkey: this.#publicKey.slice(),
            requestId: payload.requestId.slice(),
            signedAtMs: payload.signedAtMs,
            signature,
        };
    }
}
