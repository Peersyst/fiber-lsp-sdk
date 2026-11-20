import {
    COMPACT_ECDSA_SIGNATURE_LENGTH,
    COMPRESSED_POINT_LENGTH,
    HASH256_LENGTH,
    UINT64_MAX,
    isCompressedPoint,
    isHexBytes,
} from "../common";
import type { WireField } from "../wire";
import {
    decodeBareHexBytes,
    decodeBoolean,
    decodeEnum,
    decodeNonEmptyString,
    decodeOrNull,
    decodeScriptOrNull,
    decodeString,
    decodeUintHex,
    encodeBareHexBytes,
    encodeHexBytes,
    encodeUintHex,
    malformedWireField,
    readArray,
    readObject,
    requireHexBytes,
} from "../wire";
import { RPC_TENANT_RUNTIME_STATUSES } from "./rpc.constants";
import type {
    LspNodeStatus,
    LspNodeStatusWire,
    LspTenantChannel,
    LspTenantChannelWire,
    LspTenantStatus,
    LspTenantStatusWire,
    RegisterTenantParams,
    RegisterTenantParamsWire,
    RegisterTenantResult,
    RegisterTenantResultWire,
} from "./rpc.types";

/**
 * Writes the params of `lsp_register_tenant`, the signature as bare hex, as fiber's own agent writes it.
 * @param params The root signer, the request id, the signing time, and the signature over the registry payload.
 * @returns The wire params.
 */
export function encodeRegisterTenantParams(params: RegisterTenantParams): RegisterTenantParamsWire {
    return {
        root_signer_pubkey: encodeBareHexBytes("rootSignerPubkey", params.rootSignerPubkey, COMPRESSED_POINT_LENGTH),
        request_id: encodeHexBytes("requestId", params.requestId, HASH256_LENGTH),
        signed_at: encodeUintHex("signedAtMs", params.signedAtMs, UINT64_MAX),
        signature: encodeBareHexBytes("signature", params.signature, COMPACT_ECDSA_SIGNATURE_LENGTH),
    };
}

/**
 * Reads the result of `lsp_register_tenant`.
 * @param field The result field.
 * @returns The tenant as registered and its access token.
 */
export function decodeRegisterTenantResult(field: WireField): RegisterTenantResult {
    const at = readObject<RegisterTenantResultWire>(field);
    return { tenant: decodeLspTenantStatus(at("tenant")), accessToken: decodeNonEmptyString(at("access_token")) };
}

/**
 * Reads the result of `lsp_get_status`.
 * @param field The result field.
 * @returns The node's public key, tenant store root and tenant counts.
 */
export function decodeLspNodeStatus(field: WireField): LspNodeStatus {
    const at = readObject<LspNodeStatusWire>(field);
    return {
        publicNodeId: decodeBarePoint(at("public_node_id")),
        tenantStoreRoot: decodeString(at("tenant_store_root")),
        registeredTenants: decodeUintHex(at("registered_tenants"), UINT64_MAX),
        activeTenants: decodeUintHex(at("active_tenants"), UINT64_MAX),
    };
}

/**
 * Reads a bare-hex public key, refusing bytes that are not a point.
 * @param field Field to read.
 * @returns The compressed point.
 */
function decodeBarePoint(field: WireField): Uint8Array {
    const key = decodeBareHexBytes(field, COMPRESSED_POINT_LENGTH);
    if (!isCompressedPoint(key)) malformedWireField(field, "must be a compressed point on secp256k1");
    return key;
}

/**
 * Reads a tenant's status.
 * @param field Field to read.
 * @returns The status.
 */
function decodeLspTenantStatus(field: WireField): LspTenantStatus {
    const at = readObject<LspTenantStatusWire>(field);
    return {
        tenantId: decodeTenantId(at("tenant_id")),
        rootSignerPubkey: decodeOrNull(at("root_signer_pubkey"), (key) => decodeBareHexBytes(key, COMPRESSED_POINT_LENGTH)),
        invoicePubkey: decodeBareHexBytes(at("invoice_pubkey"), COMPRESSED_POINT_LENGTH),
        channels: readArray(at("channels")).map(decodeLspTenantChannel),
        createdAtMs: decodeUintHex(at("created_at"), UINT64_MAX),
        runtimeStatus: decodeEnum(at("runtime_status"), RPC_TENANT_RUNTIME_STATUSES),
    };
}

/**
 * Reads one channel of a tenant's status.
 * @param field Field to read.
 * @returns The channel.
 */
function decodeLspTenantChannel(field: WireField): LspTenantChannel {
    const at = readObject<LspTenantChannelWire>(field);
    return {
        channelId: requireHexBytes(at("channel_id"), HASH256_LENGTH),
        fundingUdtTypeScript: decodeScriptOrNull(at("funding_udt_type_script")),
        online: decodeBoolean(at("online")),
    };
}

/**
 * Reads a tenant id: the bare hex of a 32-byte digest, kept as the string.
 * @param field Field to read.
 * @returns The id.
 */
function decodeTenantId(field: WireField): string {
    if (!isHexBytes(field.value, HASH256_LENGTH))
        malformedWireField(field, `must be ${HASH256_LENGTH} bytes of lowercase hex without a 0x prefix`);
    return field.value;
}
