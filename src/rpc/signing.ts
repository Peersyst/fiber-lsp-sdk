import {
    COMPRESSED_POINT_LENGTH,
    HASH256_LENGTH,
    PARTIAL_SIGNATURE_LENGTH,
    PUBLIC_NONCE_LENGTH,
    RECOVERABLE_ECDSA_SIGNATURE_LENGTH,
    isPlainObject,
} from "../common";
import type { WireField } from "../wire";
import { assertWireHexBytes, decodeEnum, encodeBareHexBytes, encodeHexBytes, readObject, requireHexBytes } from "../wire";
import { RPC_SUBMISSION_RESULTS } from "./rpc.constants";
import type {
    NextChannelSignerMaterial,
    NextChannelSignerMaterialWire,
    RpcSigningStatusResult,
    RpcSigningStatusResultWire,
    RpcSubmissionResult,
    RpcSubmissionResultWire,
    SubmitChannelSignatureParams,
    SubmitChannelSignatureParamsWire,
    SubmitWatchtowerSignatureParams,
    SubmitWatchtowerSignatureParamsWire,
} from "./rpc.types";

/**
 * Reads the result of `get_channel_signing_status` and of `get_watchtower_signing_status`, the status left to its decoder.
 * @param field The result field.
 * @returns The channel id and the status as the field it arrived in.
 */
export function decodeRpcSigningStatusResult(field: WireField): RpcSigningStatusResult {
    const at = readObject<RpcSigningStatusResultWire>(field);
    return { channelId: requireHexBytes(at("channel_id"), HASH256_LENGTH), status: at("status") };
}

/**
 * Writes the params of `submit_channel_signature`, the next material left out when there is none.
 * @param params The request answered, the partial signature, and the next material or `null`.
 * @returns The wire params.
 */
export function encodeSubmitChannelSignatureParams(params: SubmitChannelSignatureParams): SubmitChannelSignatureParamsWire {
    const { nextMaterial } = params;
    assertWireHexBytes("channelId", params.channelId, HASH256_LENGTH);
    return {
        channel_id: params.channelId,
        request_id: encodeHexBytes("requestId", params.requestId, HASH256_LENGTH),
        partial_signature: encodeHexBytes("partialSignature", params.partialSignature, PARTIAL_SIGNATURE_LENGTH),
        ...(nextMaterial === null ? {} : { next_material: encodeNextChannelSignerMaterial(nextMaterial) }),
    };
}

/**
 * Writes the next-round material sent with a channel signature, its three members always present.
 * @param material The material.
 * @returns The wire material.
 */
function encodeNextChannelSignerMaterial(material: NextChannelSignerMaterial): NextChannelSignerMaterialWire {
    const name = "nextMaterial";
    if (!isPlainObject(material)) throw new TypeError(`${name} must be an object or null`);
    return {
        next_commitment_point: encodeBareHexBytes(`${name}.nextCommitmentPoint`, material.nextCommitmentPoint, COMPRESSED_POINT_LENGTH),
        next_commitment_nonce: encodeHexBytes(`${name}.nextCommitmentNonce`, material.nextCommitmentNonce, PUBLIC_NONCE_LENGTH),
        next_revocation_nonce: encodeHexBytes(`${name}.nextRevocationNonce`, material.nextRevocationNonce, PUBLIC_NONCE_LENGTH),
    };
}

/**
 * Writes the params of `submit_watchtower_signature`.
 * @param params The request answered and the recoverable signature.
 * @returns The wire params.
 */
export function encodeSubmitWatchtowerSignatureParams(params: SubmitWatchtowerSignatureParams): SubmitWatchtowerSignatureParamsWire {
    assertWireHexBytes("channelId", params.channelId, HASH256_LENGTH);
    return {
        channel_id: params.channelId,
        request_id: encodeHexBytes("requestId", params.requestId, HASH256_LENGTH),
        signature: encodeHexBytes("signature", params.signature, RECOVERABLE_ECDSA_SIGNATURE_LENGTH),
    };
}

/**
 * Reads the result of `submit_channel_signature` and of `submit_watchtower_signature`.
 * @param field The result field.
 * @returns `Applied`, or `AlreadyApplied` for a signature the node already had.
 */
export function decodeRpcSubmissionResult(field: WireField): RpcSubmissionResult {
    return decodeEnum(readObject<RpcSubmissionResultWire>(field)("type"), RPC_SUBMISSION_RESULTS);
}
