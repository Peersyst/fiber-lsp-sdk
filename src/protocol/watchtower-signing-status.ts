import { HASH256_LENGTH } from "../common";
import { MAX_COMMITMENT_NUMBER } from "../derivation";
import type { WatchtowerKeyPurpose } from "../policy";
import type { WireField } from "../wire";
import { asWireError, decodeHexBytes, decodeTransaction, decodeUintHexNumber, readObject, readTagged } from "../wire";
import { ONCHAIN_KEY_PURPOSE_TYPES, SIGNING_STATUS_TYPES } from "./protocol.constants";
import { ProtocolError } from "./protocol.error";
import type {
    OnchainKeyPurposeWire,
    OnchainSigningContentWire,
    WatchtowerSigningStatus,
    WatchtowerSigningStatusWire,
} from "./protocol.types";

/**
 * Reads the status of `get_watchtower_signing_status` as fiber writes it.
 * @param field The `status` member of the result.
 * @returns No request, or the decoded request.
 */
export function decodeWatchtowerSigningStatus(field: WireField): WatchtowerSigningStatus {
    try {
        return readWatchtowerSigningStatus(field);
    } catch (error) {
        const { path, reason } = asWireError(error);
        throw new ProtocolError(path, reason);
    }
}

/**
 * Reads the status, refusing with wire errors the entry point turns into protocol ones.
 * @param field The status.
 * @returns The status.
 */
function readWatchtowerSigningStatus(field: WireField): WatchtowerSigningStatus {
    const status = readTagged<WatchtowerSigningStatusWire>(field, SIGNING_STATUS_TYPES);
    if (status.tag === "NoSignatureRequired") return { kind: "none" };
    const requestId = decodeHexBytes(status.at("request_id"), HASH256_LENGTH);
    const content = readObject<OnchainSigningContentWire>(status.at("content"));
    return {
        kind: "required",
        requestId,
        purpose: decodeKeyPurpose(content("key_purpose")),
        transaction: decodeTransaction(content("transaction")),
    };
}

/**
 * Reads fiber's `OnchainKeyPurpose`, the key the spend's unlock needs.
 * @param field The `key_purpose` member.
 * @returns The purpose.
 */
function decodeKeyPurpose(field: WireField): WatchtowerKeyPurpose {
    const purpose = readTagged<OnchainKeyPurposeWire>(field, ONCHAIN_KEY_PURPOSE_TYPES);
    if (purpose.tag === "Settlement") return { kind: "settlement" };
    return { kind: "tlc", commitmentNumber: decodeUintHexNumber(purpose.at("commitment_number"), MAX_COMMITMENT_NUMBER) };
}
