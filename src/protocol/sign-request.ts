import type { ScriptTemplate } from "../common";
import { COMPRESSED_POINT_LENGTH, PARTIAL_SIGNATURE_LENGTH, PUBLIC_NONCE_LENGTH, SIGNER_ERROR_CODES, assertBytes } from "../common";
import { MAX_COMMITMENT_NUMBER, SECRET_KEY_LENGTH } from "../derivation";
import type { PolicySignRequest, SignOperation, SignSession } from "../policy";
import type { Field, FieldReader } from "../wire";
import { WireError, decodeEnum, decodeUintHexNumber, encodeHexBytes, readObject, requireObject } from "../wire";
import { decodeChannelAnnouncement, decodeCommitmentTx, decodeRevocation, decodeShutdownTx, decodeSignSession } from "./operation-params";
import { SIGNER_METHODS } from "./protocol.constants";
import { ProtocolError } from "./protocol.error";
import type {
    CommitmentNumberParamsWire,
    OutboundFrame,
    PartialSignChannelAnnouncementParamsWire,
    PartialSignClosingTxParamsWire,
    PartialSignCommitmentTxParamsWire,
    PartialSignParamsWire,
    PartialSignRevocationParamsWire,
    SignError,
    SignParams,
    SignRequest,
    SignRequestWire,
    SignResponseWire,
    SignResult,
    SignResultWire,
} from "./protocol.types";
import { assertRequestId, decodeChannelId, decodeRequestId } from "./utils";

const PARAMS_PATH = `${"sign_request" satisfies SignRequestWire["type"]}.${"params" satisfies keyof SignRequestWire}`;

const ERROR_CODES: readonly string[] = SIGNER_ERROR_CODES;

/**
 * Reads a `sign_request` frame's envelope, leaving its params to `decodeSignParams`.
 * @param field The frame, already known to be a sign request.
 * @returns The envelope; a refusal past the request id carries that id, so it can be answered.
 */
export function decodeSignRequest(field: Field): SignRequest {
    const at = readObject<SignRequestWire>(field);
    const requestId = decodeRequestId(at("request_id"));
    return correlating(requestId, () => ({
        requestId,
        channelId: decodeChannelId(at("channel_id")),
        method: decodeEnum(at("method"), SIGNER_METHODS),
        params: requireObject(at("params")),
        stateVersion: decodeUintHexNumber(at("state_version"), Number.MAX_SAFE_INTEGER),
    }));
}

/**
 * Reads a sign request's params for its method: a signing method decodes to exactly the policy engine's input.
 * @param request The envelope, as `decodeSignRequest` returned it.
 * @param commitmentLock The network's commitment lock template, which the digest inputs take from the device.
 * @returns The decoded params; a refusal carries the request id.
 */
export function decodeSignParams(request: SignRequest, commitmentLock: ScriptTemplate): SignParams {
    const params: Field = { value: request.params, path: PARAMS_PATH };
    return correlating(request.requestId, () => {
        switch (request.method) {
            case "get_base_public_keys":
            case "get_channel_announcement_pub_nonce":
                return { method: request.method };
            case "get_commitment_point":
            case "get_commitment_pub_nonce":
            case "get_revocation_pub_nonce":
            case "get_settlement_keys": {
                const at = readObject<CommitmentNumberParamsWire>(params);
                return { method: request.method, commitmentNumber: decodeUintHexNumber(at("commitment_number"), MAX_COMMITMENT_NUMBER) };
            }
            case "partial_sign_commitment_tx": {
                const at = readObject<PartialSignCommitmentTxParamsWire>(params);
                const operation: SignOperation = { kind: "commitment_tx", input: decodeCommitmentTx(at("commitment_tx"), commitmentLock) };
                return { method: request.method, request: decodeSlotRequest(request, at, operation) };
            }
            case "partial_sign_closing_tx": {
                const at = readObject<PartialSignClosingTxParamsWire>(params);
                const operation: SignOperation = { kind: "shutdown_tx", input: decodeShutdownTx(at("shutdown_tx")) };
                return { method: request.method, request: decodeSlotRequest(request, at, operation) };
            }
            case "partial_sign_revocation": {
                const at = readObject<PartialSignRevocationParamsWire>(params);
                const operation: SignOperation = { kind: "revocation", input: decodeRevocation(at("revocation"), commitmentLock) };
                return { method: request.method, request: decodeSlotRequest(request, at, operation) };
            }
            case "partial_sign_channel_announcement": {
                const at = readObject<PartialSignChannelAnnouncementParamsWire>(params);
                const operation: SignOperation = {
                    kind: "channel_announcement",
                    input: decodeChannelAnnouncement(at("channel_announcement")),
                };
                const session = decodeSignSession(at("session"));
                return { method: request.method, request: policyRequest(request, session, undefined, operation) };
            }
        }
    });
}

/**
 * Writes a `sign_response` frame.
 * @param frame The response, a result or a refusal.
 * @returns The wire object.
 */
export function encodeSignResponse(frame: Extract<OutboundFrame, { type: "sign_response" }>): SignResponseWire {
    assertRequestId(frame.requestId);
    if ("error" in frame) return { type: "sign_response", request_id: frame.requestId, error: encodeSignError(frame.error) };
    return { type: "sign_response", request_id: frame.requestId, result: encodeSignResult(frame.result) };
}

/**
 * Reads the session and nonce number of a signing request that claims a per-commitment slot.
 * @param request The envelope.
 * @param at Reader of the params.
 * @param operation The decoded operation.
 * @returns The policy engine's input.
 */
function decodeSlotRequest(request: SignRequest, at: FieldReader<PartialSignParamsWire>, operation: SignOperation): PolicySignRequest {
    const session = decodeSignSession(at("session"));
    const nonceCommitmentNumber = decodeUintHexNumber(at("nonce_commitment_number"), MAX_COMMITMENT_NUMBER);
    return policyRequest(request, session, nonceCommitmentNumber, operation);
}

/**
 * Assembles the policy engine's input from the envelope and the decoded params.
 * @param request The envelope.
 * @param session The musig2 session.
 * @param nonceCommitmentNumber The number the nonce slot is keyed by, absent when the operation's slot is fixed.
 * @param operation The decoded operation.
 * @returns The policy engine's input.
 */
function policyRequest(
    request: SignRequest,
    session: SignSession,
    nonceCommitmentNumber: number | undefined,
    operation: SignOperation,
): PolicySignRequest {
    return { channelId: request.channelId, stateVersion: request.stateVersion, nonceCommitmentNumber, session, operation };
}

/**
 * Writes a result in the shape its method answers with, checking the wire sizes on the way out.
 * @param result The result to write.
 * @returns The wire object.
 */
function encodeSignResult(result: SignResult): SignResultWire {
    switch (result.kind) {
        case "base_public_keys":
            assertBytes("fundingPubkey", result.fundingPubkey, COMPRESSED_POINT_LENGTH);
            assertBytes("tlcBasePubkey", result.tlcBasePubkey, COMPRESSED_POINT_LENGTH);
            return { funding_pubkey: encodeHexBytes(result.fundingPubkey), tlc_base_pubkey: encodeHexBytes(result.tlcBasePubkey) };
        case "commitment_point":
            assertBytes("commitmentPoint", result.commitmentPoint, COMPRESSED_POINT_LENGTH);
            return { commitment_point: encodeHexBytes(result.commitmentPoint) };
        case "pub_nonce":
            assertBytes("pubNonce", result.pubNonce, PUBLIC_NONCE_LENGTH);
            return { pub_nonce: encodeHexBytes(result.pubNonce) };
        case "settlement_keys":
            assertBytes("localSettlementKey", result.localSettlementKey, SECRET_KEY_LENGTH);
            assertBytes("tlcKey", result.tlcKey, SECRET_KEY_LENGTH);
            return { local_settlement_key: encodeHexBytes(result.localSettlementKey), tlc_key: encodeHexBytes(result.tlcKey) };
        case "partial_signature":
            assertBytes("partialSignature", result.partialSignature, PARTIAL_SIGNATURE_LENGTH);
            return { partial_signature: encodeHexBytes(result.partialSignature) };
    }
}

/**
 * Writes a refusal as exactly its code and message, whatever object carries them.
 * @param error The refusal to write.
 * @returns The wire object.
 */
function encodeSignError(error: SignError): SignError {
    if (!ERROR_CODES.includes(error.code)) throw new TypeError(`error.code must be one of ${SIGNER_ERROR_CODES.join(", ")}`);
    return { code: error.code, message: error.message };
}

/**
 * Runs a decode step of a sign request whose id is known, so a refusal in it is one the device can answer.
 * @param requestId Id of the sign request.
 * @param step Step to run.
 * @returns Whatever the step returned.
 */
function correlating<T>(requestId: string, step: () => T): T {
    try {
        return step();
    } catch (error) {
        if (error instanceof WireError) throw new ProtocolError(error.path, error.reason, requestId);
        throw error;
    }
}
