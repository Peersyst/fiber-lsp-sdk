import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE } from "@noble/curves/utils.js";
import {
    COMPRESSED_POINT_LENGTH,
    HASH256_LENGTH,
    PARTIAL_SIGNATURE_LENGTH,
    PAYMENT_HASH_LENGTH,
    PUBLIC_NONCE_LENGTH,
    UINT64_MAX,
    UINT128_MAX,
    isAggregatedNonceHalf,
    isCompressedPoint,
    nonceHalves,
} from "../common";
import { MAX_COMMITMENT_NUMBER } from "../derivation";
import type { SigningSettlement, SigningSettlementTlc } from "../digest";
import { MAX_SETTLEMENT_TLCS, REVOCATION_LOCK_ARGS_LENGTH } from "../digest";
import type { NonceCounter, SignSlotRef } from "../policy";
import type { WireField } from "../wire";
import {
    WIRE_TLC_HASH_ALGORITHMS,
    WireError,
    asWireError,
    decodeAnyHexBytes,
    decodeBareHexBytes,
    decodeBoolean,
    decodeEnum,
    decodeHexBytes,
    decodeMapped,
    decodeMoleculeCellOutput,
    decodeOrNull,
    decodeTransaction,
    decodeUintHex,
    decodeUintHexNumber,
    encodeMapped,
    malformedWireField,
    readArray,
    readObject,
    readTagged,
} from "../wire";
import { decodeKeyAggContext } from "./key-agg-context";
import {
    CHANNEL_SIGNING_RULES,
    CHANNEL_SIGNING_STATUS_TYPES,
    CHANNEL_SIGNING_TRANSITIONS,
    COMMITMENT_COUNTERS,
    MAX_SIGNING_SLOT_NUMBER,
    NONCE_PURPOSE_CONTEXTS,
    SIGNABLE_CONTENT_KINDS,
} from "./protocol.constants";
import { ProtocolError } from "./protocol.error";
import type {
    ChannelSigningContent,
    ChannelSigningRule,
    ChannelSigningStatus,
    ChannelSigningStatusWire,
    ChannelSigningTransition,
    Musig2SigningContentWire,
    NonceSlotWire,
    SignableContentTypeWire,
    SignableContentWire,
    SigningSessionEvidence,
    SigningSessionEvidenceWire,
    SigningSettlementTlcWire,
    SigningSettlementWire,
} from "./protocol.types";

const SIGNABLE_CONTENT_TYPES = Object.keys(SIGNABLE_CONTENT_KINDS) as SignableContentTypeWire[];

const HALF_NAMES = ["first", "second"] as const;

const CURVE_ORDER = secp256k1.Point.Fn.ORDER;

/**
 * Reads the status of `get_channel_signing_status` as fiber writes it, each transition held to what it must carry.
 * @param field The `status` member of the result.
 * @returns No request, or the decoded request.
 */
export function decodeChannelSigningStatus(field: WireField): ChannelSigningStatus {
    try {
        return readChannelSigningStatus(field);
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
function readChannelSigningStatus(field: WireField): ChannelSigningStatus {
    const status = readTagged<ChannelSigningStatusWire>(field, CHANNEL_SIGNING_STATUS_TYPES);
    if (status.tag === "NoSignatureRequired") return { kind: "none" };
    const { at } = status;
    const requestId = decodeHexBytes(at("request_id"), HASH256_LENGTH);
    const transition = decodeEnum(at("transition"), CHANNEL_SIGNING_TRANSITIONS);
    const rule: ChannelSigningRule = CHANNEL_SIGNING_RULES[transition];
    const signing = readObject<Musig2SigningContentWire>(at("content"));
    return {
        kind: "required",
        requestId,
        transition,
        slot: decodeNonceSlot(signing("slot"), transition, rule),
        counter: decodeCounter(signing("commitment_counter"), transition, rule),
        keyAggregation: decodeKeyAggContext(signing("key_agg_ctx")),
        aggNonce: decodeAggNonce(signing("agg_nonce")),
        content: decodeSignableContent(signing("content"), transition, rule),
        evidence: decodeEvidence(at("session_evidence"), transition, rule),
        settlement: decodeSettlementOf(at("settlement"), transition, rule),
    };
}

/**
 * Reads the nonce slot, its purpose the transition's and its number one the device can sign at and publish the next of.
 * @param field The `slot` member.
 * @param transition The request's transition.
 * @param rule What the transition must carry.
 * @returns The slot, in the device's nonce context.
 */
function decodeNonceSlot(field: WireField, transition: ChannelSigningTransition, rule: ChannelSigningRule): SignSlotRef {
    const at = readObject<NonceSlotWire>(field);
    const purpose = at("purpose");
    const context = decodeMapped(purpose, NONCE_PURPOSE_CONTEXTS);
    if (context !== rule.context) {
        malformedWireField(purpose, `must be ${encodeMapped("context", rule.context, NONCE_PURPOSE_CONTEXTS)} for ${transition}`);
    }
    const number = at("commitment_number");
    const commitmentNumber = decodeUintHexNumber(number, MAX_SIGNING_SLOT_NUMBER);
    // The announcement nonce has a single slot, fiber's `validate_nonce_slot` (`fiber-lsp-sdk/src/signer.rs:1586`).
    if (context === "ANNOUNCEMENT" && commitmentNumber !== 0) malformedWireField(number, "must be 0 for a channel announcement");
    return { context, commitmentNumber };
}

/**
 * Reads the counter the slot's number came from, the transition's.
 * @param field The `commitment_counter` member.
 * @param transition The request's transition.
 * @param rule What the transition must carry.
 * @returns The counter, or `null` for the announcement.
 */
function decodeCounter(field: WireField, transition: ChannelSigningTransition, rule: ChannelSigningRule): NonceCounter | null {
    const counter = decodeOrNull(field, (value) => decodeMapped(value, COMMITMENT_COUNTERS));
    if (counter !== rule.counter) {
        const expected = rule.counter === null ? "null" : encodeMapped("counter", rule.counter, COMMITMENT_COUNTERS);
        malformedWireField(field, `must be ${expected} for ${transition}`);
    }
    return counter;
}

/**
 * Reads the aggregate nonce, musig2's `AggNonce`: two compressed points, either of them possibly at infinity.
 * @param field The `agg_nonce` member.
 * @returns The 66 bytes.
 */
function decodeAggNonce(field: WireField): Uint8Array {
    const bytes = decodeHexBytes(field, PUBLIC_NONCE_LENGTH);
    for (const [index, half] of nonceHalves(bytes).entries()) {
        if (!isAggregatedNonceHalf(half)) {
            malformedWireField(field, `must have its ${HALF_NAMES[index]} half on the curve or at infinity`);
        }
    }
    return bytes;
}

/**
 * Reads the plaintext the message is computed from, of the kind the transition signs.
 * @param field The inner `content` member.
 * @param transition The request's transition.
 * @param rule What the transition must carry.
 * @returns The typed content.
 */
function decodeSignableContent(field: WireField, transition: ChannelSigningTransition, rule: ChannelSigningRule): ChannelSigningContent {
    const content = readTagged<SignableContentWire>(field, SIGNABLE_CONTENT_TYPES);
    if (SIGNABLE_CONTENT_KINDS[content.tag] !== rule.contentKind) {
        const expected = encodeMapped("contentKind", rule.contentKind, SIGNABLE_CONTENT_KINDS);
        throw new WireError(`${field.path}.type`, `must be ${expected} for ${transition}`);
    }
    switch (content.tag) {
        case "CommitmentTransaction":
            return { kind: "commitmentTx", transaction: decodeTransaction(content.at("transaction")) };
        case "CooperativeCloseTransaction":
            return { kind: "closingTx", transaction: decodeTransaction(content.at("transaction")) };
        case "Revocation":
            return {
                kind: "revocation",
                output: decodeMoleculeCellOutput(content.at("output")),
                outputData: decodeAnyHexBytes(content.at("output_data")),
                commitmentLockArgs: decodeHexBytes(content.at("commitment_lock_script_args"), REVOCATION_LOCK_ARGS_LENGTH),
            };
        case "ChannelAnnouncement":
            return { kind: "announcement", unsignedAnnouncement: decodeAnyHexBytes(content.at("unsigned_announcement")) };
    }
}

/**
 * Reads the peer's half of the session, its partial signature exactly where the transition received one.
 * @param field The `session_evidence` member.
 * @param transition The request's transition.
 * @param rule What the transition must carry.
 * @returns The evidence.
 */
function decodeEvidence(field: WireField, transition: ChannelSigningTransition, rule: ChannelSigningRule): SigningSessionEvidence {
    const at = readObject<SigningSessionEvidenceWire>(field);
    const nonce = at("peer_public_nonce");
    const peerPublicNonce = decodeHexBytes(nonce, PUBLIC_NONCE_LENGTH);
    for (const [index, half] of nonceHalves(peerPublicNonce).entries()) {
        if (!isCompressedPoint(half)) malformedWireField(nonce, `must have its ${HALF_NAMES[index]} half on the curve`);
    }
    const signature = at("peer_partial_signature");
    if (!rule.peerPartialSignature) {
        if (signature.value !== null) malformedWireField(signature, `must be null for ${transition}`);
        return { peerPublicNonce, peerPartialSignature: null };
    }
    if (signature.value === null) malformedWireField(signature, `must be present for ${transition}`);
    const peerPartialSignature = decodeHexBytes(signature, PARTIAL_SIGNATURE_LENGTH);
    if (bytesToNumberBE(peerPartialSignature) >= CURVE_ORDER) malformedWireField(signature, "must be a scalar below the curve order");
    return { peerPublicNonce, peerPartialSignature };
}

/**
 * Reads the settlement member, present exactly on the commitment transitions and stating which view it builds.
 * @param field The `settlement` member; fiber reads an absent one as `null`.
 * @param transition The request's transition.
 * @param rule What the transition must carry.
 * @returns The settlement, or `null` where the transition carries none.
 */
function decodeSettlementOf(field: WireField, transition: ChannelSigningTransition, rule: ChannelSigningRule): SigningSettlement | null {
    const absent = field.value === undefined || field.value === null;
    if (rule.settlementForRemote === null) {
        if (!absent) malformedWireField(field, `must be null for ${transition}`);
        return null;
    }
    if (absent) malformedWireField(field, `must be present for ${transition}`);
    return decodeSettlement(field, transition, rule.settlementForRemote);
}

/**
 * Reads fiber's `SigningSettlement`, the public snapshot behind a commitment, in the order of the wire.
 * @param field The settlement.
 * @param transition The request's transition.
 * @param forRemote The view the transition's settlement must build.
 * @returns The snapshot, untrusted until the commitment rebuilt from it matches the transaction.
 */
function decodeSettlement(field: WireField, transition: ChannelSigningTransition, forRemote: boolean): SigningSettlement {
    const at = readObject<SigningSettlementWire>(field);
    const localAmountShannons = decodeUintHex(at("local_amount"), UINT128_MAX);
    const remoteAmountShannons = decodeUintHex(at("remote_amount"), UINT128_MAX);
    const localSettlementPubkey = decodePubkey(at("local_settlement_pubkey"));
    const remoteSettlementPubkey = decodePubkey(at("remote_settlement_pubkey"));
    const view = at("for_remote");
    if (decodeBoolean(view) !== forRemote) malformedWireField(view, `must be ${forRemote} for ${transition}`);
    const tlcs = at("tlcs");
    const items = readArray(tlcs);
    if (items.length > MAX_SETTLEMENT_TLCS) malformedWireField(tlcs, `must have at most ${MAX_SETTLEMENT_TLCS} items`);
    return {
        localAmountShannons,
        remoteAmountShannons,
        localSettlementPubkey,
        remoteSettlementPubkey,
        forRemote,
        tlcs: items.map(decodeSettlementTlc),
    };
}

/**
 * Reads one TLC of the settlement, in the order of the wire.
 * @param field The TLC.
 * @returns The TLC, its direction read from fiber's `inbound`.
 */
function decodeSettlementTlc(field: WireField): SigningSettlementTlc {
    const at = readObject<SigningSettlementTlcWire>(field);
    const tlcId = decodeUintHexNumber(at("tlc_id"), Number.MAX_SAFE_INTEGER);
    const localKeyCommitmentNumber = decodeUintHexNumber(at("local_key_commitment_number"), MAX_COMMITMENT_NUMBER);
    const direction = decodeBoolean(at("inbound")) ? "received" : "offered";
    const paymentHash = decodeHexBytes(at("payment_hash"), PAYMENT_HASH_LENGTH);
    const amountShannons = decodeUintHex(at("payment_amount"), UINT128_MAX);
    const hashAlgorithm = decodeMapped(at("hash_algorithm"), WIRE_TLC_HASH_ALGORITHMS);
    const expiryMs = decodeUintHex(at("expiry"), UINT64_MAX);
    const localKeyPubkey = decodePubkey(at("local_key_pubkey"));
    const remoteTlcPubkey = decodePubkey(at("remote_key"));
    return {
        tlcId,
        direction,
        hashAlgorithm,
        amountShannons,
        paymentHash,
        expiryMs,
        localKeyCommitmentNumber,
        localKeyPubkey,
        remoteTlcPubkey,
    };
}

/**
 * Reads fiber's `Pubkey`: a compressed point in hex without the `0x` prefix.
 * @param field Field to read.
 * @returns The 33 bytes, a point on the curve.
 */
function decodePubkey(field: WireField): Uint8Array {
    const key = decodeBareHexBytes(field, COMPRESSED_POINT_LENGTH);
    if (!isCompressedPoint(key)) malformedWireField(field, "must be a compressed point on the curve");
    return key;
}
