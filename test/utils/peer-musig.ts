import { bytesToHex } from "@noble/hashes/utils.js";
import { Session, nonceAggregate, nonceGen } from "@scure/btc-signer/musig2.js";
import type { FiberChannelKeys } from "../../src/derivation";
import { pubkeyOf } from "../../src/derivation";
import { decodeChannelSigningStatus } from "../../src/protocol";
import { computeSigningMessage, getPublicNonce } from "../../src/signer";
import type { WireField } from "../../src/wire";
import { withField } from "./with-field";

export type PeerHalf = {
    peerPublicNonce: Uint8Array;
    aggNonce: Uint8Array;
    peerPartialSignature: Uint8Array;
};

export function signPeerHalf(
    peerFundingKey: Uint8Array,
    session: { keyAggregation: Uint8Array[]; devicePublicNonce: Uint8Array; message: Uint8Array },
    randByte: number,
): PeerHalf {
    // Fiber's peer nonce cannot be regenerated here: its `SecNonceBuilder` omits the public key scure's `nonceGen` takes.
    const rand = new Uint8Array(32).fill(randByte);
    const nonces = nonceGen(pubkeyOf(peerFundingKey), peerFundingKey, undefined, undefined, undefined, rand);
    const aggNonce = nonceAggregate([session.devicePublicNonce, nonces.public]);
    const peerPartialSignature = new Session(aggNonce, session.keyAggregation, session.message).sign(nonces.secret, peerFundingKey);
    return { peerPublicNonce: nonces.public, aggNonce, peerPartialSignature };
}

export function resignPeerHalf(status: WireField, deviceKeys: FiberChannelKeys, peerFundingKey: Uint8Array, randByte: number): WireField {
    const request = decodeChannelSigningStatus(status);
    if (request.kind !== "required") throw new Error("the status asks for no signature");
    const half = signPeerHalf(
        peerFundingKey,
        {
            keyAggregation: request.keyAggregation,
            devicePublicNonce: getPublicNonce(deviceKeys, request.slot.commitmentNumber, request.slot.context),
            message: computeSigningMessage(request.content),
        },
        randByte,
    );
    let value = withField(status.value, "content.agg_nonce", `0x${bytesToHex(half.aggNonce)}`);
    value = withField(value, "session_evidence.peer_public_nonce", `0x${bytesToHex(half.peerPublicNonce)}`);
    if (request.evidence.peerPartialSignature !== null) {
        value = withField(value, "session_evidence.peer_partial_signature", `0x${bytesToHex(half.peerPartialSignature)}`);
    }
    return { value, path: status.path };
}
