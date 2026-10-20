import { equalBytes } from "@noble/curves/utils.js";
import { COMPRESSED_POINT_LENGTH, MUSIG_PARTICIPANTS, UINT32_LENGTH, isCompressedPoint } from "../common";
import type { WireField } from "../wire";
import { decodeAnyHexBytes, malformedWireField } from "../wire";

// Bit 0 negates the aggregate's parity and bit 1 announces a tweak: fiber aggregates two untweaked keys, so neither is set.
const KEY_AGG_CONTEXT_HEADER = 0x00;

const HEADER_LENGTH = 1;

const KEY_AGG_CONTEXT_LENGTH = HEADER_LENGTH + UINT32_LENGTH + MUSIG_PARTICIPANTS * COMPRESSED_POINT_LENGTH;

/**
 * Reads musig2 0.2.4's `KeyAggContext::to_bytes` exactly as fiber writes it for a channel: two untweaked, distinct keys.
 * @param field Field to read, `0x`-prefixed hex.
 * @returns The two compressed keys, in the order they were aggregated.
 */
export function decodeKeyAggContext(field: WireField): [Uint8Array, Uint8Array] {
    const bytes = decodeAnyHexBytes(field);
    if (bytes.length !== KEY_AGG_CONTEXT_LENGTH) malformedWireField(field, `must be ${KEY_AGG_CONTEXT_LENGTH} bytes`);
    if (bytes[0] !== KEY_AGG_CONTEXT_HEADER) malformedWireField(field, "must have the header byte 0x00: no parity flag, no tweak");
    const count = new DataView(bytes.buffer, bytes.byteOffset + HEADER_LENGTH, UINT32_LENGTH).getUint32(0, false);
    if (count !== MUSIG_PARTICIPANTS) malformedWireField(field, `must count exactly ${MUSIG_PARTICIPANTS} keys`);
    const keysStart = HEADER_LENGTH + UINT32_LENGTH;
    const first = bytes.slice(keysStart, keysStart + COMPRESSED_POINT_LENGTH);
    const second = bytes.slice(keysStart + COMPRESSED_POINT_LENGTH);
    if (!isCompressedPoint(first)) malformedWireField(field, "must have a first key on the curve");
    if (!isCompressedPoint(second)) malformedWireField(field, "must have a second key on the curve");
    if (equalBytes(first, second)) malformedWireField(field, "must aggregate two distinct keys");
    return [first, second];
}
