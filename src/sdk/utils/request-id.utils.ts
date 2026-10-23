import { HASH256_LENGTH } from "../../common";
import { encodeHexBytes } from "../../wire";

/**
 * Writes a signing request's id as the `SIGNING` and `WATCHTOWER_SIGNING` events carry it.
 * @param requestId The request id.
 * @returns The wire hex.
 */
export function encodeSdkRequestId(requestId: Uint8Array): string {
    return encodeHexBytes("requestId", requestId, HASH256_LENGTH);
}
