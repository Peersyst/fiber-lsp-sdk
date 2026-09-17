import type { NonceContext } from "../derivation";
import type { SignSession } from "../policy";

/**
 * One partial-signature request over an already-computed 32-byte digest.
 */
export type PartialSignRequest = SignSession & {
    commitmentNumber: number;
    context: NonceContext;
};
