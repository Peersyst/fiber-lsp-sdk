import type { SIGNER_ERROR_CODES } from "./protocol.constants.js";

export type SignerErrorCode = (typeof SIGNER_ERROR_CODES)[number];
