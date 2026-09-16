import type { SCRIPT_HASH_TYPES, SIGNER_ERROR_CODES, TLC_DIRECTIONS } from "./common.constants";

export type SignerErrorCode = (typeof SIGNER_ERROR_CODES)[number];

export type ScriptHashType = (typeof SCRIPT_HASH_TYPES)[number];

export type Script = {
    codeHash: Uint8Array;
    hashType: ScriptHashType;
    args: Uint8Array;
};

/**
 * A script minus its args: what the device pins per network for locks whose args it computes itself.
 */
export type ScriptTemplate = {
    codeHash: Uint8Array;
    hashType: ScriptHashType;
};

export type OutPoint = {
    txHash: Uint8Array;
    index: number;
};

export type TlcDirection = (typeof TLC_DIRECTIONS)[number];

/**
 * The two hash locks fiber's TLCs support, encoded in the witness flag byte as `ckb-hash 0, sha256 1`.
 */
export type TlcHashAlgorithm = "ckb-hash" | "sha256";
