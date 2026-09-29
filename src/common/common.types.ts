import type { DEP_TYPES, SCRIPT_HASH_TYPES, SIGNER_ERROR_CODES, TLC_DIRECTIONS } from "./common.constants";

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

export type DepType = (typeof DEP_TYPES)[number];

export type CellDep = {
    outPoint: OutPoint;
    depType: DepType;
};

export type CellInput = {
    since: bigint;
    previousOutput: OutPoint;
};

export type CellOutput = {
    capacityShannons: bigint;
    lock: Script;
    type: Script | null;
};

/**
 * A CKB transaction without its hash.
 */
export type Transaction = {
    version: number;
    cellDeps: CellDep[];
    headerDeps: Uint8Array[];
    inputs: CellInput[];
    outputs: CellOutput[];
    outputsData: Uint8Array[];
    witnesses: Uint8Array[];
};

export type TlcDirection = (typeof TLC_DIRECTIONS)[number];

/**
 * The two hash locks fiber's TLCs support, encoded in the witness flag byte as `ckb-hash 0, sha256 1`.
 */
export type TlcHashAlgorithm = "ckb-hash" | "sha256";
