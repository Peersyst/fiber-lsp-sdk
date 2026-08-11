import { hexToBytes } from "@noble/hashes/utils.js";
import type { ScriptTemplate } from "./digest.types";

/**
 * CKB cell capacities and fees are u64 shannons, unlike the u128 channel amounts.
 */
export const MAX_CAPACITY_SHANNONS = (1n << 64n) - 1n;

/**
 * Fee rates are shannons per 1000 bytes of transaction; this is fiber's `FEE_RATE_WEIGHT_SCALE`.
 */
export const FEE_RATE_WEIGHT_SCALE = 1000n;

/**
 * The funding-cell witness is `XUDT_COMPATIBLE_WITNESS(16) || xonly_pubkey(32) || signature(64)`; fee sizing mocks it with zeros.
 */
export const FUNDING_CELL_WITNESS_LENGTH = 112;

/**
 * The commitment lock args: 20-byte key hash, 8-byte delay, 8-byte version, 20-byte settlement hash, one trailing zero byte.
 */
export const COMMITMENT_LOCK_ARGS_LENGTH = 57;

/**
 * The settlement witness counts its TLCs in a single byte.
 */
export const MAX_SETTLEMENT_TLCS = 255;

/**
 * Sanity bound on the cell-dep count that enters fee sizing: real fiber configs register a handful, never dozens.
 */
export const MAX_CELL_DEPS_COUNT = 255;

/**
 * A `since` value keeps its high byte for flags: the payload, delay epoch or expiry seconds alike, is the low 56 bits.
 */
export const MAX_SINCE_PAYLOAD = (1n << 56n) - 1n;

/**
 * `since` flag bits for a relative epoch-with-fraction delay, the commitment lock's.
 */
export const SINCE_RELATIVE_EPOCH_FLAGS = 0xa000000000000000n;

/**
 * `since` flag bit for an absolute timestamp bound, the TLC expiry's.
 */
export const SINCE_ABSOLUTE_TIMESTAMP_FLAG = 0x4000000000000000n;

/**
 * Serialized sizes of the fixed-size molecule structs: fixvec items carry no offsets, so a wrong length must be refused
 * at encoding time, and fee sizing mocks these structs as zeroed bytes of exactly these lengths.
 */
export const CELL_DEP_LENGTH = 37;

export const CELL_INPUT_LENGTH = 44;

/**
 * On mainnet and testnet the commitment lock is not derivable from the chain: fiber ships it in its node config, so the
 * device pins the same values and never accepts them from the node (the code hash decides which script guards the funds
 * after a force close). Dev chains pass their own template instead.
 */
export const COMMITMENT_LOCK_MAINNET: ScriptTemplate = {
    codeHash: hexToBytes("2d45c4d3ed3e942f1945386ee82a5d1b7e4bb16d7fe1ab015421174ab747406c"),
    hashType: "type",
};

export const COMMITMENT_LOCK_TESTNET: ScriptTemplate = {
    codeHash: hexToBytes("740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc90b1a748438afcdf81d8"),
    hashType: "type",
};
