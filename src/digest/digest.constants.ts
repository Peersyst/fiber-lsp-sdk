import { hexToBytes } from "@noble/hashes/utils.js";
import type { DepType, ScriptTemplate } from "../common";
import { BLAKE160_LENGTH, PAYMENT_HASH_LENGTH, TRUNCATED_PAYMENT_HASH_LENGTH, UINT64_MAX } from "../common";

/**
 * CKB cell capacities and fees are u64 shannons, unlike the u128 channel amounts.
 */
export const MAX_CAPACITY_SHANNONS = UINT64_MAX;

/**
 * Fee rates are shannons per 1000 bytes.
 */
export const FEE_RATE_WEIGHT_SCALE = 1000n;

/**
 * `XUDT_COMPATIBLE_WITNESS(16) || xonly_pubkey(32) || signature(64)`, zeroed in the fee mock.
 */
export const FUNDING_CELL_WITNESS_LENGTH = 112;

/**
 * Fiber's `CommitmentContractFeatures`: `fullPaymentHash` appends a feature byte to the lock args and binds each TLC's whole hash.
 */
export const COMMITMENT_LOCK_LAYOUTS = ["legacy", "fullPaymentHash"] as const;

export const COMMITMENT_LOCK_ARGS_LENGTHS = { legacy: 57, fullPaymentHash: 58 } as const satisfies Record<
    (typeof COMMITMENT_LOCK_LAYOUTS)[number],
    number
>;

/**
 * Key hash, delay and version: the revoked cell's args before the settlement hash.
 */
export const REVOCATION_LOCK_ARGS_LENGTH = 36;

export const COMMITMENT_LOCK_SETTLEMENT_HASH_OFFSET = REVOCATION_LOCK_ARGS_LENGTH;

export const COMMITMENT_LOCK_SETTLEMENT_FLAG_OFFSET = COMMITMENT_LOCK_SETTLEMENT_HASH_OFFSET + BLAKE160_LENGTH;

export const COMMITMENT_LOCK_SETTLEMENT_FLAGS = { commitment: 0x00, remainder: 0x01 } as const;

export const WITNESS_PAYMENT_HASH_LENGTHS = {
    legacy: TRUNCATED_PAYMENT_HASH_LENGTH,
    fullPaymentHash: PAYMENT_HASH_LENGTH,
} as const satisfies Record<(typeof COMMITMENT_LOCK_LAYOUTS)[number], number>;

/**
 * Fiber's `CommitmentContractFeatures::ONCHAIN_FULL_PAYMENT_HASH`, appended after the trailing zero.
 */
export const FULL_PAYMENT_HASH_FEATURE_BYTE = 0x01;

/**
 * The settlement witness counts its TLCs in a single byte.
 */
export const MAX_SETTLEMENT_TLCS = 255;

/**
 * Sanity bound: real fiber configs register a handful of cell deps.
 */
export const MAX_CELL_DEPS_COUNT = 255;

/**
 * A `since` keeps its high byte for flags; the payload is the low 56 bits.
 */
export const MAX_SINCE_PAYLOAD = (1n << 56n) - 1n;

export const SINCE_RELATIVE_EPOCH_FLAGS = 0xa000000000000000n;

export const SINCE_ABSOLUTE_TIMESTAMP_FLAG = 0x4000000000000000n;

/**
 * Fixvec items carry no offsets, so a wrong length is refused at encoding; the fee mock zeroes exactly these lengths.
 */
export const CELL_DEP_LENGTH = 37;

export const CELL_INPUT_LENGTH = 44;

export const DEP_TYPE_BYTES = { code: 0, dep_group: 1 } as const satisfies Record<DepType, number>;

/**
 * Not derivable from the chain: fiber ships it in its node config, so the device pins it instead of taking the node's.
 */
export const COMMITMENT_LOCK_MAINNET: ScriptTemplate = {
    codeHash: hexToBytes("2d45c4d3ed3e942f1945386ee82a5d1b7e4bb16d7fe1ab015421174ab747406c"),
    hashType: "type",
};

export const COMMITMENT_LOCK_TESTNET: ScriptTemplate = {
    codeHash: hexToBytes("740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc90b1a748438afcdf81d8"),
    hashType: "type",
};
