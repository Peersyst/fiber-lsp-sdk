import { UINT64_MAX } from "../common";
import type { SigningSettlementTlc } from "../digest";

// CKB's `EpochNumberWithFraction` layout: the number in bits 0-23, the index in 24-39, the length in 40-55.
const EPOCH_NUMBER_MASK = 0xffffffn;
const EPOCH_INDEX_OFFSET = 24n;
const EPOCH_LENGTH_OFFSET = 40n;
const EPOCH_FRACTION_MASK = 0xffffn;

// Where Rust's `f64 as u64` saturates; a power of two, so exact in an f64.
const U64_SATURATION = 2 ** 64;

/**
 * Port of fiber's `tlc_expiry_delay`: two thirds of the commitment delay, in milliseconds.
 * @param commitmentDelayEpoch The delay's full `EpochNumberWithFraction` value.
 * @param millisecondsPerEpoch Fiber's `MILLI_SECONDS_PER_EPOCH`.
 * @returns The delay, in fiber's f64 arithmetic and its `as u64` cast.
 */
export function tlcExpiryDelay(commitmentDelayEpoch: bigint, millisecondsPerEpoch: number): bigint {
    const { number, index, length } = readEpochFraction(commitmentDelayEpoch);
    return castF64ToU64(((number + index / length) * millisecondsPerEpoch * 2) / 3);
}

/**
 * Port of fiber's `pending_tlc_signature_deadline`: from then on, fiber force-closes a channel still awaiting a signature.
 * @param tlcs The TLCs a commitment lists, where fiber counts every TLC not confirmed removed.
 * @param commitmentDelayEpoch The channel's delay, its full `EpochNumberWithFraction` value.
 * @param millisecondsPerEpoch Fiber's `MILLI_SECONDS_PER_EPOCH`.
 * @returns The earliest expiry less the delay's two thirds, in ms since the epoch, or `null` with no TLC.
 */
export function pendingTlcSignatureDeadline(
    tlcs: readonly Pick<SigningSettlementTlc, "expiryMs">[],
    commitmentDelayEpoch: bigint,
    millisecondsPerEpoch: number,
): bigint | null {
    const reserve = tlcExpiryDelay(commitmentDelayEpoch, millisecondsPerEpoch);
    let deadline: bigint | null = null;
    for (const { expiryMs } of tlcs) {
        const candidate = expiryMs > reserve ? expiryMs - reserve : 0n;
        if (deadline === null || candidate < deadline) deadline = candidate;
    }
    return deadline;
}

/**
 * Port of CKB's `EpochNumberWithFraction::from_full_value`, which rewrites a zero length to the fraction 0/1.
 * @param value The full value.
 * @returns The number, the index and the length, as the f64s fiber casts them to.
 */
function readEpochFraction(value: bigint): { number: number; index: number; length: number } {
    const number = Number(value & EPOCH_NUMBER_MASK);
    const length = Number((value >> EPOCH_LENGTH_OFFSET) & EPOCH_FRACTION_MASK);
    if (length === 0) return { number, index: 0, length: 1 };
    return { number, index: Number((value >> EPOCH_INDEX_OFFSET) & EPOCH_FRACTION_MASK), length };
}

/**
 * Casts as Rust's `f64 as u64` does: truncated, NaN and below zero to 0, from 2^64 up to `u64::MAX`.
 * @param value The f64.
 * @returns The u64.
 */
function castF64ToU64(value: number): bigint {
    if (Number.isNaN(value) || value <= 0) return 0n;
    if (value >= U64_SATURATION) return UINT64_MAX;
    return BigInt(Math.trunc(value));
}
