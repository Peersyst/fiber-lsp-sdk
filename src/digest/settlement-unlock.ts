import { equalBytes } from "@noble/curves/utils.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import type { TlcDirection } from "../common";
import {
    BLAKE160_LENGTH,
    PREIMAGE_LENGTH,
    RECOVERABLE_ECDSA_SIGNATURE_LENGTH,
    TLC_HASH_ALGORITHM_BYTES,
    UINT128_LENGTH,
    UINT64_LENGTH,
    assertAnyBytes,
    assertBoolean,
    assertBytes,
    assertOneOf,
    blake160,
    isUnsignedInteger,
    readUintLe,
    uint128Le,
} from "../common";
import { readCommitmentLockLayout } from "./commitment-tx";
import {
    COMMITMENT_LOCK_ARGS_LENGTHS,
    COMMITMENT_LOCK_LAYOUTS,
    COMMITMENT_LOCK_SETTLEMENT_FLAGS,
    COMMITMENT_LOCK_SETTLEMENT_HASH_OFFSET,
    WITNESS_PAYMENT_HASH_LENGTHS,
} from "./digest.constants";
import type {
    CommitmentLockLayout,
    SettlementBalance,
    SettlementBody,
    SettlementTlcEntry,
    SettlementUnlock,
    SettlementUnlockTarget,
} from "./digest.types";

// Fiber's `XUDT_COMPATIBLE_WITNESS`, an empty molecule `WitnessArgs`.
const XUDT_COMPATIBLE_WITNESS = Uint8Array.of(16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0);

// Fiber's watchtower spends one unlock per tx.
const SETTLEMENT_UNLOCK_COUNT = 1;

const BODY_OFFSET = XUDT_COMPATIBLE_WITNESS.length + 1;

const BALANCE_LENGTH = BLAKE160_LENGTH + UINT128_LENGTH;

// Flag, amount, two key hashes and since; the payment hash adds its layout's length.
const TLC_ENTRY_FIXED_LENGTH = 1 + UINT128_LENGTH + 2 * BLAKE160_LENGTH + UINT64_LENGTH;

// The direction bit under the highest hash algorithm byte.
const MAX_TLC_FLAG = (Math.max(...Object.values(TLC_HASH_ALGORITHM_BYTES)) << 1) | 1;

// The unlock type and the preimage flag, then the recoverable signature.
const UNLOCK_LENGTH = 2 + RECOVERABLE_ECDSA_SIGNATURE_LENGTH;

const UNLOCK_WITH_PREIMAGE_LENGTH = UNLOCK_LENGTH + PREIMAGE_LENGTH;

// Fiber's commitment lock settles the first balance on 0xfe and the second on 0xff, so a TLC index stays below both.
const BALANCE_UNLOCK_TYPES = [0xfe, 0xff] as const;

/**
 * Reads the witness fiber's watchtower spends a commitment cell with.
 * @param witness The spend's witness 0.
 * @param layout The spent cell's lock layout.
 * @returns The body, split, and the unlock.
 */
export function readSettlementUnlock(witness: Uint8Array, layout: CommitmentLockLayout): SettlementUnlock {
    assertAnyBytes("settlement witness", witness);
    assertOneOf("layout", layout, COMMITMENT_LOCK_LAYOUTS);
    const prefixLength = XUDT_COMPATIBLE_WITNESS.length;
    if (!equalBytes(witness.subarray(0, prefixLength), XUDT_COMPATIBLE_WITNESS)) {
        throw new TypeError(`settlement witness must start with the ${prefixLength}-byte XUDT-compatible prefix`);
    }
    if (witness[prefixLength] !== SETTLEMENT_UNLOCK_COUNT) {
        throw new TypeError(`settlement witness must count exactly ${SETTLEMENT_UNLOCK_COUNT} unlock at byte ${prefixLength}`);
    }
    // An absent TLC count leaves the body empty, which its reader refuses.
    const bodyEnd = BODY_OFFSET + settlementBodyLength(witness[BODY_OFFSET] ?? 0, layout);
    const body = witness.slice(BODY_OFFSET, bodyEnd);
    const { tlcEntries, balances } = readSettlementBody(body, layout);

    const unlock = witness.subarray(bodyEnd);
    if (unlock.length !== UNLOCK_LENGTH && unlock.length !== UNLOCK_WITH_PREIMAGE_LENGTH) {
        throw new TypeError(`settlement unlock must be ${UNLOCK_LENGTH} or ${UNLOCK_WITH_PREIMAGE_LENGTH} bytes, got ${unlock.length}`);
    }
    const target = readUnlockTarget(unlock, tlcEntries.length);
    const preimageFlag = unlock[1];
    if (preimageFlag !== 0 && preimageFlag !== 1) {
        throw new TypeError(`settlement unlock preimage flag must be 0 or 1, got ${preimageFlag}`);
    }
    const expectedLength = preimageFlag === 1 ? UNLOCK_WITH_PREIMAGE_LENGTH : UNLOCK_LENGTH;
    if (unlock.length !== expectedLength) {
        throw new TypeError(
            `settlement unlock with the preimage flag ${preimageFlag} must be ${expectedLength} bytes, got ${unlock.length}`,
        );
    }
    if (preimageFlag === 1 && target.kind === "balance") {
        throw new TypeError("settlement unlock of a balance must carry no preimage");
    }
    return {
        body,
        tlcEntries,
        balances,
        target,
        signature: unlock.slice(2, UNLOCK_LENGTH),
        preimage: preimageFlag === 1 ? unlock.slice(UNLOCK_LENGTH) : null,
    };
}

/**
 * Splits a settlement body into its TLC entries and its two balances.
 * @param body The body.
 * @param layout The lock layout.
 * @returns The entries and the balances.
 */
export function readSettlementBody(body: Uint8Array, layout: CommitmentLockLayout): SettlementBody {
    assertAnyBytes("settlement body", body);
    assertOneOf("layout", layout, COMMITMENT_LOCK_LAYOUTS);
    const count = body[0];
    if (count === undefined) throw new TypeError("settlement body must start with its TLC count");
    const length = settlementBodyLength(count, layout);
    if (body.length !== length) {
        throw new TypeError(`settlement body with a TLC count of ${count} must be ${length} bytes, got ${body.length}`);
    }
    const entryLength = settlementTlcEntryLength(layout);
    const tlcEntries = Array.from({ length: count }, (_, index) => body.slice(1 + index * entryLength, 1 + (index + 1) * entryLength));
    const balancesOffset = 1 + count * entryLength;
    return { tlcEntries, balances: [readBalance(body, balancesOffset), readBalance(body, balancesOffset + BALANCE_LENGTH)] };
}

/**
 * Reads a settlement body's TLC entry from the device's side.
 * @param entry The entry.
 * @param layout The lock layout.
 * @param forRemote The view.
 * @returns The direction, the amount and the device's key hash.
 */
export function readSettlementTlcEntry(entry: Uint8Array, layout: CommitmentLockLayout, forRemote: boolean): SettlementTlcEntry {
    assertOneOf("layout", layout, COMMITMENT_LOCK_LAYOUTS);
    assertBytes("settlement TLC entry", entry, settlementTlcEntryLength(layout));
    const deviceIndex = deviceSettlementIndex(forRemote);
    const flag = entry[0];
    if (!isUnsignedInteger(flag, MAX_TLC_FLAG)) {
        throw new TypeError(`settlement TLC entry flag must be at most ${MAX_TLC_FLAG}, got ${flag}`);
    }
    // The inverse of the witness's flag: a clear bit is offered in a remote view and received in a local one.
    const direction: TlcDirection = ((flag & 1) === 0) === forRemote ? "offered" : "received";
    const keyHashOffset = 1 + UINT128_LENGTH + WITNESS_PAYMENT_HASH_LENGTHS[layout] + deviceIndex * BLAKE160_LENGTH;
    return {
        direction,
        amountShannons: readUintLe(entry.subarray(1, 1 + UINT128_LENGTH)),
        localKeyHash: entry.slice(keyHashOffset, keyHashOffset + BLAKE160_LENGTH),
    };
}

/**
 * Where the device sits in each pair a settlement body carries: a TLC entry's key hashes, the balances.
 * @param forRemote The view.
 * @returns The device's index.
 */
export function deviceSettlementIndex(forRemote: boolean): 0 | 1 {
    assertBoolean("forRemote", forRemote);
    return forRemote ? 1 : 0;
}

/**
 * Port of the body fiber's watchtower commits in a spend's remainder: the unlocked TLC dropped, or the device's balance zeroed.
 * @param unlock The spend's unlock.
 * @param forRemote The view.
 * @returns The remainder's settlement body.
 */
export function nextSettlementWitness(unlock: SettlementUnlock, forRemote: boolean): Uint8Array {
    const deviceIndex = deviceSettlementIndex(forRemote);
    const { tlcEntries, balances, target } = unlock;
    let entries = tlcEntries;
    let nextBalances: SettlementBalance[] = balances;
    if (target.kind === "tlc") {
        if (!isUnsignedInteger(target.index, tlcEntries.length - 1)) {
            throw new RangeError(`settlement unlock must spend a TLC index below ${tlcEntries.length}, got ${target.index}`);
        }
        entries = tlcEntries.filter((_, index) => index !== target.index);
    } else {
        if (target.index !== deviceIndex) {
            const unlockType = BALANCE_UNLOCK_TYPES[target.index].toString(16);
            throw new TypeError(`settlement unlock 0x${unlockType} settles the peer's balance in a ${forRemote ? "remote" : "local"} view`);
        }
        const settled: SettlementBalance = { pubkeyHash: new Uint8Array(BLAKE160_LENGTH), amountShannons: 0n };
        nextBalances = balances.map((balance, index) => (index === deviceIndex ? settled : balance));
    }
    return concatBytes(
        Uint8Array.of(entries.length),
        ...entries,
        ...nextBalances.map((balance) => concatBytes(balance.pubkeyHash, uint128Le(balance.amountShannons))),
    );
}

/**
 * Builds a remainder's lock args: the source's, committing the next body, flagged as settled.
 * @param sourceArgs The spent commitment cell's lock args.
 * @param nextBody The remainder's settlement body.
 * @returns The remainder's lock args.
 */
export function buildRemainderLockArgs(sourceArgs: Uint8Array, nextBody: Uint8Array): Uint8Array {
    readSettlementBody(nextBody, readCommitmentLockLayout(sourceArgs));
    return concatBytes(
        sourceArgs.subarray(0, COMMITMENT_LOCK_SETTLEMENT_HASH_OFFSET),
        blake160(nextBody),
        Uint8Array.of(COMMITMENT_LOCK_SETTLEMENT_FLAGS.remainder),
        sourceArgs.subarray(COMMITMENT_LOCK_ARGS_LENGTHS.legacy),
    );
}

/**
 * Classifies an unlock's type byte as a TLC's index or a balance's unlock.
 * @param unlock The unlock, its length checked.
 * @param tlcCount The body's TLC count.
 * @returns What the unlock spends.
 */
function readUnlockTarget(unlock: Uint8Array, tlcCount: number): SettlementUnlockTarget {
    const unlockType = unlock[0];
    if (unlockType === BALANCE_UNLOCK_TYPES[0]) return { kind: "balance", index: 0 };
    if (unlockType === BALANCE_UNLOCK_TYPES[1]) return { kind: "balance", index: 1 };
    if (isUnsignedInteger(unlockType, tlcCount - 1)) return { kind: "tlc", index: unlockType };
    throw new TypeError(
        `settlement unlock type must be 0xfe, 0xff or a TLC index below ${tlcCount}, got 0x${bytesToHex(unlock.subarray(0, 1))}`,
    );
}

/**
 * Reads one of a settlement body's two balances.
 * @param body The body, its length checked.
 * @param offset Where the balance starts.
 * @returns The key hash and the amount.
 */
function readBalance(body: Uint8Array, offset: number): SettlementBalance {
    return {
        pubkeyHash: body.slice(offset, offset + BLAKE160_LENGTH),
        amountShannons: readUintLe(body.subarray(offset + BLAKE160_LENGTH, offset + BALANCE_LENGTH)),
    };
}

/**
 * The length of a TLC entry under a lock layout.
 * @param layout The layout.
 * @returns The 85 bytes under `legacy`, 97 under `fullPaymentHash`.
 */
export function settlementTlcEntryLength(layout: CommitmentLockLayout): number {
    return TLC_ENTRY_FIXED_LENGTH + WITNESS_PAYMENT_HASH_LENGTHS[layout];
}

/**
 * The length of a settlement body of so many TLCs under a lock layout.
 * @param tlcCount The TLC count.
 * @param layout The layout.
 * @returns The length.
 */
function settlementBodyLength(tlcCount: number, layout: CommitmentLockLayout): number {
    return 1 + tlcCount * settlementTlcEntryLength(layout) + 2 * BALANCE_LENGTH;
}
