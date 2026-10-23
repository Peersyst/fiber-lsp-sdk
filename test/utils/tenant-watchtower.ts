import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE, equalBytes } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import type { CellDep, CellOutput, OutPoint, Script, TlcDirection, TlcHashAlgorithm, Transaction } from "../../src/common";
import {
    MILLISECONDS_PER_SECOND,
    PREIMAGE_LENGTH,
    RECOVERABLE_ECDSA_SIGNATURE_LENGTH,
    SHANNONS_PER_CKB,
    ckbBlake2b,
    moleculeBytes,
    moleculeTable,
    readUintLe,
} from "../../src/common";
import type { CommitmentTxInput, SettlementTlc } from "../../src/digest";
import {
    buildCommitmentSettlementWitness,
    buildRemainderLockArgs,
    computeTxHash,
    deviceSettlementIndex,
    moleculeOutPoint,
    nextSettlementWitness,
    readCommitmentLockDelay,
    readCommitmentLockLayout,
    readSettlementBody,
    readSettlementUnlock,
} from "../../src/digest";
import { MAX_SINCE_PAYLOAD, SINCE_RELATIVE_EPOCH_FLAGS } from "../../src/digest/digest.constants";
import { calculateTxFee } from "../../src/digest/fee";
import { serializeRawTransaction } from "../../src/digest/tx-message";
import { moleculeTransaction } from "../../src/digest/utils/molecule.utils";
import type { FiberChannelKeys } from "../../src/derivation";
import type { WatchtowerKeyPurpose } from "../../src/policy";

// A literal there (`watchtower/actor.rs:1746`); ckb's fee rate truncates (`ckb-types/src/core/fee_rate.rs:34-37`), as
// `calculateTxFee` does.
const WATCHTOWER_FEE_RATE = 1000n;

// CKB's `serialized_size_in_block` counts the tx's offset in the block's list too.
const BLOCK_SIZE_OVERHEAD = 4;

// Fiber's `XUDT_COMPATIBLE_WITNESS` (`fiber/channel.rs:11961`), an empty `WitnessArgs`.
const XUDT_COMPATIBLE_WITNESS = moleculeTable([new Uint8Array(0), new Uint8Array(0), new Uint8Array(0)]);

// The `WitnessArgs` the node's own input is signed into once the device's signature is in (`watchtower/actor.rs:1672-1674`).
const SPONSOR_PLACEHOLDER_WITNESS = moleculeTable([
    moleculeBytes(new Uint8Array(RECOVERABLE_ECDSA_SIGNATURE_LENGTH)),
    new Uint8Array(0),
    new Uint8Array(0),
]);

// One unlock per spend (`watchtower/actor.rs:1699-1704`).
const SETTLEMENT_UNLOCK_COUNT = 1;

// The node's cell a spend's fee comes from: one always covers a spend here, so the loop of `watchtower/actor.rs:1782-1830`
// adds a single one.
const SPONSOR_CAPACITY_SHANNONS = 100n * SHANNONS_PER_CKB;

// CKB's `EpochNumberWithFraction`: the number in the low 24 bits, then the index and the length in 16 each.
const EPOCH_NUMBER_MASK = 0xffffffn;

const EPOCH_FRACTION_MASK = 0xffffn;

const EPOCH_INDEX_OFFSET = 24n;

const EPOCH_LENGTH_OFFSET = 40n;

// Fiber's `mul` keeps an epoch's length within 1800 blocks (`watchtower/actor.rs:2510-2515`).
const MAX_EPOCH_LENGTH = 1800n;

// The record's last 8 bytes: the TLC's absolute timestamp since.
const RECORD_SINCE_LENGTH = 8;

const SIGNATURE_SCALAR_LENGTH = 32;

// Fiber's `TrackedSettlementTlc` (`fiber/onchain_tlc_reconcile.rs:206-226`): a TLC of the snapshot and the record it writes.
export type WatchtowerTlc = SettlementTlc & { record: Uint8Array };

// A commitment lock cell on chain, with the settlement body its lock args commit.
export type WatchtowerCell = { outPoint: OutPoint; output: CellOutput; body: Uint8Array; first: boolean };

// One side of the force close as its own watchtower acts.
export type WatchtowerParty = {
    // The commitment's view from the party's side, which places its balance: the peer sees each view flipped.
    forRemote: boolean;
    settlementKeyHash: Uint8Array;
    // The device's direction of the TLCs the party reclaims by timeout: its own offered ones.
    offered: TlcDirection;
    preimages: Uint8Array[];
};

export type WatchtowerPick = {
    unlockType: number;
    // The unlocked TLC's record, `null` for a balance.
    record: Uint8Array | null;
    preimage: Uint8Array | null;
    // As the interop vectors name the spend.
    label: string;
    amountShannons: bigint;
    purpose: WatchtowerKeyPurpose;
    since: bigint;
    sponsorSince: bigint;
    lastParty: boolean;
};

export type WatchtowerSpendContext = {
    cellDeps: CellDep[];
    // Which node's cell pays the fee.
    sponsorLabel: string;
    payTo: Script;
    // What the node keeps of the remainder for its own output; fiber's watchtower keeps nothing.
    remainderShortfallShannons: bigint;
};

export type WatchtowerSpend = { transaction: Transaction; next: WatchtowerCell | null };

// Each TLC's record, read from a body of that TLC alone: the bytes the full body carries.
export function trackWatchtowerTlcs(keys: FiberChannelKeys, input: CommitmentTxInput): WatchtowerTlc[] {
    return input.tlcs.map((tlc) => {
        const [record] = readSettlementBody(buildCommitmentSettlementWitness(keys, { ...input, tlcs: [tlc] }), input.lockLayout).tlcEntries;
        if (record === undefined) throw new Error(`TLC ${tlc.id} writes no record`);
        return { ...tlc, record };
    });
}

// The unlock fiber's `build_settlement_tx` picks on a cell for one side (`watchtower/actor.rs:1308-1621`): its first arm on the
// commitment cell, its descendant arm on a remainder, at a tip past every delay of the lock, so the clock and the preimages
// alone choose.
export function pickWatchtowerUnlock(
    cell: WatchtowerCell,
    tlcs: WatchtowerTlc[],
    party: WatchtowerParty,
    medianTimeMs: bigint,
): WatchtowerPick | null {
    const { tlcEntries, balances } = readSettlementBody(cell.body, readCommitmentLockLayout(cell.output.lock.args));
    const own = deviceSettlementIndex(party.forRemote);
    const ownBalance = balances[own];
    const delay = readCommitmentLockDelay(cell.output.lock.args);
    // The commitment cell waits out a fraction of the lock's delay per unlock (`:1523-1600`, `:1706-1721`); a remainder spends
    // at once.
    const since = (fraction: bigint | null): bigint => {
        if (!cell.first) return 0n;
        return SINCE_RELATIVE_EPOCH_FLAGS | (fraction === null ? delay : mulEpoch(delay, fraction, 3n));
    };
    if (!cell.first) {
        if (!equalBytes(ownBalance.pubkeyHash, party.settlementKeyHash)) return null;
        if (balances[own === 0 ? 1 : 0].pubkeyHash.every((byte) => byte === 0)) {
            return settlementPick(party, ownBalance.amountShannons, since(null), true);
        }
    }
    let unresolved = tlcEntries.length;
    for (const [index, entry] of tlcEntries.entries()) {
        const tlc = tlcs.find((candidate) => equalBytes(candidate.record, entry));
        if (tlc === undefined) throw new Error(`TLC ${index} of the body is no TLC of the snapshot`);
        // The snapshot's expiry on the commitment cell, the record's on a remainder (`:1349-1355`, `:2337-2350`).
        const expiryMs = cell.first ? tlc.expiryMs : (readRecordSince(tlc.record) & MAX_SINCE_PAYLOAD) * MILLISECONDS_PER_SECOND;
        if (tlc.direction === party.offered) {
            if (medianTimeMs > expiryMs) return tlcPick(index, tlc, null, since(2n));
            continue;
        }
        const preimage = party.preimages.find((candidate) => equalBytes(hashPreimage(tlc.hashAlgorithm, candidate), tlc.paymentHash));
        if (preimage !== undefined) return tlcPick(index, tlc, preimage, since(1n));
        if (medianTimeMs > expiryMs) unresolved -= 1;
    }
    return unresolved === 0 ? settlementPick(party, ownBalance.amountShannons, since(null), false) : null;
}

// The CKB arm of fiber's `build_settlement_tx` (`watchtower/actor.rs:1653-1840`): the remainder, unless no party is left, then
// the node's output, paid what the unlock releases and its own cell brings, less the fee.
export function buildWatchtowerSpend(
    cell: WatchtowerCell,
    pick: WatchtowerPick,
    party: WatchtowerParty,
    context: WatchtowerSpendContext,
): WatchtowerSpend {
    const { lock } = cell.output;
    const unlock = concatBytes(
        Uint8Array.of(pick.unlockType, pick.preimage === null ? 0 : 1),
        new Uint8Array(RECOVERABLE_ECDSA_SIGNATURE_LENGTH),
        pick.preimage ?? new Uint8Array(0),
    );
    const witness = concatBytes(XUDT_COMPATIBLE_WITNESS, Uint8Array.of(SETTLEMENT_UNLOCK_COUNT), cell.body, unlock);
    const capacity = cell.output.capacityShannons;
    const released = pick.lastParty ? capacity : pick.amountShannons;
    const body = nextSettlementWitness(readSettlementUnlock(witness, readCommitmentLockLayout(lock.args)), party.forRemote);
    const remainder: CellOutput = {
        capacityShannons: (capacity > released ? capacity - released : 0n) - context.remainderShortfallShannons,
        lock: { ...lock, args: buildRemainderLockArgs(lock.args, body) },
        type: cell.output.type,
    };
    const kept = pick.lastParty ? [] : [remainder];
    const sponsor: OutPoint = {
        txHash: ckbBlake2b(utf8ToBytes(`${context.sponsorLabel} sponsor of `), moleculeOutPoint(cell.outPoint)),
        index: 0,
    };
    const draft: Transaction = {
        version: 0,
        cellDeps: context.cellDeps,
        headerDeps: [],
        inputs: [
            { since: pick.since, previousOutput: cell.outPoint },
            { since: pick.sponsorSince, previousOutput: sponsor },
        ],
        outputs: [...kept, { capacityShannons: released, lock: context.payTo, type: null }],
        outputsData: [...kept, null].map(() => new Uint8Array(0)),
        witnesses: [witness, SPONSOR_PLACEHOLDER_WITNESS],
    };
    const fee = calculateTxFee(WATCHTOWER_FEE_RATE, moleculeTx(draft).length + BLOCK_SIZE_OVERHEAD);
    const keptShannons = kept.reduce((sum, output) => sum + output.capacityShannons, 0n);
    const paid: CellOutput = {
        capacityShannons: capacity + SPONSOR_CAPACITY_SHANNONS - keptShannons - fee,
        lock: context.payTo,
        type: null,
    };
    const transaction = { ...draft, outputs: [...kept, paid] };
    const next = { outPoint: { txHash: computeTxHash(transaction), index: 0 }, output: remainder, body, first: false };
    return { transaction, next: pick.lastParty ? null : next };
}

// Fiber's request id (`watchtower/signer.rs:95`): the CKB blake2b of the molecule `Transaction`, witnesses included.
export function watchtowerRequestId(transaction: Transaction): Uint8Array {
    return ckbBlake2b(moleculeTx(transaction));
}

// Fiber's `verify_onchain_signature` (`watchtower/signer.rs:131-147`): the refusal as it reads, or `null`.
export function verifyWatchtowerSignature(expected: Uint8Array, message: Uint8Array, signature: Uint8Array): string | null {
    const recovery = signature[RECOVERABLE_ECDSA_SIGNATURE_LENGTH - 1] ?? 0;
    if (recovery > 3) return "invalid recovery id: bad recovery id";
    const order = secp256k1.Point.Fn.ORDER;
    const compact = signature.subarray(0, 2 * SIGNATURE_SCALAR_LENGTH);
    // libsecp256k1 parses any scalar below the order and refuses a zero one at the recovery, as noble does at parsing.
    if (
        bytesToNumberBE(compact.subarray(0, SIGNATURE_SCALAR_LENGTH)) >= order ||
        bytesToNumberBE(compact.subarray(SIGNATURE_SCALAR_LENGTH)) >= order
    ) {
        return "invalid compact signature: malformed signature";
    }
    let recovered: Uint8Array;
    try {
        recovered = secp256k1.recoverPublicKey(concatBytes(Uint8Array.of(recovery), compact), message, { prehash: false });
    } catch {
        return "failed to recover pubkey: malformed signature";
    }
    return equalBytes(recovered, expected) ? null : "recovered public key does not match expected public key";
}

function tlcPick(index: number, tlc: WatchtowerTlc, preimage: Uint8Array | null, since: bigint): WatchtowerPick {
    return {
        unlockType: index,
        record: tlc.record,
        preimage,
        label: preimage === null ? "outbound TLC by timeout" : "inbound TLC by preimage",
        amountShannons: tlc.amountShannons,
        purpose: { kind: "tlc", commitmentNumber: tlc.localKeyCommitmentNumber },
        since,
        // The lock wants an absolute since at the TLC's expiry, which the node's own input carries (`watchtower/actor.rs:1637-1652`).
        sponsorSince: preimage === null ? readRecordSince(tlc.record) : 0n,
        lastParty: false,
    };
}

function settlementPick(party: WatchtowerParty, amountShannons: bigint, since: bigint, lastParty: boolean): WatchtowerPick {
    return {
        unlockType: party.forRemote ? 0xff : 0xfe,
        record: null,
        preimage: null,
        label: lastParty ? "settlement as the last party" : "settlement",
        amountShannons,
        purpose: { kind: "settlement" },
        since,
        sponsorSince: 0n,
        lastParty,
    };
}

// Fiber's `mul` (`watchtower/actor.rs:2493-2522`): a fraction of a delay, the epoch length normalized to at most 1800.
function mulEpoch(delay: bigint, numerator: bigint, denominator: bigint): bigint {
    const number = delay & EPOCH_NUMBER_MASK;
    const index = (delay >> EPOCH_INDEX_OFFSET) & EPOCH_FRACTION_MASK;
    const length = (delay >> EPOCH_LENGTH_OFFSET) & EPOCH_FRACTION_MASK;
    const fullNumerator = numerator * (number * length + index);
    const fullDenominator = denominator * length;
    const scale = fullDenominator > MAX_EPOCH_LENGTH ? fullDenominator / MAX_EPOCH_LENGTH + 1n : 1n;
    const fraction =
        ((fullDenominator / scale) << EPOCH_LENGTH_OFFSET) | (((fullNumerator % fullDenominator) / scale) << EPOCH_INDEX_OFFSET);
    return fraction | (fullNumerator / fullDenominator);
}

// Fiber's `HashAlgorithm::hash`, which `verified_watch_preimage` checks a held preimage with (`watchtower/actor.rs:1212-1231`).
function hashPreimage(algorithm: TlcHashAlgorithm, preimage: Uint8Array): Uint8Array {
    if (preimage.length !== PREIMAGE_LENGTH) throw new Error(`a preimage is ${PREIMAGE_LENGTH} bytes`);
    return algorithm === "sha256" ? sha256(preimage) : ckbBlake2b(preimage);
}

function readRecordSince(record: Uint8Array): bigint {
    return readUintLe(record.subarray(record.length - RECORD_SINCE_LENGTH));
}

function moleculeTx(transaction: Transaction): Uint8Array {
    return moleculeTransaction(serializeRawTransaction(transaction, true), transaction.witnesses);
}
