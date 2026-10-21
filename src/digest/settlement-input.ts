import { equalBytes } from "@noble/curves/utils.js";
import {
    COMPRESSED_POINT_LENGTH,
    MAX_AMOUNT_SHANNONS,
    assertBoolean,
    assertBytes,
    assertUnsignedBigInt,
    assertUnsignedInteger,
    isPlainObject,
} from "../common";
import type { FiberChannelKeys } from "../derivation";
import { MAX_COMMITMENT_NUMBER, deriveTlcKey, pubkeyOf } from "../derivation";
import { MAX_CAPACITY_SHANNONS, MAX_SETTLEMENT_TLCS } from "./digest.constants";
import type { CommitmentSettlementTerms, CommitmentTxInput, SettlementTlc, SigningSettlement, SigningSettlementTlc } from "./digest.types";

/**
 * Turns fiber's settlement snapshot into the commitment input, refusing keys that are not the channel's.
 * @param keys The channel's secrets.
 * @param settlement The snapshot.
 * @param terms The channel's pins and the network's constants.
 * @param commitmentNumber The lock args version.
 * @returns The input whose digest must match the node's tx.
 */
export function settlementToCommitmentInput(
    keys: FiberChannelKeys,
    settlement: SigningSettlement,
    terms: CommitmentSettlementTerms,
    commitmentNumber: number,
): CommitmentTxInput {
    if (!isPlainObject(settlement)) throw new TypeError("settlement must be an object");
    if (!isPlainObject(terms)) throw new TypeError("terms must be an object");
    assertBoolean("settlement.forRemote", settlement.forRemote);
    // Fiber settles on the TLC base keys (get_settlement_keys): the device's own is derived here.
    assertBytes("settlement.localSettlementPubkey", settlement.localSettlementPubkey, COMPRESSED_POINT_LENGTH);
    if (!equalBytes(settlement.localSettlementPubkey, pubkeyOf(keys.tlcBaseKey))) {
        throw new TypeError("settlement.localSettlementPubkey is not this device's TLC base key");
    }
    // The peer's is the remote TLC base key, which the policy pins at first sight.
    assertBytes("settlement.remoteSettlementPubkey", settlement.remoteSettlementPubkey, COMPRESSED_POINT_LENGTH);
    if (!Array.isArray(settlement.tlcs) || settlement.tlcs.length > MAX_SETTLEMENT_TLCS) {
        throw new TypeError(`settlement.tlcs must be an array of at most ${MAX_SETTLEMENT_TLCS} TLCs`);
    }

    // Checked on UDT channels too, where they pass whole.
    assertUnsignedBigInt("settlement.localAmountShannons", settlement.localAmountShannons, MAX_AMOUNT_SHANNONS);
    assertUnsignedBigInt("settlement.remoteAmountShannons", settlement.remoteAmountShannons, MAX_AMOUNT_SHANNONS);
    assertUnsignedBigInt("terms.localReservedCkbShannons", terms.localReservedCkbShannons, MAX_CAPACITY_SHANNONS);
    assertUnsignedBigInt("terms.remoteReservedCkbShannons", terms.remoteReservedCkbShannons, MAX_CAPACITY_SHANNONS);

    // Fiber adds each side's reserve to the snapshot amounts on CKB channels only (build_settlement_data).
    const isUdt = terms.udtTypeScript !== null;
    const settlementLocalShannons = isUdt
        ? settlement.localAmountShannons
        : withoutReserve("local", settlement.localAmountShannons, terms.localReservedCkbShannons);
    const settlementRemoteShannons = isUdt
        ? settlement.remoteAmountShannons
        : withoutReserve("remote", settlement.remoteAmountShannons, terms.remoteReservedCkbShannons);
    return {
        forRemote: settlement.forRemote,
        fundingOutPoint: terms.fundingOutPoint,
        remoteFundingPubkey: terms.remoteFundingPubkey,
        remoteTlcBasePubkey: settlement.remoteSettlementPubkey,
        commitmentNumber,
        commitmentDelayEpoch: terms.commitmentDelayEpoch,
        commitmentFeeRate: terms.commitmentFeeRate,
        cellDepsCount: terms.cellDepsCount,
        udtTypeScript: terms.udtTypeScript,
        liquidCapacityShannons: terms.liquidCapacityShannons,
        settlementLocalShannons,
        settlementRemoteShannons,
        localReservedCkbShannons: terms.localReservedCkbShannons,
        remoteReservedCkbShannons: terms.remoteReservedCkbShannons,
        tlcs: settlement.tlcs.map((tlc, index) => toSettlementTlc(keys, tlc, `settlement.tlcs[${index}]`)),
        commitmentLock: terms.commitmentLock,
        lockLayout: terms.lockLayout,
    };
}

/**
 * Takes a side's reserve back out of its snapshot amount, which the witness adds again.
 * @param side The side, for the refusal.
 * @param amount The snapshot amount.
 * @param reserve The side's reserve.
 * @returns The amount without the reserve.
 */
function withoutReserve(side: "local" | "remote", amount: bigint, reserve: bigint): bigint {
    if (amount < reserve) {
        throw new RangeError(`settlement.${side}AmountShannons ${amount} is below the ${side} reserve ${reserve} it includes`);
    }
    return amount - reserve;
}

/**
 * Turns a snapshot TLC into a witness TLC, refusing a key the device does not derive at the stated number.
 * @param keys The channel's secrets.
 * @param tlc The snapshot TLC.
 * @param name Its path, for the refusal.
 * @returns The witness TLC.
 */
function toSettlementTlc(keys: FiberChannelKeys, tlc: SigningSettlementTlc, name: string): SettlementTlc {
    if (!isPlainObject(tlc)) throw new TypeError(`${name} must be an object`);
    assertUnsignedInteger(`${name}.localKeyCommitmentNumber`, tlc.localKeyCommitmentNumber, MAX_COMMITMENT_NUMBER);
    assertBytes(`${name}.localKeyPubkey`, tlc.localKeyPubkey, COMPRESSED_POINT_LENGTH);
    if (!equalBytes(tlc.localKeyPubkey, pubkeyOf(deriveTlcKey(keys, tlc.localKeyCommitmentNumber)))) {
        throw new TypeError(`${name}.localKeyPubkey is not this device's TLC key at commitment number ${tlc.localKeyCommitmentNumber}`);
    }
    return {
        id: tlc.tlcId,
        direction: tlc.direction,
        hashAlgorithm: tlc.hashAlgorithm,
        amountShannons: tlc.amountShannons,
        paymentHash: tlc.paymentHash,
        expiryMs: tlc.expiryMs,
        localKeyCommitmentNumber: tlc.localKeyCommitmentNumber,
        remoteTlcPubkey: tlc.remoteTlcPubkey,
    };
}
