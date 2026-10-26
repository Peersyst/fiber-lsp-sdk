import { equalBytes } from "@noble/curves/utils.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { CellInput, CellOutput, Script, Transaction } from "../common";
import { HASH256_LENGTH, assertBytes, assertUnsignedInteger, blake160, isPlainObject } from "../common";
import type { FiberChannelKeys } from "../derivation";
import { MAX_COMMITMENT_NUMBER, deriveTlcKey, pubkeyOf } from "../derivation";
import type { CommitmentLockLayout, SettlementBalance, SettlementBody, SettlementUnlock } from "../digest";
import {
    buildRemainderLockArgs,
    computeTxHash,
    deviceSettlementIndex,
    moleculeCellOutput,
    nextSettlementWitness,
    REVOCATION_LOCK_ARGS_LENGTH,
    readCommitmentLockLayout,
    readSettlementBody,
    readSettlementTlcEntry,
    readSettlementUnlock,
} from "../digest";
import { WIRE_HEX_PREFIX, decodeMoleculeCellOutput } from "../wire";
import { MAX_WATCHTOWER_DESTINATION_OUTPUTS } from "./policy.constants";
import { refusePolicyRequest, withPolicyRefusal } from "./policy.error";
import type {
    ChannelPolicyRecord,
    PolicyView,
    PreviousRemoteCommitmentRecord,
    SignedCommitmentRecord,
    WatchtowerApproval,
    WatchtowerKeyPurpose,
    WatchtowerSpendRecord,
    WatchtowerSpendRequest,
    WatchtowerSpendVerdict,
} from "./policy.types";

type RegisteredCommitment = {
    view: PolicyView;
    commitmentNumber: number;
    // How a refusal names it.
    name: string;
    settlementWitness: string;
    cell: CellOutput;
};

type SpendSource = {
    view: PolicyView;
    commitmentNumber: number;
    // The view's commitment cell's: a descendant's differs in the settlement hash and flag alone, which no remainder keeps.
    lock: Script;
    // Known for the commitment cell alone: a descendant's is whatever the chain holds.
    capacityShannons: bigint | null;
    layout: CommitmentLockLayout;
    unlock: SettlementUnlock;
};

/**
 * Runs the watchtower rules on a spend against a channel's record, writing nothing.
 * @param keys The channel's four secrets.
 * @param record The channel's record.
 * @param approval What the host approved the spends for.
 * @param request The spend as fiber's watchtower built it.
 * @returns The verdict, and the record to write: the one given unless fresh.
 */
export function decideWatchtowerSpend(
    keys: FiberChannelKeys,
    record: ChannelPolicyRecord,
    approval: WatchtowerApproval,
    request: WatchtowerSpendRequest,
): { verdict: WatchtowerSpendVerdict; record: ChannelPolicyRecord } {
    const txHash = bytesToHex(withPolicyRefusal("malformed", () => readSpendStructure(request)));
    const { transaction, purpose } = request;
    const registered = registeredCommitments(record);
    const source = findSpendSource(registered, transaction);
    const forRemote = source.view === "remote";
    const released = releasedByKey(keys, purpose, source, forRemote);
    if (source.unlock.signature.some((byte) => byte !== 0)) {
        refusePolicyRequest("malformed", "watchtower placeholder: the unlock's signature must be the 65 zero bytes of an unsigned spend");
    }
    const remainder = released.finalParty ? null : readRemainder(transaction, source, released.shannons, forRemote);
    assertPaidOut(transaction, remainder !== null, approval, released.shannons);

    const requestId = bytesToHex(request.requestId);
    const spends = record.watchtowerSpends ?? [];
    const repeat = spends.find((spend) => spend.requestId === requestId);
    // Past every rule, on the record and the approval as they are now: a repeat skips the claim alone.
    if (repeat !== undefined) return { verdict: repeatVerdict(repeat, txHash), record };
    const { target, tlcEntries } = source.unlock;
    const spend: WatchtowerSpendRecord = {
        requestId,
        purpose: purpose.kind === "settlement" ? { kind: "settlement" } : { kind: "tlc", commitmentNumber: purpose.commitmentNumber },
        view: source.view,
        commitmentNumber: source.commitmentNumber,
        tlcEntry: target.kind === "tlc" ? bytesToHex(tlcEntries[target.index] as Uint8Array) : null,
        txHash,
        remainder:
            remainder === null
                ? null
                : { output: bytesToHex(moleculeCellOutput(remainder.capacityShannons, remainder.lock, remainder.type)), outputData: "" },
        signature: null,
        applied: false,
    };
    // The first spend signed for an unlock stays the record's: a later one goes unclaimed.
    if (spends.some((recorded) => recorded.signature !== null && isSameSpendKey(recorded, spend))) {
        return { verdict: { status: "unclaimed" }, record };
    }
    // A claim never signed gives way to the spend fiber rebuilt, and a commitment no longer registered is never spent again.
    const kept = spends.filter(
        (recorded) =>
            !isSameSpendKey(recorded, spend) &&
            registered.some((commitment) => commitment.view === recorded.view && commitment.commitmentNumber === recorded.commitmentNumber),
    );
    return { verdict: { status: "fresh" }, record: { ...record, watchtowerSpends: [...kept, spend] } };
}

/**
 * Checks the request's shape and the tx's structure, as fiber's watchtower builds every spend.
 * @param request The request.
 * @returns The spend's CKB tx hash.
 */
function readSpendStructure(request: WatchtowerSpendRequest): Uint8Array {
    if (!isPlainObject(request)) throw new TypeError("request must be an object");
    assertBytes("request.requestId", request.requestId, HASH256_LENGTH);
    assertWatchtowerKeyPurpose("request.purpose", request.purpose);
    const { transaction } = request;
    // Checks every field the hash covers.
    const txHash = computeTxHash(transaction);
    const faults = [
        [transaction.version !== 0, "be version 0"],
        [transaction.headerDeps.length !== 0, "carry no header deps"],
        [transaction.inputs.length === 0, "spend an input"],
        [transaction.outputs.length !== transaction.outputsData.length, "carry one data per output"],
        [!Array.isArray(transaction.witnesses), "carry a witness list"],
    ] as const;
    const fault = faults.find(([faulty]) => faulty);
    if (fault !== undefined) throw new TypeError(`watchtower structure: the spend must ${fault[1]}`);
    return txHash;
}

/**
 * Asserts that a value names a key a watchtower spend is signed with.
 * @param name Name of the value, used in the error message.
 * @param value Value to check.
 */
export function assertWatchtowerKeyPurpose(name: string, value: unknown): asserts value is WatchtowerKeyPurpose {
    if (!isPlainObject(value)) throw new TypeError(`${name} must be an object`);
    if (value.kind === "settlement") return;
    if (value.kind !== "tlc") throw new TypeError(`${name}.kind must be settlement or tlc`);
    assertUnsignedInteger(`${name}.commitmentNumber`, value.commitmentNumber, MAX_COMMITMENT_NUMBER);
}

/**
 * Answers a request already claimed, if it is the same spend.
 * @param spend The spend recorded for the request.
 * @param txHash The request's tx hash, lowercase hex.
 * @returns The repeat's verdict.
 */
function repeatVerdict(spend: WatchtowerSpendRecord, txHash: string): WatchtowerSpendVerdict {
    // The tx fixes the unlock, and the key rule the one key that signs it.
    if (spend.txHash !== txHash) {
        refusePolicyRequest("policy_refusal", `watchtower repeat: request ${spend.requestId} was claimed for another spend`);
    }
    return { status: "already-signed", signature: spend.signature === null ? null : hexToBytes(spend.signature) };
}

/**
 * Tells whether two spends settle the same unlock of the same commitment.
 * @param spend A spend.
 * @param other Another.
 * @returns Whether they do.
 */
function isSameSpendKey(spend: WatchtowerSpendRecord, other: WatchtowerSpendRecord): boolean {
    return spend.view === other.view && spend.commitmentNumber === other.commitmentNumber && spend.tlcEntry === other.tlcEntry;
}

/**
 * Lists the commitments fiber's watchtower settles: the last remote one and the one before it, and the last local one.
 * @param record The channel's record.
 * @returns Those whose cells the record kept.
 */
function registeredCommitments(record: ChannelPolicyRecord): RegisteredCommitment[] {
    const { remote, local } = record.commitmentHashes;
    const candidates: [PolicyView, string, SignedCommitmentRecord | PreviousRemoteCommitmentRecord | undefined][] = [
        ["remote", "remote view's", remote],
        ["remote", "remote view's previous", record.previousRemoteCommitment],
        ["local", "local view's", local],
    ];
    return candidates.flatMap(([view, name, commitment]): RegisteredCommitment[] => {
        // The record guard keeps the two together.
        if (commitment?.source === undefined || commitment.settlementWitness === undefined) return [];
        const cell = decodeMoleculeCellOutput({ value: WIRE_HEX_PREFIX + commitment.source.output, path: "source.output" });
        const { commitmentNumber, settlementWitness } = commitment;
        return [{ view, commitmentNumber, name, settlementWitness, cell }];
    });
}

/**
 * Finds the cell input 0 spends by its settlement body: a registered commitment's cell, or a cell descending from one.
 * @param registered The commitments fiber's watchtower settles.
 * @param transaction The spend, its structure checked.
 * @returns The source.
 */
function findSpendSource(registered: RegisteredCommitment[], transaction: Transaction): SpendSource {
    // The structure holds an input.
    const [{ previousOutput, since }] = transaction.inputs as [CellInput];
    // Its tx hash goes unchecked: the peer picks the cell deps of the commitment it broadcasts, which no signature covers.
    if (previousOutput.index !== 0) {
        refusePolicyRequest(
            "policy_refusal",
            `watchtower source: input 0 must spend output 0, which holds every commitment lock cell, not output ${previousOutput.index}`,
        );
    }
    // The lock holds a commitment cell to its delay, and fiber's watchtower spends a remainder at once.
    return since === 0n ? findDescendantSource(registered, transaction) : findCommitmentSource(registered, transaction);
}

/**
 * Finds the registered commitment whose cell a spend with a since takes: the one whose settlement body the witness carries.
 * @param registered The commitments fiber's watchtower settles.
 * @param transaction The spend, its structure checked.
 * @returns The source.
 */
function findCommitmentSource(registered: RegisteredCommitment[], transaction: Transaction): SpendSource {
    // Fiber signs a commitment again with nothing changed but its number, so two may carry the same body.
    const candidates = registered.flatMap(({ view, commitmentNumber, settlementWitness, cell }): SpendSource[] => {
        const { lock } = cell;
        const layout = readCommitmentLockLayout(lock.args);
        const unlock = readUnlock(transaction, layout);
        // The record guard holds the cell's args, flag 0, to this body.
        if (bytesToHex(unlock.body) !== settlementWitness) return [];
        return [{ view, commitmentNumber, lock, capacityShannons: cell.capacityShannons, layout, unlock }];
    });
    const source = pickSource(candidates, transaction);
    if (source !== undefined) return source;
    return refusePolicyRequest(
        "policy_refusal",
        "watchtower source: input 0, spent with a since, must be the cell of the last local or remote commitment signed, or of " +
            "the remote one before it, and the settlement body is none of theirs",
    );
}

/**
 * Finds the registered commitment a cell spent at a zero since descends from, which the device may never have signed.
 * @param registered The commitments fiber's watchtower settles.
 * @param transaction The spend, its structure checked.
 * @returns The source, with no capacity.
 */
function findDescendantSource(registered: RegisteredCommitment[], transaction: Transaction): SpendSource {
    const faults: string[] = [];
    const candidates: SpendSource[] = [];
    for (const { view, commitmentNumber, name, settlementWitness, cell } of registered) {
        const { lock } = cell;
        const layout = readCommitmentLockLayout(lock.args);
        const unlock = readUnlock(transaction, layout);
        const fault = findDescentFault(unlock, readSettlementBody(hexToBytes(settlementWitness), layout));
        if (fault === null) candidates.push({ view, commitmentNumber, lock, capacityShannons: null, layout, unlock });
        else faults.push(`the ${name} ${fault}`);
    }
    const source = pickSource(candidates, transaction);
    if (source !== undefined) return source;
    const reason = faults.length === 0 ? "no commitment has been signed" : faults.join(", and ");
    return refusePolicyRequest(
        "policy_refusal",
        `watchtower source: input 0, spent with a zero since, is no cell descending from a signed commitment: ${reason}`,
    );
}

/**
 * Picks among the sources a spend may take the one its remainder's args name, or the first when it leaves no remainder.
 * @param candidates The sources.
 * @param transaction The spend.
 * @returns The source, `undefined` when there is none.
 */
function pickSource(candidates: SpendSource[], transaction: Transaction): SpendSource | undefined {
    const [first] = transaction.outputs;
    // A remainder keeps the first args of its source, the ones a revocation signs, the commitment number among them.
    const named = first?.lock.args.subarray(0, REVOCATION_LOCK_ARGS_LENGTH);
    const source = candidates.find(
        ({ lock }) => named !== undefined && equalBytes(lock.args.subarray(0, REVOCATION_LOCK_ARGS_LENGTH), named),
    );
    return source ?? candidates[0];
}

/**
 * Reads witness 0's settlement unlock.
 * @param transaction The spend.
 * @param layout The commitment lock's layout.
 * @returns The unlock.
 */
function readUnlock(transaction: Transaction, layout: CommitmentLockLayout): SettlementUnlock {
    const [witness] = transaction.witnesses;
    if (witness === undefined) refusePolicyRequest("malformed", "watchtower witness: the spend carries no settlement witness at index 0");
    return withPolicyRefusal("malformed", () => readSettlementUnlock(witness, layout));
}

/**
 * Tells why a settlement body cannot descend from a registered commitment's: a TLC it never listed, or a balance it never had.
 * @param unlock The unlock.
 * @param committed The body of the registered commitment.
 * @returns The fault, or `null`.
 */
function findDescentFault(unlock: SettlementUnlock, committed: SettlementBody): string | null {
    for (const [index, entry] of unlock.tlcEntries.entries()) {
        const listed = countEntry(committed.tlcEntries, entry);
        if (listed === 0) return `commitment does not list TLC ${index} of the settlement body`;
        // A multiset, unlike fiber's validate: equal entries, the parts of one payment among them, each stay claimable.
        if (countEntry(unlock.tlcEntries.slice(0, index + 1), entry) > listed) {
            return `commitment lists TLC ${index} of the settlement body fewer times than the body does`;
        }
    }
    for (const index of [0, 1] as const) {
        const balance = unlock.balances[index];
        if (!isSettledBalance(balance) && !isSameBalance(balance, committed.balances[index])) {
            return `commitment holds another balance ${index} than the settlement body, which has not settled it`;
        }
    }
    return null;
}

/**
 * Counts the entries equal to one.
 * @param entries The entries.
 * @param entry The one.
 * @returns How many of them equal it.
 */
function countEntry(entries: Uint8Array[], entry: Uint8Array): number {
    return entries.filter((candidate) => equalBytes(candidate, entry)).length;
}

/**
 * Tells whether a balance is settled: its key hash and its amount zeroed.
 * @param balance The balance.
 * @returns Whether it is.
 */
function isSettledBalance(balance: SettlementBalance): boolean {
    return balance.amountShannons === 0n && isZeroHash(balance.pubkeyHash);
}

/**
 * Tells whether two balances are the same.
 * @param balance A balance.
 * @param other Another.
 * @returns Whether their key hashes and amounts match.
 */
function isSameBalance(balance: SettlementBalance, other: SettlementBalance): boolean {
    return balance.amountShannons === other.amountShannons && equalBytes(balance.pubkeyHash, other.pubkeyHash);
}

/**
 * Tells whether a key hash is zeroed.
 * @param hash The hash.
 * @returns Whether every byte is zero.
 */
function isZeroHash(hash: Uint8Array): boolean {
    return hash.every((byte) => byte === 0);
}

/**
 * Holds the unlock to the key the purpose names, and reads what it releases.
 * @param keys The channel's four secrets.
 * @param purpose The key the request names.
 * @param source The source, with its unlock.
 * @param forRemote The view.
 * @returns What the unlock releases to the device, and whether no party is left after it.
 */
function releasedByKey(
    keys: FiberChannelKeys,
    purpose: WatchtowerKeyPurpose,
    source: SpendSource,
    forRemote: boolean,
): { shannons: bigint; finalParty: boolean } {
    const { unlock, layout } = source;
    const { target } = unlock;
    if (purpose.kind === "tlc") {
        if (target.kind !== "tlc") refusePolicyRequest("policy_refusal", "watchtower key: a TLC key signs a TLC's unlock, not a balance's");
        // The unlock reader bounds the index by the body's TLCs.
        const entry = readSettlementTlcEntry(unlock.tlcEntries[target.index] as Uint8Array, layout, forRemote);
        if (!equalBytes(entry.localKeyHash, blake160(pubkeyOf(deriveTlcKey(keys, purpose.commitmentNumber))))) {
            refusePolicyRequest(
                "policy_refusal",
                `watchtower key: TLC ${target.index} does not settle to the device's TLC key at commitment number ` +
                    `${purpose.commitmentNumber}`,
            );
        }
        // Fiber's validate without its clock: the device claims a TLC it received by the preimage, one it offered by the timeout.
        const received = entry.direction === "received";
        if (received !== (unlock.preimage !== null)) {
            refusePolicyRequest(
                "policy_refusal",
                `watchtower preimage: TLC ${target.index} is one the device ${entry.direction}, which ` +
                    `${received ? "its preimage" : "its timeout"} alone unlocks`,
            );
        }
        return { shannons: entry.amountShannons, finalParty: false };
    }
    const deviceIndex = deviceSettlementIndex(forRemote);
    // Fiber's commitment lock settles balance 0 on 0xfe and balance 1 on 0xff, and the device's sits at 1 in a remote view.
    if (target.kind !== "balance" || target.index !== deviceIndex) {
        const [unlockType, view] = forRemote ? ["ff", "remote"] : ["fe", "local"];
        refusePolicyRequest(
            "policy_refusal",
            `watchtower key: the settlement key signs the unlock 0x${unlockType} of the device's balance in a ${view} view`,
        );
    }
    const balance = unlock.balances[deviceIndex];
    if (!equalBytes(balance.pubkeyHash, blake160(pubkeyOf(keys.tlcBaseKey)))) {
        refusePolicyRequest("policy_refusal", "watchtower key: the device's balance does not settle to its TLC base key");
    }
    // Once the peer settled, the device's unlock takes the whole cell: its balance and every TLC still in the body.
    const finalParty = isZeroHash(unlock.balances[deviceIndex === 0 ? 1 : 0].pubkeyHash);
    const entries = unlock.tlcEntries.map((entry) => readSettlementTlcEntry(entry, layout, forRemote));
    // Fiber's watchtower claims every TLC the device offered before it settles the device's balance.
    const offered = entries.findIndex((entry) => entry.direction === "offered");
    if (!finalParty && offered !== -1) {
        refusePolicyRequest(
            "policy_refusal",
            `watchtower settlement: the body still holds TLC ${offered}, which the device offered and fiber's watchtower claims first`,
        );
    }
    const shannons = finalParty
        ? entries.reduce((sum, entry) => sum + entry.amountShannons, balance.amountShannons)
        : balance.amountShannons;
    if (shannons === 0n) refusePolicyRequest("policy_refusal", "watchtower key: the unlock releases nothing to the device");
    return { shannons, finalParty };
}

/**
 * Port of the remainder fiber's watchtower leaves at output 0: the source cell, less what is released, committing the next body.
 * @param transaction The spend.
 * @param source The source, with its unlock.
 * @param releasedShannons What the unlock releases.
 * @param forRemote The view.
 * @returns Output 0.
 */
function readRemainder(transaction: Transaction, source: SpendSource, releasedShannons: bigint, forRemote: boolean): CellOutput {
    const { lock, capacityShannons, unlock } = source;
    const [first] = transaction.outputs;
    const args = buildRemainderLockArgs(lock.args, nextSettlementWitness(unlock, forRemote));
    if (
        first === undefined ||
        !isSameScript(first.lock, { ...lock, args }) ||
        first.type !== null ||
        transaction.outputsData[0]?.length !== 0 ||
        (capacityShannons !== null && first.capacityShannons + releasedShannons !== capacityShannons)
    ) {
        refusePolicyRequest("policy_refusal", "watchtower remainder: output 0 is not the remainder fiber's watchtower leaves");
    }
    return first;
}

/**
 * Holds every output but the remainder to the approved destination, paid at least what is released less the fee approved.
 * @param transaction The spend.
 * @param withRemainder Whether output 0 is the remainder.
 * @param approval What the host approved.
 * @param releasedShannons What the unlock releases.
 */
function assertPaidOut(transaction: Transaction, withRemainder: boolean, approval: WatchtowerApproval, releasedShannons: bigint): void {
    const skipped = withRemainder ? 1 : 0;
    const paid = transaction.outputs.slice(skipped);
    if (paid.length === 0 || paid.length > MAX_WATCHTOWER_DESTINATION_OUTPUTS) {
        refusePolicyRequest(
            "policy_refusal",
            `watchtower destination: the spend pays ${paid.length} outputs besides the remainder, ` +
                `not 1 to ${MAX_WATCHTOWER_DESTINATION_OUTPUTS}`,
        );
    }
    for (const [offset, output] of paid.entries()) {
        const index = skipped + offset;
        if (!isSameScript(output.lock, approval.destination) || output.type !== null || transaction.outputsData[index]?.length !== 0) {
            refusePolicyRequest(
                "policy_refusal",
                `watchtower destination: output ${index} must pay the approved destination, with no type and no data`,
            );
        }
    }
    const paidShannons = paid.reduce((sum, output) => sum + output.capacityShannons, 0n);
    const maxFeeShannons = BigInt(approval.maxFeeShannons);
    if (paidShannons < releasedShannons - maxFeeShannons) {
        refusePolicyRequest(
            "policy_refusal",
            `watchtower destination: the destination is paid ${paidShannons} shannons, below the ${releasedShannons} released less the ` +
                `${maxFeeShannons} fee approved`,
        );
    }
}

/**
 * Tells whether two scripts are the same.
 * @param script A script.
 * @param other Another.
 * @returns Whether they are.
 */
function isSameScript(script: Script, other: Script): boolean {
    return equalBytes(script.codeHash, other.codeHash) && script.hashType === other.hashType && equalBytes(script.args, other.args);
}
