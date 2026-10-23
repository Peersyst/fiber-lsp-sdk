import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import type { CellInput, CellOutput, Transaction } from "../../../src/common";
import { blake160, uint128Le } from "../../../src/common";
import {
    buildCommitmentSettlementWitness,
    buildCommitmentTx,
    buildRemainderLockArgs,
    computeTxHash,
    moleculeCellOutput,
    nextSettlementWitness,
    readSettlementUnlock,
} from "../../../src/digest";
import type {
    ChannelPolicyRecord,
    SignedCommitmentRecord,
    WatchtowerApproval,
    WatchtowerKeyPurpose,
    WatchtowerSpendRecord,
    WatchtowerSpendRequest,
} from "../../../src/policy";
import { PolicyEngine, PolicyRefusalError, SignerStore, decideWatchtowerSpend } from "../../../src/policy";
import { InMemorySignerStorage } from "../../mocks/policy";
import { toScript, toTransaction } from "../../utils/digest-inputs";
import { WATCHTOWER_VARIANT_REFUSALS, policyRefusal } from "../../utils/refusal";
import { signingCommitmentLock, signingDeviceKeys } from "../../utils/signing-channel";
import {
    loadSigningVectors,
    toWatchtowerKeyPurpose,
    watchtowerApprovalOf,
    watchtowerSignedCommitmentOf,
    watchtowerSpendOf,
    watchtowerViewOf,
} from "../../utils/signing-vectors";

const vectors = loadSigningVectors();
const { watchtower } = vectors;
const KEYS = signingDeviceKeys(vectors);

const APPROVAL = watchtowerApprovalOf(vectors);

// The watchtower's spends of the peer's commitment: from the commitment cell, then from the remainders it leaves.
const INBOUND_TLC = "peer's commitment: inbound TLC by preimage";
const OUTBOUND_TLC = "peer's commitment: outbound TLC by timeout";
const SETTLEMENT = "peer's commitment: settlement";
const PEER_FIRST_OUTBOUND_TLC = "peer's commitment, peer first: outbound TLC by timeout";
const LAST_PARTY = "peer's commitment, peer first: settlement as the last party";
const OWN_INBOUND_TLC = "own commitment: inbound TLC by preimage";
const OWN_SETTLEMENT = "own commitment: settlement";
const OWN_PEER_FIRST_OUTBOUND_TLC = "own commitment, peer first: outbound TLC by timeout";
const OWN_LAST_PARTY = "own commitment, peer first: settlement as the last party";

const WITNESS_PREFIX = hexToBytes("10000000100000001000000010000000");
const UNSIGNED = new Uint8Array(65);
const PREIMAGE = new Uint8Array(32).fill(0x5a);
const SIGNATURE = "ab".repeat(65);
const NOT_THE_REMAINDER = "watchtower remainder: output 0 is not the remainder fiber's watchtower leaves";
const COMMITMENT_SOURCE =
    "watchtower source: input 0, spent with a since, must be the cell of the last local or remote commitment signed, or of the " +
    "remote one before it, and the settlement body is none of theirs";
const DESCENDANT_SOURCE = "watchtower source: input 0, spent with a zero since, is no cell descending from a signed commitment: ";
const MAX_FEE = BigInt(APPROVAL.maxFeeShannons);

const OPENING_VIEW = { exposureShannons: "72000000000", tlcs: [], chargedShannons: {}, creditedShannons: {} };

function cellHex(output: CellOutput): string {
    return bytesToHex(moleculeCellOutput(output.capacityShannons, output.lock, output.type));
}

// Version 7 in the peer's view, version 6 in the device's.
const REMOTE_COMMITMENT = watchtowerSignedCommitmentOf(vectors, true);
const LOCAL_COMMITMENT = watchtowerSignedCommitmentOf(vectors, false);
const [REMOTE_CELL] = toTransaction(watchtowerViewOf(vectors, true).commitment.transaction).outputs as [CellOutput];

const RECORD: ChannelPolicyRecord = {
    version: 1,
    channelId: vectors.channel.channel_id,
    lastSignedCommitmentNumbers: { "COMMITMENT:local": 7 },
    signedSessions: { "COMMITMENT:7": "cd".repeat(32) },
    nonceReuse: {},
    commitmentHashes: { remote: REMOTE_COMMITMENT, local: LOCAL_COMMITMENT },
    revocations: [],
    pins: {
        fundedShannons: "72000000000",
        localCloseScript: "ab".repeat(53),
        localReservedCkbShannons: { legacy: "9900000000", fullPaymentHash: "10000000000" },
        udtTypeScript: null,
    },
    views: { remote: OPENING_VIEW, local: OPENING_VIEW },
};

// The peer's view alone, so a descendant's refusal names one view's fault.
const REMOTE_RECORD: ChannelPolicyRecord = { ...RECORD, commitmentHashes: { remote: REMOTE_COMMITMENT } };

function requestOf(name: string): WatchtowerSpendRequest {
    const spend = watchtowerSpendOf(vectors, name);
    return {
        requestId: hexToBytes(spend.request_id.slice(2)),
        purpose: toWatchtowerKeyPurpose(spend.key_purpose),
        transaction: toTransaction(spend.transaction),
    };
}

function withTransaction(request: WatchtowerSpendRequest, change: (tx: Transaction) => Partial<Transaction>): WatchtowerSpendRequest {
    return { ...request, transaction: { ...request.transaction, ...change(request.transaction) } };
}

function withOutput(request: WatchtowerSpendRequest, index: number, change: (output: CellOutput) => CellOutput): WatchtowerSpendRequest {
    return withTransaction(request, (tx) => ({ outputs: tx.outputs.map((output, at) => (at === index ? change(output) : output)) }));
}

function withWitness(request: WatchtowerSpendRequest, witness: Uint8Array): WatchtowerSpendRequest {
    return withTransaction(request, (tx) => ({ witnesses: [witness, ...tx.witnesses.slice(1)] }));
}

function witnessOf(request: WatchtowerSpendRequest): Uint8Array {
    const [witness] = request.transaction.witnesses;
    if (witness === undefined) throw new Error("the spend carries no witness");
    return witness;
}

function decide(request: WatchtowerSpendRequest, record: ChannelPolicyRecord = RECORD, approval: WatchtowerApproval = APPROVAL) {
    return decideWatchtowerSpend(KEYS, record, approval, request);
}

function bodyOf(entries: Uint8Array[], balances: [Uint8Array, bigint][]): Uint8Array {
    return concatBytes(
        Uint8Array.of(entries.length),
        ...entries,
        ...balances.map(([hash, amount]) => concatBytes(hash, uint128Le(amount))),
    );
}

function unlockWitness(body: Uint8Array, unlockType: number): Uint8Array {
    return concatBytes(WITNESS_PREFIX, Uint8Array.of(1), body, Uint8Array.of(unlockType, 0), UNSIGNED);
}

// The peer's commitment's settlement body.
const COMMITTED = readSettlementUnlock(witnessOf(requestOf(INBOUND_TLC)), "fullPaymentHash");
const [INBOUND_ENTRY, OUTBOUND_ENTRY] = COMMITTED.tlcEntries as [Uint8Array, Uint8Array];
const [PEER_BALANCE, DEVICE_BALANCE] = COMMITTED.balances;
const INBOUND_SHANNONS = BigInt(watchtowerSpendOf(vectors, INBOUND_TLC).released_shannons);
const OUTBOUND_SHANNONS = BigInt(watchtowerSpendOf(vectors, OUTBOUND_TLC).released_shannons);
const ZERO_HASH = new Uint8Array(20);
const KEPT_BALANCES: [Uint8Array, bigint][] = [
    [PEER_BALANCE.pubkeyHash, PEER_BALANCE.amountShannons],
    [DEVICE_BALANCE.pubkeyHash, DEVICE_BALANCE.amountShannons],
];
const PEER_SETTLED: [Uint8Array, bigint][] = [
    [ZERO_HASH, 0n],
    [DEVICE_BALANCE.pubkeyHash, DEVICE_BALANCE.amountShannons],
];

// Spent at a zero since, its witness carrying the body given.
function descendantRequest(body: Uint8Array, unlockType: number, purpose: WatchtowerKeyPurpose): WatchtowerSpendRequest {
    return withWitness({ ...requestOf(SETTLEMENT), purpose }, unlockWitness(body, unlockType));
}

function withOwnRemainder(request: WatchtowerSpendRequest): WatchtowerSpendRequest {
    const next = nextSettlementWitness(readSettlementUnlock(witnessOf(request), "fullPaymentHash"), true);
    return withOutput(request, 0, (output) => ({
        ...output,
        lock: { ...output.lock, args: buildRemainderLockArgs(REMOTE_CELL.lock.args, next) },
    }));
}

// The last party's unlock leaves no remainder.
function paidOut(request: WatchtowerSpendRequest, shannons: bigint): WatchtowerSpendRequest {
    const destination = requestOf(SETTLEMENT).transaction.outputs[1] as CellOutput;
    return withTransaction(request, () => ({
        outputs: [{ ...destination, capacityShannons: shannons }],
        outputsData: [new Uint8Array(0)],
    }));
}

// The peer's commitment, its lock args committing the body given instead of fiber's.
function committing(body: Uint8Array, commitmentNumber = 7): SignedCommitmentRecord {
    // The version sits big-endian at bytes 28 to 36 of the args.
    const version = new Uint8Array(8);
    new DataView(version.buffer).setBigUint64(0, BigInt(commitmentNumber), false);
    const args = concatBytes(REMOTE_CELL.lock.args.subarray(0, 28), version, blake160(body), REMOTE_CELL.lock.args.subarray(56));
    return {
        ...REMOTE_COMMITMENT,
        commitmentNumber,
        source: {
            ...(REMOTE_COMMITMENT.source as NonNullable<SignedCommitmentRecord["source"]>),
            output: cellHex({ ...REMOTE_CELL, lock: { ...REMOTE_CELL.lock, args } }),
        },
        settlementWitness: bytesToHex(body),
    };
}

// The unlock without a preimage: its type, the preimage flag, then the 65-byte signature.
function withUnlockType(request: WatchtowerSpendRequest, unlockType: number): WatchtowerSpendRequest {
    const witness = witnessOf(request).slice();
    witness[witness.length - 67] = unlockType;
    return withWitness(request, witness);
}

function splitDestination(request: WatchtowerSpendRequest, parts: number): WatchtowerSpendRequest {
    const { outputs, outputsData } = request.transaction;
    const [remainder, paid] = outputs as [CellOutput, CellOutput];
    const share = paid.capacityShannons / BigInt(parts);
    const split = Array.from({ length: parts }, (_, index) => ({
        ...paid,
        capacityShannons: index === 0 ? paid.capacityShannons - share * BigInt(parts - 1) : share,
    }));
    return withTransaction(request, () => ({
        outputs: [remainder, ...split],
        outputsData: [...outputsData.slice(0, 1), ...split.map(() => new Uint8Array(0))],
    }));
}

describe("decideWatchtowerSpend", () => {
    // Through the engine: the record stored, every spend fiber's watchtower built, every variant fiber refuses.
    describe("fiber's spends", () => {
        async function engineOverVectors() {
            const store = new SignerStore(new InMemorySignerStorage());
            const engine = new PolicyEngine(store, { watchtower: APPROVAL });
            const { channel, device } = vectors;
            await engine.registerChannel(channel.channel_id, device.channel_index, "72000000000", toScript(channel.local_close_script));
            await store.updateChannelRecord(device.channel_index, (current) => {
                if (current === null) throw new Error("the channel was registered and holds no record");
                return { ...current, commitmentHashes: RECORD.commitmentHashes };
            });
            return { engine, store };
        }

        function recordedSpend(name: string, forRemote: boolean): WatchtowerSpendRecord {
            const spend = watchtowerSpendOf(vectors, name);
            const tx = toTransaction(spend.transaction);
            const unlock = readSettlementUnlock(tx.witnesses[0] as Uint8Array, "fullPaymentHash");
            // The last party's spend pays its one output out: it leaves no remainder.
            const [remainder] = tx.outputs.length === 1 ? [] : tx.outputs;
            return {
                requestId: spend.request_id.slice(2),
                purpose: toWatchtowerKeyPurpose(spend.key_purpose),
                view: forRemote ? "remote" : "local",
                commitmentNumber: forRemote ? 7 : 6,
                tlcEntry: unlock.target.kind === "tlc" ? bytesToHex(unlock.tlcEntries[unlock.target.index] as Uint8Array) : null,
                txHash: spend.tx_hash.slice(2),
                remainder: remainder === undefined ? null : { output: cellHex(remainder), outputData: "" },
                signature: null,
                applied: false,
            };
        }

        // The peer first takes back its own TLC by timeout, so the device's spends after it are the same unlocks rebuilt.
        it.each<[string, boolean, string[]]>([
            ["peer's", true, [INBOUND_TLC, PEER_FIRST_OUTBOUND_TLC, LAST_PARTY]],
            ["device's own", false, [OWN_INBOUND_TLC, OWN_PEER_FIRST_OUTBOUND_TLC, OWN_LAST_PARTY]],
        ])(
            "claims every spend of the %s commitment in the watchtower's order, each replacing the one of its unlock",
            async (_, forRemote, kept) => {
                const { engine, store } = await engineOverVectors();
                const { spends } = watchtowerViewOf(vectors, forRemote);
                for (const spend of spends) {
                    await expect(engine.checkWatchtowerSpend(KEYS, vectors.channel.channel_id, requestOf(spend.name))).resolves.toEqual({
                        status: "fresh",
                    });
                }
                const record = await store.getChannelRecord(vectors.device.channel_index);
                expect(record?.watchtowerSpends).toEqual(kept.map((name) => recordedSpend(name, forRemote)));
            },
        );

        it.each(watchtower.variants.map((variant) => [variant.name, variant] as const))("refuses %s, as fiber does", async (_, variant) => {
            const { engine, store } = await engineOverVectors();
            const before = await store.getChannelRecord(vectors.device.channel_index);
            const request: WatchtowerSpendRequest = {
                requestId: hexToBytes(variant.request_id.slice(2)),
                purpose: toWatchtowerKeyPurpose(variant.key_purpose),
                transaction: toTransaction(variant.transaction),
            };
            const refused = engine.checkWatchtowerSpend(KEYS, vectors.channel.channel_id, request);
            await expect(refused).rejects.toBeInstanceOf(PolicyRefusalError);
            await expect(refused).rejects.toMatchObject({ code: "policy_refusal", message: WATCHTOWER_VARIANT_REFUSALS[variant.name] });
            await expect(store.getChannelRecord(vectors.device.channel_index)).resolves.toEqual(before);
        });
    });

    describe("the claim", () => {
        it("records the purpose alone, whatever else the request carries", () => {
            const request = { ...requestOf(INBOUND_TLC), purpose: { kind: "tlc" as const, commitmentNumber: 6, extra: "x" } };
            expect(decide(request).record.watchtowerSpends?.[0]?.purpose).toEqual({ kind: "tlc", commitmentNumber: 6 });
            const settlement = { ...requestOf(SETTLEMENT), purpose: { kind: "settlement" as const, commitmentNumber: 6 } };
            expect(decide(settlement).record.watchtowerSpends?.[0]?.purpose).toEqual({ kind: "settlement" });
        });

        it("records the entry of the TLC its unlock names", () => {
            const request = descendantRequest(bodyOf([INBOUND_ENTRY, OUTBOUND_ENTRY], KEPT_BALANCES), 1, {
                kind: "tlc",
                commitmentNumber: 5,
            });
            expect(decide(withOwnRemainder(request)).record.watchtowerSpends?.[0]?.tlcEntry).toBe(bytesToHex(OUTBOUND_ENTRY));
        });

        it("leaves the record it was given untouched", () => {
            const before = structuredClone(RECORD);
            decide(requestOf(INBOUND_TLC));
            expect(RECORD).toEqual(before);
        });
    });

    describe("the structure", () => {
        it.each<[string, () => WatchtowerSpendRequest, string]>([
            ["a request that is no object", () => null as never, "TypeError: request must be an object"],
            [
                "a request id of 31 bytes",
                () => ({ ...requestOf(INBOUND_TLC), requestId: new Uint8Array(31) }),
                "TypeError: request.requestId must be 32 bytes, got 31",
            ],
            [
                "a request id in hex",
                () => ({ ...requestOf(INBOUND_TLC), requestId: "00".repeat(32) as never }),
                "TypeError: request.requestId must be a Uint8Array",
            ],
            [
                "no purpose",
                () => ({ ...requestOf(INBOUND_TLC), purpose: undefined as never }),
                "TypeError: request.purpose must be an object",
            ],
            [
                "a purpose of another kind",
                () => ({ ...requestOf(INBOUND_TLC), purpose: { kind: "revocation" } as never }),
                "TypeError: request.purpose.kind must be settlement or tlc",
            ],
            [
                "a TLC purpose without its number",
                () => ({ ...requestOf(INBOUND_TLC), purpose: { kind: "tlc" } as never }),
                "RangeError: request.purpose.commitmentNumber must be an integer between 0 and 281474976710655, got undefined",
            ],
            [
                "a TLC purpose above the chain's last number",
                () => ({ ...requestOf(INBOUND_TLC), purpose: { kind: "tlc", commitmentNumber: 2 ** 48 } }),
                "RangeError: request.purpose.commitmentNumber must be an integer between 0 and 281474976710655, got 281474976710656",
            ],
            [
                "version 1",
                () => withTransaction(requestOf(INBOUND_TLC), () => ({ version: 1 })),
                "TypeError: watchtower structure: the spend must be version 0",
            ],
            [
                "a header dep",
                () => withTransaction(requestOf(INBOUND_TLC), () => ({ headerDeps: [new Uint8Array(32)] })),
                "TypeError: watchtower structure: the spend must carry no header deps",
            ],
            [
                "no input",
                () => withTransaction(requestOf(INBOUND_TLC), () => ({ inputs: [] })),
                "TypeError: watchtower structure: the spend must spend an input",
            ],
            [
                "a data missing for an output",
                () => withTransaction(requestOf(INBOUND_TLC), (tx) => ({ outputsData: tx.outputsData.slice(1) })),
                "TypeError: watchtower structure: the spend must carry one data per output",
            ],
            [
                "a data more than its outputs",
                () => withTransaction(requestOf(INBOUND_TLC), (tx) => ({ outputsData: [...tx.outputsData, new Uint8Array(0)] })),
                "TypeError: watchtower structure: the spend must carry one data per output",
            ],
            [
                "no witness list",
                () => withTransaction(requestOf(INBOUND_TLC), () => ({ witnesses: null as never })),
                "TypeError: watchtower structure: the spend must carry a witness list",
            ],
            [
                "a field the tx hash covers malformed",
                () =>
                    withTransaction(requestOf(INBOUND_TLC), (tx) => ({
                        cellDeps: tx.cellDeps.map((cellDep) => ({ ...cellDep, depType: "none" as never })),
                    })),
                "TypeError: transaction.cellDeps[0].depType must be one of code, dep_group",
            ],
        ])("refuses %s as malformed", (_, request, message) => {
            const refusal = policyRefusal(() => decide(request()));
            expect(refusal.code).toBe("malformed");
            expect(refusal.message).toBe(message);
        });
    });

    describe("a repeat", () => {
        it("serves a request claimed already, changing nothing", () => {
            const { record } = decide(requestOf(INBOUND_TLC));
            const repeat = decide(requestOf(INBOUND_TLC), record);
            expect(repeat.verdict).toEqual({ status: "already-signed", signature: null });
            expect(repeat.record).toBe(record);
        });

        it("carries the signature recorded for it", () => {
            const { record } = decide(requestOf(INBOUND_TLC));
            const [spend] = record.watchtowerSpends ?? [];
            const signed = { ...record, watchtowerSpends: [{ ...(spend as WatchtowerSpendRecord), signature: SIGNATURE }] };
            expect(decide(requestOf(INBOUND_TLC), signed).verdict).toEqual({ status: "already-signed", signature: hexToBytes(SIGNATURE) });
        });

        it.each<[string, string | null]>([
            ["pending", null],
            ["signed", SIGNATURE],
        ])("runs every rule again on a %s repeat, which a destination the host no longer approves refuses", (_, signature) => {
            const { record } = decide(requestOf(INBOUND_TLC));
            const [spend] = record.watchtowerSpends ?? [];
            const claimed = { ...record, watchtowerSpends: [{ ...(spend as WatchtowerSpendRecord), signature }] };
            const moved = { ...APPROVAL, destination: { ...APPROVAL.destination, args: new Uint8Array(20) } };
            const refusal = policyRefusal(() => decide(requestOf(INBOUND_TLC), claimed, moved));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe("watchtower destination: output 1 must pay the approved destination, with no type and no data");
        });

        it("refuses the request again for another spend", () => {
            const { record } = decide(requestOf(INBOUND_TLC));
            const another = withTransaction(requestOf(INBOUND_TLC), (tx) => ({ inputs: tx.inputs.slice(0, 2) }));
            const refusal = policyRefusal(() => decide(another, record));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe(
                `watchtower repeat: request ${watchtowerSpendOf(vectors, INBOUND_TLC).request_id.slice(2)} was claimed for another spend`,
            );
        });

        it("refuses the request again under another key by the key rule", () => {
            const { record } = decide(requestOf(INBOUND_TLC));
            const refusal = policyRefusal(() =>
                decide({ ...requestOf(INBOUND_TLC), purpose: { kind: "tlc", commitmentNumber: 5 } }, record),
            );
            expect(refusal.message).toBe("watchtower key: TLC 0 does not settle to the device's TLC key at commitment number 5");
        });
    });

    describe("the spends recorded", () => {
        function recorded(view: "remote" | "local", commitmentNumber: number, tlcEntry: string | null): WatchtowerSpendRecord {
            return {
                requestId: `${view === "remote" ? "a" : "b"}${commitmentNumber}`.padEnd(64, "0"),
                purpose: tlcEntry === null ? { kind: "settlement" } : { kind: "tlc", commitmentNumber: 5 },
                view,
                commitmentNumber,
                tlcEntry,
                txHash: "ef".repeat(32),
                remainder: null,
                signature: SIGNATURE,
                applied: false,
            };
        }

        // Fiber asks again under a new request each time the spend it rebuilds changes, the fee inputs it found among them.
        it("replaces a claim of the same commitment and unlock never signed, by the spend of another request", () => {
            const { record } = decide(requestOf(INBOUND_TLC));
            const replacement = withTransaction({ ...requestOf(INBOUND_TLC), requestId: new Uint8Array(32).fill(0x77) }, (tx) => ({
                inputs: tx.inputs.slice(0, 2),
            }));
            const decision = decide(replacement, record);
            expect(decision.verdict).toEqual({ status: "fresh" });
            expect(decision.record.watchtowerSpends?.map((spend) => [spend.requestId, spend.txHash])).toEqual([
                ["77".repeat(32), bytesToHex(computeTxHash(replacement.transaction))],
            ]);
        });

        it("keeps the spends of the other unlocks, in the order claimed", () => {
            const { record } = decide(requestOf(INBOUND_TLC));
            const decision = decide(requestOf(OUTBOUND_TLC), record);
            expect(decision.record.watchtowerSpends?.map((spend) => [spend.tlcEntry, spend.commitmentNumber])).toEqual([
                [bytesToHex(INBOUND_ENTRY), 7],
                [bytesToHex(OUTBOUND_ENTRY), 7],
            ]);
        });

        it("keeps the spend of the other view's commitment at the same version, for the same unlock", () => {
            const atSeven: ChannelPolicyRecord = {
                ...RECORD,
                commitmentHashes: { remote: REMOTE_COMMITMENT, local: { ...LOCAL_COMMITMENT, commitmentNumber: 7 } },
                watchtowerSpends: [recorded("local", 7, null)],
            };
            const decision = decide(requestOf(SETTLEMENT), atSeven);
            expect(decision.record.watchtowerSpends?.map((spend) => [spend.view, spend.commitmentNumber, spend.tlcEntry])).toEqual([
                ["local", 7, null],
                ["remote", 7, null],
            ]);
        });

        // Fiber keeps the requests a rebuild superseded and serves the lowest id first, and its answer or the mark may be lost.
        describe("of an unlock whose spend the record signed", () => {
            const REBUILT = withTransaction({ ...requestOf(INBOUND_TLC), requestId: new Uint8Array(32).fill(0x77) }, (tx) => ({
                inputs: tx.inputs.slice(0, 2),
            }));

            function signedRecord(applied: boolean): ChannelPolicyRecord {
                const { record } = decide(requestOf(INBOUND_TLC));
                const [spend] = record.watchtowerSpends ?? [];
                return { ...record, watchtowerSpends: [{ ...(spend as WatchtowerSpendRecord), signature: SIGNATURE, applied }] };
            }

            it.each([
                ["not yet confirmed by fiber", false],
                ["fiber confirmed", true],
            ])("signs another request for it unclaimed, keeping the spend %s", (_, applied) => {
                const record = signedRecord(applied);
                const decision = decide(REBUILT, record);
                expect(decision.verdict).toEqual({ status: "unclaimed" });
                expect(decision.record).toBe(record);
            });

            it("runs every rule on that request first", () => {
                const moved = { ...APPROVAL, destination: { ...APPROVAL.destination, args: new Uint8Array(20) } };
                const refusal = policyRefusal(() => decide(REBUILT, signedRecord(false), moved));
                expect(refusal.message).toBe(
                    "watchtower destination: output 1 must pay the approved destination, with no type and no data",
                );
            });

            it("serves the signed request itself as a repeat, with its signature", () => {
                expect(decide(requestOf(INBOUND_TLC), signedRecord(false)).verdict).toEqual({
                    status: "already-signed",
                    signature: hexToBytes(SIGNATURE),
                });
            });

            it("claims the spend of another unlock beside it", () => {
                const decision = decide(requestOf(OUTBOUND_TLC), signedRecord(true));
                expect(decision.verdict).toEqual({ status: "fresh" });
                expect(decision.record.watchtowerSpends?.map((spend) => [spend.tlcEntry, spend.signature, spend.applied])).toEqual([
                    [bytesToHex(INBOUND_ENTRY), SIGNATURE, true],
                    [bytesToHex(OUTBOUND_ENTRY), null, false],
                ]);
            });

            it("claims the spend of the same unlock in the other view's commitment at the same version", () => {
                const atSeven: ChannelPolicyRecord = {
                    ...RECORD,
                    commitmentHashes: { remote: REMOTE_COMMITMENT, local: { ...LOCAL_COMMITMENT, commitmentNumber: 7 } },
                    watchtowerSpends: [recorded("local", 7, null)],
                };
                expect(decide(requestOf(SETTLEMENT), atSeven).verdict).toEqual({ status: "fresh" });
            });
        });

        it("drops the spends of a commitment no longer registered", () => {
            const stale: ChannelPolicyRecord = {
                ...RECORD,
                watchtowerSpends: [recorded("remote", 6, null), recorded("local", 6, null), recorded("local", 7, null)],
            };
            const decision = decide(requestOf(SETTLEMENT), stale);
            expect(decision.record.watchtowerSpends?.map((spend) => [spend.view, spend.commitmentNumber])).toEqual([
                ["local", 6],
                ["remote", 7],
            ]);
        });
    });

    describe("the source", () => {
        function withInput0(request: WatchtowerSpendRequest, change: (input: CellInput) => CellInput): WatchtowerSpendRequest {
            return withTransaction(request, (tx) => ({ inputs: tx.inputs.map((input, index) => (index === 0 ? change(input) : input)) }));
        }

        it("takes the commitment cell whatever tx hash names it", () => {
            const request = withInput0(requestOf(INBOUND_TLC), (input) => ({
                ...input,
                previousOutput: { ...input.previousOutput, txHash: new Uint8Array(32).fill(0x3c) },
            }));
            expect(decide(request).verdict).toEqual({ status: "fresh" });
        });

        it("takes the commitment cell at any since past zero, which its lock holds to the delay", () => {
            expect(decide(withInput0(requestOf(INBOUND_TLC), (input) => ({ ...input, since: 1n }))).verdict).toEqual({ status: "fresh" });
        });

        // The lock refuses the commitment cell before its delay, so the chain holds its capacity to whatever it is.
        it("reads the commitment's body at a zero since as a descendant's, its remainder held to no capacity", () => {
            const request = withOutput(
                withInput0(requestOf(INBOUND_TLC), (input) => ({ ...input, since: 0n })),
                0,
                (output) => ({ ...output, capacityShannons: output.capacityShannons + 1n }),
            );
            expect(decide(request).verdict).toEqual({ status: "fresh" });
        });

        it.each<[string, (request: WatchtowerSpendRequest) => WatchtowerSpendRequest, ChannelPolicyRecord]>([
            [
                "a body a shannon off the commitment's",
                (request) =>
                    withWitness(
                        request,
                        concatBytes(
                            WITNESS_PREFIX,
                            Uint8Array.of(1),
                            bodyOf(
                                [INBOUND_ENTRY, OUTBOUND_ENTRY],
                                [
                                    [PEER_BALANCE.pubkeyHash, PEER_BALANCE.amountShannons + 1n],
                                    [DEVICE_BALANCE.pubkeyHash, DEVICE_BALANCE.amountShannons],
                                ],
                            ),
                            witnessOf(request).slice(17 + COMMITTED.body.length),
                        ),
                    ),
                RECORD,
            ],
            ["a descendant's body", (request) => withWitness(request, witnessOf(requestOf(OUTBOUND_TLC))), RECORD],
            [
                "a commitment the record keeps no cell for",
                (request) => request,
                { ...RECORD, commitmentHashes: { remote: { commitmentNumber: 7, txHash: "34".repeat(32) } } },
            ],
            [
                "a commitment the record keeps no settlement body for",
                (request) => request,
                { ...RECORD, commitmentHashes: { remote: { ...REMOTE_COMMITMENT, settlementWitness: undefined } } },
            ],
            ["a channel that signed no commitment", (request) => request, { ...RECORD, commitmentHashes: {} }],
        ])("refuses, at a since, %s", (_, change, record) => {
            const refusal = policyRefusal(() => decide(change(requestOf(INBOUND_TLC)), record));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe(COMMITMENT_SOURCE);
        });

        it.each([
            ["the commitment's", INBOUND_TLC],
            ["a descendant's", OUTBOUND_TLC],
        ])("refuses %s other output", (_, name) => {
            const request = withInput0(requestOf(name), (input) => ({ ...input, previousOutput: { ...input.previousOutput, index: 1 } }));
            const refusal = policyRefusal(() => decide(request));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe(
                "watchtower source: input 0 must spend output 0, which holds every commitment lock cell, not output 1",
            );
        });

        it("refuses a descendant on a channel that signed no commitment", () => {
            const refusal = policyRefusal(() => decide(requestOf(OUTBOUND_TLC), { ...RECORD, commitmentHashes: {} }));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe(`${DESCENDANT_SOURCE}no commitment has been signed`);
        });
    });

    // The peer may broadcast the commitment the last one replaced until it revokes it, and fiber's watchtower settles either.
    describe("the remote commitment before the last", () => {
        // The one after it, no TLC left and the peer paid a shannon more: no spend below descends from it.
        const NEXT_REMOTE_COMMITMENT = committing(
            bodyOf([], [[PEER_BALANCE.pubkeyHash, PEER_BALANCE.amountShannons + 1n], KEPT_BALANCES[1] as [Uint8Array, bigint]]),
            8,
        );
        const PREVIOUS_RECORD: ChannelPolicyRecord = {
            ...RECORD,
            commitmentHashes: { remote: NEXT_REMOTE_COMMITMENT, local: LOCAL_COMMITMENT },
            previousRemoteCommitment: {
                commitmentNumber: 7,
                source: REMOTE_COMMITMENT.source as NonNullable<SignedCommitmentRecord["source"]>,
                settlementWitness: REMOTE_COMMITMENT.settlementWitness as string,
            },
        };

        it.each([
            ["its commitment cell", INBOUND_TLC],
            ["a cell descending from it", OUTBOUND_TLC],
        ])("spends %s, recording its version", (_, name) => {
            const decision = decide(requestOf(name), PREVIOUS_RECORD);
            expect(decision.verdict).toEqual({ status: "fresh" });
            expect(decision.record.watchtowerSpends?.map((spend) => [spend.view, spend.commitmentNumber])).toEqual([["remote", 7]]);
        });

        // The last one added a TLC the peer offered, from the peer's balance: once the peer settled, a body may descend from both,
        // and the final sweep leaves no remainder whose args would name one.
        it("records a final sweep descending from both under the last one, the first it can descend from", () => {
            const added = Uint8Array.from(INBOUND_ENTRY, (byte, index) => (index === 1 ? byte ^ 1 : byte));
            const withAdded = committing(
                bodyOf(
                    [INBOUND_ENTRY, OUTBOUND_ENTRY, added],
                    [[PEER_BALANCE.pubkeyHash, PEER_BALANCE.amountShannons - 1n], KEPT_BALANCES[1] as [Uint8Array, bigint]],
                ),
                8,
            );
            const released = DEVICE_BALANCE.amountShannons + INBOUND_SHANNONS + OUTBOUND_SHANNONS;
            const sweep = paidOut(
                descendantRequest(bodyOf([INBOUND_ENTRY, OUTBOUND_ENTRY], PEER_SETTLED), 0xff, { kind: "settlement" }),
                released - MAX_FEE,
            );
            const recordedUnder = (remote: SignedCommitmentRecord) =>
                decide(sweep, { ...PREVIOUS_RECORD, commitmentHashes: { remote, local: LOCAL_COMMITMENT } }).record.watchtowerSpends?.map(
                    (spend) => [spend.view, spend.commitmentNumber],
                );
            expect(recordedUnder(withAdded)).toEqual([["remote", 8]]);
            expect(recordedUnder(NEXT_REMOTE_COMMITMENT)).toEqual([["remote", 7]]);
        });

        // Fiber signs a commitment again with nothing changed but its number: the peer may broadcast either.
        describe("of the same body as the last one", () => {
            function sameBody(body: Uint8Array): ChannelPolicyRecord {
                const previous = committing(body, 7);
                return {
                    ...RECORD,
                    commitmentHashes: { remote: committing(body, 8), local: LOCAL_COMMITMENT },
                    previousRemoteCommitment: {
                        commitmentNumber: 7,
                        source: previous.source as NonNullable<SignedCommitmentRecord["source"]>,
                        settlementWitness: previous.settlementWitness as string,
                    },
                };
            }

            it("records the cell's spend under the commitment its remainder's args name", () => {
                const decision = decide(requestOf(INBOUND_TLC), sameBody(COMMITTED.body));
                expect(decision.verdict).toEqual({ status: "fresh" });
                expect(decision.record.watchtowerSpends?.map((spend) => [spend.view, spend.commitmentNumber])).toEqual([["remote", 7]]);
            });

            it("records a final sweep of the cell, which leaves no remainder, under the last one", () => {
                const body = bodyOf([INBOUND_ENTRY, OUTBOUND_ENTRY], PEER_SETTLED);
                const released = DEVICE_BALANCE.amountShannons + INBOUND_SHANNONS + OUTBOUND_SHANNONS;
                const sweep = paidOut(
                    withWitness({ ...requestOf(INBOUND_TLC), purpose: { kind: "settlement" } }, unlockWitness(body, 0xff)),
                    released - MAX_FEE,
                );
                const decision = decide(sweep, sameBody(body));
                expect(decision.verdict).toEqual({ status: "fresh" });
                expect(decision.record.watchtowerSpends?.map((spend) => [spend.view, spend.commitmentNumber])).toEqual([["remote", 8]]);
            });
        });

        // The peer broadcast N-1 = {IN, OUT}, and N = {X, OUT} holds the same balances: once the device claimed IN, the body
        // {OUT} descends from both, and the remainder of its claim keeps N-1's args.
        it("records a descendant's non-final spend under the commitment its remainder's args name", () => {
            const foreign = Uint8Array.from(INBOUND_ENTRY, (byte, index) => (index === 1 ? byte ^ 1 : byte));
            const record: ChannelPolicyRecord = {
                ...PREVIOUS_RECORD,
                commitmentHashes: { remote: committing(bodyOf([foreign, OUTBOUND_ENTRY], KEPT_BALANCES), 8), local: LOCAL_COMMITMENT },
            };
            const claimed = decide(requestOf(INBOUND_TLC), record);
            const decision = decide(requestOf(OUTBOUND_TLC), claimed.record);
            expect(decision.verdict).toEqual({ status: "fresh" });
            expect(decision.record.watchtowerSpends?.map((spend) => [spend.commitmentNumber, spend.tlcEntry])).toEqual([
                [7, bytesToHex(INBOUND_ENTRY)],
                [7, bytesToHex(OUTBOUND_ENTRY)],
            ]);
        });

        it("names its fault after the last remote commitment's", () => {
            const body = bodyOf([OUTBOUND_ENTRY], [[PEER_BALANCE.pubkeyHash, 1n], KEPT_BALANCES[1] as [Uint8Array, bigint]]);
            expect(
                policyRefusal(() => decide(descendantRequest(body, 0, { kind: "tlc", commitmentNumber: 5 }), PREVIOUS_RECORD)).message,
            ).toBe(
                `${DESCENDANT_SOURCE}the remote view's commitment ` +
                    "does not list TLC 0 of the settlement body, and the remote view's previous commitment holds another balance 0 than the " +
                    "settlement body, which has not settled it, and the local view's commitment does not list TLC 0 of the settlement body",
            );
        });

        it("keeps the spend of the last remote commitment beside one of it, for the same unlock", () => {
            const lastSpend: WatchtowerSpendRecord = {
                requestId: "a8".padEnd(64, "0"),
                purpose: { kind: "settlement" },
                view: "remote",
                commitmentNumber: 8,
                tlcEntry: null,
                txHash: "ef".repeat(32),
                remainder: null,
                signature: SIGNATURE,
                applied: false,
            };
            const decision = decide(requestOf(SETTLEMENT), { ...PREVIOUS_RECORD, watchtowerSpends: [lastSpend] });
            expect(decision.record.watchtowerSpends?.map((spend) => [spend.commitmentNumber, spend.tlcEntry])).toEqual([
                [8, null],
                [7, null],
            ]);
        });
    });

    describe("the witness", () => {
        it.each([
            ["the commitment cell", INBOUND_TLC],
            ["a descendant", OUTBOUND_TLC],
        ])("refuses a spend of %s without witness 0 as malformed", (_, name) => {
            const refusal = policyRefusal(() => decide(withTransaction(requestOf(name), () => ({ witnesses: [] }))));
            expect(refusal.code).toBe("malformed");
            expect(refusal.message).toBe("watchtower witness: the spend carries no settlement witness at index 0");
        });

        it("refuses a witness the unlock reader refuses as malformed", () => {
            const witness = witnessOf(requestOf(INBOUND_TLC)).slice();
            witness[16] = 2;
            const refusal = policyRefusal(() => decide(withWitness(requestOf(INBOUND_TLC), witness)));
            expect(refusal.code).toBe("malformed");
            expect(refusal.message).toBe("TypeError: settlement witness must count exactly 1 unlock at byte 16");
        });
    });

    // A cell the device never signed, the peer's own spend's remainder among them: the lock holds its body to its args.
    describe("a descendant", () => {
        it.each<[string, Uint8Array, string]>([
            [
                "a TLC the commitment never listed",
                bodyOf([Uint8Array.from(OUTBOUND_ENTRY, (byte, index) => (index === 1 ? byte ^ 1 : byte))], KEPT_BALANCES),
                "commitment does not list TLC 0 of the settlement body",
            ],
            [
                "a TLC twice",
                bodyOf([OUTBOUND_ENTRY, OUTBOUND_ENTRY], KEPT_BALANCES),
                "commitment lists TLC 1 of the settlement body fewer times than the body does",
            ],
            [
                "a balance neither kept nor settled",
                bodyOf([], [[PEER_BALANCE.pubkeyHash, PEER_BALANCE.amountShannons - 1n], KEPT_BALANCES[1] as [Uint8Array, bigint]]),
                "commitment holds another balance 0 than the settlement body, which has not settled it",
            ],
            [
                "a balance whose key alone is zeroed",
                bodyOf([], [[ZERO_HASH, PEER_BALANCE.amountShannons], KEPT_BALANCES[1] as [Uint8Array, bigint]]),
                "commitment holds another balance 0 than the settlement body, which has not settled it",
            ],
            [
                "a balance whose amount alone is zeroed",
                bodyOf([], [KEPT_BALANCES[0] as [Uint8Array, bigint], [DEVICE_BALANCE.pubkeyHash, 0n]]),
                "commitment holds another balance 1 than the settlement body, which has not settled it",
            ],
        ])("refuses a body listing %s", (_, body, fault) => {
            const refusal = policyRefusal(() => decide(descendantRequest(body, 0xff, { kind: "settlement" }), REMOTE_RECORD));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe(`${DESCENDANT_SOURCE}the remote view's ${fault}`);
        });

        it("names the fault the body has against each view's commitment", () => {
            const body = bodyOf(
                [],
                [
                    [PEER_BALANCE.pubkeyHash, 1n],
                    [DEVICE_BALANCE.pubkeyHash, DEVICE_BALANCE.amountShannons],
                ],
            );
            expect(policyRefusal(() => decide(descendantRequest(body, 0xff, { kind: "settlement" }))).message).toBe(
                `${DESCENDANT_SOURCE}the remote view's commitment ` +
                    "holds another balance 0 than the settlement body, which has not settled it, and the local view's commitment holds " +
                    "another balance 0 than the settlement body, which has not settled it",
            );
        });

        // Equal entries, the parts of one payment among them, each stay claimable: fiber's validate takes a remaining TLC once.
        describe("of a commitment listing a TLC twice", () => {
            const TWICE_RECORD: ChannelPolicyRecord = {
                ...REMOTE_RECORD,
                commitmentHashes: { remote: committing(bodyOf([OUTBOUND_ENTRY, OUTBOUND_ENTRY], KEPT_BALANCES)) },
            };

            it("takes a body listing it twice", () => {
                const request = descendantRequest(bodyOf([OUTBOUND_ENTRY, OUTBOUND_ENTRY], KEPT_BALANCES), 1, {
                    kind: "tlc",
                    commitmentNumber: 5,
                });
                expect(decide(withOwnRemainder(request), TWICE_RECORD).verdict).toEqual({ status: "fresh" });
            });

            it("refuses a body listing it three times", () => {
                const body = bodyOf([OUTBOUND_ENTRY, OUTBOUND_ENTRY, OUTBOUND_ENTRY], KEPT_BALANCES);
                const refusal = policyRefusal(() => decide(descendantRequest(body, 1, { kind: "tlc", commitmentNumber: 5 }), TWICE_RECORD));
                expect(refusal.message).toBe(
                    `${DESCENDANT_SOURCE}the remote view's ` +
                        "commitment lists TLC 2 of the settlement body fewer times than the body does",
                );
            });
        });

        it("takes the remainder at whatever capacity: the chain holds the one its source left", () => {
            const request = withOutput(requestOf(SETTLEMENT), 0, (output) => ({
                ...output,
                capacityShannons: output.capacityShannons + 1n,
            }));
            expect(decide(request).verdict).toEqual({ status: "fresh" });
        });
    });

    describe("the key", () => {
        it.each<[string, WatchtowerSpendRequest, string]>([
            [
                "a TLC key on the balance's unlock",
                { ...requestOf(SETTLEMENT), purpose: { kind: "tlc", commitmentNumber: 6 } },
                "watchtower key: a TLC key signs a TLC's unlock, not a balance's",
            ],
            [
                "the settlement key on a TLC's unlock",
                { ...requestOf(INBOUND_TLC), purpose: { kind: "settlement" } },
                "watchtower key: the settlement key signs the unlock 0xff of the device's balance in a remote view",
            ],
            [
                "the settlement key on the unlock of the TLC at the device balance's index",
                descendantRequest(bodyOf([INBOUND_ENTRY, OUTBOUND_ENTRY], KEPT_BALANCES), 1, { kind: "settlement" }),
                "watchtower key: the settlement key signs the unlock 0xff of the device's balance in a remote view",
            ],
            [
                "the settlement key on the peer's balance in the peer's view",
                descendantRequest(bodyOf([], KEPT_BALANCES), 0xfe, { kind: "settlement" }),
                "watchtower key: the settlement key signs the unlock 0xff of the device's balance in a remote view",
            ],
            [
                "the settlement key on the peer's balance in the device's view",
                withUnlockType(requestOf(OWN_SETTLEMENT), 0xff),
                "watchtower key: the settlement key signs the unlock 0xfe of the device's balance in a local view",
            ],
            [
                "the key of another TLC's number",
                { ...requestOf(INBOUND_TLC), purpose: { kind: "tlc", commitmentNumber: 5 } },
                "watchtower key: TLC 0 does not settle to the device's TLC key at commitment number 5",
            ],
            [
                "the settlement key on a balance already settled",
                descendantRequest(
                    bodyOf(
                        [],
                        [
                            [PEER_BALANCE.pubkeyHash, PEER_BALANCE.amountShannons],
                            [ZERO_HASH, 0n],
                        ],
                    ),
                    0xff,
                    { kind: "settlement" },
                ),
                "watchtower key: the device's balance does not settle to its TLC base key",
            ],
        ])("refuses %s", (_, request, message) => {
            const refusal = policyRefusal(() => decide(request));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe(message);
        });

        it.each<[string, () => WatchtowerSpendRequest, string]>([
            [
                "a TLC the device received, unlocked without its preimage",
                () => withWitness(requestOf(INBOUND_TLC), unlockWitness(COMMITTED.body, 0)),
                "watchtower preimage: TLC 0 is one the device received, which its preimage alone unlocks",
            ],
            [
                "a TLC the device offered, unlocked with a preimage",
                () => {
                    const { body } = readSettlementUnlock(witnessOf(requestOf(OUTBOUND_TLC)), "fullPaymentHash");
                    const witness = concatBytes(WITNESS_PREFIX, Uint8Array.of(1), body, Uint8Array.of(0, 1), UNSIGNED, PREIMAGE);
                    return withWitness(requestOf(OUTBOUND_TLC), witness);
                },
                "watchtower preimage: TLC 0 is one the device offered, which its timeout alone unlocks",
            ],
        ])("refuses %s", (_, request, message) => {
            const refusal = policyRefusal(() => decide(request()));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe(message);
        });

        // A commitment whose device balance is empty, built by the SDK's own builders over these inputs.
        it("refuses the settlement key on a balance of zero", () => {
            const input = {
                forRemote: true,
                fundingOutPoint: { txHash: hexToBytes("41".repeat(32)), index: 0 },
                remoteFundingPubkey: hexToBytes(vectors.peer.funding_pubkey),
                remoteTlcBasePubkey: hexToBytes(vectors.peer.tlc_base_pubkey),
                commitmentNumber: 3,
                commitmentDelayEpoch: 1099511627777n,
                commitmentFeeRate: 1000n,
                cellDepsCount: 2,
                udtTypeScript: null,
                liquidCapacityShannons: 80500000000n,
                settlementLocalShannons: 0n,
                settlementRemoteShannons: 80500000000n,
                localReservedCkbShannons: 0n,
                remoteReservedCkbShannons: 6300000000n,
                tlcs: [],
                commitmentLock: signingCommitmentLock(vectors),
                lockLayout: "fullPaymentHash" as const,
            };
            const tx = buildCommitmentTx(KEYS, input);
            const [output] = tx.outputs as [CellOutput];
            const body = buildCommitmentSettlementWitness(KEYS, input);
            const commitment: SignedCommitmentRecord = {
                commitmentNumber: 3,
                txHash: "12".repeat(32),
                source: { output: cellHex(output), outputData: "" },
                settlementWitness: bytesToHex(body),
            };
            // Its cell, at its delay.
            const request = withWitness(
                withTransaction(requestOf(SETTLEMENT), (spend) => ({
                    inputs: [
                        { since: 0xa000010000000001n, previousOutput: { txHash: computeTxHash(tx), index: 0 } },
                        ...spend.inputs.slice(1),
                    ],
                })),
                unlockWitness(body, 0xff),
            );
            const refusal = policyRefusal(() => decide(request, { ...RECORD, commitmentHashes: { remote: commitment } }));
            expect(refusal.message).toBe("watchtower key: the unlock releases nothing to the device");
        });
    });

    describe("the settlement", () => {
        it("refuses the device's balance while the body still holds a TLC the device offered", () => {
            const request = descendantRequest(bodyOf([INBOUND_ENTRY, OUTBOUND_ENTRY], KEPT_BALANCES), 0xff, { kind: "settlement" });
            const refusal = policyRefusal(() => decide(withOwnRemainder(request)));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe(
                "watchtower settlement: the body still holds TLC 1, which the device offered and fiber's watchtower claims first",
            );
        });

        // What it releases is its balance alone: the TLCs stay in the remainder.
        it("settles the device's balance while the body holds TLCs the device received alone", () => {
            const request = descendantRequest(bodyOf([INBOUND_ENTRY], KEPT_BALANCES), 0xff, { kind: "settlement" });
            const atBound = withOutput(withOwnRemainder(request), 1, (output) => ({
                ...output,
                capacityShannons: DEVICE_BALANCE.amountShannons - MAX_FEE,
            }));
            expect(decide(atBound).verdict).toEqual({ status: "fresh" });
        });

        describe("as the last party", () => {
            const RELEASED = DEVICE_BALANCE.amountShannons + INBOUND_SHANNONS + OUTBOUND_SHANNONS;
            const SWEEP = descendantRequest(bodyOf([INBOUND_ENTRY, OUTBOUND_ENTRY], PEER_SETTLED), 0xff, { kind: "settlement" });

            it("pays the destination its balance and every TLC left, less the fee approved", () => {
                const decision = decide(paidOut(SWEEP, RELEASED - MAX_FEE));
                expect(decision.verdict).toEqual({ status: "fresh" });
                expect(decision.record.watchtowerSpends?.[0]?.remainder).toBeNull();
            });

            it("refuses a shannon less", () => {
                const refusal = policyRefusal(() => decide(paidOut(SWEEP, RELEASED - MAX_FEE - 1n)));
                expect(refusal.message).toBe(
                    `watchtower destination: the destination is paid ${RELEASED - MAX_FEE - 1n} shannons, below the ${RELEASED} released ` +
                        `less the ${MAX_FEE} fee approved`,
                );
            });

            describe("of a commitment where the device's balance is zero", () => {
                const ZERO_BALANCE_RECORD: ChannelPolicyRecord = {
                    ...REMOTE_RECORD,
                    commitmentHashes: {
                        remote: committing(
                            bodyOf([INBOUND_ENTRY], [KEPT_BALANCES[0] as [Uint8Array, bigint], [DEVICE_BALANCE.pubkeyHash, 0n]]),
                        ),
                    },
                };

                it("sweeps the TLC left", () => {
                    const body = bodyOf(
                        [INBOUND_ENTRY],
                        [
                            [ZERO_HASH, 0n],
                            [DEVICE_BALANCE.pubkeyHash, 0n],
                        ],
                    );
                    const request = paidOut(descendantRequest(body, 0xff, { kind: "settlement" }), INBOUND_SHANNONS - MAX_FEE);
                    expect(decide(request, ZERO_BALANCE_RECORD).verdict).toEqual({ status: "fresh" });
                });

                it("refuses a body with no TLC left, which releases nothing", () => {
                    const body = bodyOf(
                        [],
                        [
                            [ZERO_HASH, 0n],
                            [DEVICE_BALANCE.pubkeyHash, 0n],
                        ],
                    );
                    const request = paidOut(descendantRequest(body, 0xff, { kind: "settlement" }), 0n);
                    const refusal = policyRefusal(() => decide(request, ZERO_BALANCE_RECORD));
                    expect(refusal.message).toBe("watchtower key: the unlock releases nothing to the device");
                });
            });
        });
    });

    it("refuses an unlock already signed as malformed", () => {
        const witness = witnessOf(requestOf(SETTLEMENT)).slice();
        witness[witness.length - 1] = 1;
        const refusal = policyRefusal(() => decide(withWitness(requestOf(SETTLEMENT), witness)));
        expect(refusal.code).toBe("malformed");
        expect(refusal.message).toBe("watchtower placeholder: the unlock's signature must be the 65 zero bytes of an unsigned spend");
    });

    describe("the remainder", () => {
        it.each<[string, WatchtowerSpendRequest]>([
            [
                "lock args that commit another body",
                withOutput(requestOf(INBOUND_TLC), 0, (output) => ({
                    ...output,
                    lock: { ...output.lock, args: Uint8Array.from(output.lock.args, (byte, index) => (index === 40 ? byte ^ 1 : byte)) },
                })),
            ],
            [
                "another lock's code hash",
                withOutput(requestOf(INBOUND_TLC), 0, (output) => ({ ...output, lock: { ...output.lock, codeHash: new Uint8Array(32) } })),
            ],
            [
                "another lock's hash type",
                withOutput(requestOf(INBOUND_TLC), 0, (output) => ({ ...output, lock: { ...output.lock, hashType: "data1" } })),
            ],
            ["a type", withOutput(requestOf(INBOUND_TLC), 0, (output) => ({ ...output, type: output.lock }))],
            ["data", withTransaction(requestOf(INBOUND_TLC), (tx) => ({ outputsData: [Uint8Array.of(0), ...tx.outputsData.slice(1)] }))],
            [
                "a shannon more than the commitment cell leaves",
                withOutput(requestOf(INBOUND_TLC), 0, (output) => ({ ...output, capacityShannons: output.capacityShannons + 1n })),
            ],
            [
                "a shannon less than the commitment cell leaves",
                withOutput(requestOf(INBOUND_TLC), 0, (output) => ({ ...output, capacityShannons: output.capacityShannons - 1n })),
            ],
            ["no output at all", withTransaction(requestOf(INBOUND_TLC), () => ({ outputs: [], outputsData: [] }))],
        ])("refuses output 0 with %s", (_, request) => {
            const refusal = policyRefusal(() => decide(request));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe(NOT_THE_REMAINDER);
        });

        it("takes no remainder from the last party, whose unlock takes the whole cell", () => {
            const request = requestOf(LAST_PARTY);
            expect(request.transaction.outputs).toHaveLength(1);
            expect(decide(request).record.watchtowerSpends?.at(-1)?.remainder).toBeNull();
        });

        it("refuses a remainder the last party's unlock leaves no room for", () => {
            const spend = requestOf(SETTLEMENT);
            const request = withTransaction(requestOf(LAST_PARTY), (tx) => ({
                outputs: [spend.transaction.outputs[0] as CellOutput, ...tx.outputs],
                outputsData: [new Uint8Array(0), ...tx.outputsData],
            }));
            expect(policyRefusal(() => decide(request)).message).toBe(
                "watchtower destination: output 0 must pay the approved destination, with no type and no data",
            );
        });
    });

    describe("the destination", () => {
        const RELEASED = INBOUND_SHANNONS;

        it.each([1, 2])("pays %s output to the destination", (parts) => {
            expect(decide(splitDestination(requestOf(INBOUND_TLC), parts)).verdict).toEqual({ status: "fresh" });
        });

        it.each<[string, WatchtowerSpendRequest, number]>([
            [
                "none",
                withTransaction(requestOf(INBOUND_TLC), (tx) => ({
                    outputs: tx.outputs.slice(0, 1),
                    outputsData: tx.outputsData.slice(0, 1),
                })),
                0,
            ],
            ["three", splitDestination(requestOf(INBOUND_TLC), 3), 3],
        ])("refuses %s besides the remainder", (_, request, count) => {
            const refusal = policyRefusal(() => decide(request));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe(`watchtower destination: the spend pays ${count} outputs besides the remainder, not 1 to 2`);
        });

        it.each<[string, WatchtowerSpendRequest, number]>([
            [
                "another lock's args",
                withOutput(requestOf(INBOUND_TLC), 1, (output) => ({ ...output, lock: { ...output.lock, args: new Uint8Array(20) } })),
                1,
            ],
            [
                "another lock's code hash",
                withOutput(requestOf(INBOUND_TLC), 1, (output) => ({ ...output, lock: { ...output.lock, codeHash: new Uint8Array(32) } })),
                1,
            ],
            [
                "another lock's hash type",
                withOutput(requestOf(INBOUND_TLC), 1, (output) => ({ ...output, lock: { ...output.lock, hashType: "data" } })),
                1,
            ],
            ["a type", withOutput(requestOf(INBOUND_TLC), 1, (output) => ({ ...output, type: output.lock })), 1],
            [
                "data",
                withTransaction(requestOf(INBOUND_TLC), (tx) => ({ outputsData: [...tx.outputsData.slice(0, 1), Uint8Array.of(0)] })),
                1,
            ],
            [
                "a second output elsewhere",
                withOutput(splitDestination(requestOf(INBOUND_TLC), 2), 2, (output) => ({
                    ...output,
                    lock: { ...output.lock, args: new Uint8Array(20) },
                })),
                2,
            ],
        ])("refuses an output with %s", (_, request, index) => {
            expect(policyRefusal(() => decide(request)).message).toBe(
                `watchtower destination: output ${index} must pay the approved destination, with no type and no data`,
            );
        });

        it("pays exactly what the TLC releases less the fee approved", () => {
            const request = withOutput(requestOf(INBOUND_TLC), 1, (output) => ({ ...output, capacityShannons: RELEASED - MAX_FEE }));
            expect(decide(request).verdict).toEqual({ status: "fresh" });
        });

        it("sums the payment over both destination outputs", () => {
            const atBound = withOutput(requestOf(INBOUND_TLC), 1, (output) => ({ ...output, capacityShannons: RELEASED - MAX_FEE }));
            expect(decide(splitDestination(atBound, 2)).verdict).toEqual({ status: "fresh" });
        });

        it("refuses a shannon less", () => {
            const request = withOutput(requestOf(INBOUND_TLC), 1, (output) => ({ ...output, capacityShannons: RELEASED - MAX_FEE - 1n }));
            const refusal = policyRefusal(() => decide(request));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe(
                `watchtower destination: the destination is paid ${RELEASED - MAX_FEE - 1n} shannons, below the ${RELEASED} released less the ${MAX_FEE} fee approved`,
            );
        });

        it.each<[string, string, bigint]>([
            ["the device's balance", SETTLEMENT, BigInt(watchtowerSpendOf(vectors, SETTLEMENT).released_shannons)],
            // Its body holds no TLC left, so what it releases is the device's balance.
            ["the device's balance, as the last party", LAST_PARTY, DEVICE_BALANCE.amountShannons],
        ])("holds the payment of %s at the same bound", (_, name, released) => {
            const last = requestOf(name).transaction.outputs.length - 1;
            const at = (shannons: bigint) => withOutput(requestOf(name), last, (output) => ({ ...output, capacityShannons: shannons }));
            expect(decide(at(released - MAX_FEE)).verdict).toEqual({ status: "fresh" });
            expect(policyRefusal(() => decide(at(released - MAX_FEE - 1n))).message).toMatch(
                /^watchtower destination: the destination is paid /,
            );
        });

        it("lets a fee approved above the release through any payment", () => {
            const request = withOutput(requestOf(INBOUND_TLC), 1, (output) => ({ ...output, capacityShannons: 0n }));
            expect(decide(request, RECORD, { ...APPROVAL, maxFeeShannons: RELEASED.toString() }).verdict).toEqual({ status: "fresh" });
        });
    });
});
