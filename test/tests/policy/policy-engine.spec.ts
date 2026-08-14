import { hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation";
import { COMMITMENT_LOCK_TESTNET } from "../../../src/digest";
import type { ChannelPolicyRecord, PolicySignRequest, SignSession } from "../../../src/policy";
import { PolicyEngine, PolicyRefusalError, SignerStore } from "../../../src/policy";
import { buildSessionCommitment } from "../../../src/policy/utils";
import { AsyncInMemorySignerStorage, InMemorySignerStorage } from "../../mocks/policy";
import { toOutPoint, toScript, toScriptOrNull, toTlc } from "../../utils/digest-inputs";
import { loadInteropVectors } from "../../utils/interop-vectors";

const vectors = loadInteropVectors();
const digest = vectors.digest;

const CHANNEL_ID = "0x1f".padEnd(66, "a");
const CHANNEL_INDEX = vectors.sdk_scheme.channel.channel_index;
const KEYS = deriveChannelKeys(hexToBytes(vectors.sdk_scheme.channel.seed));
const LOCAL_FUNDING_PUBKEY = pubkeyOf(KEYS.fundingKey);
const REMOTE_FUNDING_PUBKEY = hexToBytes(digest.remote.funding_pubkey);
const REMOTE_TLC_BASE_PUBKEY = hexToBytes(digest.remote.tlc_base_pubkey);

const OTHER_KEYS = deriveChannelKeys(hexToBytes(vectors.fiber_scheme.channel_seed));
const OTHER_FUNDING_PUBKEY = pubkeyOf(OTHER_KEYS.fundingKey);

const AGGREGATED_NONCE = hexToBytes("02".repeat(33) + "03".repeat(33));
const OTHER_AGGREGATED_NONCE = hexToBytes("02".repeat(33) + "04".repeat(33));

const OPENING_EXPOSURE = "62000000000";
const THREE_TLC_EXPOSURE = "59750000000";
const TLC_DECREASE = "2250000000";

function caseOf<Vector extends { name: string }>(cases: Vector[], name: string): Vector {
    const found = cases.find((entry) => entry.name === name);
    if (found === undefined) throw new Error(`the vectors carry no case named "${name}"`);
    return found;
}

function session(message: Uint8Array, overrides: Partial<SignSession> = {}): SignSession {
    return {
        orderedPublicKeys: [LOCAL_FUNDING_PUBKEY, REMOTE_FUNDING_PUBKEY],
        aggregatedNonce: AGGREGATED_NONCE,
        message,
        ...overrides,
    };
}

function commitmentRequest(name: string, overrides: Partial<PolicySignRequest> = {}): PolicySignRequest {
    const kase = caseOf(digest.commitment_cases, name);
    return {
        channelId: CHANNEL_ID,
        stateVersion: 1,
        nonceCommitmentNumber: kase.commitment_number,
        session: session(hexToBytes(kase.digest)),
        operation: {
            kind: "commitment_tx",
            input: {
                forRemote: kase.for_remote,
                fundingOutPoint: toOutPoint(kase.funding_out_point),
                remoteFundingPubkey: REMOTE_FUNDING_PUBKEY,
                remoteTlcBasePubkey: REMOTE_TLC_BASE_PUBKEY,
                commitmentNumber: kase.commitment_number,
                commitmentDelayEpoch: BigInt(kase.delay_epoch),
                commitmentFeeRate: BigInt(kase.fee_rate),
                cellDepsCount: kase.cell_deps_count,
                udtTypeScript: toScriptOrNull(kase.udt_type_script),
                toLocalShannons: BigInt(kase.to_local),
                toRemoteShannons: BigInt(kase.to_remote),
                settlementLocalShannons: BigInt(kase.settlement_local),
                settlementRemoteShannons: BigInt(kase.settlement_remote),
                localReservedCkbShannons: BigInt(kase.local_reserved),
                remoteReservedCkbShannons: BigInt(kase.remote_reserved),
                tlcs: kase.tlcs.map(toTlc),
                commitmentLock: COMMITMENT_LOCK_TESTNET,
            },
        },
        ...overrides,
    };
}

function shutdownRequest(name: string, overrides: Partial<PolicySignRequest> = {}): PolicySignRequest {
    const kase = caseOf(digest.shutdown_cases, name);
    return {
        channelId: CHANNEL_ID,
        stateVersion: 1,
        // Fiber signs a close with the commitment nonce of the current local number.
        nonceCommitmentNumber: 20,
        session: session(hexToBytes(kase.digest)),
        operation: {
            kind: "shutdown_tx",
            input: {
                fundingOutPoint: toOutPoint(kase.funding_out_point),
                remoteFundingPubkey: REMOTE_FUNDING_PUBKEY,
                localCloseScript: toScript(kase.local_close_script),
                remoteCloseScript: toScript(kase.remote_close_script),
                localFeeRate: BigInt(kase.local_fee_rate),
                remoteFeeRate: BigInt(kase.remote_fee_rate),
                cellDepsCount: kase.cell_deps_count,
                udtTypeScript: toScriptOrNull(kase.udt_type_script),
                toLocalShannons: BigInt(kase.to_local),
                toRemoteShannons: BigInt(kase.to_remote),
                localReservedCkbShannons: BigInt(kase.local_reserved),
                remoteReservedCkbShannons: BigInt(kase.remote_reserved),
            },
        },
        ...overrides,
    };
}

function revocationRequest(name: string, overrides: Partial<PolicySignRequest> = {}): PolicySignRequest {
    const kase = caseOf(digest.revocation_cases, name);
    return {
        channelId: CHANNEL_ID,
        stateVersion: 1,
        // Fiber's off-by-one: the nonce is one above the number the message revokes.
        nonceCommitmentNumber: kase.revoked_commitment_number + 1,
        session: session(hexToBytes(kase.digest)),
        operation: {
            kind: "revocation",
            input: {
                forRemote: kase.for_remote,
                revokedCommitmentNumber: kase.revoked_commitment_number,
                payoutScript: toScript(kase.payout_script),
                remoteFundingPubkey: REMOTE_FUNDING_PUBKEY,
                commitmentDelayEpoch: BigInt(kase.delay_epoch),
                commitmentFeeRate: BigInt(kase.fee_rate),
                cellDepsCount: kase.cell_deps_count,
                udtTypeScript: toScriptOrNull(kase.udt_type_script),
                toLocalShannons: BigInt(kase.to_local),
                toRemoteShannons: BigInt(kase.to_remote),
                localReservedCkbShannons: BigInt(kase.local_reserved),
                remoteReservedCkbShannons: BigInt(kase.remote_reserved),
                commitmentLock: COMMITMENT_LOCK_TESTNET,
            },
        },
        ...overrides,
    };
}

function announcementRequest(name: string, overrides: Partial<PolicySignRequest> = {}): PolicySignRequest {
    const kase = caseOf(digest.announcement_cases, name);
    return {
        channelId: CHANNEL_ID,
        stateVersion: 1,
        // Deliberately not zero: the announcement slot must not follow the request.
        nonceCommitmentNumber: 7,
        session: session(hexToBytes(kase.digest)),
        operation: {
            kind: "channel_announcement",
            input: {
                chainHash: hexToBytes(kase.chain_hash),
                fundingOutPoint: toOutPoint(kase.funding_out_point),
                nodeIds: [hexToBytes(kase.node_ids[0]), hexToBytes(kase.node_ids[1])],
                remoteFundingPubkey: REMOTE_FUNDING_PUBKEY,
                capacityShannons: BigInt(kase.capacity),
                udtTypeScript: toScriptOrNull(kase.udt_type_script),
            },
        },
        ...overrides,
    };
}

function newEngine(storage: InMemorySignerStorage | AsyncInMemorySignerStorage = new InMemorySignerStorage()): {
    engine: PolicyEngine;
    store: SignerStore;
    storage: InMemorySignerStorage | AsyncInMemorySignerStorage;
} {
    const store = new SignerStore(storage);
    return { engine: new PolicyEngine(store), store, storage };
}

function tamper(message: Uint8Array): Uint8Array {
    const copy = Uint8Array.from(message);
    copy.set([(copy.at(0) ?? 0) ^ 0x01], 0);
    return copy;
}

async function refusalOf(promise: Promise<unknown>): Promise<PolicyRefusalError> {
    try {
        await promise;
    } catch (error) {
        if (error instanceof PolicyRefusalError) return error;
        throw error;
    }
    throw new Error("expected a policy refusal");
}

describe("registerChannel", () => {
    it("creates a record with empty registries", async () => {
        const { engine, store } = newEngine();
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toEqual<ChannelPolicyRecord>({
            version: 1,
            channelId: CHANNEL_ID,
            lastSignedCommitmentNumbers: {},
            signedSessions: {},
            lastStateVersion: 0,
            localExposureShannons: OPENING_EXPOSURE,
            pendingDebitsShannons: [],
        });
    });

    it("keeps the existing record when the same channel is registered again", async () => {
        const { engine, store, storage } = newEngine();
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE);
        await engine.recordDebitIntent(CHANNEL_ID, "1000");
        storage.ops.length = 0;

        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, "1");

        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
            localExposureShannons: OPENING_EXPOSURE,
            pendingDebitsShannons: ["1000"],
        });
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
    });

    it("rejects a re-registration under a different channel index", async () => {
        const { engine, storage } = newEngine();
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE);
        await expect(engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX + 1, OPENING_EXPOSURE)).rejects.toThrow(TypeError);
        expect([...storage.map.keys()].filter((key) => key.startsWith("fiber-lsp-sdk:channel:"))).toEqual([
            `fiber-lsp-sdk:channel:${CHANNEL_INDEX}`,
        ]);
    });

    it("lets only one of two concurrent registrations take a name", async () => {
        const { engine, storage } = newEngine(new AsyncInMemorySignerStorage());

        const outcomes = await Promise.allSettled([
            engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE),
            engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX + 1, OPENING_EXPOSURE),
        ]);

        expect(outcomes.map((outcome) => outcome.status)).toEqual(["fulfilled", "rejected"]);
        await expect(engine.requireChannelIndex(CHANNEL_ID)).resolves.toBe(CHANNEL_INDEX);
        expect(storage.map.get(`fiber-lsp-sdk:alias:${CHANNEL_ID}`)).toBe(String(CHANNEL_INDEX));
    });

    // Fiber names a channel twice: a temporary id at open, then the id its tlc base keys derive, at AcceptChannel.
    it("points a second name at the record the first one created", async () => {
        const { engine, store, storage } = newEngine();
        await engine.registerChannel("temporary-id", CHANNEL_INDEX, OPENING_EXPOSURE);
        await engine.recordDebitIntent("temporary-id", "1000");
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, "1");

        await expect(engine.requireChannelIndex("temporary-id")).resolves.toBe(CHANNEL_INDEX);
        await expect(engine.requireChannelIndex(CHANNEL_ID)).resolves.toBe(CHANNEL_INDEX);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
            channelId: CHANNEL_ID,
            localExposureShannons: OPENING_EXPOSURE,
            pendingDebitsShannons: ["1000"],
        });
        expect([...storage.map.keys()].filter((key) => key.startsWith("fiber-lsp-sdk:channel:"))).toHaveLength(1);
    });

    // A record that has served holds a live channel's nonce space, and handing it to another name re-opens its slots.
    it("rejects a new name on an index whose record has served a slot", async () => {
        const { engine, store } = newEngine();
        await engine.registerChannel("temporary-id", CHANNEL_INDEX, OPENING_EXPOSURE);
        await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote", { channelId: "temporary-id" }));

        await expect(engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE)).rejects.toThrow(TypeError);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ channelId: "temporary-id" });
        expect((await refusalOf(engine.requireChannelIndex(CHANNEL_ID))).code).toBe("unknown_channel");
    });

    it("rejects a new name on an index whose record only moved a counter", async () => {
        const { engine, store } = newEngine();
        await engine.registerChannel("temporary-id", CHANNEL_INDEX, OPENING_EXPOSURE);
        await store.setChannelRecord(CHANNEL_INDEX, {
            version: 1,
            channelId: "temporary-id",
            lastSignedCommitmentNumbers: { COMMITMENT: 0 },
            signedSessions: {},
            lastStateVersion: 1,
            localExposureShannons: OPENING_EXPOSURE,
            pendingDebitsShannons: [],
        });
        await expect(engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE)).rejects.toThrow(TypeError);
    });

    it.each([
        ["an empty channelId", "", CHANNEL_INDEX, OPENING_EXPOSURE],
        ["a negative channel index", CHANNEL_ID, -1, OPENING_EXPOSURE],
        ["a fractional channel index", CHANNEL_ID, 1.5, OPENING_EXPOSURE],
        ["a signed exposure", CHANNEL_ID, CHANNEL_INDEX, "-1"],
        ["an exposure with leading zeros", CHANNEL_ID, CHANNEL_INDEX, "0100"],
        ["an exposure above u128", CHANNEL_ID, CHANNEL_INDEX, "340282366920938463463374607431768211456"],
    ])("rejects %s", async (_, channelId, channelIndex, exposure) => {
        const { engine } = newEngine();
        await expect(engine.registerChannel(channelId, channelIndex, exposure)).rejects.toThrow(Error);
    });
});

describe("requireChannelIndex", () => {
    it("returns the index a channel's keys re-derive from", async () => {
        const { engine } = newEngine();
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE);
        await expect(engine.requireChannelIndex(CHANNEL_ID)).resolves.toBe(CHANNEL_INDEX);
    });

    it("refuses a channel this device never registered", async () => {
        const { engine } = newEngine();
        expect((await refusalOf(engine.requireChannelIndex(CHANNEL_ID))).code).toBe("unknown_channel");
    });
});

describe("recordDebitIntent", () => {
    it("appends intents in the order the user authorised them", async () => {
        const { engine, store } = newEngine();
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE);
        await engine.recordDebitIntent(CHANNEL_ID, "1000");
        await engine.recordDebitIntent(CHANNEL_ID, "250");
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ pendingDebitsShannons: ["1000", "250"] });
    });

    it("refuses an intent on an unregistered channel", async () => {
        const { engine, storage } = newEngine();
        expect((await refusalOf(engine.recordDebitIntent(CHANNEL_ID, "1000"))).code).toBe("unknown_channel");
        expect(storage.map.size).toBe(0);
    });

    it("rejects an amount that is not decimal shannons", async () => {
        const { engine } = newEngine();
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE);
        await expect(engine.recordDebitIntent(CHANNEL_ID, "0x10")).rejects.toThrow(TypeError);
    });

    it("throws when a name resolves to an index holding no record", async () => {
        const { engine, store } = newEngine();
        await store.claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX);
        await expect(engine.recordDebitIntent(CHANNEL_ID, "1000")).rejects.toThrow(TypeError);
    });
});

describe("checkAndClaim", () => {
    async function registered(
        storage: InMemorySignerStorage | AsyncInMemorySignerStorage = new InMemorySignerStorage(),
        exposure = OPENING_EXPOSURE,
    ) {
        const context = newEngine(storage);
        await context.engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, exposure);
        return context;
    }

    describe("the served path", () => {
        it("claims the commitment slot and records the session", async () => {
            const { engine, store } = await registered();
            const request = commitmentRequest("ckb, no tlcs, for remote");

            await expect(engine.checkAndClaim(KEYS, request)).resolves.toEqual({
                status: "fresh",
                context: "COMMITMENT",
                commitmentNumber: 0,
            });
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toEqual<ChannelPolicyRecord>({
                version: 1,
                channelId: CHANNEL_ID,
                lastSignedCommitmentNumbers: { COMMITMENT: 0 },
                signedSessions: { "COMMITMENT:0": buildSessionCommitment(request.session) },
                lastStateVersion: 1,
                localExposureShannons: OPENING_EXPOSURE,
                pendingDebitsShannons: [],
            });
        });

        it("claims the commitment slot for a cooperative close", async () => {
            const { engine } = await registered();
            await expect(engine.checkAndClaim(KEYS, shutdownRequest("ckb"))).resolves.toEqual({
                status: "fresh",
                context: "COMMITMENT",
                commitmentNumber: 20,
            });
        });

        it("claims the revocation slot at the nonce number while the message commits to the previous one", async () => {
            const { engine, store } = await registered();
            const request = revocationRequest("ckb, send side");

            await expect(engine.checkAndClaim(KEYS, request)).resolves.toEqual({
                status: "fresh",
                context: "REVOKE",
                commitmentNumber: 5,
            });
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                lastSignedCommitmentNumbers: { REVOKE: 5 },
            });
        });

        it("claims the fixed announcement slot whatever number the request carries", async () => {
            const { engine, store } = await registered();

            await expect(engine.checkAndClaim(KEYS, announcementRequest("ckb"))).resolves.toEqual({
                status: "fresh",
                context: "ANNOUNCEMENT",
                commitmentNumber: 0,
            });
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                lastSignedCommitmentNumbers: { ANNOUNCEMENT: 0 },
            });
        });

        it("keeps counters per context", async () => {
            const { engine, store } = await registered();
            await engine.recordDebitIntent(CHANNEL_ID, TLC_DECREASE);
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote", { stateVersion: 3 }));
            await engine.checkAndClaim(KEYS, revocationRequest("ckb, send side", { stateVersion: 3 }));

            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                lastSignedCommitmentNumbers: { COMMITMENT: 11, REVOKE: 5 },
            });
        });

        it("accepts a state version equal to the last one seen", async () => {
            const { engine } = await registered();
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote", { stateVersion: 4 }));
            await expect(engine.checkAndClaim(KEYS, announcementRequest("ckb", { stateVersion: 4 }))).resolves.toMatchObject({
                status: "fresh",
            });
        });
    });

    describe("the already-signed path", () => {
        it("answers a byte-identical repeat without moving the record", async () => {
            const { engine, store, storage } = await registered();
            await engine.recordDebitIntent(CHANNEL_ID, TLC_DECREASE);
            const request = commitmentRequest("ckb, three tlcs, for remote");
            await engine.checkAndClaim(KEYS, request);
            const afterFirst = await store.getChannelRecord(CHANNEL_INDEX);
            storage.ops.length = 0;

            await expect(engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote"))).resolves.toEqual({
                status: "already-signed",
                context: "COMMITMENT",
                commitmentNumber: 11,
            });
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toEqual(afterFirst);
            expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
        });

        // It leaves at the sign-once check, so the counters it would trip never run.
        it("answers a repeat that a stale state version would otherwise refuse", async () => {
            const { engine } = await registered();
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote", { stateVersion: 9 }));
            await expect(
                engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote", { stateVersion: 9 })),
            ).resolves.toMatchObject({ status: "already-signed" });
        });
    });

    describe("check 0: the shape of the request", () => {
        it.each([
            ["an empty channelId", commitmentRequest("ckb, no tlcs, for remote", { channelId: "" })],
            ["a negative state version", commitmentRequest("ckb, no tlcs, for remote", { stateVersion: -1 })],
            ["a fractional state version", commitmentRequest("ckb, no tlcs, for remote", { stateVersion: 1.5 })],
            ["a commitment number above the chain", commitmentRequest("ckb, no tlcs, for remote", { nonceCommitmentNumber: 2 ** 48 })],
            [
                "one public key",
                commitmentRequest("ckb, no tlcs, for remote", {
                    session: session(hexToBytes(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote").digest), {
                        orderedPublicKeys: [LOCAL_FUNDING_PUBKEY],
                    }),
                }),
            ],
            [
                "three public keys",
                commitmentRequest("ckb, no tlcs, for remote", {
                    session: session(hexToBytes(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote").digest), {
                        orderedPublicKeys: [LOCAL_FUNDING_PUBKEY, REMOTE_FUNDING_PUBKEY, OTHER_FUNDING_PUBKEY],
                    }),
                }),
            ],
            [
                "two identical public keys",
                commitmentRequest("ckb, no tlcs, for remote", {
                    session: session(hexToBytes(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote").digest), {
                        orderedPublicKeys: [LOCAL_FUNDING_PUBKEY, LOCAL_FUNDING_PUBKEY],
                    }),
                }),
            ],
            [
                "a key list without the channel funding key",
                commitmentRequest("ckb, no tlcs, for remote", {
                    session: session(hexToBytes(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote").digest), {
                        orderedPublicKeys: [OTHER_FUNDING_PUBKEY, REMOTE_FUNDING_PUBKEY],
                    }),
                }),
            ],
            [
                "a 65-byte aggregated nonce",
                commitmentRequest("ckb, no tlcs, for remote", {
                    session: session(hexToBytes(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote").digest), {
                        aggregatedNonce: AGGREGATED_NONCE.slice(1),
                    }),
                }),
            ],
            [
                "a 31-byte message",
                commitmentRequest("ckb, no tlcs, for remote", {
                    session: session(hexToBytes(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote").digest).slice(1)),
                }),
            ],
            [
                "an unknown operation kind",
                commitmentRequest("ckb, no tlcs, for remote", {
                    operation: { kind: "settlement", input: {} } as unknown as PolicySignRequest["operation"],
                }),
            ],
        ])("refuses a request with %s as malformed", async (_, request) => {
            const { engine } = await registered();
            expect((await refusalOf(engine.checkAndClaim(KEYS, request))).code).toBe("malformed");
        });

        it("refuses a malformed request for an unregistered channel as malformed", async () => {
            const { engine } = newEngine();
            const request = commitmentRequest("ckb, no tlcs, for remote", { stateVersion: -1 });
            expect((await refusalOf(engine.checkAndClaim(KEYS, request))).code).toBe("malformed");
        });
    });

    describe("check 1: known channel", () => {
        it("refuses a request for a channel this device never registered", async () => {
            const { engine, storage } = newEngine();
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote")));
            expect(refusal.code).toBe("unknown_channel");
            expect(storage.map.size).toBe(0);
        });

        it("serves a request under either name of a renamed channel", async () => {
            const { engine } = newEngine();
            await engine.registerChannel("temporary-id", CHANNEL_INDEX, OPENING_EXPOSURE);
            await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE);
            await expect(
                engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote", { channelId: "temporary-id" })),
            ).resolves.toMatchObject({ status: "fresh" });
        });

        // Storage that lost a record but kept the name pointing at it is broken, not a channel we never knew.
        it("throws when a name resolves to an index holding no record", async () => {
            const { engine, store } = newEngine();
            await store.claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX);
            await expect(engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote"))).rejects.toThrow(TypeError);
        });
    });

    describe("check 2: no blind signing", () => {
        it("refuses a message that is not the digest of the attached state", async () => {
            const { engine } = await registered();
            const tampered = tamper(hexToBytes(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote").digest));
            const refusal = await refusalOf(
                engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote", { session: session(tampered) })),
            );
            expect(refusal.code).toBe("malformed");
            expect(refusal.message).toContain("does not match");
        });

        it("refuses state the balances contradict, instead of throwing", async () => {
            const { engine } = await registered();
            const request = commitmentRequest("ckb, no tlcs, for remote");
            const operation = request.operation;
            if (operation.kind !== "commitment_tx") throw new Error("expected a commitment request");
            // A fee no capacity can cover.
            operation.input.commitmentFeeRate = 10n ** 18n;
            expect((await refusalOf(engine.checkAndClaim(KEYS, request))).code).toBe("malformed");
        });

        it("refuses a request rebuilt with another channel's keys", async () => {
            const { engine } = await registered();
            const kase = caseOf(digest.commitment_cases, "ckb, no tlcs, for remote");
            const request = commitmentRequest("ckb, no tlcs, for remote", {
                session: session(hexToBytes(kase.digest), { orderedPublicKeys: [OTHER_FUNDING_PUBKEY, REMOTE_FUNDING_PUBKEY] }),
            });
            const refusal = await refusalOf(engine.checkAndClaim(OTHER_KEYS, request));
            expect(refusal.code).toBe("malformed");
            expect(refusal.message).toContain("does not match");
        });

        // The key aggregation throws a plain Error, not one of our guards.
        it("refuses a remote public key that is not a point on the curve", async () => {
            const { engine } = await registered();
            const request = commitmentRequest("ckb, no tlcs, for remote");
            const operation = request.operation;
            if (operation.kind !== "commitment_tx") throw new Error("expected a commitment request");
            operation.input.remoteFundingPubkey = hexToBytes("02".repeat(33));
            expect((await refusalOf(engine.checkAndClaim(KEYS, request))).code).toBe("malformed");
        });

        it("refuses a revocation whose message commits to another commitment number", async () => {
            const { engine } = await registered();
            const request = revocationRequest("ckb, send side");
            const operation = request.operation;
            if (operation.kind !== "revocation") throw new Error("expected a revocation request");
            operation.input.revokedCommitmentNumber += 1;
            expect((await refusalOf(engine.checkAndClaim(KEYS, request))).code).toBe("malformed");
        });
    });

    describe("check 3: sign-once", () => {
        it("refuses a different message on a served slot", async () => {
            const { engine } = await registered();
            await engine.recordDebitIntent(CHANNEL_ID, TLC_DECREASE);
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote", { stateVersion: 1 }));
            const other = commitmentRequest("udt, two tlcs, for remote", { stateVersion: 1 });
            expect((await refusalOf(engine.checkAndClaim(KEYS, other))).code).toBe("policy_refusal");
        });

        // The aggregated nonce enters the challenge: three of these recover the funding key.
        it("refuses the same message under a different aggregated nonce", async () => {
            const { engine } = await registered();
            const kase = caseOf(digest.commitment_cases, "ckb, no tlcs, for remote");
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote"));
            const replayed = commitmentRequest("ckb, no tlcs, for remote", {
                session: session(hexToBytes(kase.digest), { aggregatedNonce: OTHER_AGGREGATED_NONCE }),
            });
            expect((await refusalOf(engine.checkAndClaim(KEYS, replayed))).code).toBe("policy_refusal");
        });

        it("refuses the same message and nonce under a reordered key list", async () => {
            const { engine } = await registered();
            const kase = caseOf(digest.commitment_cases, "ckb, no tlcs, for remote");
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote"));
            const reordered = commitmentRequest("ckb, no tlcs, for remote", {
                session: session(hexToBytes(kase.digest), { orderedPublicKeys: [REMOTE_FUNDING_PUBKEY, LOCAL_FUNDING_PUBKEY] }),
            });
            expect((await refusalOf(engine.checkAndClaim(KEYS, reordered))).code).toBe("policy_refusal");
        });

        it("refuses a cooperative close on a slot a commitment already served", async () => {
            const { engine } = await registered();
            await engine.recordDebitIntent(CHANNEL_ID, TLC_DECREASE);
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote"));
            const close = shutdownRequest("ckb", { nonceCommitmentNumber: 11 });
            expect((await refusalOf(engine.checkAndClaim(KEYS, close))).code).toBe("policy_refusal");
        });

        it("refuses a commitment on a slot a cooperative close already served", async () => {
            const { engine } = await registered();
            await engine.checkAndClaim(KEYS, shutdownRequest("ckb", { nonceCommitmentNumber: 11 }));
            const commitment = commitmentRequest("ckb, three tlcs, for remote");
            expect((await refusalOf(engine.checkAndClaim(KEYS, commitment))).code).toBe("policy_refusal");
        });

        // The reason the record is keyed by the channel index: two names must never mean two slot registries.
        it("refuses a slot the channel's other name already served", async () => {
            const { engine } = newEngine();
            await engine.registerChannel("temporary-id", CHANNEL_INDEX, OPENING_EXPOSURE);
            await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE);
            const kase = caseOf(digest.commitment_cases, "ckb, no tlcs, for remote");
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote", { channelId: "temporary-id" }));

            const renamed = commitmentRequest("ckb, no tlcs, for remote", {
                session: session(hexToBytes(kase.digest), { aggregatedNonce: OTHER_AGGREGATED_NONCE }),
            });
            expect((await refusalOf(engine.checkAndClaim(KEYS, renamed))).code).toBe("policy_refusal");
        });

        it("answers a byte-identical repeat arriving under the channel's other name", async () => {
            const { engine } = newEngine();
            await engine.registerChannel("temporary-id", CHANNEL_INDEX, OPENING_EXPOSURE);
            await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE);
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote", { channelId: "temporary-id" }));

            await expect(engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote"))).resolves.toMatchObject({
                status: "already-signed",
            });
        });

        it("latches the announcement slot after the first session", async () => {
            const { engine } = await registered();
            await engine.checkAndClaim(KEYS, announcementRequest("ckb"));
            expect((await refusalOf(engine.checkAndClaim(KEYS, announcementRequest("udt")))).code).toBe("policy_refusal");
        });
    });

    describe("check 4: monotonicity", () => {
        it("refuses a commitment number below the last signed for its context", async () => {
            const { engine } = await registered();
            await engine.recordDebitIntent(CHANNEL_ID, TLC_DECREASE);
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote"));
            const older = commitmentRequest("ckb, no tlcs, for remote");
            expect((await refusalOf(engine.checkAndClaim(KEYS, older))).code).toBe("stale_state");
        });

        it("refuses a commitment number equal to the last signed when its slot is missing from the registry", async () => {
            const { engine, store } = await registered();
            await store.setChannelRecord(CHANNEL_INDEX, {
                version: 1,
                channelId: CHANNEL_ID,
                lastSignedCommitmentNumbers: { COMMITMENT: 0 },
                signedSessions: {},
                lastStateVersion: 1,
                localExposureShannons: OPENING_EXPOSURE,
                pendingDebitsShannons: [],
            });
            expect((await refusalOf(engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote")))).code).toBe("stale_state");
        });

        it("refuses a state version below the last one seen", async () => {
            const { engine } = await registered();
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote", { stateVersion: 5 }));
            const rolledBack = announcementRequest("ckb", { stateVersion: 4 });
            expect((await refusalOf(engine.checkAndClaim(KEYS, rolledBack))).code).toBe("stale_state");
        });
    });

    describe("check 5: the balance rule", () => {
        it("records an exposure that grows without asking for an intent", async () => {
            const { engine, store } = await registered(new InMemorySignerStorage(), "1000");
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote"));
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                localExposureShannons: OPENING_EXPOSURE,
                pendingDebitsShannons: [],
            });
        });

        it("refuses a decrease no debit intent explains", async () => {
            const { engine, store } = await registered();
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote")));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toContain(TLC_DECREASE);
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                lastSignedCommitmentNumbers: {},
                signedSessions: {},
            });
        });

        it("refuses a decrease no recorded intent covers", async () => {
            const { engine } = await registered();
            await engine.recordDebitIntent(CHANNEL_ID, "2249999999");
            expect((await refusalOf(engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote")))).code).toBe(
                "policy_refusal",
            );
        });

        it.each([
            ["after a larger one", ["9000000000", TLC_DECREASE, "100"]],
            ["before a larger one", [TLC_DECREASE, "9000000000", "100"]],
        ])("consumes the smallest intent that covers the decrease, recorded %s", async (_, intents) => {
            const { engine, store } = await registered();
            for (const intent of intents) await engine.recordDebitIntent(CHANNEL_ID, intent);
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote"));
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                localExposureShannons: THREE_TLC_EXPOSURE,
                pendingDebitsShannons: ["9000000000", "100"],
            });
        });

        it("refuses a cooperative close that pays the device less than its exposure", async () => {
            const { engine } = await registered(new InMemorySignerStorage(), "70000000000");
            expect((await refusalOf(engine.checkAndClaim(KEYS, shutdownRequest("ckb")))).code).toBe("policy_refusal");
        });

        it("signs a cooperative close covered by an intent, and records the payout", async () => {
            const { engine, store } = await registered(new InMemorySignerStorage(), "70000000000");
            await engine.recordDebitIntent(CHANNEL_ID, "8000000000");
            await engine.checkAndClaim(KEYS, shutdownRequest("ckb"));
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                localExposureShannons: OPENING_EXPOSURE,
                pendingDebitsShannons: [],
            });
        });

        it.each([
            ["a revocation", revocationRequest("ckb, send side")],
            ["an announcement", announcementRequest("ckb")],
        ])("leaves the exposure and the intents untouched for %s", async (_, request) => {
            const { engine, store } = await registered();
            await engine.recordDebitIntent(CHANNEL_ID, "1000");
            await engine.checkAndClaim(KEYS, request);
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                localExposureShannons: OPENING_EXPOSURE,
                pendingDebitsShannons: ["1000"],
            });
        });
    });

    describe("atomicity", () => {
        // Without the store's per-key lane the second write would drop the first claim.
        it("lets only one of two concurrent sessions take a slot", async () => {
            const { engine, store } = await registered(new AsyncInMemorySignerStorage());
            const kase = caseOf(digest.commitment_cases, "ckb, no tlcs, for remote");
            const first = commitmentRequest("ckb, no tlcs, for remote");
            const second = commitmentRequest("ckb, no tlcs, for remote", {
                session: session(hexToBytes(kase.digest), { aggregatedNonce: OTHER_AGGREGATED_NONCE }),
            });

            const outcomes = await Promise.allSettled([engine.checkAndClaim(KEYS, first), engine.checkAndClaim(KEYS, second)]);

            expect(outcomes.map((outcome) => outcome.status)).toEqual(["fulfilled", "rejected"]);
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                signedSessions: { "COMMITMENT:0": buildSessionCommitment(first.session) },
            });
        });

        // Two names, one lane: the record's key is the index, so the alias they arrive under cannot split the claim.
        it("lets only one of two concurrent sessions take a slot through different names", async () => {
            const { engine, store } = await registered(new AsyncInMemorySignerStorage());
            await engine.registerChannel("temporary-id", CHANNEL_INDEX, OPENING_EXPOSURE);
            const kase = caseOf(digest.commitment_cases, "ckb, no tlcs, for remote");
            const first = commitmentRequest("ckb, no tlcs, for remote", { channelId: "temporary-id" });
            const second = commitmentRequest("ckb, no tlcs, for remote", {
                session: session(hexToBytes(kase.digest), { aggregatedNonce: OTHER_AGGREGATED_NONCE }),
            });

            const outcomes = await Promise.allSettled([engine.checkAndClaim(KEYS, first), engine.checkAndClaim(KEYS, second)]);

            expect(outcomes.map((outcome) => outcome.status)).toEqual(["fulfilled", "rejected"]);
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                signedSessions: { "COMMITMENT:0": buildSessionCommitment(first.session) },
            });
        });

        it("writes nothing when a check refuses", async () => {
            const { engine, storage } = await registered();
            const stored = new Map(storage.map);
            storage.ops.length = 0;
            await refusalOf(engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote")));
            expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
            expect(storage.map).toEqual(stored);
        });
    });

    it("never names a secret in its refusals", async () => {
        const { engine } = await registered();
        const tampered = tamper(hexToBytes(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote").digest));
        const refusal = await refusalOf(
            engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote", { session: session(tampered) })),
        );
        expect(refusal.message).not.toContain(vectors.sdk_scheme.channel.channel_keys.funding_key);
        expect(refusal.message).not.toContain(vectors.sdk_scheme.channel.seed);
    });
});
