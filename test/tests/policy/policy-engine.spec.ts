import { hexToBytes } from "@noble/hashes/utils.js";
import type { FiberChannelKeys } from "../../../src/derivation";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation";
import { computeCommitmentTxDigest } from "../../../src/digest";
import type { ChannelPolicyRecord, DebitIntentRecord, HoldInvoicePolicyRecord, PolicySignRequest, SignSession } from "../../../src/policy";
import { DebitIntentError, HoldInvoiceError, PolicyEngine, PolicyRefusalError, SignerStore } from "../../../src/policy";
import { buildSessionCommitment } from "../../../src/policy/utils";
import { AsyncInMemorySignerStorage, InMemorySignerStorage } from "../../mocks/policy";
import { toChannelAnnouncementInput, toCommitmentTxInput, toRevocationInput, toShutdownTxInput, toTlc } from "../../utils/digest-inputs";
import { caseOf, loadInteropVectors } from "../../utils/interop-vectors";
import { SHUTDOWN_NONCE_NUMBER, revocationNonceNumber } from "../../utils/nonce-numbers";

const vectors = loadInteropVectors();
const digest = vectors.digest;

const CHANNEL_ID = "0x1f".padEnd(66, "a");
const CHANNEL_INDEX = vectors.sdk_scheme.channel.channel_index;
const KEYS = deriveChannelKeys(hexToBytes(vectors.sdk_scheme.channel.seed));
const LOCAL_FUNDING_PUBKEY = pubkeyOf(KEYS.fundingKey);
const REMOTE_FUNDING_PUBKEY = hexToBytes(digest.remote.funding_pubkey);

const OTHER_KEYS = deriveChannelKeys(hexToBytes(vectors.fiber_scheme.channel_seed));
const OTHER_FUNDING_PUBKEY = pubkeyOf(OTHER_KEYS.fundingKey);

const AGGREGATED_NONCE = hexToBytes(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
);
const OTHER_AGGREGATED_NONCE = hexToBytes(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
        "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
);

const OTHER_CHANNEL_ID = "0x2e".padEnd(66, "b");
const OTHER_CHANNEL_INDEX = CHANNEL_INDEX + 1;

const OPENING_EXPOSURE = "62000000000";
const THREE_TLC_EXPOSURE = "59750000000";

const OFFERED_HASH = "6844f645bb03ff9d1c9c48ee5e9e971be09bf34a3612c81b20c2a5a1bff2a6b6";
const OFFERED_AMOUNT = "1500000000";
const OTHER_OFFERED_HASH = "c5403872f3e0258e74e8b2ae5aa77e4d8b8dc93c799288270fef73997f8d93f5";
const OTHER_OFFERED_AMOUNT = "750000000";
const RECEIVED_HASH = "5b36757f3945408453a6282c4aba2c78bfaba94219e459932924b01f7fc09d1e";
const RECEIVED_AMOUNT = "2250000000";
const OFFERED_TLC_ID = 7;
const OTHER_OFFERED_TLC_ID = 5;
const RECEIVED_TLC_ID = 2;

const OPENING_VIEW = { exposureShannons: OPENING_EXPOSURE, tlcs: [], chargedShannons: {}, creditedShannons: {} };

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
        operation: { kind: "commitment_tx", input: toCommitmentTxInput(kase, digest.remote) },
        ...overrides,
    };
}

function shutdownRequest(name: string, overrides: Partial<PolicySignRequest> = {}): PolicySignRequest {
    const kase = caseOf(digest.shutdown_cases, name);
    return {
        channelId: CHANNEL_ID,
        stateVersion: 1,
        nonceCommitmentNumber: SHUTDOWN_NONCE_NUMBER,
        session: session(hexToBytes(kase.digest)),
        operation: { kind: "shutdown_tx", input: toShutdownTxInput(kase, digest.remote) },
        ...overrides,
    };
}

type CustomCommitment = {
    forRemote: boolean;
    commitmentNumber: number;
    settlementLocalShannons: string;
    tlcIds: number[];
};

// Varies a vector case's balance-rule fields; the digest is the SDK's own, pinned elsewhere.
function customCommitmentRequest(
    custom: CustomCommitment,
    channel: { keys: FiberChannelKeys; channelId: string } = { keys: KEYS, channelId: CHANNEL_ID },
): PolicySignRequest {
    const kase = caseOf(digest.commitment_cases, "ckb, three tlcs, for remote");
    const input = {
        ...toCommitmentTxInput(kase, digest.remote),
        forRemote: custom.forRemote,
        commitmentNumber: custom.commitmentNumber,
        settlementLocalShannons: BigInt(custom.settlementLocalShannons),
        tlcs: kase.tlcs.filter((tlc) => custom.tlcIds.includes(tlc.id)).map(toTlc),
    };
    return {
        channelId: channel.channelId,
        stateVersion: 1,
        nonceCommitmentNumber: custom.commitmentNumber,
        session: session(computeCommitmentTxDigest(channel.keys, input), {
            orderedPublicKeys: [pubkeyOf(channel.keys.fundingKey), REMOTE_FUNDING_PUBKEY],
        }),
        operation: { kind: "commitment_tx", input },
    };
}

async function recordThreeTlcIntents(engine: PolicyEngine): Promise<void> {
    await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
    await engine.recordDebitIntent(OTHER_OFFERED_HASH, OTHER_OFFERED_AMOUNT);
}

function revocationRequest(name: string, overrides: Partial<PolicySignRequest> = {}): PolicySignRequest {
    const kase = caseOf(digest.revocation_cases, name);
    return {
        channelId: CHANNEL_ID,
        stateVersion: 1,
        nonceCommitmentNumber: revocationNonceNumber(kase),
        session: session(hexToBytes(kase.digest)),
        operation: { kind: "revocation", input: toRevocationInput(kase, digest.remote) },
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
        operation: { kind: "channel_announcement", input: toChannelAnnouncementInput(kase, digest.remote) },
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

async function registeredEngine(
    storage: InMemorySignerStorage | AsyncInMemorySignerStorage = new InMemorySignerStorage(),
): Promise<ReturnType<typeof newEngine>> {
    const context = newEngine(storage);
    await context.engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE);
    return context;
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
            views: { remote: OPENING_VIEW, local: OPENING_VIEW },
        });
    });

    it("keeps the existing record when the same channel is registered again", async () => {
        const { engine, store, storage } = newEngine();
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE);
        storage.ops.length = 0;

        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, "1");

        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
            views: { remote: OPENING_VIEW, local: OPENING_VIEW },
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
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, "1");

        await expect(engine.requireChannelIndex("temporary-id")).resolves.toBe(CHANNEL_INDEX);
        await expect(engine.requireChannelIndex(CHANNEL_ID)).resolves.toBe(CHANNEL_INDEX);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
            channelId: CHANNEL_ID,
            views: { remote: OPENING_VIEW, local: OPENING_VIEW },
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
            views: { remote: OPENING_VIEW, local: OPENING_VIEW },
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

describe("debit intents", () => {
    it("records an open intent under the bound 20 bytes of its hash", async () => {
        const { engine, store, storage } = newEngine();
        await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
        await expect(store.getDebitIntent(OFFERED_HASH.slice(0, 40))).resolves.toEqual<DebitIntentRecord>({
            version: 1,
            paymentHash: OFFERED_HASH,
            maxShannons: OFFERED_AMOUNT,
            open: true,
            channelIndexes: [],
        });
        expect([...storage.map.keys()]).toEqual([`fiber-lsp-sdk:intent:${OFFERED_HASH.slice(0, 40)}`]);
    });

    // A host unsure whether the first call landed repeats it.
    it("writes nothing when the same open intent is recorded again", async () => {
        const { engine, store, storage } = newEngine();
        await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
        storage.ops.length = 0;
        await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
        await expect(store.getDebitIntent(OFFERED_HASH.slice(0, 40))).resolves.toMatchObject({ maxShannons: OFFERED_AMOUNT, open: true });
    });

    it("refuses a second intent with another maximum while the first is open", async () => {
        const { engine, store } = newEngine();
        await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
        const error = await engine.recordDebitIntent(OFFERED_HASH, "9000000000").catch((cause: unknown) => cause);
        expect(error).toBeInstanceOf(DebitIntentError);
        expect(error).toMatchObject({
            code: "intent_open",
            message: `a debit intent for ${OFFERED_HASH} is already open with another maximum`,
        });
        await expect(store.getDebitIntent(OFFERED_HASH.slice(0, 40))).resolves.toMatchObject({ maxShannons: OFFERED_AMOUNT });
    });

    it("closes an intent, and closing it again writes nothing", async () => {
        const { engine, store, storage } = newEngine();
        await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
        await engine.closeDebitIntent(OFFERED_HASH);
        await expect(store.getDebitIntent(OFFERED_HASH.slice(0, 40))).resolves.toMatchObject({ open: false });
        storage.ops.length = 0;
        await engine.closeDebitIntent(OFFERED_HASH);
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
    });

    // Fiber lets a failed hash be sent again.
    it("opens a closed intent again with a new budget when nothing was charged to it", async () => {
        const { engine, store } = await registeredEngine();
        await recordThreeTlcIntents(engine);
        await engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote"));
        await engine.closeDebitIntent(OFFERED_HASH);
        await engine.recordDebitIntent(OFFERED_HASH, "1600000000");
        await expect(store.getDebitIntent(OFFERED_HASH.slice(0, 40))).resolves.toEqual<DebitIntentRecord>({
            version: 1,
            paymentHash: OFFERED_HASH,
            maxShannons: "1600000000",
            open: true,
            channelIndexes: [CHANNEL_INDEX],
        });
    });

    // A crossing removal may charge the local view alone.
    it("never opens again an intent charged in the local view alone", async () => {
        const { engine } = await registeredEngine();
        await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
        await engine.checkAndClaim(
            KEYS,
            customCommitmentRequest({
                forRemote: false,
                commitmentNumber: 11,
                settlementLocalShannons: "60500000000",
                tlcIds: [OFFERED_TLC_ID],
            }),
        );
        await engine.checkAndClaim(
            KEYS,
            customCommitmentRequest({ forRemote: false, commitmentNumber: 12, settlementLocalShannons: "60500000000", tlcIds: [] }),
        );
        await engine.closeDebitIntent(OFFERED_HASH);
        await expect(engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT)).rejects.toMatchObject({ code: "intent_charged" });
    });

    it("never opens again an intent something was charged to", async () => {
        const { engine } = await registeredEngine();
        await recordThreeTlcIntents(engine);
        await engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote"));
        // The first offered TLC leaves with its amount.
        await engine.checkAndClaim(
            KEYS,
            customCommitmentRequest({
                forRemote: true,
                commitmentNumber: 12,
                settlementLocalShannons: THREE_TLC_EXPOSURE,
                tlcIds: [OTHER_OFFERED_TLC_ID, RECEIVED_TLC_ID],
            }),
        );
        await engine.closeDebitIntent(OFFERED_HASH);
        const error = await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT).catch((cause: unknown) => cause);
        expect(error).toBeInstanceOf(DebitIntentError);
        expect(error).toMatchObject({
            code: "intent_charged",
            message: `a payment under ${OFFERED_HASH} has already been charged, it cannot be authorised again`,
        });
    });

    it("refuses a hash that shares its bound 20 bytes with a recorded one", async () => {
        const { engine } = newEngine();
        const twin = OFFERED_HASH.slice(0, 40) + "00".repeat(12);
        await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
        await engine.closeDebitIntent(OFFERED_HASH);
        await expect(engine.recordDebitIntent(twin, OFFERED_AMOUNT)).rejects.toThrow(
            new TypeError(`${twin} shares its bound 20 bytes with a recorded payment, ${OFFERED_HASH}`),
        );
        await expect(engine.closeDebitIntent(twin)).rejects.toThrow(TypeError);
    });

    it("refuses an intent under the hash of one of this device's hold invoices", async () => {
        const { engine, store } = newEngine();
        await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
        const error = await engine.recordDebitIntent(RECEIVED_HASH, RECEIVED_AMOUNT).catch((cause: unknown) => cause);
        expect(error).toBeInstanceOf(DebitIntentError);
        expect(error).toMatchObject({ code: "own_invoice", message: `${RECEIVED_HASH} is the hash of a hold invoice of this device` });
        await expect(store.getDebitIntent(RECEIVED_HASH.slice(0, 40))).resolves.toBeNull();
    });

    it("refuses to close an intent that was never recorded", async () => {
        const { engine } = newEngine();
        await expect(engine.closeDebitIntent(OFFERED_HASH)).rejects.toThrow(
            new TypeError(`no debit intent was recorded for ${OFFERED_HASH}`),
        );
    });

    it("throws when an intent lists a channel that holds no record", async () => {
        const { engine, store } = newEngine();
        await store.updateDebitIntent(OFFERED_HASH.slice(0, 40), () => ({
            version: 1,
            paymentHash: OFFERED_HASH,
            maxShannons: OFFERED_AMOUNT,
            open: false,
            channelIndexes: [CHANNEL_INDEX],
        }));
        await expect(engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT)).rejects.toThrow(
            new TypeError(`a payment record lists channel index ${CHANNEL_INDEX}, which holds no record`),
        );
    });

    it.each([
        ["a hash of 31 bytes", OFFERED_HASH.slice(2), OFFERED_AMOUNT],
        ["an uppercase hash", OFFERED_HASH.toUpperCase(), OFFERED_AMOUNT],
        ["a maximum in hex", OFFERED_HASH, "0x10"],
        ["a negative maximum", OFFERED_HASH, "-1"],
    ])("rejects %s", async (_, hash, max) => {
        const { engine, storage } = newEngine();
        await expect(engine.recordDebitIntent(hash, max)).rejects.toThrow(TypeError);
        expect(storage.map.size).toBe(0);
    });

    it("keeps a malformed argument a TypeError, never a DebitIntentError", async () => {
        const { engine } = newEngine();
        const error = await engine.recordDebitIntent(OFFERED_HASH, "-1").catch((cause: unknown) => cause);
        expect(error).toBeInstanceOf(TypeError);
        expect(error).not.toBeInstanceOf(DebitIntentError);
    });

    it("rejects closing under a hash of the wrong shape", async () => {
        const { engine } = newEngine();
        await expect(engine.closeDebitIntent(OFFERED_HASH.slice(2))).rejects.toThrow(TypeError);
    });
});

describe("hold invoices", () => {
    it("records an unreleased invoice under the bound 20 bytes of its hash", async () => {
        const { engine, store, storage } = newEngine();
        await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
        await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toEqual<HoldInvoicePolicyRecord>({
            version: 1,
            paymentHash: RECEIVED_HASH,
            amountShannons: RECEIVED_AMOUNT,
            hashAlgorithm: "sha256",
            released: false,
            channelIndexes: [],
        });
        expect([...storage.map.keys()]).toEqual([`fiber-lsp-sdk:invoice:${RECEIVED_HASH.slice(0, 40)}`]);
    });

    it("refuses an invoice under the hash of a payment this device authorised", async () => {
        const { engine, store } = newEngine();
        await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
        await expect(engine.recordHoldInvoice(OFFERED_HASH, OFFERED_AMOUNT, "ckb-hash")).rejects.toThrow(
            new TypeError(`${OFFERED_HASH} is the hash of a payment this device has authorised`),
        );
        await expect(store.getHoldInvoiceRecord(OFFERED_HASH.slice(0, 40))).resolves.toBeNull();
    });

    it("writes nothing when the same invoice is recorded again", async () => {
        const { engine, storage } = newEngine();
        await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
        storage.ops.length = 0;
        await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
    });

    it("refuses the same hash with another algorithm", async () => {
        const { engine } = newEngine();
        await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
        await expect(engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "ckb-hash")).rejects.toThrow(
            new TypeError(`a hold invoice for ${RECEIVED_HASH} is already recorded with another amount or algorithm`),
        );
    });

    it("rejects an algorithm fiber does not define", async () => {
        const { engine, storage } = newEngine();
        await expect(engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "ckb_hash" as never)).rejects.toThrow(TypeError);
        expect(storage.map.size).toBe(0);
    });

    it("refuses the same hash with another amount", async () => {
        const { engine } = newEngine();
        await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
        await expect(engine.recordHoldInvoice(RECEIVED_HASH, "1", "sha256")).rejects.toThrow(
            new TypeError(`a hold invoice for ${RECEIVED_HASH} is already recorded with another amount or algorithm`),
        );
    });

    it("refuses a hash that shares its bound 20 bytes with a recorded one", async () => {
        const { engine } = newEngine();
        const twin = RECEIVED_HASH.slice(0, 40) + "00".repeat(12);
        await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
        await expect(engine.recordHoldInvoice(twin, RECEIVED_AMOUNT, "ckb-hash")).rejects.toThrow(TypeError);
        await expect(engine.markHoldInvoiceReleased(twin)).rejects.toThrow(TypeError);
    });

    it("marks an invoice released, and marking it again writes nothing", async () => {
        const { engine, store, storage } = newEngine();
        await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
        await engine.markHoldInvoiceReleased(RECEIVED_HASH);
        await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({ released: true });
        storage.ops.length = 0;
        await engine.markHoldInvoiceReleased(RECEIVED_HASH);
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
    });

    it("refuses to release an invoice that was never recorded", async () => {
        const { engine } = newEngine();
        await expect(engine.markHoldInvoiceReleased(RECEIVED_HASH)).rejects.toThrow(
            new TypeError(`no hold invoice was recorded for ${RECEIVED_HASH}`),
        );
    });

    it.each([
        ["a hash of 31 bytes", RECEIVED_HASH.slice(2), RECEIVED_AMOUNT],
        ["an amount in hex", RECEIVED_HASH, "0x10"],
    ])("rejects %s", async (_, hash, amount) => {
        const { engine, storage } = newEngine();
        await expect(engine.recordHoldInvoice(hash, amount, "ckb-hash")).rejects.toThrow(TypeError);
        await expect(engine.markHoldInvoiceReleased(hash.slice(2))).rejects.toThrow(TypeError);
        expect(storage.map.size).toBe(0);
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
                views: { remote: OPENING_VIEW, local: OPENING_VIEW },
            });
        });

        it("claims the commitment slot for a cooperative close", async () => {
            const { engine } = await registered();
            await expect(engine.checkAndClaim(KEYS, shutdownRequest("ckb"))).resolves.toEqual({
                status: "fresh",
                context: "COMMITMENT",
                commitmentNumber: SHUTDOWN_NONCE_NUMBER,
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
            await recordThreeTlcIntents(engine);
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
            await recordThreeTlcIntents(engine);
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
            ["no nonce number on a commitment tx", commitmentRequest("ckb, no tlcs, for remote", { nonceCommitmentNumber: undefined })],
            ["no nonce number on a close", shutdownRequest("ckb", { nonceCommitmentNumber: undefined })],
            ["no nonce number on a revocation", revocationRequest("ckb, send side", { nonceCommitmentNumber: undefined })],
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
                "a public key off the curve",
                commitmentRequest("ckb, no tlcs, for remote", {
                    session: session(hexToBytes(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote").digest), {
                        orderedPublicKeys: [LOCAL_FUNDING_PUBKEY, hexToBytes("03".repeat(33))],
                    }),
                }),
            ],
            [
                "an aggregated nonce off the curve",
                commitmentRequest("ckb, no tlcs, for remote", {
                    session: session(hexToBytes(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote").digest), {
                        aggregatedNonce: hexToBytes("03".repeat(66)),
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
        it.each([
            ["a commitment", commitmentRequest("ckb, no tlcs, for remote")],
            ["a revocation", revocationRequest("ckb, send side")],
        ])("throws when a name resolves to an index holding no record, for %s", async (_, request) => {
            const { engine, store } = newEngine();
            await store.claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX);
            await expect(engine.checkAndClaim(KEYS, request)).rejects.toThrow(
                new TypeError(`channel ${CHANNEL_ID} resolves to channel index ${CHANNEL_INDEX}, which holds no record`),
            );
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
            await recordThreeTlcIntents(engine);
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
            await recordThreeTlcIntents(engine);
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
            await recordThreeTlcIntents(engine);
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
                views: { remote: OPENING_VIEW, local: OPENING_VIEW },
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
        it("signs the first commitment of a view against the opening state, and files the channel on its intents", async () => {
            const { engine, store } = await registered();
            await recordThreeTlcIntents(engine);
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote"));

            const record = await store.getChannelRecord(CHANNEL_INDEX);
            expect(record?.views).toEqual({
                remote: {
                    exposureShannons: THREE_TLC_EXPOSURE,
                    tlcs: [
                        {
                            direction: "offered",
                            hashAlgorithm: "ckb-hash",
                            boundPaymentHash: OFFERED_HASH.slice(0, 40),
                            amountShannons: OFFERED_AMOUNT,
                            expirySeconds: "1723257890",
                        },
                        {
                            direction: "offered",
                            hashAlgorithm: "sha256",
                            boundPaymentHash: OTHER_OFFERED_HASH.slice(0, 40),
                            amountShannons: OTHER_OFFERED_AMOUNT,
                            expirySeconds: "1699999999",
                        },
                        {
                            direction: "received",
                            hashAlgorithm: "sha256",
                            boundPaymentHash: RECEIVED_HASH.slice(0, 40),
                            amountShannons: RECEIVED_AMOUNT,
                            expirySeconds: "1750000000",
                        },
                    ],
                    chargedShannons: {},
                    creditedShannons: {},
                },
                local: OPENING_VIEW,
            });
            await expect(store.getDebitIntent(OFFERED_HASH.slice(0, 40))).resolves.toMatchObject({ channelIndexes: [CHANNEL_INDEX] });
            await expect(store.getDebitIntent(OTHER_OFFERED_HASH.slice(0, 40))).resolves.toMatchObject({ channelIndexes: [CHANNEL_INDEX] });
        });

        it("refuses an offered TLC under a hash the user never approved", async () => {
            const { engine, store } = await registered();
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote")));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe(
                `the remote commitment offers a TLC under ${OTHER_OFFERED_HASH.slice(0, 40)}, which no debit intent covers`,
            );
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                signedSessions: {},
                views: { remote: OPENING_VIEW },
            });
            await expect(store.getDebitIntent(OFFERED_HASH.slice(0, 40))).resolves.toMatchObject({ channelIndexes: [] });
        });

        it("refuses an offered TLC above what its intent approved", async () => {
            const { engine } = await registered();
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            await engine.recordDebitIntent(OTHER_OFFERED_HASH, "749999999");
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote")));
            expect(refusal.message).toContain("above its debit intent of 749999999");
        });

        // The local commitment may list the device's latest add one round later.
        it("judges each view against its own previous message, so the views may cross", async () => {
            const { engine, store } = await registered();
            await recordThreeTlcIntents(engine);
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote"));
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({ forRemote: false, commitmentNumber: 12, settlementLocalShannons: OPENING_EXPOSURE, tlcIds: [] }),
            );
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({
                    forRemote: true,
                    commitmentNumber: 13,
                    settlementLocalShannons: THREE_TLC_EXPOSURE,
                    tlcIds: [OFFERED_TLC_ID, OTHER_OFFERED_TLC_ID, RECEIVED_TLC_ID],
                }),
            );
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({
                    forRemote: false,
                    commitmentNumber: 14,
                    settlementLocalShannons: THREE_TLC_EXPOSURE,
                    tlcIds: [OFFERED_TLC_ID, OTHER_OFFERED_TLC_ID, RECEIVED_TLC_ID],
                }),
            );
            const record = await store.getChannelRecord(CHANNEL_INDEX);
            expect(record?.views.local).toEqual(record?.views.remote);
        });

        it("signs the device's own commitment catching up with an add after the payment's intent closed", async () => {
            const { engine } = await registered();
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({
                    forRemote: true,
                    commitmentNumber: 11,
                    settlementLocalShannons: "60500000000",
                    tlcIds: [OFFERED_TLC_ID],
                }),
            );
            await engine.closeDebitIntent(OFFERED_HASH);
            await expect(
                engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: false,
                        commitmentNumber: 12,
                        settlementLocalShannons: "60500000000",
                        tlcIds: [OFFERED_TLC_ID],
                    }),
                ),
            ).resolves.toMatchObject({ status: "fresh" });
        });

        it("charges a fulfilled TLC in the view it left", async () => {
            const { engine, store } = await registered();
            await recordThreeTlcIntents(engine);
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote"));
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({
                    forRemote: true,
                    commitmentNumber: 12,
                    settlementLocalShannons: THREE_TLC_EXPOSURE,
                    tlcIds: [OTHER_OFFERED_TLC_ID, RECEIVED_TLC_ID],
                }),
            );
            const record = await store.getChannelRecord(CHANNEL_INDEX);
            expect(record?.views.remote.chargedShannons).toEqual({ [OFFERED_HASH.slice(0, 40)]: OFFERED_AMOUNT });
            expect(record?.views.local.chargedShannons).toEqual({});
        });

        it("refuses a fall no departed offered TLC accounts for", async () => {
            const { engine } = await registered();
            const refusal = await refusalOf(
                engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({ forRemote: true, commitmentNumber: 11, settlementLocalShannons: "61999999999", tlcIds: [] }),
                ),
            );
            expect(refusal.message).toBe("the remote commitment lowers the holdings by 1 shannons, which no offered TLC took");
        });

        it("draws one budget across every channel the payment shows on", async () => {
            const { engine, store } = await registered(new AsyncInMemorySignerStorage());
            await engine.registerChannel(OTHER_CHANNEL_ID, OTHER_CHANNEL_INDEX, OPENING_EXPOSURE);
            await engine.recordDebitIntent(OFFERED_HASH, "2999999999");
            const part = { forRemote: true, commitmentNumber: 11, settlementLocalShannons: "60500000000", tlcIds: [OFFERED_TLC_ID] };

            await engine.checkAndClaim(KEYS, customCommitmentRequest(part));
            const refusal = await refusalOf(
                engine.checkAndClaim(OTHER_KEYS, customCommitmentRequest(part, { keys: OTHER_KEYS, channelId: OTHER_CHANNEL_ID })),
            );
            expect(refusal.message).toBe(
                `the remote view draws 3000000000 shannons under ${OFFERED_HASH.slice(0, 40)}, above its debit intent of 2999999999`,
            );

            await engine.closeDebitIntent(OFFERED_HASH);
            await engine.recordDebitIntent(OFFERED_HASH, "3000000000");
            await engine.checkAndClaim(OTHER_KEYS, customCommitmentRequest(part, { keys: OTHER_KEYS, channelId: OTHER_CHANNEL_ID }));
            await expect(store.getDebitIntent(OFFERED_HASH.slice(0, 40))).resolves.toMatchObject({
                channelIndexes: [CHANNEL_INDEX, OTHER_CHANNEL_INDEX],
            });
        });

        // The node may broadcast either commitment of each channel.
        it("refuses a second channel's view drawing a budget another channel's other view already draws", async () => {
            const { engine } = await registered();
            await engine.registerChannel(OTHER_CHANNEL_ID, OTHER_CHANNEL_INDEX, OPENING_EXPOSURE);
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({
                    forRemote: true,
                    commitmentNumber: 11,
                    settlementLocalShannons: "60500000000",
                    tlcIds: [OFFERED_TLC_ID],
                }),
            );
            const crossed = customCommitmentRequest(
                { forRemote: false, commitmentNumber: 11, settlementLocalShannons: "60500000000", tlcIds: [OFFERED_TLC_ID] },
                { keys: OTHER_KEYS, channelId: OTHER_CHANNEL_ID },
            );
            const refusal = await refusalOf(engine.checkAndClaim(OTHER_KEYS, crossed));
            expect(refusal.message).toBe(
                `the local view draws 3000000000 shannons under ${OFFERED_HASH.slice(0, 40)}, above its debit intent of ${OFFERED_AMOUNT}`,
            );
        });

        // Otherwise the channel would stay filed for a claim that fails.
        it("keeps a revocation from landing between a commitment's decision and its claim", async () => {
            const inner = new InMemorySignerStorage();
            const intentKey = `fiber-lsp-sdk:intent:${OFFERED_HASH.slice(0, 40)}`;
            let armed = false;
            let revocation: Promise<unknown> | null = null;
            const engine: PolicyEngine = new PolicyEngine(
                new SignerStore({
                    get: (key: string) => Promise.resolve(inner.get(key)),
                    async set(key: string, value: string): Promise<void> {
                        // Between the commitment's decision and its claim.
                        if (armed && key === intentKey && revocation === null) {
                            revocation = engine.checkAndClaim(KEYS, revocationRequest("ckb, send side", { stateVersion: 2 }));
                            await new Promise((resolve) => setTimeout(resolve, 0));
                        }
                        inner.set(key, value);
                    },
                }),
            );
            await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE);
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            const part = { forRemote: true, commitmentNumber: 11, settlementLocalShannons: "60500000000", tlcIds: [OFFERED_TLC_ID] };
            armed = true;

            await expect(engine.checkAndClaim(KEYS, customCommitmentRequest(part))).resolves.toMatchObject({ status: "fresh" });
            expect(revocation).not.toBeNull();
            await expect(revocation).resolves.toMatchObject({ status: "fresh", context: "REVOKE" });
            await expect(new SignerStore(inner).getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                lastSignedCommitmentNumbers: { COMMITMENT: 11, REVOKE: 5 },
                lastStateVersion: 2,
            });
        });

        it("lets only one of two channels racing for one budget take it", async () => {
            const { engine } = await registered(new AsyncInMemorySignerStorage());
            await engine.registerChannel(OTHER_CHANNEL_ID, OTHER_CHANNEL_INDEX, OPENING_EXPOSURE);
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            const part = { forRemote: true, commitmentNumber: 11, settlementLocalShannons: "60500000000", tlcIds: [OFFERED_TLC_ID] };

            const outcomes = await Promise.allSettled([
                engine.checkAndClaim(KEYS, customCommitmentRequest(part)),
                engine.checkAndClaim(OTHER_KEYS, customCommitmentRequest(part, { keys: OTHER_KEYS, channelId: OTHER_CHANNEL_ID })),
            ]);
            expect(outcomes.map((outcome) => outcome.status)).toEqual(["fulfilled", "rejected"]);
        });

        it("throws when a payment record disappears between the read and the write", async () => {
            const inner = new InMemorySignerStorage();
            const intentKey = `fiber-lsp-sdk:intent:${OFFERED_HASH.slice(0, 40)}`;
            let intentReads = 0;
            const storage = {
                get(key: string): string | null {
                    if (key === intentKey && ++intentReads > 1) return null;
                    return inner.get(key);
                },
                set(key: string, value: string): void {
                    inner.set(key, value);
                },
            };
            const engine = new PolicyEngine(new SignerStore(storage));
            await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE);
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            intentReads = 0;
            const part = { forRemote: true, commitmentNumber: 11, settlementLocalShannons: "60500000000", tlcIds: [OFFERED_TLC_ID] };
            await expect(engine.checkAndClaim(KEYS, customCommitmentRequest(part))).rejects.toThrow(
                new TypeError("a payment record disappeared inside the balance lane"),
            );
        });

        it("throws when the channel's record disappears between the decision and the claim", async () => {
            const inner = new InMemorySignerStorage();
            const recordKey = `fiber-lsp-sdk:channel:${CHANNEL_INDEX}`;
            let armed = false;
            let recordReads = 0;
            const engine = new PolicyEngine(
                new SignerStore({
                    get: (key: string) => (armed && key === recordKey && ++recordReads > 1 ? null : inner.get(key)),
                    set: (key: string, value: string) => inner.set(key, value),
                }),
            );
            await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, OPENING_EXPOSURE);
            armed = true;
            await expect(engine.checkAndClaim(KEYS, revocationRequest("ckb, send side"))).rejects.toThrow(
                new TypeError(`channel ${CHANNEL_ID} resolves to channel index ${CHANNEL_INDEX}, which holds no record`),
            );
            expect(recordReads).toBe(2);
        });

        it("throws when a payment record lists a channel that holds no record", async () => {
            const { engine, store } = await registered();
            await store.updateDebitIntent(OFFERED_HASH.slice(0, 40), () => ({
                version: 1,
                paymentHash: OFFERED_HASH,
                maxShannons: OFFERED_AMOUNT,
                open: true,
                channelIndexes: [OTHER_CHANNEL_INDEX],
            }));
            const part = { forRemote: true, commitmentNumber: 11, settlementLocalShannons: "60500000000", tlcIds: [OFFERED_TLC_ID] };
            await expect(engine.checkAndClaim(KEYS, customCommitmentRequest(part))).rejects.toThrow(
                new TypeError(`a payment record lists channel index ${OTHER_CHANNEL_INDEX}, which holds no record`),
            );
        });

        describe("a released preimage", () => {
            // A channel listing the received TLC alone.
            async function holding() {
                const context = await registered();
                await recordThreeTlcIntents(context.engine);
                await context.engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
                await context.engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 11,
                        settlementLocalShannons: OPENING_EXPOSURE,
                        tlcIds: [RECEIVED_TLC_ID],
                    }),
                );
                await context.engine.markHoldInvoiceReleased(RECEIVED_HASH);
                return context;
            }

            // A part that failed on a channel busy with outgoing payments must not hold the release back.
            it("releases while a channel the invoice was shown on no longer lists it, whatever else it lists", async () => {
                const { engine, store } = await registered();
                await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 11,
                        settlementLocalShannons: OPENING_EXPOSURE,
                        tlcIds: [RECEIVED_TLC_ID],
                    }),
                );
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 12,
                        settlementLocalShannons: OPENING_EXPOSURE,
                        tlcIds: [],
                    }),
                );
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 13,
                        settlementLocalShannons: "60500000000",
                        tlcIds: [OFFERED_TLC_ID],
                    }),
                );
                await engine.markHoldInvoiceReleased(RECEIVED_HASH);
                await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({
                    released: true,
                    channelIndexes: [CHANNEL_INDEX],
                });
                // Safe: a part arriving now is refused beside the offered TLC.
                const refusal = await refusalOf(
                    engine.checkAndClaim(
                        KEYS,
                        customCommitmentRequest({
                            forRemote: true,
                            commitmentNumber: 14,
                            settlementLocalShannons: "60500000000",
                            tlcIds: [OFFERED_TLC_ID, RECEIVED_TLC_ID],
                        }),
                    ),
                );
                expect(refusal.message).toBe(
                    "the remote commitment would show an offered TLC beside a held TLC whose preimage was released",
                );
            });

            it("refuses the release while a TLC of the invoice is locked with another algorithm", async () => {
                const { engine, store } = await registered();
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "ckb-hash");
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 11,
                        settlementLocalShannons: OPENING_EXPOSURE,
                        tlcIds: [RECEIVED_TLC_ID],
                    }),
                );
                const error = await engine.markHoldInvoiceReleased(RECEIVED_HASH).catch((cause: unknown) => cause);
                expect(error).toBeInstanceOf(HoldInvoiceError);
                expect(error).toMatchObject({
                    code: "algorithm_mismatch",
                    message: `channel index ${CHANNEL_INDEX} lists a TLC under ${RECEIVED_HASH} locked with another algorithm than the invoice's`,
                });
                await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({ released: false });
            });

            it("refuses the release while the offered TLC is listed in the local view alone", async () => {
                const { engine } = await registered();
                await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 11,
                        settlementLocalShannons: OPENING_EXPOSURE,
                        tlcIds: [RECEIVED_TLC_ID],
                    }),
                );
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: false,
                        commitmentNumber: 12,
                        settlementLocalShannons: "60500000000",
                        tlcIds: [OFFERED_TLC_ID],
                    }),
                );
                await expect(engine.markHoldInvoiceReleased(RECEIVED_HASH)).rejects.toMatchObject({ code: "offered_in_flight" });
            });

            it("refuses an offered TLC in one view while the other lists a released held TLC", async () => {
                const { engine } = await holding();
                const refusal = await refusalOf(
                    engine.checkAndClaim(
                        KEYS,
                        customCommitmentRequest({
                            forRemote: false,
                            commitmentNumber: 12,
                            settlementLocalShannons: "60500000000",
                            tlcIds: [OFFERED_TLC_ID],
                        }),
                    ),
                );
                expect(refusal.message).toBe(
                    "the local commitment would show an offered TLC beside a held TLC whose preimage was released",
                );
            });

            it("refuses to release the preimage while a channel of the invoice lists an offered TLC", async () => {
                const { engine, store } = await registered();
                await recordThreeTlcIntents(engine);
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
                await engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote"));
                const error = await engine.markHoldInvoiceReleased(RECEIVED_HASH).catch((cause: unknown) => cause);
                expect(error).toBeInstanceOf(HoldInvoiceError);
                expect(error).toMatchObject({
                    code: "offered_in_flight",
                    message: `channel index ${CHANNEL_INDEX} lists an offered TLC, so the preimage of ${RECEIVED_HASH} is not released yet`,
                });
                await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({ released: false });
            });

            it("refuses an offered TLC on a channel holding a released TLC", async () => {
                const { engine } = await holding();
                const refusal = await refusalOf(
                    engine.checkAndClaim(
                        KEYS,
                        customCommitmentRequest({
                            forRemote: true,
                            commitmentNumber: 12,
                            settlementLocalShannons: "60500000000",
                            tlcIds: [OFFERED_TLC_ID, RECEIVED_TLC_ID],
                        }),
                    ),
                );
                expect(refusal.message).toBe(
                    "the remote commitment would show an offered TLC beside a held TLC whose preimage was released",
                );
            });

            it("throws when the invoice disappears between the check and the release", async () => {
                const inner = new InMemorySignerStorage();
                const invoiceKey = `fiber-lsp-sdk:invoice:${RECEIVED_HASH.slice(0, 40)}`;
                let armed = false;
                let invoiceReads = 0;
                const engine = new PolicyEngine(
                    new SignerStore({
                        get: (key: string) => (armed && key === invoiceKey && ++invoiceReads > 1 ? null : inner.get(key)),
                        set: (key: string, value: string) => inner.set(key, value),
                    }),
                );
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
                armed = true;
                await expect(engine.markHoldInvoiceReleased(RECEIVED_HASH)).rejects.toThrow(
                    new TypeError("a payment record disappeared inside the balance lane"),
                );
                expect(invoiceReads).toBe(2);
            });

            it("throws when the invoice lists a channel that holds no record", async () => {
                const { engine, store } = await registered();
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
                await store.updateHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40), (current) => ({
                    ...(current as HoldInvoicePolicyRecord),
                    channelIndexes: [OTHER_CHANNEL_INDEX],
                }));
                await expect(engine.markHoldInvoiceReleased(RECEIVED_HASH)).rejects.toThrow(
                    new TypeError(`a payment record lists channel index ${OTHER_CHANNEL_INDEX}, which holds no record`),
                );
            });

            it("files the channel on the invoice its commitment shows a TLC of", async () => {
                const { store } = await holding();
                await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({
                    channelIndexes: [CHANNEL_INDEX],
                });
            });

            it("refuses a commitment that drops the released TLC as failed", async () => {
                const { engine } = await holding();
                const refusal = await refusalOf(
                    engine.checkAndClaim(
                        KEYS,
                        customCommitmentRequest({
                            forRemote: true,
                            commitmentNumber: 12,
                            settlementLocalShannons: OPENING_EXPOSURE,
                            tlcIds: [],
                        }),
                    ),
                );
                expect(refusal.message).toBe(
                    `the remote commitment lowers the holdings by ${RECEIVED_AMOUNT} shannons, which no offered TLC took`,
                );
            });

            // Otherwise the node could broadcast the two commitments that did not pay.
            it("asks a channel for the invoice unless every commitment another channel holds has already paid it", async () => {
                const { engine } = await registered();
                await engine.registerChannel(OTHER_CHANNEL_ID, OTHER_CHANNEL_INDEX, OPENING_EXPOSURE);
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
                const other = { keys: OTHER_KEYS, channelId: OTHER_CHANNEL_ID };
                const holding = (forRemote: boolean, commitmentNumber: number) => ({
                    forRemote,
                    commitmentNumber,
                    settlementLocalShannons: OPENING_EXPOSURE,
                    tlcIds: [RECEIVED_TLC_ID],
                });
                await engine.checkAndClaim(KEYS, customCommitmentRequest(holding(true, 11)));
                await engine.checkAndClaim(KEYS, customCommitmentRequest(holding(false, 12)));
                await engine.checkAndClaim(OTHER_KEYS, customCommitmentRequest(holding(true, 11), other));
                await engine.checkAndClaim(OTHER_KEYS, customCommitmentRequest(holding(false, 12), other));
                await engine.markHoldInvoiceReleased(RECEIVED_HASH);
                // The first channel's remote commitment pays the invoice; its local one does not yet.
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({ forRemote: true, commitmentNumber: 13, settlementLocalShannons: "64250000000", tlcIds: [] }),
                );

                const dropped = customCommitmentRequest(
                    { forRemote: true, commitmentNumber: 13, settlementLocalShannons: OPENING_EXPOSURE, tlcIds: [] },
                    other,
                );
                const refusal = await refusalOf(engine.checkAndClaim(OTHER_KEYS, dropped));
                expect(refusal.message).toBe(
                    `the remote commitment lowers the holdings by ${RECEIVED_AMOUNT} shannons, which no offered TLC took`,
                );
            });

            it("signs one that pays for it, and records the credit", async () => {
                const { engine, store } = await holding();
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 12,
                        settlementLocalShannons: "64250000000",
                        tlcIds: [],
                    }),
                );
                const record = await store.getChannelRecord(CHANNEL_INDEX);
                expect(record?.views.remote.creditedShannons).toEqual({ [RECEIVED_HASH.slice(0, 40)]: RECEIVED_AMOUNT });
            });
        });

        it("reads the two views alone on a record that carries an unknown key beside them", async () => {
            const { engine, store } = await registered();
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({
                    forRemote: true,
                    commitmentNumber: 11,
                    settlementLocalShannons: OPENING_EXPOSURE,
                    tlcIds: [RECEIVED_TLC_ID],
                }),
            );
            const record = await store.getChannelRecord(CHANNEL_INDEX);
            const views = { ...(record as ChannelPolicyRecord).views, futureView: "x" } as unknown as ChannelPolicyRecord["views"];
            await store.setChannelRecord(CHANNEL_INDEX, { ...(record as ChannelPolicyRecord), views });

            await engine.markHoldInvoiceReleased(RECEIVED_HASH);
            await engine.closeDebitIntent(OFFERED_HASH);
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            await expect(
                engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({ forRemote: true, commitmentNumber: 12, settlementLocalShannons: "64250000000", tlcIds: [] }),
                ),
            ).resolves.toMatchObject({ status: "fresh" });
        });

        it("refuses a cooperative close that pays the device less than a view showed", async () => {
            const { engine } = await registered(new InMemorySignerStorage(), "70000000000");
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, shutdownRequest("ckb")));
            expect(refusal.message).toBe("the close pays the device 62000000000 shannons, below the 70000000000 of the remote commitment");
        });

        it("refuses a cooperative close while a view still lists TLCs", async () => {
            const { engine } = await registered();
            await recordThreeTlcIntents(engine);
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, three tlcs, for remote"));
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, shutdownRequest("ckb", { nonceCommitmentNumber: 12 })));
            expect(refusal.message).toBe("a cooperative close while the remote commitment still lists TLCs");
        });

        it("signs a cooperative close that pays what both views showed, and moves no snapshot", async () => {
            const { engine, store } = await registered();
            await engine.checkAndClaim(KEYS, shutdownRequest("ckb"));
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                views: { remote: OPENING_VIEW, local: OPENING_VIEW },
            });
        });

        it.each([
            ["a revocation", revocationRequest("ckb, send side")],
            ["an announcement", announcementRequest("ckb")],
        ])("leaves the views untouched for %s", async (_, request) => {
            const { engine, store } = await registered();
            await engine.checkAndClaim(KEYS, request);
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                views: { remote: OPENING_VIEW, local: OPENING_VIEW },
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

        it("writes nothing when a check refuses, not even on the intents it read", async () => {
            const { engine, storage } = await registered();
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
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
