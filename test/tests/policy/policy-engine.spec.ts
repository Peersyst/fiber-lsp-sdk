import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { OutPoint } from "../../../src/common";
import type { FiberChannelKeys } from "../../../src/derivation";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation";
import {
    computeChannelAnnouncementDigest,
    computeCommitmentTxDigest,
    computeRevocationDigest,
    computeShutdownTxDigest,
} from "../../../src/digest";
import type {
    ChannelPins,
    ChannelPolicyRecord,
    DebitIntentRecord,
    HoldInvoicePolicyRecord,
    PolicySignRequest,
    SignOperation,
    SignSession,
} from "../../../src/policy";
import { DebitIntentError, FundingCellError, HoldInvoiceError, PolicyEngine, PolicyRefusalError, SignerStore } from "../../../src/policy";
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

const OPENING_SETTLEMENT = "62000000000";
const THREE_TLC_SETTLEMENT = "59750000000";
// The "ckb" cases' opening settlement plus their local reserve.
const FUNDED = "71900000000";
const CLOSE_SCRIPT = toShutdownTxInput(caseOf(digest.shutdown_cases, "ckb"), digest.remote).localCloseScript;

const OFFERED_HASH = "6844f645bb03ff9d1c9c48ee5e9e971be09bf34a3612c81b20c2a5a1bff2a6b6";
const OFFERED_AMOUNT = "1500000000";
const OTHER_OFFERED_HASH = "c5403872f3e0258e74e8b2ae5aa77e4d8b8dc93c799288270fef73997f8d93f5";
const OTHER_OFFERED_AMOUNT = "750000000";
const RECEIVED_HASH = "5b36757f3945408453a6282c4aba2c78bfaba94219e459932924b01f7fc09d1e";
const RECEIVED_AMOUNT = "2250000000";
const OFFERED_TLC_ID = 7;
const OTHER_OFFERED_TLC_ID = 5;
const RECEIVED_TLC_ID = 2;

const REGISTERED_PINS: ChannelPins = {
    fundedShannons: FUNDED,
    localCloseScript:
        "4900000010000000300000003100000074d3f63a22681bdb6ff6512866db95264338cfaee12f71e28b9f23c414990c9c0114000000da694932ba803b4c07f6e3a9b6b2ea3f9c6c66c7",
    // Args under 57 bytes: 98 CKB occupied plus the 1 CKB close fee.
    localReservedCkbShannons: "9900000000",
    udtTypeScript: null,
};

// What the "ckb" cases state.
const OPENED_PINS: ChannelPins = {
    ...REGISTERED_PINS,
    fundingOutPoint: "6f4ea49726c322dbedceb12a09d013a0256ea697dc362cc8865f8bbcdd17684e:0",
    fundingCapacityShannons: "96700000000",
    liquidCapacityShannons: "80500000000",
    remoteFundingPubkey: "026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638",
    remoteTlcBasePubkey: "032559e1b167552782cab5be4294260d51edfc36aef4ca7cc165b3b21b15e98e21",
    commitmentDelayEpoch: "1099511627777",
    commitmentFeeRate: "1000",
    remoteReservedCkbShannons: "6300000000",
};

const FUNDING_TX_HASH = "6f4ea49726c322dbedceb12a09d013a0256ea697dc362cc8865f8bbcdd17684e";
const UDT_SCRIPT_PIN =
    "5500000010000000300000003100000091" +
    "2f64f976947ed5467ff5e7ba4c87bd37f240cdbdba0b38da619372056ef82701200000008612706980baca14e3d03ea4d77d185e6f7338cd6e98a0ea0cd17a69918f2578";
const REMOTE_CLOSE_SCRIPT_PIN =
    "55000000100000003000000031000000014f879c667f549df6067c1797534f2b2de2312feff188d100669d4b8ad6f04502200000000682a2f376b830a421ddc7d3b8cf4bffb31bfdf2942f46780359b1ef4f107f36";

const OPENING_VIEW = { exposureShannons: FUNDED, tlcs: [], chargedShannons: {}, creditedShannons: {} };

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

type Channel = { keys: FiberChannelKeys; channelId: string };

const OTHER_CHANNEL: Channel = { keys: OTHER_KEYS, channelId: OTHER_CHANNEL_ID };

// The "ckb" channel with the three-TLC case's TLCs; the peer's settlement takes the rest. The digest is the SDK's.
function customCommitmentRequest(custom: CustomCommitment, channel: Channel = { keys: KEYS, channelId: CHANNEL_ID }): PolicySignRequest {
    const base = toCommitmentTxInput(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote"), digest.remote);
    const tlcs = caseOf(digest.commitment_cases, "ckb, three tlcs, for remote")
        .tlcs.filter((tlc) => custom.tlcIds.includes(tlc.id))
        .map(toTlc);
    const settlementLocalShannons = BigInt(custom.settlementLocalShannons);
    const input = {
        ...base,
        forRemote: custom.forRemote,
        commitmentNumber: custom.commitmentNumber,
        settlementLocalShannons,
        settlementRemoteShannons:
            base.toLocalShannons +
            base.toRemoteShannons -
            settlementLocalShannons -
            tlcs.reduce((sum, tlc) => sum + tlc.amountShannons, 0n),
        tlcs,
    };
    return signedRequest({ kind: "commitment_tx", input }, custom.commitmentNumber, channel);
}

function ckbCommitment(): Extract<SignOperation, { kind: "commitment_tx" }>["input"] {
    return { ...toCommitmentTxInput(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote"), digest.remote), commitmentNumber: 11 };
}

function ckbShutdown(): Extract<SignOperation, { kind: "shutdown_tx" }>["input"] {
    return toShutdownTxInput(caseOf(digest.shutdown_cases, "ckb"), digest.remote);
}

function ckbRevocation(): Extract<SignOperation, { kind: "revocation" }>["input"] {
    return toRevocationInput(caseOf(digest.revocation_cases, "ckb, send side"), digest.remote);
}

function ckbAnnouncement(): Extract<SignOperation, { kind: "channel_announcement" }>["input"] {
    return toChannelAnnouncementInput(caseOf(digest.announcement_cases, "ckb"), digest.remote);
}

function signedRequest(
    operation: SignOperation,
    nonceCommitmentNumber: number,
    channel: Channel = { keys: KEYS, channelId: CHANNEL_ID },
): PolicySignRequest {
    return {
        channelId: channel.channelId,
        stateVersion: 1,
        nonceCommitmentNumber,
        session: session(digestOf(channel.keys, operation), {
            orderedPublicKeys: [pubkeyOf(channel.keys.fundingKey), REMOTE_FUNDING_PUBKEY],
        }),
        operation,
    };
}

function digestOf(keys: FiberChannelKeys, operation: SignOperation): Uint8Array {
    switch (operation.kind) {
        case "commitment_tx":
            return computeCommitmentTxDigest(keys, operation.input);
        case "shutdown_tx":
            return computeShutdownTxDigest(keys, operation.input);
        case "revocation":
            return computeRevocationDigest(keys, operation.input);
        case "channel_announcement":
            return computeChannelAnnouncementDigest(keys, operation.input);
    }
}

// The three-TLC case on the "ckb" channel.
function threeTlcRequest(overrides: Partial<PolicySignRequest> = {}): PolicySignRequest {
    return {
        ...customCommitmentRequest({
            forRemote: true,
            commitmentNumber: 11,
            settlementLocalShannons: THREE_TLC_SETTLEMENT,
            tlcIds: [OFFERED_TLC_ID, RECEIVED_TLC_ID, OTHER_OFFERED_TLC_ID],
        }),
        ...overrides,
    };
}

async function openChannel(engine: PolicyEngine, channel: Channel = { keys: KEYS, channelId: CHANNEL_ID }): Promise<void> {
    await engine.checkAndClaim(
        channel.keys,
        customCommitmentRequest({ forRemote: true, commitmentNumber: 0, settlementLocalShannons: OPENING_SETTLEMENT, tlcIds: [] }, channel),
    );
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
    await context.engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
    return context;
}

async function openedEngine(): Promise<ReturnType<typeof newEngine>> {
    const context = await registeredEngine();
    await openChannel(context.engine);
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
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toEqual<ChannelPolicyRecord>({
            version: 1,
            channelId: CHANNEL_ID,
            lastSignedCommitmentNumbers: {},
            signedSessions: {},
            lastStateVersion: 0,
            pins: REGISTERED_PINS,
            views: { remote: OPENING_VIEW, local: OPENING_VIEW },
        });
    });

    it("keeps the existing record when the same channel is registered again", async () => {
        const { engine, store, storage } = newEngine();
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        storage.ops.length = 0;

        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);

        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
            views: { remote: OPENING_VIEW, local: OPENING_VIEW },
        });
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
    });

    // Both values are the facade's own, so a mismatch is a host bug.
    it.each([
        ["another funded amount", "71900000001", CLOSE_SCRIPT],
        ["another close script", FUNDED, { ...CLOSE_SCRIPT, args: new Uint8Array(20) }],
    ])("rejects a re-registration with %s, under either name", async (_, funded, closeScript) => {
        const { engine, store, storage } = newEngine();
        await engine.registerChannel("temporary-id", CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        const stored = new Map(storage.map);
        for (const channelId of ["temporary-id", CHANNEL_ID]) {
            await expect(engine.registerChannel(channelId, CHANNEL_INDEX, funded, closeScript)).rejects.toThrow(
                new TypeError(`channel index ${CHANNEL_INDEX} is already registered with another funded amount or close script`),
            );
        }
        expect(storage.map).toEqual(stored);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ channelId: "temporary-id" });
    });

    it("rejects a re-registration under a different channel index", async () => {
        const { engine, storage } = newEngine();
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        await expect(engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX + 1, FUNDED, CLOSE_SCRIPT)).rejects.toThrow(TypeError);
        expect([...storage.map.keys()].filter((key) => key.startsWith("fiber-lsp-sdk:channel:"))).toEqual([
            `fiber-lsp-sdk:channel:${CHANNEL_INDEX}`,
        ]);
    });

    it("lets only one of two concurrent registrations take a name", async () => {
        const { engine, storage } = newEngine(new AsyncInMemorySignerStorage());

        const outcomes = await Promise.allSettled([
            engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT),
            engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX + 1, FUNDED, CLOSE_SCRIPT),
        ]);

        expect(outcomes.map((outcome) => outcome.status)).toEqual(["fulfilled", "rejected"]);
        await expect(engine.requireChannelIndex(CHANNEL_ID)).resolves.toBe(CHANNEL_INDEX);
        expect(storage.map.get(`fiber-lsp-sdk:alias:${CHANNEL_ID}`)).toBe(String(CHANNEL_INDEX));
    });

    // Fiber names a channel twice: a temporary id at open, then the id its tlc base keys derive, at AcceptChannel.
    it("points a second name at the record the first one created", async () => {
        const { engine, store, storage } = newEngine();
        await engine.registerChannel("temporary-id", CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);

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
        await engine.registerChannel("temporary-id", CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote", { channelId: "temporary-id" }));

        await expect(engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT)).rejects.toThrow(TypeError);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ channelId: "temporary-id" });
        expect((await refusalOf(engine.requireChannelIndex(CHANNEL_ID))).code).toBe("unknown_channel");
    });

    it("rejects a new name on an index whose record only moved a counter", async () => {
        const { engine, store } = newEngine();
        await engine.registerChannel("temporary-id", CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        await store.setChannelRecord(CHANNEL_INDEX, {
            version: 1,
            channelId: "temporary-id",
            lastSignedCommitmentNumbers: { COMMITMENT: 0 },
            signedSessions: {},
            lastStateVersion: 1,
            pins: REGISTERED_PINS,
            views: { remote: OPENING_VIEW, local: OPENING_VIEW },
        });
        await expect(engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT)).rejects.toThrow(TypeError);
    });

    it.each([
        ["an empty channelId", "", CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT],
        ["a negative channel index", CHANNEL_ID, -1, FUNDED, CLOSE_SCRIPT],
        ["a fractional channel index", CHANNEL_ID, 1.5, FUNDED, CLOSE_SCRIPT],
        ["a close script with a short code hash", CHANNEL_ID, CHANNEL_INDEX, FUNDED, { ...CLOSE_SCRIPT, codeHash: new Uint8Array(31) }],
        ["a close script of an unknown hash type", CHANNEL_ID, CHANNEL_INDEX, FUNDED, { ...CLOSE_SCRIPT, hashType: "data3" as never }],
        ["a close script that is no object", CHANNEL_ID, CHANNEL_INDEX, FUNDED, null as never],
    ])("rejects %s, writing nothing", async (_, channelId, channelIndex, funded, closeScript) => {
        const { engine, storage } = newEngine();
        await expect(engine.registerChannel(channelId, channelIndex, funded, closeScript)).rejects.toThrow(Error);
        expect(storage.map.size).toBe(0);
    });

    // Caught at the argument, not later as a corrupt record.
    it.each([
        ["a signed funded amount", "-1"],
        ["a funded amount with leading zeros", "0100"],
        ["a funded amount above u128", "340282366920938463463374607431768211456"],
    ])("rejects %s, writing nothing", async (_, funded) => {
        const { engine, storage } = newEngine();
        await expect(engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, funded, CLOSE_SCRIPT)).rejects.toThrow(
            new TypeError("fundedShannons must be an amount in decimal shannons"),
        );
        expect(storage.map.size).toBe(0);
    });

    it.each([
        [
            "one shannon below the reserve",
            "9899999999",
            new RangeError("fundedShannons 9899999999 is below the 9900000000 the device's reserve takes over that close script"),
        ],
        [
            "u64's maximum",
            "18446744073709551615",
            new RangeError("fundedShannons must be below 18446744073709551615, the most a CKB channel's capacity holds"),
        ],
    ])("rejects a funded amount %s, writing nothing", async (_, funded, error) => {
        const { engine, storage } = newEngine();
        await expect(engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, funded, CLOSE_SCRIPT)).rejects.toThrow(error);
        expect(storage.map.size).toBe(0);
    });
});

describe("pinFundingCell", () => {
    const FUNDING_OUT_POINT = { txHash: hexToBytes(FUNDING_TX_HASH), index: 0 };

    it("pins the funding cell the host signed, which the opening commitment then has to state", async () => {
        const { engine, store } = await registeredEngine();
        await engine.pinFundingCell(CHANNEL_ID, FUNDING_OUT_POINT, "96700000000");
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
            pins: { ...REGISTERED_PINS, fundingOutPoint: `${FUNDING_TX_HASH}:0`, fundingCapacityShannons: "96700000000" },
        });
        await openChannel(engine);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ pins: OPENED_PINS });
    });

    it.each([
        [
            "another out point",
            { txHash: FUNDING_OUT_POINT.txHash, index: 1 },
            "96700000000",
            "fundingOutPoint",
            `${FUNDING_TX_HASH}:0`,
            `${FUNDING_TX_HASH}:1`,
        ],
        ["another capacity", FUNDING_OUT_POINT, "96700000001", "fundingCapacityShannons", "96700000000", "96700000001"],
    ])("refuses an opening commitment on %s than the host signed", async (_, outPoint, capacity, field, stated, pinned) => {
        const { engine, store } = await registeredEngine();
        await engine.pinFundingCell(CHANNEL_ID, outPoint, capacity);
        const refusal = await refusalOf(openChannel(engine));
        expect(refusal.code).toBe("policy_refusal");
        expect(refusal.message).toBe(`the request states ${field} ${stated}, but the channel pinned ${pinned}`);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ signedSessions: {} });
    });

    it("pins a capacity of u64's maximum, the most a cell holds", async () => {
        const { engine, store } = await registeredEngine();
        await engine.pinFundingCell(CHANNEL_ID, FUNDING_OUT_POINT, "18446744073709551615");
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
            pins: { fundingCapacityShannons: "18446744073709551615" },
        });
    });

    it("writes nothing when the same cell is pinned again, under either name", async () => {
        const { engine, storage } = await registeredEngine();
        await engine.registerChannel("temporary-id", CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        await engine.pinFundingCell("temporary-id", FUNDING_OUT_POINT, "96700000000");
        storage.ops.length = 0;
        await engine.pinFundingCell(CHANNEL_ID, FUNDING_OUT_POINT, "96700000000");
        await openChannel(engine);
        storage.ops.length = 0;
        await engine.pinFundingCell(CHANNEL_ID, FUNDING_OUT_POINT, "96700000000");
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
    });

    it.each([
        [
            "another out point",
            { ...FUNDING_OUT_POINT, index: 1 },
            "96700000000",
            { field: "fundingOutPoint", pinned: `${FUNDING_TX_HASH}:0`, stated: `${FUNDING_TX_HASH}:1` },
        ],
        ["another capacity", FUNDING_OUT_POINT, "1", { field: "fundingCapacityShannons", pinned: "96700000000", stated: "1" }],
    ])("throws a FundingCellError on %s once the node pinned the cell, naming both values", async (_, outPoint, capacity, conflict) => {
        const { engine, storage } = await openedEngine();
        const stored = new Map(storage.map);
        const error: unknown = await engine.pinFundingCell(CHANNEL_ID, outPoint, capacity).catch((caught: unknown) => caught);
        expect(error).toBeInstanceOf(FundingCellError);
        expect(error).toMatchObject({
            name: "FundingCellError",
            message: `channel ${CHANNEL_ID} already pins ${conflict.field} to ${conflict.pinned}, not ${conflict.stated}`,
            conflict,
        });
        expect(storage.map).toEqual(stored);
    });

    it("throws a FundingCellError on another cell than an earlier host pin", async () => {
        const { engine, storage } = await registeredEngine();
        await engine.pinFundingCell(CHANNEL_ID, FUNDING_OUT_POINT, "96700000000");
        const stored = new Map(storage.map);
        await expect(engine.pinFundingCell(CHANNEL_ID, FUNDING_OUT_POINT, "96700000001")).rejects.toThrow(FundingCellError);
        expect(storage.map).toEqual(stored);
    });

    it("throws when the channel's name resolves to an index holding no record", async () => {
        const { engine, store } = newEngine();
        await store.claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX);
        await expect(engine.pinFundingCell(CHANNEL_ID, FUNDING_OUT_POINT, "96700000000")).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} resolves to channel index ${CHANNEL_INDEX}, which holds no record`),
        );
    });

    // Hosts register before pinning, so this is a host bug.
    it("throws on a channel this device never registered", async () => {
        const { engine } = newEngine();
        await expect(engine.pinFundingCell(CHANNEL_ID, FUNDING_OUT_POINT, "96700000000")).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} is not registered on this device`),
        );
    });

    it("rejects an empty channel id", async () => {
        const { engine } = newEngine();
        await expect(engine.pinFundingCell("", FUNDING_OUT_POINT, "96700000000")).rejects.toThrow(
            new TypeError("channelId must be a non-empty string"),
        );
    });

    // Caught at the argument, not later as a corrupt record.
    it.each([
        [
            "a tx hash of 31 bytes",
            { txHash: new Uint8Array(31), index: 0 },
            "96700000000",
            new TypeError("fundingOutPoint.txHash must be 32 bytes, got 31"),
        ],
        [
            "a negative index",
            { txHash: FUNDING_OUT_POINT.txHash, index: -1 },
            "96700000000",
            new RangeError("fundingOutPoint.index must be an integer between 0 and 4294967295, got -1"),
        ],
        [
            "an index above u32",
            { txHash: FUNDING_OUT_POINT.txHash, index: 2 ** 32 },
            "96700000000",
            new RangeError("fundingOutPoint.index must be an integer between 0 and 4294967295, got 4294967296"),
        ],
        ["a capacity in hex", FUNDING_OUT_POINT, "0x1", new TypeError("capacityShannons must be an amount in decimal shannons")],
        [
            "a capacity above u64",
            FUNDING_OUT_POINT,
            "18446744073709551616",
            new RangeError("capacityShannons must be at most 18446744073709551615, the most a CKB cell's capacity holds"),
        ],
        ["a null out point", null as unknown as OutPoint, "96700000000", new TypeError("fundingOutPoint must be an object")],
    ])("rejects %s, writing nothing", async (_, outPoint, capacity, error) => {
        const { engine, storage } = await registeredEngine();
        const stored = new Map(storage.map);
        await expect(engine.pinFundingCell(CHANNEL_ID, outPoint, capacity)).rejects.toThrow(error);
        expect(storage.map).toEqual(stored);
    });

    it("holds the host's pin until a commitment that is being decided has claimed", async () => {
        const inner = new InMemorySignerStorage();
        const recordKey = `fiber-lsp-sdk:channel:${CHANNEL_INDEX}`;
        let armed = false;
        let pin: Promise<void> | null = null;
        const engine: PolicyEngine = new PolicyEngine(
            new SignerStore({
                async get(key: string): Promise<string | null> {
                    // While the commitment reads the record it decides on.
                    if (armed && key === recordKey && pin === null) {
                        pin = engine.pinFundingCell(CHANNEL_ID, { ...FUNDING_OUT_POINT, index: 1 }, "96700000000");
                        pin.catch(() => undefined);
                        await new Promise((resolve) => setTimeout(resolve, 0));
                    }
                    return inner.get(key);
                },
                set(key: string, value: string): Promise<void> {
                    inner.set(key, value);
                    return Promise.resolve();
                },
            }),
        );
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        armed = true;

        await openChannel(engine);
        expect(pin).not.toBeNull();
        await expect(pin).rejects.toBeInstanceOf(FundingCellError);
        await expect(pin).rejects.toThrow(
            `channel ${CHANNEL_ID} already pins fundingOutPoint to ${FUNDING_TX_HASH}:0, not ${FUNDING_TX_HASH}:1`,
        );
        await expect(new SignerStore(inner).getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ pins: OPENED_PINS });
    });
});

describe("requireChannelIndex", () => {
    it("returns the index a channel's keys re-derive from", async () => {
        const { engine } = newEngine();
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
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
        const { engine, store } = await openedEngine();
        await recordThreeTlcIntents(engine);
        await engine.checkAndClaim(KEYS, threeTlcRequest());
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
        const { engine } = await openedEngine();
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
        const { engine } = await openedEngine();
        await recordThreeTlcIntents(engine);
        await engine.checkAndClaim(KEYS, threeTlcRequest());
        // The first offered TLC leaves with its amount.
        await engine.checkAndClaim(
            KEYS,
            customCommitmentRequest({
                forRemote: true,
                commitmentNumber: 12,
                settlementLocalShannons: THREE_TLC_SETTLEMENT,
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
    async function registered(storage: InMemorySignerStorage | AsyncInMemorySignerStorage = new InMemorySignerStorage(), funded = FUNDED) {
        const context = newEngine(storage);
        await context.engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, funded, CLOSE_SCRIPT);
        return context;
    }

    async function opened(storage: InMemorySignerStorage | AsyncInMemorySignerStorage = new InMemorySignerStorage()) {
        const context = await registered(storage);
        await openChannel(context.engine);
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
                pins: OPENED_PINS,
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
            const { engine, store } = await opened();
            await recordThreeTlcIntents(engine);
            await engine.checkAndClaim(KEYS, threeTlcRequest({ stateVersion: 3 }));
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
            const { engine, store, storage } = await opened();
            await recordThreeTlcIntents(engine);
            const request = threeTlcRequest();
            await engine.checkAndClaim(KEYS, request);
            const afterFirst = await store.getChannelRecord(CHANNEL_INDEX);
            storage.ops.length = 0;

            await expect(engine.checkAndClaim(KEYS, threeTlcRequest())).resolves.toEqual({
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
            await engine.registerChannel("temporary-id", CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
            await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
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

        // A close can precede any pin; the record guard would otherwise throw on the capacity.
        it("refuses a close whose sides together exceed a u64, writing nothing", async () => {
            const { engine, storage } = await registered();
            const request = shutdownRequest("ckb");
            const operation = request.operation;
            if (operation.kind !== "shutdown_tx") throw new Error("expected a shutdown request");
            operation.input.toRemoteShannons = (1n << 64n) - 1n - operation.input.remoteReservedCkbShannons;
            const stored = new Map(storage.map);
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, request));
            expect(refusal.code).toBe("malformed");
            expect(refusal.message).toContain("funding capacity must be a bigint between 0 and 18446744073709551615");
            expect(storage.map).toEqual(stored);
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
            const { engine } = await opened();
            await recordThreeTlcIntents(engine);
            await engine.checkAndClaim(KEYS, threeTlcRequest({ stateVersion: 1 }));
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
            const { engine } = await opened();
            await recordThreeTlcIntents(engine);
            await engine.checkAndClaim(KEYS, threeTlcRequest());
            const close = shutdownRequest("ckb", { nonceCommitmentNumber: 11 });
            expect((await refusalOf(engine.checkAndClaim(KEYS, close))).code).toBe("policy_refusal");
        });

        it("refuses a commitment on a slot a cooperative close already served", async () => {
            const { engine } = await registered();
            await engine.checkAndClaim(KEYS, shutdownRequest("ckb", { nonceCommitmentNumber: 11 }));
            const commitment = threeTlcRequest();
            expect((await refusalOf(engine.checkAndClaim(KEYS, commitment))).code).toBe("policy_refusal");
        });

        // The reason the record is keyed by the channel index: two names must never mean two slot registries.
        it("refuses a slot the channel's other name already served", async () => {
            const { engine } = newEngine();
            await engine.registerChannel("temporary-id", CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
            await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
            const kase = caseOf(digest.commitment_cases, "ckb, no tlcs, for remote");
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote", { channelId: "temporary-id" }));

            const renamed = commitmentRequest("ckb, no tlcs, for remote", {
                session: session(hexToBytes(kase.digest), { aggregatedNonce: OTHER_AGGREGATED_NONCE }),
            });
            expect((await refusalOf(engine.checkAndClaim(KEYS, renamed))).code).toBe("policy_refusal");
        });

        it("answers a byte-identical repeat arriving under the channel's other name", async () => {
            const { engine } = newEngine();
            await engine.registerChannel("temporary-id", CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
            await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
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
            const { engine } = await opened();
            await recordThreeTlcIntents(engine);
            await engine.checkAndClaim(KEYS, threeTlcRequest());
            const older = customCommitmentRequest({
                forRemote: true,
                commitmentNumber: 10,
                settlementLocalShannons: OPENING_SETTLEMENT,
                tlcIds: [],
            });
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
                pins: OPENED_PINS,
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

    describe("check 5: the channel's pins and bounds", () => {
        it.each<[string, () => PolicySignRequest, string, string, string]>([
            [
                "a commitment on another funding output",
                () =>
                    signedRequest(
                        {
                            kind: "commitment_tx",
                            input: { ...ckbCommitment(), fundingOutPoint: { txHash: hexToBytes(FUNDING_TX_HASH), index: 1 } },
                        },
                        11,
                    ),
                "fundingOutPoint",
                `${FUNDING_TX_HASH}:1`,
                `${FUNDING_TX_HASH}:0`,
            ],
            [
                "a commitment on another funding tx",
                () =>
                    signedRequest(
                        {
                            kind: "commitment_tx",
                            input: { ...ckbCommitment(), fundingOutPoint: { txHash: hexToBytes("11".repeat(32)), index: 0 } },
                        },
                        11,
                    ),
                "fundingOutPoint",
                `${"11".repeat(32)}:0`,
                `${FUNDING_TX_HASH}:0`,
            ],
            [
                "a commitment over more liquid capacity",
                () => signedRequest({ kind: "commitment_tx", input: { ...ckbCommitment(), toRemoteShannons: 18_500_000_001n } }, 11),
                "liquidCapacityShannons",
                "80500000001",
                "80500000000",
            ],
            [
                "a commitment over a larger reserve",
                () => signedRequest({ kind: "commitment_tx", input: { ...ckbCommitment(), localReservedCkbShannons: 9_900_000_001n } }, 11),
                "fundingCapacityShannons",
                "96700000001",
                "96700000000",
            ],
            [
                "a commitment moving reserve from one side to the other",
                () =>
                    signedRequest(
                        {
                            kind: "commitment_tx",
                            input: {
                                ...ckbCommitment(),
                                localReservedCkbShannons: 9_900_000_001n,
                                remoteReservedCkbShannons: 6_299_999_999n,
                            },
                        },
                        11,
                    ),
                "localReservedCkbShannons",
                "9900000001",
                "9900000000",
            ],
            [
                "a commitment under another peer funding key",
                () =>
                    signedRequest({ kind: "commitment_tx", input: { ...ckbCommitment(), remoteFundingPubkey: OTHER_FUNDING_PUBKEY } }, 11),
                "remoteFundingPubkey",
                bytesToHex(OTHER_FUNDING_PUBKEY),
                digest.remote.funding_pubkey,
            ],
            [
                "a commitment under another peer TLC base key",
                () =>
                    signedRequest({ kind: "commitment_tx", input: { ...ckbCommitment(), remoteTlcBasePubkey: OTHER_FUNDING_PUBKEY } }, 11),
                "remoteTlcBasePubkey",
                bytesToHex(OTHER_FUNDING_PUBKEY),
                digest.remote.tlc_base_pubkey,
            ],
            [
                "a commitment with another delay",
                () =>
                    signedRequest({ kind: "commitment_tx", input: { ...ckbCommitment(), commitmentDelayEpoch: 13_194_189_864_967n } }, 11),
                "commitmentDelayEpoch",
                "13194189864967",
                "1099511627777",
            ],
            [
                "a commitment at another fee rate",
                () => signedRequest({ kind: "commitment_tx", input: { ...ckbCommitment(), commitmentFeeRate: 1001n } }, 11),
                "commitmentFeeRate",
                "1001",
                "1000",
            ],
            [
                "a commitment of a UDT channel",
                () =>
                    signedRequest(
                        {
                            kind: "commitment_tx",
                            input: {
                                ...ckbCommitment(),
                                udtTypeScript: toCommitmentTxInput(
                                    caseOf(digest.commitment_cases, "udt, two tlcs, for remote"),
                                    digest.remote,
                                ).udtTypeScript,
                            },
                        },
                        11,
                    ),
                "udtTypeScript",
                UDT_SCRIPT_PIN,
                "null",
            ],
            [
                "a close on another funding output",
                () =>
                    signedRequest(
                        {
                            kind: "shutdown_tx",
                            input: { ...ckbShutdown(), fundingOutPoint: { txHash: hexToBytes(FUNDING_TX_HASH), index: 1 } },
                        },
                        11,
                    ),
                "fundingOutPoint",
                `${FUNDING_TX_HASH}:1`,
                `${FUNDING_TX_HASH}:0`,
            ],
            [
                "a close over more liquid capacity",
                () => signedRequest({ kind: "shutdown_tx", input: { ...ckbShutdown(), toLocalShannons: 62_000_000_001n } }, 11),
                "liquidCapacityShannons",
                "80500000001",
                "80500000000",
            ],
            [
                "a close under another peer funding key",
                () => signedRequest({ kind: "shutdown_tx", input: { ...ckbShutdown(), remoteFundingPubkey: OTHER_FUNDING_PUBKEY } }, 11),
                "remoteFundingPubkey",
                bytesToHex(OTHER_FUNDING_PUBKEY),
                digest.remote.funding_pubkey,
            ],
            [
                "a close paying the device to another script",
                () =>
                    signedRequest(
                        {
                            kind: "shutdown_tx",
                            input: { ...ckbShutdown(), localCloseScript: { ...CLOSE_SCRIPT, args: new Uint8Array(20) } },
                        },
                        11,
                    ),
                "localCloseScript",
                "4900000010000000300000003100000074d3f63a22681bdb6ff6512866db95264338cfaee12f71e28b9f23c414990c9c0114000000" +
                    "00".repeat(20),
                REGISTERED_PINS.localCloseScript,
            ],
            [
                "a close of a UDT channel",
                () =>
                    signedRequest(
                        {
                            kind: "shutdown_tx",
                            input: {
                                ...ckbShutdown(),
                                udtTypeScript: toShutdownTxInput(caseOf(digest.shutdown_cases, "udt"), digest.remote).udtTypeScript,
                            },
                        },
                        11,
                    ),
                "udtTypeScript",
                UDT_SCRIPT_PIN,
                "null",
            ],
            [
                "a revocation of a UDT channel",
                () =>
                    signedRequest(
                        {
                            kind: "revocation",
                            input: {
                                ...ckbRevocation(),
                                udtTypeScript: toRevocationInput(caseOf(digest.revocation_cases, "udt, receive side"), digest.remote)
                                    .udtTypeScript,
                            },
                        },
                        5,
                    ),
                "udtTypeScript",
                UDT_SCRIPT_PIN,
                "null",
            ],
            [
                "a received revocation sweeping to another script than the device's",
                () => signedRequest({ kind: "revocation", input: { ...ckbRevocation(), forRemote: true } }, 5),
                "localCloseScript",
                REMOTE_CLOSE_SCRIPT_PIN,
                REGISTERED_PINS.localCloseScript,
            ],
            [
                "a revocation over more liquid capacity",
                () => signedRequest({ kind: "revocation", input: { ...ckbRevocation(), toLocalShannons: 62_000_000_001n } }, 5),
                "liquidCapacityShannons",
                "80500000001",
                "80500000000",
            ],
            [
                "a revocation with another delay",
                () => signedRequest({ kind: "revocation", input: { ...ckbRevocation(), commitmentDelayEpoch: 13_194_189_864_967n } }, 5),
                "commitmentDelayEpoch",
                "13194189864967",
                "1099511627777",
            ],
            [
                "a revocation at another fee rate",
                () => signedRequest({ kind: "revocation", input: { ...ckbRevocation(), commitmentFeeRate: 1001n } }, 5),
                "commitmentFeeRate",
                "1001",
                "1000",
            ],
            [
                "an announcement of another funding output",
                () =>
                    signedRequest(
                        {
                            kind: "channel_announcement",
                            input: { ...ckbAnnouncement(), fundingOutPoint: { txHash: hexToBytes(FUNDING_TX_HASH), index: 1 } },
                        },
                        0,
                    ),
                "fundingOutPoint",
                `${FUNDING_TX_HASH}:1`,
                `${FUNDING_TX_HASH}:0`,
            ],
            [
                "an announcement of another capacity",
                () =>
                    signedRequest({ kind: "channel_announcement", input: { ...ckbAnnouncement(), capacityShannons: 80_500_000_001n } }, 0),
                "liquidCapacityShannons",
                "80500000001",
                "80500000000",
            ],
            [
                "an announcement under another peer funding key",
                () =>
                    signedRequest(
                        { kind: "channel_announcement", input: { ...ckbAnnouncement(), remoteFundingPubkey: OTHER_FUNDING_PUBKEY } },
                        0,
                    ),
                "remoteFundingPubkey",
                bytesToHex(OTHER_FUNDING_PUBKEY),
                digest.remote.funding_pubkey,
            ],
        ])("refuses %s than the channel pinned, and moves nothing", async (_, request, field, stated, pinned) => {
            const { engine, storage } = await opened();
            const stored = new Map(storage.map);
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, request()));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe(`the request states ${field} ${stated}, but the channel pinned ${pinned}`);
            expect(storage.map).toEqual(stored);
        });

        it("refuses an opening that turns the whole funding into the device's reserve, which pays the funded amount but locks it", async () => {
            const { engine, storage } = await registered();
            const stored = new Map(storage.map);
            const input = {
                ...ckbCommitment(),
                commitmentNumber: 0,
                toLocalShannons: 0n,
                settlementLocalShannons: 0n,
                localReservedCkbShannons: 71_900_000_000n,
            };
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, signedRequest({ kind: "commitment_tx", input }, 0)));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe("the request states localReservedCkbShannons 71900000000, but the channel pinned 9900000000");
            expect(storage.map).toEqual(stored);
        });

        it.each([
            ["a revocation it sends, whose payout is the peer's", () => signedRequest({ kind: "revocation", input: ckbRevocation() }, 5)],
            [
                "a revocation it receives, sweeping to its own script",
                () => signedRequest({ kind: "revocation", input: { ...ckbRevocation(), forRemote: true, payoutScript: CLOSE_SCRIPT } }, 5),
            ],
            ["a close to its own script", () => signedRequest({ kind: "shutdown_tx", input: ckbShutdown() }, 11)],
            ["an announcement", () => signedRequest({ kind: "channel_announcement", input: ckbAnnouncement() }, 0)],
        ])("signs %s that states every pinned value as pinned", async (_, request) => {
            const { engine, store } = await opened();
            await expect(engine.checkAndClaim(KEYS, request())).resolves.toMatchObject({ status: "fresh" });
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ pins: OPENED_PINS });
        });

        it.each<[string, () => PolicySignRequest, Partial<ChannelPins>]>([
            [
                "a close",
                () => shutdownRequest("ckb"),
                {
                    fundingOutPoint: OPENED_PINS.fundingOutPoint,
                    fundingCapacityShannons: OPENED_PINS.fundingCapacityShannons,
                    liquidCapacityShannons: OPENED_PINS.liquidCapacityShannons,
                    remoteFundingPubkey: OPENED_PINS.remoteFundingPubkey,
                    localReservedCkbShannons: OPENED_PINS.localReservedCkbShannons,
                    remoteReservedCkbShannons: OPENED_PINS.remoteReservedCkbShannons,
                },
            ],
            [
                "a revocation",
                () => revocationRequest("ckb, send side"),
                {
                    fundingCapacityShannons: OPENED_PINS.fundingCapacityShannons,
                    liquidCapacityShannons: OPENED_PINS.liquidCapacityShannons,
                    remoteFundingPubkey: OPENED_PINS.remoteFundingPubkey,
                    commitmentDelayEpoch: OPENED_PINS.commitmentDelayEpoch,
                    commitmentFeeRate: OPENED_PINS.commitmentFeeRate,
                    localReservedCkbShannons: OPENED_PINS.localReservedCkbShannons,
                    remoteReservedCkbShannons: OPENED_PINS.remoteReservedCkbShannons,
                },
            ],
            [
                "an announcement",
                () => announcementRequest("ckb"),
                {
                    fundingOutPoint: OPENED_PINS.fundingOutPoint,
                    liquidCapacityShannons: OPENED_PINS.liquidCapacityShannons,
                    remoteFundingPubkey: OPENED_PINS.remoteFundingPubkey,
                },
            ],
        ])("pins what %s states, when it is the channel's first message", async (_, request, pinned) => {
            const { engine, store } = await registered();
            await engine.checkAndClaim(KEYS, request());
            const record = await store.getChannelRecord(CHANNEL_INDEX);
            expect(record?.pins).toEqual({ ...REGISTERED_PINS, ...pinned });
        });

        it.each([
            ["a commitment", () => commitmentRequest("udt, two tlcs, for remote")],
            ["a close", () => shutdownRequest("udt")],
            ["a revocation", () => revocationRequest("udt, receive side")],
            ["an announcement", () => announcementRequest("udt")],
        ])("refuses %s of a UDT channel, the asset being fixed at registration", async (_, request) => {
            const { engine, storage } = await registered();
            const stored = new Map(storage.map);
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, request()));
            expect(refusal.message).toBe(`the request states udtTypeScript ${UDT_SCRIPT_PIN}, but the channel pinned null`);
            expect(storage.map).toEqual(stored);
        });

        it("signs a commitment fee of exactly half the reserve's margin", async () => {
            const { engine, store } = await registered();
            const input = { ...ckbCommitment(), commitmentNumber: 0, commitmentFeeRate: 109_649_124n };
            await expect(engine.checkAndClaim(KEYS, signedRequest({ kind: "commitment_tx", input }, 0))).resolves.toMatchObject({
                status: "fresh",
            });
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ pins: { commitmentFeeRate: "109649124" } });
        });

        it("refuses a commitment fee one shannon past it, pinning nothing", async () => {
            const { engine, storage } = await registered();
            const stored = new Map(storage.map);
            const input = { ...ckbCommitment(), commitmentNumber: 0, commitmentFeeRate: 109_649_125n };
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, signedRequest({ kind: "commitment_tx", input }, 0)));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe("the commitment fee is 50000001 shannons, above the 50000000 the reserve keeps for it");
            expect(storage.map).toEqual(stored);
        });

        // Cell deps are not pinned, so the bound is on the fee, not the rate.
        it.each([
            [
                "a commitment",
                () =>
                    signedRequest(
                        { kind: "commitment_tx", input: { ...ckbCommitment(), commitmentFeeRate: 109_649_124n, cellDepsCount: 3 } },
                        11,
                    ),
            ],
            [
                "a revocation",
                () =>
                    signedRequest(
                        { kind: "revocation", input: { ...ckbRevocation(), commitmentFeeRate: 109_649_124n, cellDepsCount: 3 } },
                        5,
                    ),
            ],
        ])("refuses %s whose cell deps alone push the pinned rate's fee past the bound", async (_, request) => {
            const { engine } = await registered();
            const opening = { ...ckbCommitment(), commitmentNumber: 0, commitmentFeeRate: 109_649_124n };
            await engine.checkAndClaim(KEYS, signedRequest({ kind: "commitment_tx", input: opening }, 0));
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, request()));
            expect(refusal.message).toBe("the commitment fee is 54057018 shannons, above the 50000000 the reserve keeps for it");
        });

        it("signs a close whose local fee is the 1 CKB the reserve keeps for it", async () => {
            const { engine } = await opened();
            const request = signedRequest({ kind: "shutdown_tx", input: { ...ckbShutdown(), localFeeRate: 185_185_187n } }, 11);
            await expect(engine.checkAndClaim(KEYS, request)).resolves.toMatchObject({ status: "fresh" });
        });

        it("refuses a close whose local fee is one shannon more, whatever the peer pays", async () => {
            const { engine } = await opened();
            const request = signedRequest({ kind: "shutdown_tx", input: { ...ckbShutdown(), localFeeRate: 185_185_188n } }, 11);
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, request));
            expect(refusal.message).toBe("the close takes a local fee of 100000001 shannons, above the 100000000 the reserve keeps for it");
            const peerPays = signedRequest({ kind: "shutdown_tx", input: { ...ckbShutdown(), remoteFeeRate: 185_185_188n } }, 11);
            await expect(engine.checkAndClaim(KEYS, peerPays)).resolves.toMatchObject({ status: "fresh" });
        });

        it("refuses a commitment whose settlement and TLCs pay more than the liquid capacity", async () => {
            const { engine } = await opened();
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            const { input } = customCommitmentRequest({
                forRemote: true,
                commitmentNumber: 11,
                settlementLocalShannons: "60500000000",
                tlcIds: [OFFERED_TLC_ID],
            }).operation as Extract<SignOperation, { kind: "commitment_tx" }>;
            const inflated = { ...input, settlementRemoteShannons: input.settlementRemoteShannons + 1n };
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, signedRequest({ kind: "commitment_tx", input: inflated }, 11)));
            expect(refusal.message).toBe(
                "the commitment's settlement pays 80500000001 shannons with its TLCs, above the channel's liquid capacity of 80500000000",
            );
        });

        // Fiber's own view while a removal awaits its ack: the TLC is unlisted but still deducted.
        it("signs a commitment that pays out less than the liquid capacity", async () => {
            const { engine } = await opened();
            const input = { ...ckbCommitment(), settlementRemoteShannons: 18_499_999_999n };
            await expect(engine.checkAndClaim(KEYS, signedRequest({ kind: "commitment_tx", input }, 11))).resolves.toMatchObject({
                status: "fresh",
            });
        });

        // Only the raw balances size the commitment cell; the balance rule never reads them.
        it("refuses a commitment whose raw balances no longer hold the channel's capacity", async () => {
            const { engine } = await opened();
            const input = {
                ...ckbCommitment(),
                toLocalShannons: 0n,
                toRemoteShannons: 0n,
                settlementLocalShannons: 0n,
                settlementRemoteShannons: 0n,
            };
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, signedRequest({ kind: "commitment_tx", input }, 11)));
            expect(refusal.message).toBe("the request states liquidCapacityShannons 0, but the channel pinned 80500000000");
        });
    });

    describe("check 6: the balance rule", () => {
        // Fiber may ask for the device's own commitment first.
        it.each([true, false])(
            "refuses a first commitment that lists TLCs, signing and pinning nothing (for remote: %s)",
            async (forRemote) => {
                const { engine, storage } = await registered();
                await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
                const stored = new Map(storage.map);
                const refusal = await refusalOf(
                    engine.checkAndClaim(
                        KEYS,
                        customCommitmentRequest({
                            forRemote,
                            commitmentNumber: 0,
                            settlementLocalShannons: "60500000000",
                            tlcIds: [OFFERED_TLC_ID],
                        }),
                    ),
                );
                expect(refusal.code).toBe("policy_refusal");
                expect(refusal.message).toBe("the channel's first commitment lists TLCs");
                expect(storage.map).toEqual(stored);
            },
        );

        it.each([
            ["one shannon more", true, "62000000001", "71900000001"],
            ["one shannon less", true, "61999999999", "71899999999"],
            ["one shannon more", false, "62000000001", "71900000001"],
            ["one shannon less", false, "61999999999", "71899999999"],
        ])("refuses a first commitment paying the device %s than it funded (for remote: %s)", async (_, forRemote, settlement, paid) => {
            const { engine, storage } = await registered();
            const stored = new Map(storage.map);
            const refusal = await refusalOf(
                engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({ forRemote, commitmentNumber: 0, settlementLocalShannons: settlement, tlcIds: [] }),
                ),
            );
            expect(refusal.message).toBe(`the channel's first commitment pays the device ${paid} shannons, not the ${FUNDED} it funded`);
            expect(storage.map).toEqual(stored);
        });

        it("refuses the opening the node states when the device funded another amount", async () => {
            const { engine } = await registered(new InMemorySignerStorage(), "71900000001");
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote")));
            expect(refusal.message).toBe(
                "the channel's first commitment pays the device 71900000000 shannons, not the 71900000001 it funded",
            );
        });

        it("opens on the device's own commitment too, and judges the peer's first one against the opening state", async () => {
            const { engine } = await registered();
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({ forRemote: false, commitmentNumber: 0, settlementLocalShannons: OPENING_SETTLEMENT, tlcIds: [] }),
            );
            const refusal = await refusalOf(
                engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({ forRemote: true, commitmentNumber: 1, settlementLocalShannons: "61999999999", tlcIds: [] }),
                ),
            );
            expect(refusal.message).toBe("the remote commitment lowers the holdings by 1 shannons, which no offered TLC took");
        });

        // Only the commitment slot opens a channel.
        it.each([
            ["an announcement", () => announcementRequest("ckb")],
            ["a revocation", () => revocationRequest("ckb, send side")],
        ])("judges the first commitment after %s as the opening", async (_, first) => {
            const { engine } = await registered();
            await engine.checkAndClaim(KEYS, first());
            const refusal = await refusalOf(
                engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({ forRemote: true, commitmentNumber: 0, settlementLocalShannons: "62000000001", tlcIds: [] }),
                ),
            );
            expect(refusal.message).toBe(
                `the channel's first commitment pays the device 71900000001 shannons, not the ${FUNDED} it funded`,
            );
        });

        // A close claims the commitment slot too, leaving the views at the opening state.
        it("judges a commitment after a close by its view alone", async () => {
            const { engine } = await registered();
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            await engine.checkAndClaim(KEYS, shutdownRequest("ckb", { nonceCommitmentNumber: 10 }));
            await expect(
                engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 11,
                        settlementLocalShannons: "60500000000",
                        tlcIds: [OFFERED_TLC_ID],
                    }),
                ),
            ).resolves.toMatchObject({ status: "fresh" });
        });

        it("signs a commitment against its view's previous message, and files the channel on its intents", async () => {
            const { engine, store } = await opened();
            await recordThreeTlcIntents(engine);
            await engine.checkAndClaim(KEYS, threeTlcRequest());

            const record = await store.getChannelRecord(CHANNEL_INDEX);
            expect(record?.views).toEqual({
                remote: {
                    exposureShannons: "69650000000",
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
            const { engine, store } = await opened();
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, threeTlcRequest()));
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
            const { engine } = await opened();
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            await engine.recordDebitIntent(OTHER_OFFERED_HASH, "749999999");
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, threeTlcRequest()));
            expect(refusal.message).toContain("above its debit intent of 749999999");
        });

        // The local commitment may list the device's latest add one round later.
        it("judges each view against its own previous message, so the views may cross", async () => {
            const { engine, store } = await opened();
            await recordThreeTlcIntents(engine);
            await engine.checkAndClaim(KEYS, threeTlcRequest());
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({
                    forRemote: false,
                    commitmentNumber: 12,
                    settlementLocalShannons: OPENING_SETTLEMENT,
                    tlcIds: [],
                }),
            );
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({
                    forRemote: true,
                    commitmentNumber: 13,
                    settlementLocalShannons: THREE_TLC_SETTLEMENT,
                    tlcIds: [OFFERED_TLC_ID, OTHER_OFFERED_TLC_ID, RECEIVED_TLC_ID],
                }),
            );
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({
                    forRemote: false,
                    commitmentNumber: 14,
                    settlementLocalShannons: THREE_TLC_SETTLEMENT,
                    tlcIds: [OFFERED_TLC_ID, OTHER_OFFERED_TLC_ID, RECEIVED_TLC_ID],
                }),
            );
            const record = await store.getChannelRecord(CHANNEL_INDEX);
            expect(record?.views.local).toEqual(record?.views.remote);
        });

        it("signs the device's own commitment catching up with an add after the payment's intent closed", async () => {
            const { engine } = await opened();
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
            const { engine, store } = await opened();
            await recordThreeTlcIntents(engine);
            await engine.checkAndClaim(KEYS, threeTlcRequest());
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({
                    forRemote: true,
                    commitmentNumber: 12,
                    settlementLocalShannons: THREE_TLC_SETTLEMENT,
                    tlcIds: [OTHER_OFFERED_TLC_ID, RECEIVED_TLC_ID],
                }),
            );
            const record = await store.getChannelRecord(CHANNEL_INDEX);
            expect(record?.views.remote.chargedShannons).toEqual({ [OFFERED_HASH.slice(0, 40)]: OFFERED_AMOUNT });
            expect(record?.views.local.chargedShannons).toEqual({});
        });

        it("refuses a fall no departed offered TLC accounts for", async () => {
            const { engine } = await opened();
            const refusal = await refusalOf(
                engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({ forRemote: true, commitmentNumber: 11, settlementLocalShannons: "61999999999", tlcIds: [] }),
                ),
            );
            expect(refusal.message).toBe("the remote commitment lowers the holdings by 1 shannons, which no offered TLC took");
        });

        it("draws one budget across every channel the payment shows on", async () => {
            const { engine, store } = await opened(new AsyncInMemorySignerStorage());
            await engine.registerChannel(OTHER_CHANNEL_ID, OTHER_CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
            await openChannel(engine, OTHER_CHANNEL);
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
            const { engine } = await opened();
            await engine.registerChannel(OTHER_CHANNEL_ID, OTHER_CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
            await openChannel(engine, OTHER_CHANNEL);
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
            await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
            await openChannel(engine);
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
            const { engine } = await opened(new AsyncInMemorySignerStorage());
            await engine.registerChannel(OTHER_CHANNEL_ID, OTHER_CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
            await openChannel(engine, OTHER_CHANNEL);
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
            await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
            await openChannel(engine);
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
            await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
            armed = true;
            await expect(engine.checkAndClaim(KEYS, revocationRequest("ckb, send side"))).rejects.toThrow(
                new TypeError(`channel ${CHANNEL_ID} resolves to channel index ${CHANNEL_INDEX}, which holds no record`),
            );
            expect(recordReads).toBe(2);
        });

        it("throws when a payment record lists a channel that holds no record", async () => {
            const { engine, store } = await opened();
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
                const context = await opened();
                await recordThreeTlcIntents(context.engine);
                await context.engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
                await context.engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 11,
                        settlementLocalShannons: OPENING_SETTLEMENT,
                        tlcIds: [RECEIVED_TLC_ID],
                    }),
                );
                await context.engine.markHoldInvoiceReleased(RECEIVED_HASH);
                return context;
            }

            // A part that failed on a channel busy with outgoing payments must not hold the release back.
            it("releases while a channel the invoice was shown on no longer lists it, whatever else it lists", async () => {
                const { engine, store } = await opened();
                await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 11,
                        settlementLocalShannons: OPENING_SETTLEMENT,
                        tlcIds: [RECEIVED_TLC_ID],
                    }),
                );
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 12,
                        settlementLocalShannons: OPENING_SETTLEMENT,
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
                const { engine, store } = await opened();
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "ckb-hash");
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 11,
                        settlementLocalShannons: OPENING_SETTLEMENT,
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
                const { engine } = await opened();
                await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 11,
                        settlementLocalShannons: OPENING_SETTLEMENT,
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
                const { engine, store } = await opened();
                await recordThreeTlcIntents(engine);
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
                await engine.checkAndClaim(KEYS, threeTlcRequest());
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
                            settlementLocalShannons: OPENING_SETTLEMENT,
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
                const { engine } = await opened();
                await engine.registerChannel(OTHER_CHANNEL_ID, OTHER_CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
                await openChannel(engine, OTHER_CHANNEL);
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
                const other = { keys: OTHER_KEYS, channelId: OTHER_CHANNEL_ID };
                const holding = (forRemote: boolean, commitmentNumber: number) => ({
                    forRemote,
                    commitmentNumber,
                    settlementLocalShannons: OPENING_SETTLEMENT,
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
                    { forRemote: true, commitmentNumber: 13, settlementLocalShannons: OPENING_SETTLEMENT, tlcIds: [] },
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
            const { engine, store } = await opened();
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256");
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({
                    forRemote: true,
                    commitmentNumber: 11,
                    settlementLocalShannons: OPENING_SETTLEMENT,
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
            const { engine } = await registered(new InMemorySignerStorage(), "75000000000");
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, shutdownRequest("ckb")));
            expect(refusal.message).toBe("the close pays the device 71900000000 shannons, below the 75000000000 of the remote commitment");
        });

        it("refuses a cooperative close while a view still lists TLCs", async () => {
            const { engine } = await opened();
            await recordThreeTlcIntents(engine);
            await engine.checkAndClaim(KEYS, threeTlcRequest());
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
            await engine.registerChannel("temporary-id", CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
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
            const { engine, storage } = await opened();
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            const stored = new Map(storage.map);
            storage.ops.length = 0;
            await refusalOf(engine.checkAndClaim(KEYS, threeTlcRequest()));
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
