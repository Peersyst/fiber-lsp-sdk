import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { CellDep, CellOutput, OutPoint, Script } from "../../../src/common";
import type { FiberChannelKeys } from "../../../src/derivation";
import { deriveChannelKeys, pubkeyOf } from "../../../src/derivation";
import {
    buildRemainderLockArgs,
    computeChannelAnnouncementDigest,
    computeClosingTxDigest,
    computeCommitmentTxDigest,
    computeRevocationDigest,
    computeTxHash,
    computeTxMessage,
    moleculeCellOutput,
    readClosingTx,
} from "../../../src/digest";
import type {
    ChannelPinConflict,
    ChannelPins,
    ChannelPolicyRecord,
    DebitIntentRecord,
    HoldInvoicePolicyRecord,
    HoldInvoiceReleaseTiming,
    NonceCounter,
    PolicyChannelTerms,
    PolicyEngineOptions,
    PolicySignRequest,
    PolicyView,
    SignOperation,
    SignSession,
    WatchtowerApproval,
    WatchtowerSpendRecord,
    WatchtowerSpendRequest,
} from "../../../src/policy";
import {
    ChannelPinError,
    ChannelRegistrationError,
    DebitIntentError,
    HoldInvoiceError,
    PolicyEngine,
    PolicyRefusalError,
    SignerStore,
} from "../../../src/policy";
import { buildSessionCommitment } from "../../../src/policy/utils";
import { AsyncInMemorySignerStorage, InMemorySignerStorage } from "../../mocks/policy";
import { fundedShannonsOf } from "../../utils/channel-opening";
import {
    toChannelAnnouncementInput,
    toClosingTxInput,
    toCommitmentTxInput,
    toRevocationInput,
    toTlc,
    toTransaction,
} from "../../utils/digest-inputs";
import { caseOf, loadInteropVectors } from "../../utils/interop-vectors";
import { SHUTDOWN_NONCE_NUMBER, revocationCounter, revocationNonceNumber } from "../../utils/nonce-numbers";

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
const CLOSE_SCRIPT = toClosingTxInput(caseOf(digest.shutdown_cases, "ckb"), digest.remote).localCloseScript;
// What the "ckb" close pays the device: its settlement and reserve, less its 540-shannon fee.
const CLOSE_LOCAL_CAPACITY = "71899999460";

// The "ckb" cases' terms, which no request vouches for, and their first-sight values: the host pins them from the node's
// opening context.
const TERMS: PolicyChannelTerms = {
    commitmentFeeRate: 1000n,
    remoteReservedCkbShannons: "6300000000",
    liquidCapacityShannons: "80500000000",
    remoteCloseScript: {
        codeHash: hexToBytes("014f879c667f549df6067c1797534f2b2de2312feff188d100669d4b8ad6f045"),
        hashType: "data1",
        args: hexToBytes("0682a2f376b830a421ddc7d3b8cf4bffb31bfdf2942f46780359b1ef4f107f36"),
    },
    remoteFundingPubkey: hexToBytes("026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638"),
    remoteTlcBasePubkey: hexToBytes("032559e1b167552782cab5be4294260d51edfc36aef4ca7cc165b3b21b15e98e21"),
    commitmentDelayEpoch: 1099511627777n,
};

const OFFERED_HASH = "6844f645bb03ff9d1c9c48ee5e9e971be09bf34a3612c81b20c2a5a1bff2a6b6";
const OFFERED_AMOUNT = "1500000000";
const OTHER_OFFERED_HASH = "c5403872f3e0258e74e8b2ae5aa77e4d8b8dc93c799288270fef73997f8d93f5";
const OTHER_OFFERED_AMOUNT = "750000000";
const RECEIVED_HASH = "5b36757f3945408453a6282c4aba2c78bfaba94219e459932924b01f7fc09d1e";
const RECEIVED_AMOUNT = "2250000000";
const OFFERED_TLC_ID = 7;
const OTHER_OFFERED_TLC_ID = 5;
const RECEIVED_TLC_ID = 2;
const INVOICE_INDEX = 1761475200000;
// Ten minutes of margin, well before the received TLC's expiry at 1750000000000 ms.
const RELEASE_TIMING: HoldInvoiceReleaseTiming = { now: () => 1749990000000, releaseMarginMs: () => 600000n };

const REMOTE_CLOSE_SCRIPT_PIN =
    "55000000100000003000000031000000014f879c667f549df6067c1797534f2b2de2312feff188d100669d4b8ad6f04502200000000682a2f376b830a421ddc7d3b8cf4bffb31bfdf2942f46780359b1ef4f107f36";

const REGISTERED_PINS: ChannelPins = {
    fundedShannons: FUNDED,
    localCloseScript:
        "4900000010000000300000003100000074d3f63a22681bdb6ff6512866db95264338cfaee12f71e28b9f23c414990c9c0114000000da694932ba803b4c07f6e3a9b6b2ea3f9c6c66c7",
    // Args under 57 bytes: 98 CKB occupied plus the 1 CKB close fee under legacy, one byte more under the full hash.
    localReservedCkbShannons: { legacy: "9900000000", fullPaymentHash: "10000000000" },
    udtTypeScript: null,
};

const TERMS_PINNED_PINS: ChannelPins = {
    ...REGISTERED_PINS,
    liquidCapacityShannons: "80500000000",
    commitmentFeeRate: "1000",
    remoteReservedCkbShannons: "6300000000",
    remoteCloseScript: REMOTE_CLOSE_SCRIPT_PIN,
    remoteFundingPubkey: "026372d1f1bf5f44d3bf185fe8f69502f36c9a01760029db0a15f6c7dedb4f5638",
    remoteTlcBasePubkey: "032559e1b167552782cab5be4294260d51edfc36aef4ca7cc165b3b21b15e98e21",
    commitmentDelayEpoch: "1099511627777",
};

// The terms and what the "ckb" cases state.
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
    remoteCloseScript: REMOTE_CLOSE_SCRIPT_PIN,
    lockLayout: "legacy",
};

const FUNDING_TX_HASH = "6f4ea49726c322dbedceb12a09d013a0256ea697dc362cc8865f8bbcdd17684e";
const UDT_SCRIPT_PIN =
    "5500000010000000300000003100000091" +
    "2f64f976947ed5467ff5e7ba4c87bd37f240cdbdba0b38da619372056ef82701200000008612706980baca14e3d03ea4d77d185e6f7338cd6e98a0ea0cd17a69918f2578";

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
        slot: { commitmentNumber: kase.commitment_number, counter: "local" },
        session: session(hexToBytes(kase.digest)),
        operation: { kind: "commitment_tx", input: toCommitmentTxInput(kase, digest.remote) },
        ...overrides,
    };
}

function closingRequest(name: string, overrides: Partial<PolicySignRequest> = {}): PolicySignRequest {
    const kase = caseOf(digest.shutdown_cases, name);
    return {
        channelId: CHANNEL_ID,
        slot: { commitmentNumber: SHUTDOWN_NONCE_NUMBER, counter: "local" },
        session: session(hexToBytes(kase.digest)),
        operation: { kind: "closing_tx", input: toClosingTxInput(kase, digest.remote) },
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
            base.liquidCapacityShannons - settlementLocalShannons - tlcs.reduce((sum, tlc) => sum + tlc.amountShannons, 0n),
        tlcs,
    };
    return signedRequest({ kind: "commitment_tx", input }, custom.commitmentNumber, channel);
}

function ckbCommitment(): Extract<SignOperation, { kind: "commitment_tx" }>["input"] {
    return { ...toCommitmentTxInput(caseOf(digest.commitment_cases, "ckb, no tlcs, for remote"), digest.remote), commitmentNumber: 11 };
}

function ckbClose(): Extract<SignOperation, { kind: "closing_tx" }>["input"] {
    return toClosingTxInput(caseOf(digest.shutdown_cases, "ckb"), digest.remote);
}

function ckbRevocation(): Extract<SignOperation, { kind: "revocation" }>["input"] {
    return toRevocationInput(caseOf(digest.revocation_cases, "ckb, send side"), digest.remote);
}

function ckbAnnouncement(): Extract<SignOperation, { kind: "channel_announcement" }>["input"] {
    return toChannelAnnouncementInput(caseOf(digest.announcement_cases, "ckb"), digest.remote);
}

// The counter fiber reads each operation's slot from.
function counterOf(operation: SignOperation): NonceCounter | null {
    if (operation.kind === "channel_announcement") return null;
    if (operation.kind === "revocation") return operation.input.forRemote ? "local" : "remote";
    return "local";
}

function signedRequest(
    operation: SignOperation,
    commitmentNumber: number,
    channel: Channel = { keys: KEYS, channelId: CHANNEL_ID },
): PolicySignRequest {
    return {
        channelId: channel.channelId,
        slot: { commitmentNumber, counter: counterOf(operation) },
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
        case "closing_tx":
            return computeClosingTxDigest(keys, operation.input);
        case "revocation":
            return computeRevocationDigest(keys, operation.input);
        case "channel_announcement":
            return computeChannelAnnouncementDigest(keys, operation.input);
    }
}

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

// The remote view's first commitment, so 11 follows it with no revocation.
async function openChannel(engine: PolicyEngine, channel: Channel = { keys: KEYS, channelId: CHANNEL_ID }): Promise<void> {
    await engine.checkAndClaim(
        channel.keys,
        customCommitmentRequest(
            { forRemote: true, commitmentNumber: 10, settlementLocalShannons: OPENING_SETTLEMENT, tlcIds: [] },
            channel,
        ),
    );
}

// The received TLC in both views: the peer's commitment at 11, the device's own at 12.
async function holdReceived(engine: PolicyEngine, channel: Channel = { keys: KEYS, channelId: CHANNEL_ID }): Promise<void> {
    for (const [forRemote, commitmentNumber] of [
        [true, 11],
        [false, 12],
    ] as const) {
        await engine.checkAndClaim(
            channel.keys,
            customCommitmentRequest(
                { forRemote, commitmentNumber, settlementLocalShannons: OPENING_SETTLEMENT, tlcIds: [RECEIVED_TLC_ID] },
                channel,
            ),
        );
    }
}

async function recordThreeTlcIntents(engine: PolicyEngine): Promise<void> {
    await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
    await engine.recordDebitIntent(OTHER_OFFERED_HASH, OTHER_OFFERED_AMOUNT);
}

function revocationRequest(name: string, overrides: Partial<PolicySignRequest> = {}): PolicySignRequest {
    const kase = caseOf(digest.revocation_cases, name);
    return {
        channelId: CHANNEL_ID,
        slot: { commitmentNumber: revocationNonceNumber(kase), counter: revocationCounter(kase) },
        session: session(hexToBytes(kase.digest)),
        operation: { kind: "revocation", input: toRevocationInput(kase, digest.remote) },
        ...overrides,
    };
}

// The revocation of the peer's commitment one below the slot, sweeping to the device's script, the digest the SDK's.
function receivedRevocation(slot: number, channel: Channel = { keys: KEYS, channelId: CHANNEL_ID }): PolicySignRequest {
    const input = { ...ckbRevocation(), forRemote: true, payoutScript: CLOSE_SCRIPT, revokedCommitmentNumber: slot - 1 };
    return signedRequest({ kind: "revocation", input }, slot, channel);
}

// The revocation of the device's own commitment one below the slot.
function sentRevocation(slot: number): PolicySignRequest {
    return signedRequest({ kind: "revocation", input: { ...ckbRevocation(), revokedCommitmentNumber: slot - 1 } }, slot);
}

const SIGNATURE = Uint8Array.from({ length: 64 }, (_, index) => index);
const OTHER_SIGNATURE = Uint8Array.from({ length: 64 }, (_, index) => 255 - index);

async function peerRevokes(engine: PolicyEngine, slot: number, channel: Channel = { keys: KEYS, channelId: CHANNEL_ID }): Promise<void> {
    await engine.checkAndClaim(channel.keys, receivedRevocation(slot, channel));
    await engine.recordRevocation(channel.channelId, { version: slot - 1, signature: SIGNATURE });
}

// Never read by the revocation rule, which holds the replacement's version; the hash only records what was signed.
const REPLACEMENT_TX_HASH = "5e".repeat(32);

// The cells and settlement bodies of two vector commitments, molecule hex written by hand from fiber's txs and witnesses.
const NO_TLC_REMOTE_OUTPUT =
    "8600000010000000180000008600000038e5c483160000006e000000100000003000000031000000740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc" +
    "90b1a748438afcdf81d801390000007ff980b4d180ee128bbfc295ef936f8d73a5dea501000000000100a00000000000000000d192bbc331c35aebda34ea" +
    "9953c40f79a54bab8900";
const NO_TLC_REMOTE_WITNESS =
    "00e5b099614920970b0ec3c35f979f4d1a070336d600f831c60500000000000000000000006b5e8d9ad1828550472e07fe80b39585cc0837d600ef92bd10" +
    "0000000000000000000000";
const THREE_TLC_LOCAL_OUTPUT =
    "8600000010000000180000008600000038e5c483160000006e000000100000003000000031000000740dee83f87c6f309824d8fd3fbdd3c8380ee6fc9acc" +
    "90b1a748438afcdf81d801390000004483f0fbfe1784b42de8fd2c7900febe16cf8c7907000003000c00a0000000000000000ce291deb0de8d8f0ea152d9" +
    "bc6a7d42a55b0dcc1100";

async function holdLastCommitment(store: SignerStore, view: PolicyView, commitmentNumber: number): Promise<void> {
    await store.updateChannelRecord(CHANNEL_INDEX, (current) => {
        if (current === null) throw new Error("the channel holds no record");
        const last = { commitmentNumber, txHash: REPLACEMENT_TX_HASH };
        // The record guard holds a previous remote commitment to one below the last remote one, which this one replaces.
        const previous = view === "remote" ? { previousRemoteCommitment: undefined } : {};
        return { ...current, commitmentHashes: { ...current.commitmentHashes, [view]: last }, ...previous };
    });
}

// A revocation follows its replacement, the commitment at the slot's number, as the last one signed in the revoked one's
// view. Any other request passes untouched.
async function holdingReplacement(store: SignerStore, request: PolicySignRequest): Promise<PolicySignRequest> {
    const { operation, slot } = request;
    if (operation.kind === "revocation") {
        await holdLastCommitment(store, operation.input.forRemote ? "remote" : "local", slot.commitmentNumber);
    }
    return request;
}

function announcementRequest(name: string, overrides: Partial<PolicySignRequest> = {}): PolicySignRequest {
    const kase = caseOf(digest.announcement_cases, name);
    return {
        channelId: CHANNEL_ID,
        slot: { commitmentNumber: 0, counter: null },
        session: session(hexToBytes(kase.digest)),
        operation: { kind: "channel_announcement", input: toChannelAnnouncementInput(kase, digest.remote) },
        ...overrides,
    };
}

type Storage = InMemorySignerStorage | AsyncInMemorySignerStorage;

function newEngine(
    storage: Storage = new InMemorySignerStorage(),
    options?: PolicyEngineOptions,
): {
    engine: PolicyEngine;
    store: SignerStore;
    storage: Storage;
} {
    const store = new SignerStore(storage);
    return { engine: new PolicyEngine(store, options), store, storage };
}

// As the host registers it: terms pinned from the open's context before anything is signed.
async function registeredEngine(storage: Storage = new InMemorySignerStorage(), options?: PolicyEngineOptions) {
    const context = newEngine(storage, options);
    await context.engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
    await context.engine.pinChannelTerms(CHANNEL_ID, TERMS);
    return context;
}

async function openedEngine(storage: Storage = new InMemorySignerStorage(), options?: PolicyEngineOptions) {
    const context = await registeredEngine(storage, options);
    await openChannel(context.engine);
    return context;
}

async function addOtherChannel(engine: PolicyEngine): Promise<void> {
    await engine.registerChannel(OTHER_CHANNEL_ID, OTHER_CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
    await engine.pinChannelTerms(OTHER_CHANNEL_ID, TERMS);
    await openChannel(engine, OTHER_CHANNEL);
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

async function registrationErrorOf(promise: Promise<unknown>): Promise<ChannelRegistrationError> {
    try {
        await promise;
    } catch (error) {
        if (error instanceof ChannelRegistrationError) return error;
        throw error;
    }
    throw new Error("expected a registration error");
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
            nonceReuse: {},
            commitmentHashes: {},
            revocations: [],
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
            const error = await registrationErrorOf(engine.registerChannel(channelId, CHANNEL_INDEX, funded, closeScript));
            expect(error).toBeInstanceOf(TypeError);
            expect(error).toMatchObject({
                name: "ChannelRegistrationError",
                message: `channel index ${CHANNEL_INDEX} is already registered with another funded amount or close script`,
                channelId,
                channelIndex: CHANNEL_INDEX,
            });
        }
        expect(storage.map).toEqual(stored);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ channelId: "temporary-id" });
    });

    it("rejects a re-registration under a different channel index", async () => {
        const { engine, storage } = newEngine();
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        const error = await registrationErrorOf(engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX + 1, FUNDED, CLOSE_SCRIPT));
        expect(error).toBeInstanceOf(TypeError);
        expect(error).toMatchObject({
            name: "ChannelRegistrationError",
            message: `channel ${CHANNEL_ID} is already registered under a different channel index`,
            channelId: CHANNEL_ID,
            channelIndex: CHANNEL_INDEX + 1,
        });
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
        // The loser reads the name free and meets it taken at the claim.
        const loser = outcomes[1];
        const reason: unknown = loser.status === "rejected" ? loser.reason : null;
        expect(reason).toBeInstanceOf(ChannelRegistrationError);
        expect(reason).toMatchObject({
            message: `the name at fiber-lsp-sdk:alias:${CHANNEL_ID} already resolves to channel index ${CHANNEL_INDEX}`,
            channelId: CHANNEL_ID,
            channelIndex: CHANNEL_INDEX + 1,
        });
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
        await engine.pinChannelTerms("temporary-id", TERMS);
        await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote", { channelId: "temporary-id" }));

        await expect(registrationErrorOf(engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT))).resolves.toMatchObject({
            name: "ChannelRegistrationError",
            message: `channel index ${CHANNEL_INDEX} already serves channel temporary-id`,
            channelId: CHANNEL_ID,
            channelIndex: CHANNEL_INDEX,
        });
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ channelId: "temporary-id" });
        expect((await refusalOf(engine.requireChannelIndex(CHANNEL_ID))).code).toBe("unknown_channel");
    });

    it("rejects a new name on an index whose record only moved a counter", async () => {
        const { engine, store } = newEngine();
        await engine.registerChannel("temporary-id", CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        await store.setChannelRecord(CHANNEL_INDEX, {
            version: 1,
            channelId: "temporary-id",
            lastSignedCommitmentNumbers: { "COMMITMENT:local": 0 },
            signedSessions: {},
            nonceReuse: {},
            commitmentHashes: {},
            revocations: [],
            pins: REGISTERED_PINS,
            views: { remote: OPENING_VIEW, local: OPENING_VIEW },
        });
        const error = await registrationErrorOf(engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT));
        expect(error).toBeInstanceOf(TypeError);
        expect(error).toMatchObject({
            message: `channel index ${CHANNEL_INDEX} already serves channel temporary-id`,
            channelId: CHANNEL_ID,
            channelIndex: CHANNEL_INDEX,
        });
    });

    // A broken store is no registration the records contradict: the host must not read it as one.
    it.each([
        ["a record", `fiber-lsp-sdk:channel:${CHANNEL_INDEX}`, "{}", "is not a channel policy record"],
        ["a name", `fiber-lsp-sdk:alias:${CHANNEL_ID}`, "x", "is not a channel index"],
    ])("throws a plain TypeError over %s the store holds corrupt, writing nothing", async (_, key, value, reason) => {
        const { engine, storage } = newEngine();
        storage.map.set(key, value);
        const error: unknown = await engine
            .registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT)
            .catch((caught: unknown) => caught);
        expect(error).toEqual(new TypeError(`stored value at ${key} ${reason}`));
        expect(error).not.toBeInstanceOf(ChannelRegistrationError);
        expect(storage.map).toEqual(new Map([[key, value]]));
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
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toEqual(
            expect.objectContaining({
                pins: { ...TERMS_PINNED_PINS, fundingOutPoint: `${FUNDING_TX_HASH}:0`, fundingCapacityShannons: "96700000000" },
            }),
        );
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
    ])("throws a ChannelPinError on %s once the node pinned the cell, naming both values", async (_, outPoint, capacity, conflict) => {
        const { engine, storage } = await openedEngine();
        const stored = new Map(storage.map);
        const error: unknown = await engine.pinFundingCell(CHANNEL_ID, outPoint, capacity).catch((caught: unknown) => caught);
        expect(error).toBeInstanceOf(ChannelPinError);
        expect(error).toMatchObject({
            name: "ChannelPinError",
            message: `channel ${CHANNEL_ID} already pins ${conflict.field} to ${conflict.pinned}, not ${conflict.stated}`,
            conflict,
        });
        expect(storage.map).toEqual(stored);
    });

    it("throws a ChannelPinError on another cell than an earlier host pin", async () => {
        const { engine, storage } = await registeredEngine();
        await engine.pinFundingCell(CHANNEL_ID, FUNDING_OUT_POINT, "96700000000");
        const stored = new Map(storage.map);
        await expect(engine.pinFundingCell(CHANNEL_ID, FUNDING_OUT_POINT, "96700000001")).rejects.toThrow(ChannelPinError);
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
        await engine.pinChannelTerms(CHANNEL_ID, TERMS);
        armed = true;

        await openChannel(engine);
        expect(pin).not.toBeNull();
        await expect(pin).rejects.toBeInstanceOf(ChannelPinError);
        await expect(pin).rejects.toThrow(
            `channel ${CHANNEL_ID} already pins fundingOutPoint to ${FUNDING_TX_HASH}:0, not ${FUNDING_TX_HASH}:1`,
        );
        await expect(new SignerStore(inner).getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ pins: OPENED_PINS });
    });
});

describe("pinChannelTerms", () => {
    async function bare(storage: Storage = new InMemorySignerStorage()) {
        const context = newEngine(storage);
        await context.engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        return context;
    }

    it("pins the four terms no request vouches for and the opening's three first-sight values, beside the registration's pins", async () => {
        const { engine, store } = await bare();
        await engine.pinChannelTerms(CHANNEL_ID, TERMS);
        expect((await store.getChannelRecord(CHANNEL_INDEX))?.pins).toEqual(TERMS_PINNED_PINS);
    });

    it("pins u64's maximum in each", async () => {
        const { engine, store } = await bare();
        await engine.pinChannelTerms(CHANNEL_ID, {
            ...TERMS,
            commitmentFeeRate: 18446744073709551615n,
            remoteReservedCkbShannons: "18446744073709551615",
            liquidCapacityShannons: "18446744073709551615",
            commitmentDelayEpoch: 18446744073709551615n,
        });
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
            pins: {
                commitmentFeeRate: "18446744073709551615",
                remoteReservedCkbShannons: "18446744073709551615",
                liquidCapacityShannons: "18446744073709551615",
                commitmentDelayEpoch: "18446744073709551615",
            },
        });
    });

    it("writes nothing when the same terms are pinned again, under either name, before or after the opening", async () => {
        const { engine, storage } = await bare();
        await engine.registerChannel("temporary-id", CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        await engine.pinChannelTerms("temporary-id", TERMS);
        storage.ops.length = 0;
        await engine.pinChannelTerms(CHANNEL_ID, TERMS);
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
        await openChannel(engine);
        storage.ops.length = 0;
        await engine.pinChannelTerms(CHANNEL_ID, { ...TERMS });
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
        await engine.pinChannelTerms(CHANNEL_ID, {
            ...TERMS,
            remoteCloseScript: {
                codeHash: hexToBytes("014f879c667f549df6067c1797534f2b2de2312feff188d100669d4b8ad6f045"),
                hashType: "data1",
                args: hexToBytes("0682a2f376b830a421ddc7d3b8cf4bffb31bfdf2942f46780359b1ef4f107f36"),
            },
        });
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
    });

    it.each<[string, Partial<PolicyChannelTerms>, ChannelPinConflict]>([
        ["another fee rate", { commitmentFeeRate: 1001n }, { field: "commitmentFeeRate", pinned: "1000", stated: "1001" }],
        [
            "another peer reserve",
            { remoteReservedCkbShannons: "6299999999" },
            { field: "remoteReservedCkbShannons", pinned: "6300000000", stated: "6299999999" },
        ],
        [
            "another liquid capacity",
            { liquidCapacityShannons: "80500000001" },
            { field: "liquidCapacityShannons", pinned: "80500000000", stated: "80500000001" },
        ],
        [
            "another peer funding key",
            { remoteFundingPubkey: OTHER_FUNDING_PUBKEY },
            { field: "remoteFundingPubkey", pinned: digest.remote.funding_pubkey, stated: bytesToHex(OTHER_FUNDING_PUBKEY) },
        ],
        [
            "another peer TLC base key",
            { remoteTlcBasePubkey: OTHER_FUNDING_PUBKEY },
            { field: "remoteTlcBasePubkey", pinned: digest.remote.tlc_base_pubkey, stated: bytesToHex(OTHER_FUNDING_PUBKEY) },
        ],
        [
            "another delay",
            { commitmentDelayEpoch: 1099511627778n },
            { field: "commitmentDelayEpoch", pinned: "1099511627777", stated: "1099511627778" },
        ],
        [
            "another peer close script",
            { remoteCloseScript: CLOSE_SCRIPT },
            { field: "remoteCloseScript", pinned: REMOTE_CLOSE_SCRIPT_PIN, stated: REGISTERED_PINS.localCloseScript },
        ],
        [
            "a peer close script one args byte shorter",
            {
                remoteCloseScript: {
                    codeHash: hexToBytes("014f879c667f549df6067c1797534f2b2de2312feff188d100669d4b8ad6f045"),
                    hashType: "data1",
                    args: hexToBytes("0682a2f376b830a421ddc7d3b8cf4bffb31bfdf2942f46780359b1ef4f107f"),
                },
            },
            {
                field: "remoteCloseScript",
                pinned: REMOTE_CLOSE_SCRIPT_PIN,
                stated:
                    "54000000100000003000000031000000014f879c667f549df6067c1797534f2b2de2312feff188d100669d4b8ad6f045" +
                    "021f0000000682a2f376b830a421ddc7d3b8cf4bffb31bfdf2942f46780359b1ef4f107f",
            },
        ],
        [
            "a peer close script under another hash type",
            {
                remoteCloseScript: {
                    codeHash: hexToBytes("014f879c667f549df6067c1797534f2b2de2312feff188d100669d4b8ad6f045"),
                    hashType: "data2",
                    args: hexToBytes("0682a2f376b830a421ddc7d3b8cf4bffb31bfdf2942f46780359b1ef4f107f36"),
                },
            },
            {
                field: "remoteCloseScript",
                pinned: REMOTE_CLOSE_SCRIPT_PIN,
                stated:
                    "55000000100000003000000031000000014f879c667f549df6067c1797534f2b2de2312feff188d100669d4b8ad6f045" +
                    "04200000000682a2f376b830a421ddc7d3b8cf4bffb31bfdf2942f46780359b1ef4f107f36",
            },
        ],
    ])("throws a ChannelPinError on %s than pinned, naming both values, writing nothing", async (_, override, conflict) => {
        const { engine, storage } = await registeredEngine();
        const stored = new Map(storage.map);
        const error: unknown = await engine.pinChannelTerms(CHANNEL_ID, { ...TERMS, ...override }).catch((caught: unknown) => caught);
        expect(error).toBeInstanceOf(ChannelPinError);
        expect(error).toMatchObject({
            name: "ChannelPinError",
            message: `channel ${CHANNEL_ID} already pins ${conflict.field} to ${conflict.pinned}, not ${conflict.stated}`,
            conflict,
        });
        expect(storage.map).toEqual(stored);
    });

    it.each<[string, PolicyChannelTerms, Error]>([
        ["a terms argument that is no object", null as unknown as PolicyChannelTerms, new TypeError("terms must be an object")],
        [
            "a negative fee rate",
            { ...TERMS, commitmentFeeRate: -1n },
            new RangeError("terms.commitmentFeeRate must be a bigint between 0 and 18446744073709551615, got -1"),
        ],
        [
            "a fee rate above u64",
            { ...TERMS, commitmentFeeRate: 18446744073709551616n },
            new RangeError("terms.commitmentFeeRate must be a bigint between 0 and 18446744073709551615, got 18446744073709551616"),
        ],
        [
            "a fee rate that is a number",
            { ...TERMS, commitmentFeeRate: 1000 as unknown as bigint },
            new RangeError("terms.commitmentFeeRate must be a bigint between 0 and 18446744073709551615, got 1000"),
        ],
        [
            "a peer reserve in hex",
            { ...TERMS, remoteReservedCkbShannons: "0x1" },
            new TypeError("terms.remoteReservedCkbShannons must be an amount in decimal shannons"),
        ],
        [
            "a peer reserve above u64",
            { ...TERMS, remoteReservedCkbShannons: "18446744073709551616" },
            new RangeError("terms.remoteReservedCkbShannons must be at most 18446744073709551615, the most a CKB cell's capacity holds"),
        ],
        [
            "an absent liquid capacity",
            { ...TERMS, liquidCapacityShannons: undefined as unknown as string },
            new TypeError("terms.liquidCapacityShannons must be an amount in decimal shannons"),
        ],
        [
            "a liquid capacity with a leading zero",
            { ...TERMS, liquidCapacityShannons: "080500000000" },
            new TypeError("terms.liquidCapacityShannons must be an amount in decimal shannons"),
        ],
        [
            "a liquid capacity above u64",
            { ...TERMS, liquidCapacityShannons: "18446744073709551616" },
            new RangeError("terms.liquidCapacityShannons must be at most 18446744073709551615, the most a CKB cell's capacity holds"),
        ],
        [
            "an absent peer funding key",
            { ...TERMS, remoteFundingPubkey: undefined as unknown as Uint8Array },
            new TypeError("terms.remoteFundingPubkey must be a Uint8Array"),
        ],
        [
            "a peer funding key in hex",
            { ...TERMS, remoteFundingPubkey: digest.remote.funding_pubkey as unknown as Uint8Array },
            new TypeError("terms.remoteFundingPubkey must be a Uint8Array"),
        ],
        [
            "a peer funding key of 32 bytes",
            { ...TERMS, remoteFundingPubkey: hexToBytes(digest.remote.funding_pubkey).subarray(1) },
            new TypeError("terms.remoteFundingPubkey must be 33 bytes, got 32"),
        ],
        [
            "a peer funding key of 34 bytes",
            { ...TERMS, remoteFundingPubkey: hexToBytes(`${digest.remote.funding_pubkey}00`) },
            new TypeError("terms.remoteFundingPubkey must be 33 bytes, got 34"),
        ],
        [
            "a peer funding key off the curve",
            { ...TERMS, remoteFundingPubkey: hexToBytes(`02${"00".repeat(32)}`) },
            new TypeError("terms.remoteFundingPubkey must be a compressed point on secp256k1"),
        ],
        [
            "an absent peer TLC base key",
            { ...TERMS, remoteTlcBasePubkey: undefined as unknown as Uint8Array },
            new TypeError("terms.remoteTlcBasePubkey must be a Uint8Array"),
        ],
        [
            "a peer TLC base key in hex",
            { ...TERMS, remoteTlcBasePubkey: digest.remote.tlc_base_pubkey as unknown as Uint8Array },
            new TypeError("terms.remoteTlcBasePubkey must be a Uint8Array"),
        ],
        [
            "a peer TLC base key of 32 bytes",
            { ...TERMS, remoteTlcBasePubkey: hexToBytes(digest.remote.tlc_base_pubkey).subarray(1) },
            new TypeError("terms.remoteTlcBasePubkey must be 33 bytes, got 32"),
        ],
        [
            "a peer TLC base key of 34 bytes",
            { ...TERMS, remoteTlcBasePubkey: hexToBytes(`${digest.remote.tlc_base_pubkey}00`) },
            new TypeError("terms.remoteTlcBasePubkey must be 33 bytes, got 34"),
        ],
        [
            "a peer TLC base key off the curve",
            { ...TERMS, remoteTlcBasePubkey: hexToBytes(`02${"00".repeat(32)}`) },
            new TypeError("terms.remoteTlcBasePubkey must be a compressed point on secp256k1"),
        ],
        [
            "an absent delay",
            { ...TERMS, commitmentDelayEpoch: undefined as unknown as bigint },
            new RangeError("terms.commitmentDelayEpoch must be a bigint between 0 and 18446744073709551615, got undefined"),
        ],
        [
            "a delay that is a number",
            { ...TERMS, commitmentDelayEpoch: 1099511627777 as unknown as bigint },
            new RangeError("terms.commitmentDelayEpoch must be a bigint between 0 and 18446744073709551615, got 1099511627777"),
        ],
        [
            "a negative delay",
            { ...TERMS, commitmentDelayEpoch: -1n },
            new RangeError("terms.commitmentDelayEpoch must be a bigint between 0 and 18446744073709551615, got -1"),
        ],
        [
            "a delay above u64",
            { ...TERMS, commitmentDelayEpoch: 18446744073709551616n },
            new RangeError("terms.commitmentDelayEpoch must be a bigint between 0 and 18446744073709551615, got 18446744073709551616"),
        ],
        [
            "an absent peer close script",
            { ...TERMS, remoteCloseScript: undefined as unknown as Script },
            new TypeError("terms.remoteCloseScript must be an object"),
        ],
        [
            "a peer close script in molecule hex, its pin's form",
            { ...TERMS, remoteCloseScript: REMOTE_CLOSE_SCRIPT_PIN as unknown as Script },
            new TypeError("terms.remoteCloseScript must be an object"),
        ],
        [
            "a peer close script with no code hash",
            { ...TERMS, remoteCloseScript: { hashType: "data1", args: new Uint8Array(32) } as unknown as Script },
            new TypeError("terms.remoteCloseScript.codeHash must be a Uint8Array"),
        ],
        [
            "a peer close script whose code hash is hex",
            {
                ...TERMS,
                remoteCloseScript: {
                    codeHash: "014f879c667f549df6067c1797534f2b2de2312feff188d100669d4b8ad6f045",
                    hashType: "data1",
                    args: new Uint8Array(32),
                } as unknown as Script,
            },
            new TypeError("terms.remoteCloseScript.codeHash must be a Uint8Array"),
        ],
        [
            "a peer close script whose code hash is 31 bytes",
            { ...TERMS, remoteCloseScript: { codeHash: new Uint8Array(31), hashType: "data1", args: new Uint8Array(32) } },
            new TypeError("terms.remoteCloseScript.codeHash must be 32 bytes, got 31"),
        ],
        [
            "a peer close script whose code hash is 33 bytes",
            { ...TERMS, remoteCloseScript: { codeHash: new Uint8Array(33), hashType: "data1", args: new Uint8Array(32) } },
            new TypeError("terms.remoteCloseScript.codeHash must be 32 bytes, got 33"),
        ],
        [
            "a peer close script with no hash type",
            { ...TERMS, remoteCloseScript: { codeHash: new Uint8Array(32), args: new Uint8Array(32) } as unknown as Script },
            new TypeError("terms.remoteCloseScript.hashType must be one of data, type, data1, data2"),
        ],
        [
            "a peer close script under a hash type CKB does not define",
            {
                ...TERMS,
                remoteCloseScript: { codeHash: new Uint8Array(32), hashType: "data3", args: new Uint8Array(32) } as unknown as Script,
            },
            new TypeError("terms.remoteCloseScript.hashType must be one of data, type, data1, data2"),
        ],
        [
            "a peer close script with no args",
            { ...TERMS, remoteCloseScript: { codeHash: new Uint8Array(32), hashType: "data1" } as unknown as Script },
            new TypeError("terms.remoteCloseScript.args must be a Uint8Array"),
        ],
        [
            "a peer close script whose args are hex",
            {
                ...TERMS,
                remoteCloseScript: {
                    codeHash: new Uint8Array(32),
                    hashType: "data1",
                    args: "0682a2f376b830a421ddc7d3b8cf4bffb31bfdf2942f46780359b1ef4f107f36",
                } as unknown as Script,
            },
            new TypeError("terms.remoteCloseScript.args must be a Uint8Array"),
        ],
    ])("rejects %s, writing nothing", async (_, terms, error) => {
        const { engine, storage } = await bare();
        const stored = new Map(storage.map);
        await expect(engine.pinChannelTerms(CHANNEL_ID, terms)).rejects.toThrow(error);
        expect(storage.map).toEqual(stored);
    });

    // The terms pinned without the first-sight values, as before the host pinned them: the opening's commitment pins those.
    async function firstSeen() {
        const context = await bare();
        await context.store.updateChannelRecord(CHANNEL_INDEX, (current) => {
            if (current === null) throw new Error("the channel is registered");
            const pins: ChannelPins = {
                ...REGISTERED_PINS,
                liquidCapacityShannons: "80500000000",
                commitmentFeeRate: "1000",
                remoteReservedCkbShannons: "6300000000",
                remoteCloseScript: REMOTE_CLOSE_SCRIPT_PIN,
            };
            return { ...current, pins };
        });
        await openChannel(context.engine);
        return context;
    }

    it.each([
        [
            "peer funding key",
            { remoteFundingPubkey: OTHER_FUNDING_PUBKEY },
            { field: "remoteFundingPubkey", pinned: digest.remote.funding_pubkey, stated: bytesToHex(OTHER_FUNDING_PUBKEY) },
        ],
        [
            "peer TLC base key",
            { remoteTlcBasePubkey: OTHER_FUNDING_PUBKEY },
            { field: "remoteTlcBasePubkey", pinned: digest.remote.tlc_base_pubkey, stated: bytesToHex(OTHER_FUNDING_PUBKEY) },
        ],
        [
            "delay",
            { commitmentDelayEpoch: 1099511627778n },
            { field: "commitmentDelayEpoch", pinned: "1099511627777", stated: "1099511627778" },
        ],
    ])(
        "throws a ChannelPinError on a %s other than the one a commitment pinned at first sight, writing nothing",
        async (_, override, conflict) => {
            const { engine, store, storage } = await firstSeen();
            expect((await store.getChannelRecord(CHANNEL_INDEX))?.pins).toEqual(OPENED_PINS);
            const stored = new Map(storage.map);
            const error: unknown = await engine.pinChannelTerms(CHANNEL_ID, { ...TERMS, ...override }).catch((caught: unknown) => caught);
            expect(error).toBeInstanceOf(ChannelPinError);
            expect(error).toMatchObject({ conflict });
            expect(storage.map).toEqual(stored);
        },
    );

    it("writes nothing when it states the first-sight values a commitment pinned", async () => {
        const { engine, store, storage } = await firstSeen();
        storage.ops.length = 0;
        await engine.pinChannelTerms(CHANNEL_ID, TERMS);
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
        expect((await store.getChannelRecord(CHANNEL_INDEX))?.pins).toEqual(OPENED_PINS);
    });

    // The host's pin stands for the first sight: the channel's first commitment is held to it.
    it.each([
        [
            "peer funding key",
            { remoteFundingPubkey: OTHER_FUNDING_PUBKEY },
            "remoteFundingPubkey",
            bytesToHex(OTHER_FUNDING_PUBKEY),
            digest.remote.funding_pubkey,
        ],
        [
            "peer TLC base key",
            { remoteTlcBasePubkey: OTHER_FUNDING_PUBKEY },
            "remoteTlcBasePubkey",
            bytesToHex(OTHER_FUNDING_PUBKEY),
            digest.remote.tlc_base_pubkey,
        ],
        ["delay", { commitmentDelayEpoch: 1099511627778n }, "commitmentDelayEpoch", "1099511627778", "1099511627777"],
    ])(
        "has the channel's first commitment stating another %s than pinned refused at the claim, writing nothing",
        async (_, override, field, stated, pinned) => {
            const { engine, storage } = await registeredEngine();
            const stored = new Map(storage.map);
            const request = signedRequest({ kind: "commitment_tx", input: { ...ckbCommitment(), ...override } }, 11);
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, request));
            expect(refusal).toMatchObject({
                code: "policy_refusal",
                message: `the request states ${field} ${stated}, but the channel pinned ${pinned}`,
            });
            expect(storage.map).toEqual(stored);
        },
    );

    it("throws on a channel this device never registered", async () => {
        const { engine } = newEngine();
        await expect(engine.pinChannelTerms(CHANNEL_ID, TERMS)).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} is not registered on this device`),
        );
    });

    it("throws when the channel's name resolves to an index holding no record", async () => {
        const { engine, store } = newEngine();
        await store.claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX);
        await expect(engine.pinChannelTerms(CHANNEL_ID, TERMS)).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} resolves to channel index ${CHANNEL_INDEX}, which holds no record`),
        );
    });

    // A message is no evidence of a term: the node would state whatever rate and reserve it wants pinned.
    it.each([
        ["a commitment", () => commitmentRequest("ckb, no tlcs, for remote")],
        ["a revocation it sends", () => revocationRequest("ckb, send side")],
        ["a revocation it receives", () => receivedRevocation(5)],
        ["an announcement", () => announcementRequest("ckb")],
    ])("refuses %s on a channel whose terms the host has not pinned, writing nothing", async (_, request) => {
        const { engine, store, storage } = await bare();
        const held = await holdingReplacement(store, request());
        const stored = new Map(storage.map);
        const refusal = await refusalOf(engine.checkAndClaim(KEYS, held));
        expect(refusal.code).toBe("policy_refusal");
        expect(refusal.message).toBe("the request states liquidCapacityShannons, which the host has not pinned for the channel yet");
        expect(storage.map).toEqual(stored);
    });

    it.each([
        ["the fee rate", { liquidCapacityShannons: "80500000000" }, "commitmentFeeRate"],
        ["the peer's reserve", { liquidCapacityShannons: "80500000000", commitmentFeeRate: "1000" }, "remoteReservedCkbShannons"],
    ])("names %s when only it is left unpinned", async (_, pinned, missing) => {
        const { engine, store } = await bare();
        const record = (await store.getChannelRecord(CHANNEL_INDEX)) as ChannelPolicyRecord;
        await store.setChannelRecord(CHANNEL_INDEX, { ...record, pins: { ...record.pins, ...pinned } });
        const refusal = await refusalOf(engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote")));
        expect(refusal.message).toBe(`the request states ${missing}, which the host has not pinned for the channel yet`);
    });

    // Fiber never holds the peer's `Shutdown` to the script of the open, so only the host's pin can.
    it("refuses a close on a channel whose terms the host has not pinned, naming the peer's close script, writing nothing", async () => {
        const { engine, storage } = await bare();
        const stored = new Map(storage.map);
        const refusal = await refusalOf(engine.checkAndClaim(KEYS, closingRequest("ckb")));
        expect(refusal.code).toBe("policy_refusal");
        expect(refusal.message).toBe("the request states remoteCloseScript, which the host has not pinned for the channel yet");
        expect(storage.map).toEqual(stored);
    });

    async function pinnedButTheCloseScript() {
        const context = await bare();
        const record = (await context.store.getChannelRecord(CHANNEL_INDEX)) as ChannelPolicyRecord;
        const { remoteCloseScript, ...pins } = TERMS_PINNED_PINS;
        expect(remoteCloseScript).toBe(REMOTE_CLOSE_SCRIPT_PIN);
        await context.store.setChannelRecord(CHANNEL_INDEX, { ...record, pins });
        return context;
    }

    it("refuses a close on a channel whose host pinned every term but the peer's close script, naming it, writing nothing", async () => {
        const { engine, storage } = await pinnedButTheCloseScript();
        const stored = new Map(storage.map);
        const refusal = await refusalOf(engine.checkAndClaim(KEYS, closingRequest("ckb")));
        expect(refusal.code).toBe("policy_refusal");
        expect(refusal.message).toBe("the request states remoteCloseScript, which the host has not pinned for the channel yet");
        expect(storage.map).toEqual(stored);
    });

    it.each([
        ["a commitment", () => commitmentRequest("ckb, no tlcs, for remote")],
        ["a revocation it sends", () => revocationRequest("ckb, send side")],
        ["a revocation it receives", () => receivedRevocation(5)],
        ["an announcement", () => announcementRequest("ckb")],
    ])("signs %s on a channel whose host pinned every term but the peer's close script, which only a close states", async (_, request) => {
        const { engine, store } = await pinnedButTheCloseScript();
        await expect(engine.checkAndClaim(KEYS, await holdingReplacement(store, request()))).resolves.toMatchObject({ status: "fresh" });
    });

    it("signs the close once the host pins the peer's close script beside the other terms", async () => {
        const { engine, store } = await pinnedButTheCloseScript();
        await engine.pinChannelTerms(CHANNEL_ID, TERMS);
        expect((await store.getChannelRecord(CHANNEL_INDEX))?.pins).toEqual(TERMS_PINNED_PINS);
        await expect(engine.checkAndClaim(KEYS, closingRequest("ckb"))).resolves.toMatchObject({ status: "fresh" });
    });

    it("refuses a commitment once the terms are pinned to other values than it states", async () => {
        const { engine } = await bare();
        await engine.pinChannelTerms(CHANNEL_ID, { ...TERMS, commitmentFeeRate: 1537n });
        const refusal = await refusalOf(engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote")));
        expect(refusal.message).toBe("the request states commitmentFeeRate 1000, but the channel pinned 1537");
    });
});

describe("recordRevocation", () => {
    it("keeps the complete signature of a revoked peer commitment the device signed for", async () => {
        const { engine, store } = await registeredEngine();
        await engine.checkAndClaim(KEYS, await holdingReplacement(store, receivedRevocation(5)));
        await engine.recordRevocation(CHANNEL_ID, { version: 4, signature: SIGNATURE });
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
            revocations: [{ version: 4, forRemote: true, signature: bytesToHex(SIGNATURE) }],
        });
    });

    // A crash between signing and recording is healed by the already-signed path, which records again.
    it("writes nothing when the same evidence is recorded again, under either name", async () => {
        const { engine, store, storage } = await registeredEngine();
        await engine.registerChannel("temporary-id", CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        await engine.checkAndClaim(KEYS, await holdingReplacement(store, receivedRevocation(5)));
        await engine.recordRevocation("temporary-id", { version: 4, signature: SIGNATURE });
        storage.ops.length = 0;
        await engine.recordRevocation(CHANNEL_ID, { version: 4, signature: Uint8Array.from(SIGNATURE) });
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
    });

    it("replaces the evidence of a version with another signature of it, keeping one entry per version", async () => {
        const { engine, store } = await registeredEngine();
        await engine.checkAndClaim(KEYS, await holdingReplacement(store, receivedRevocation(5)));
        await engine.recordRevocation(CHANNEL_ID, { version: 4, signature: SIGNATURE });
        await engine.recordRevocation(CHANNEL_ID, { version: 4, signature: OTHER_SIGNATURE });
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
            revocations: [{ version: 4, forRemote: true, signature: bytesToHex(OTHER_SIGNATURE) }],
        });
    });

    it("keeps one entry per update, in ascending version order whatever the order recorded", async () => {
        const { engine, store } = await registeredEngine();
        await engine.checkAndClaim(KEYS, await holdingReplacement(store, receivedRevocation(5)));
        await engine.checkAndClaim(KEYS, await holdingReplacement(store, receivedRevocation(8)));
        await engine.checkAndClaim(KEYS, await holdingReplacement(store, receivedRevocation(9)));
        await engine.recordRevocation(CHANNEL_ID, { version: 8, signature: SIGNATURE });
        await engine.recordRevocation(CHANNEL_ID, { version: 4, signature: OTHER_SIGNATURE });
        await engine.recordRevocation(CHANNEL_ID, { version: 7, signature: SIGNATURE });
        const record = await store.getChannelRecord(CHANNEL_INDEX);
        expect(record?.revocations.map((revocation) => revocation.version)).toEqual([4, 7, 8]);
    });

    it("leaves the claims the record holds untouched", async () => {
        const { engine, store } = await registeredEngine();
        await engine.checkAndClaim(KEYS, await holdingReplacement(store, receivedRevocation(5)));
        const before = (await store.getChannelRecord(CHANNEL_INDEX)) as ChannelPolicyRecord;
        await engine.recordRevocation(CHANNEL_ID, { version: 4, signature: SIGNATURE });
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toEqual({
            ...before,
            revocations: [{ version: 4, forRemote: true, signature: bytesToHex(SIGNATURE) }],
        });
    });

    // A caller bug: evidence of a revocation this device never signed would be no evidence.
    it.each([
        ["the slot above was never served", 3],
        ["only the slot of the version itself was served", 5],
    ])("throws when %s, writing nothing", async (_, version) => {
        const { engine, store, storage } = await registeredEngine();
        await engine.checkAndClaim(KEYS, await holdingReplacement(store, receivedRevocation(5)));
        const stored = new Map(storage.map);
        await expect(engine.recordRevocation(CHANNEL_ID, { version, signature: SIGNATURE })).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} never signed the revocation of version ${version}, at slot REVOKE:${version + 1}`),
        );
        expect(storage.map).toEqual(stored);
    });

    it("records the highest version whose revocation slot the chain holds", async () => {
        const { engine, store } = await registeredEngine();
        const top = 2 ** 48 - 1;
        await engine.checkAndClaim(KEYS, await holdingReplacement(store, receivedRevocation(top)));
        await engine.recordRevocation(CHANNEL_ID, { version: top - 1, signature: SIGNATURE });
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ revocations: [{ version: top - 1 }] });
    });

    it.each([
        ["evidence that is no object", null as never, new TypeError("evidence must be an object")],
        [
            "a negative version",
            { version: -1, signature: SIGNATURE },
            new RangeError(`evidence.version must be an integer between 0 and ${2 ** 48 - 2}, got -1`),
        ],
        [
            "a fractional version",
            { version: 4.5, signature: SIGNATURE },
            new RangeError(`evidence.version must be an integer between 0 and ${2 ** 48 - 2}, got 4.5`),
        ],
        [
            "a version whose revocation slot is past the chain",
            { version: 2 ** 48 - 1, signature: SIGNATURE },
            new RangeError(`evidence.version must be an integer between 0 and ${2 ** 48 - 2}, got ${2 ** 48 - 1}`),
        ],
        [
            "a partial signature",
            { version: 4, signature: SIGNATURE.slice(0, 32) },
            new TypeError("evidence.signature must be 64 bytes, got 32"),
        ],
        [
            "a signature one byte short",
            { version: 4, signature: SIGNATURE.slice(1) },
            new TypeError("evidence.signature must be 64 bytes, got 63"),
        ],
        [
            "a signature in hex",
            { version: 4, signature: bytesToHex(SIGNATURE) as never },
            new TypeError("evidence.signature must be a Uint8Array"),
        ],
    ])("rejects %s, writing nothing", async (_, evidence, error) => {
        const { engine, store, storage } = await registeredEngine();
        await engine.checkAndClaim(KEYS, await holdingReplacement(store, receivedRevocation(5)));
        const stored = new Map(storage.map);
        await expect(engine.recordRevocation(CHANNEL_ID, evidence)).rejects.toThrow(error);
        expect(storage.map).toEqual(stored);
    });

    it("throws on a channel this device never registered", async () => {
        const { engine } = newEngine();
        await expect(engine.recordRevocation(CHANNEL_ID, { version: 4, signature: SIGNATURE })).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} is not registered on this device`),
        );
    });

    it("throws when the channel's name resolves to an index holding no record", async () => {
        const { engine, store } = newEngine();
        await store.claimChannelAlias(CHANNEL_ID, CHANNEL_INDEX);
        await expect(engine.recordRevocation(CHANNEL_ID, { version: 4, signature: SIGNATURE })).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} resolves to channel index ${CHANNEL_INDEX}, which holds no record`),
        );
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

describe("readChannelPins", () => {
    it("reads the pins of the registration, then the host's terms, then what the first message stated", async () => {
        const { engine } = newEngine();
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        await expect(engine.readChannelPins(CHANNEL_ID)).resolves.toEqual(REGISTERED_PINS);
        await engine.pinChannelTerms(CHANNEL_ID, TERMS);
        await expect(engine.readChannelPins(CHANNEL_ID)).resolves.toEqual(TERMS_PINNED_PINS);
        await openChannel(engine);
        await expect(engine.readChannelPins(CHANNEL_ID)).resolves.toEqual(OPENED_PINS);
    });

    it("reads them under any name the channel was registered under", async () => {
        const { engine } = newEngine();
        await engine.registerChannel("temporary-id", CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
        await expect(engine.readChannelPins("temporary-id")).resolves.toEqual(REGISTERED_PINS);
    });

    it("hands out a copy, which the caller's writes do not reach", async () => {
        const { engine } = await registeredEngine();
        const pins = await engine.readChannelPins(CHANNEL_ID);
        pins.localReservedCkbShannons.legacy = "0";
        pins.commitmentFeeRate = "1";
        await expect(engine.readChannelPins(CHANNEL_ID)).resolves.toEqual(TERMS_PINNED_PINS);
    });

    it("refuses a channel this device never registered", async () => {
        const { engine } = newEngine();
        expect((await refusalOf(engine.readChannelPins(CHANNEL_ID))).code).toBe("unknown_channel");
    });

    it("throws for a name that resolves to an index holding no record", async () => {
        const { engine, storage } = newEngine();
        storage.map.set(`fiber-lsp-sdk:alias:${CHANNEL_ID}`, String(CHANNEL_INDEX));
        await expect(engine.readChannelPins(CHANNEL_ID)).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} resolves to channel index ${CHANNEL_INDEX}, which holds no record`),
        );
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

    // A repeat would be a second payment under the hash; whether the first landed is the node's to say.
    it("refuses the same open intent recorded again, and writes nothing", async () => {
        const { engine, store, storage } = newEngine();
        await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
        storage.ops.length = 0;
        const error = await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT).catch((cause: unknown) => cause);
        expect(error).toBeInstanceOf(DebitIntentError);
        expect(error).toMatchObject({ code: "intent_open", message: `a debit intent for ${OFFERED_HASH} is already open` });
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
        await expect(store.getDebitIntent(OFFERED_HASH.slice(0, 40))).resolves.toMatchObject({ maxShannons: OFFERED_AMOUNT, open: true });
    });

    it("refuses a second intent with another maximum while the first is open", async () => {
        const { engine, store } = newEngine();
        await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
        const error = await engine.recordDebitIntent(OFFERED_HASH, "9000000000").catch((cause: unknown) => cause);
        expect(error).toBeInstanceOf(DebitIntentError);
        expect(error).toMatchObject({ code: "intent_open", message: `a debit intent for ${OFFERED_HASH} is already open` });
        await expect(store.getDebitIntent(OFFERED_HASH.slice(0, 40))).resolves.toMatchObject({ maxShannons: OFFERED_AMOUNT });
    });

    it("lets one of two concurrent records of the same intent through", async () => {
        const { engine, store } = newEngine();
        const outcomes = await Promise.allSettled([
            engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT),
            engine.recordDebitIntent(OFFERED_HASH, "9000000000"),
        ]);
        expect(outcomes[0]).toEqual({ status: "fulfilled", value: undefined });
        expect(outcomes[1]).toMatchObject({ status: "rejected", reason: { code: "intent_open" } });
        await expect(store.getDebitIntent(OFFERED_HASH.slice(0, 40))).resolves.toMatchObject({ maxShannons: OFFERED_AMOUNT, open: true });
    });

    it("opens again a closed intent nothing was shown or charged under", async () => {
        const { engine, store } = newEngine();
        await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
        await engine.closeDebitIntent(OFFERED_HASH);
        await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
        await expect(store.getDebitIntent(OFFERED_HASH.slice(0, 40))).resolves.toEqual<DebitIntentRecord>({
            version: 1,
            paymentHash: OFFERED_HASH,
            maxShannons: OFFERED_AMOUNT,
            open: true,
            channelIndexes: [],
        });
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
        await peerRevokes(engine, 11);
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

    // A payee picks the hash freely, so a twin is the user's to refuse, not a host bug.
    it("refuses as hash_twin a hash that shares its bound 20 bytes with a recorded intent, and writes nothing", async () => {
        const { engine, store, storage } = newEngine();
        const twin = OFFERED_HASH.slice(0, 40) + "00".repeat(12);
        await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
        await engine.closeDebitIntent(OFFERED_HASH);
        storage.ops.length = 0;
        const error = await engine.recordDebitIntent(twin, OFFERED_AMOUNT).catch((cause: unknown) => cause);
        expect(error).toBeInstanceOf(DebitIntentError);
        expect(error).toMatchObject({ code: "hash_twin", message: `the 20 bytes of ${twin} a TLC's witness binds are another payment's` });
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
        await expect(store.getDebitIntent(OFFERED_HASH.slice(0, 40))).resolves.toMatchObject({ paymentHash: OFFERED_HASH, open: false });
        await expect(engine.closeDebitIntent(twin)).rejects.toThrow(TypeError);
    });

    it("refuses as hash_twin a hash that shares its bound 20 bytes with a hold invoice, and writes nothing", async () => {
        const { engine, store, storage } = newEngine();
        const twin = RECEIVED_HASH.slice(0, 40) + "00".repeat(12);
        await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
        storage.ops.length = 0;
        const error = await engine.recordDebitIntent(twin, RECEIVED_AMOUNT).catch((cause: unknown) => cause);
        expect(error).toBeInstanceOf(DebitIntentError);
        expect(error).toMatchObject({ code: "hash_twin", message: `the 20 bytes of ${twin} a TLC's witness binds are another payment's` });
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
        await expect(store.getDebitIntent(RECEIVED_HASH.slice(0, 40))).resolves.toBeNull();
    });

    it("refuses an intent under the hash of one of this device's hold invoices", async () => {
        const { engine, store } = newEngine();
        await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
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

    describe("readDebitIntent", () => {
        it("reads the record by its full hash", async () => {
            const { engine } = await openedEngine();
            await recordThreeTlcIntents(engine);
            await engine.checkAndClaim(KEYS, threeTlcRequest());
            await engine.closeDebitIntent(OFFERED_HASH);
            await expect(engine.readDebitIntent(OFFERED_HASH)).resolves.toEqual<DebitIntentRecord>({
                version: 1,
                paymentHash: OFFERED_HASH,
                maxShannons: OFFERED_AMOUNT,
                open: false,
                channelIndexes: [CHANNEL_INDEX],
            });
        });

        it("reads null under a hash no intent was recorded under", async () => {
            const { engine } = newEngine();
            await expect(engine.readDebitIntent(OFFERED_HASH)).resolves.toBeNull();
        });

        it("hands back a copy the store never sees changed", async () => {
            const { engine, storage } = newEngine();
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            const record = await engine.readDebitIntent(OFFERED_HASH);
            if (record === null) throw new Error("the intent was recorded");
            record.open = false;
            record.channelIndexes.push(CHANNEL_INDEX);
            storage.ops.length = 0;
            await expect(engine.readDebitIntent(OFFERED_HASH)).resolves.toMatchObject({ open: true, channelIndexes: [] });
            expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
        });

        // The record under the bound bytes is another payment's, so a watch of the twin can end.
        it("reads null under a hash that shares its bound 20 bytes with a recorded one", async () => {
            const { engine } = newEngine();
            const twin = OFFERED_HASH.slice(0, 40) + "00".repeat(12);
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            await expect(engine.readDebitIntent(twin)).resolves.toBeNull();
        });

        it.each([
            ["no hash", undefined],
            ["a hash of 31 bytes", OFFERED_HASH.slice(2)],
            ["an uppercase hash", OFFERED_HASH.toUpperCase()],
        ])("rejects %s before touching the storage", async (_, hash) => {
            const { engine, storage } = newEngine();
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            storage.ops.length = 0;
            await expect(engine.readDebitIntent(hash as string)).rejects.toThrow(
                new TypeError("paymentHashHex must be 32 bytes of lowercase hex"),
            );
            expect(storage.ops).toEqual([]);
        });
    });
});

describe("hold invoices", () => {
    it("records an unreleased invoice under the bound 20 bytes of its hash", async () => {
        const { engine, store, storage } = newEngine();
        await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
        await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toEqual<HoldInvoicePolicyRecord>({
            version: 1,
            paymentHash: RECEIVED_HASH,
            amountShannons: RECEIVED_AMOUNT,
            hashAlgorithm: "sha256",
            invoiceIndex: INVOICE_INDEX,
            released: false,
            channelIndexes: [],
        });
        expect([...storage.map.keys()]).toEqual([`fiber-lsp-sdk:invoice:${RECEIVED_HASH.slice(0, 40)}`]);
    });

    it.each([0, Number.MAX_SAFE_INTEGER])("records the invoice index %p, at either end of its range", async (invoiceIndex) => {
        const { engine } = newEngine();
        await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", invoiceIndex);
        await expect(engine.readHoldInvoice(RECEIVED_HASH)).resolves.toMatchObject({ invoiceIndex });
    });

    it("refuses an invoice under the hash of a payment this device authorised", async () => {
        const { engine, store } = newEngine();
        await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
        await expect(engine.recordHoldInvoice(OFFERED_HASH, OFFERED_AMOUNT, "ckb-hash", INVOICE_INDEX)).rejects.toThrow(
            new TypeError(`${OFFERED_HASH} is the hash of a payment this device has authorised`),
        );
        await expect(store.getHoldInvoiceRecord(OFFERED_HASH.slice(0, 40))).resolves.toBeNull();
    });

    it("writes nothing when the same invoice is recorded again", async () => {
        const { engine, storage } = newEngine();
        await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
        storage.ops.length = 0;
        await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
        expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
    });

    it.each([
        ["amount", "1", "sha256", INVOICE_INDEX],
        ["algorithm", RECEIVED_AMOUNT, "ckb-hash", INVOICE_INDEX],
        ["invoice index", RECEIVED_AMOUNT, "sha256", INVOICE_INDEX + 1],
    ] as const)("refuses the same hash with another %s, writing nothing", async (_, amount, algorithm, invoiceIndex) => {
        const { engine, storage } = newEngine();
        await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
        const stored = new Map(storage.map);
        await expect(engine.recordHoldInvoice(RECEIVED_HASH, amount, algorithm, invoiceIndex)).rejects.toThrow(
            new TypeError(`a hold invoice for ${RECEIVED_HASH} is already recorded with another amount, algorithm or invoice index`),
        );
        expect(storage.map).toEqual(stored);
    });

    it("refuses a hash that shares its bound 20 bytes with a recorded one", async () => {
        const { engine } = newEngine();
        const twin = RECEIVED_HASH.slice(0, 40) + "00".repeat(12);
        const error = new TypeError(`${twin} shares its bound 20 bytes with a recorded payment, ${RECEIVED_HASH}`);
        await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
        await expect(engine.recordHoldInvoice(twin, RECEIVED_AMOUNT, "ckb-hash", INVOICE_INDEX)).rejects.toThrow(error);
        await expect(engine.markHoldInvoiceReleased(twin, RELEASE_TIMING)).rejects.toThrow(error);
        await expect(engine.readHoldInvoice(twin)).rejects.toThrow(error);
        await expect(engine.listsHoldInvoiceTlc(twin)).rejects.toThrow(error);
    });

    it.each([
        [
            "no hash",
            [undefined, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX],
            new TypeError("paymentHashHex must be 32 bytes of lowercase hex"),
        ],
        [
            "a hash of 31 bytes",
            [RECEIVED_HASH.slice(2), RECEIVED_AMOUNT, "sha256", INVOICE_INDEX],
            new TypeError("paymentHashHex must be 32 bytes of lowercase hex"),
        ],
        [
            "an uppercase hash",
            [RECEIVED_HASH.toUpperCase(), RECEIVED_AMOUNT, "sha256", INVOICE_INDEX],
            new TypeError("paymentHashHex must be 32 bytes of lowercase hex"),
        ],
        [
            "no amount",
            [RECEIVED_HASH, undefined, "sha256", INVOICE_INDEX],
            new TypeError("amountShannons must be an amount in decimal shannons"),
        ],
        [
            "an amount in hex",
            [RECEIVED_HASH, "0x10", "sha256", INVOICE_INDEX],
            new TypeError("amountShannons must be an amount in decimal shannons"),
        ],
        [
            "a negative amount",
            [RECEIVED_HASH, "-1", "sha256", INVOICE_INDEX],
            new TypeError("amountShannons must be an amount in decimal shannons"),
        ],
        ["a zero amount", [RECEIVED_HASH, "0", "sha256", INVOICE_INDEX], new RangeError("amountShannons must be greater than 0, got 0")],
        [
            "no algorithm",
            [RECEIVED_HASH, RECEIVED_AMOUNT, undefined, INVOICE_INDEX],
            new TypeError("hashAlgorithm must be one of ckb-hash, sha256"),
        ],
        [
            "an algorithm fiber does not define",
            [RECEIVED_HASH, RECEIVED_AMOUNT, "ckb_hash", INVOICE_INDEX],
            new TypeError("hashAlgorithm must be one of ckb-hash, sha256"),
        ],
        [
            "no invoice index",
            [RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", undefined],
            new RangeError("invoiceIndex must be an integer between 0 and 9007199254740991, got undefined"),
        ],
        [
            "a fractional invoice index",
            [RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", 1.5],
            new RangeError("invoiceIndex must be an integer between 0 and 9007199254740991, got 1.5"),
        ],
        [
            "a negative invoice index",
            [RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", -1],
            new RangeError("invoiceIndex must be an integer between 0 and 9007199254740991, got -1"),
        ],
        [
            "an invoice index past the highest a preimage derives from",
            [RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", 2 ** 53],
            new RangeError("invoiceIndex must be an integer between 0 and 9007199254740991, got 9007199254740992"),
        ],
        [
            "an invoice index in a string",
            [RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", "1761475200000"],
            new RangeError("invoiceIndex must be an integer between 0 and 9007199254740991, got 1761475200000"),
        ],
    ])("rejects %s, touching nothing", async (_, args, error) => {
        const { engine, storage } = newEngine();
        await expect(engine.recordHoldInvoice(...(args as Parameters<PolicyEngine["recordHoldInvoice"]>))).rejects.toThrow(error);
        expect(storage.ops).toEqual([]);
    });

    describe("the release", () => {
        it("marks an invoice its channel holds released, and marking it again reads no condition and writes nothing", async () => {
            const { engine, store, storage } = await openedEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await holdReceived(engine);
            await engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING);
            await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({ released: true });
            storage.ops.length = 0;
            // Past the TLC's expiry: a released invoice is not judged again.
            const now = jest.fn(() => 1750000000000);
            const releaseMarginMs = jest.fn(() => 600000n);
            await engine.markHoldInvoiceReleased(RECEIVED_HASH, { now, releaseMarginMs });
            expect(storage.ops).toEqual([`get fiber-lsp-sdk:invoice:${RECEIVED_HASH.slice(0, 40)}`]);
            expect(now).not.toHaveBeenCalled();
            expect(releaseMarginMs).not.toHaveBeenCalled();
        });

        it("refuses an invoice no channel has shown yet, writing nothing", async () => {
            const { engine, store, storage } = await openedEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            const stored = new Map(storage.map);
            const error = await engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING).catch((cause: unknown) => cause);
            expect(error).toBeInstanceOf(HoldInvoiceError);
            expect(error).toMatchObject({
                code: "not_held",
                message: `the channels hold 0 shannons under ${RECEIVED_HASH}, each at its view holding less, short of the invoice's ${RECEIVED_AMOUNT}`,
            });
            expect(storage.map).toEqual(stored);
            await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({ released: false });
        });

        it.each([true, false])("refuses an invoice one view holds alone (for remote: %s)", async (forRemote) => {
            const { engine, store } = await openedEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({
                    forRemote,
                    commitmentNumber: 11,
                    settlementLocalShannons: OPENING_SETTLEMENT,
                    tlcIds: [RECEIVED_TLC_ID],
                }),
            );
            await expect(engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING)).rejects.toMatchObject({ code: "not_held" });
            await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({ released: false });
        });

        it.each([
            ["one shannon less than", "2249999999"],
            ["exactly", RECEIVED_AMOUNT],
        ])("releases an invoice of %s what its channel holds", async (_, amount) => {
            const { engine, store } = await openedEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, amount, "sha256", INVOICE_INDEX);
            await holdReceived(engine);
            await engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING);
            await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({ released: true });
        });

        it("refuses an invoice one shannon above what its channel holds", async () => {
            const { engine } = await openedEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, "2250000001", "sha256", INVOICE_INDEX);
            await holdReceived(engine);
            await expect(engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING)).rejects.toMatchObject({
                code: "not_held",
                message: `the channels hold ${RECEIVED_AMOUNT} shannons under ${RECEIVED_HASH}, each at its view holding less, short of the invoice's 2250000001`,
            });
        });

        it("sums the channels the invoice lists", async () => {
            const { engine, store } = await openedEngine();
            await addOtherChannel(engine);
            await engine.recordHoldInvoice(RECEIVED_HASH, "4500000000", "sha256", INVOICE_INDEX);
            await holdReceived(engine);
            await expect(engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING)).rejects.toMatchObject({ code: "not_held" });
            await holdReceived(engine, OTHER_CHANNEL);
            await engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING);
            await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({
                released: true,
                channelIndexes: [CHANNEL_INDEX, OTHER_CHANNEL_INDEX],
            });
        });

        it("refuses a TLC expiring exactly at the margin past now, and releases one millisecond earlier", async () => {
            const { engine, store } = await openedEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await holdReceived(engine);
            const error = await engine
                .markHoldInvoiceReleased(RECEIVED_HASH, { now: () => 1749999400000, releaseMarginMs: () => 600000n })
                .catch((cause: unknown) => cause);
            expect(error).toBeInstanceOf(HoldInvoiceError);
            expect(error).toMatchObject({
                code: "expiry_too_close",
                message: `channel index ${CHANNEL_INDEX} holds a TLC under ${RECEIVED_HASH} expiring at 1750000000000, not after 1750000000000`,
            });
            await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({ released: false });
            await engine.markHoldInvoiceReleased(RECEIVED_HASH, { now: () => 1749999399999, releaseMarginMs: () => 600000n });
            await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({ released: true });
        });

        it("asks the margin of the delay the channel pinned", async () => {
            const { engine } = await openedEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await holdReceived(engine);
            const releaseMarginMs = jest.fn(() => 600000n);
            await engine.markHoldInvoiceReleased(RECEIVED_HASH, { now: () => 1749990000000, releaseMarginMs });
            expect(releaseMarginMs.mock.calls).toEqual([[1099511627777n]]);
        });

        it("refuses to release an invoice that was never recorded", async () => {
            const { engine } = newEngine();
            await expect(engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING)).rejects.toThrow(
                new TypeError(`no hold invoice was recorded for ${RECEIVED_HASH}`),
            );
        });

        it.each<[string, unknown, unknown, Error]>([
            ["no hash", undefined, RELEASE_TIMING, new TypeError("paymentHashHex must be 32 bytes of lowercase hex")],
            [
                "a hash of 31 bytes",
                RECEIVED_HASH.slice(2),
                RELEASE_TIMING,
                new TypeError("paymentHashHex must be 32 bytes of lowercase hex"),
            ],
            [
                "an uppercase hash",
                RECEIVED_HASH.toUpperCase(),
                RELEASE_TIMING,
                new TypeError("paymentHashHex must be 32 bytes of lowercase hex"),
            ],
            ["no timing", RECEIVED_HASH, undefined, new TypeError("timing must be an object")],
            ["a timing that is no object", RECEIVED_HASH, 1749990000000, new TypeError("timing must be an object")],
            ["no clock", RECEIVED_HASH, { releaseMarginMs: () => 600000n }, new TypeError("timing.now must be a function")],
            [
                "a clock that is a reading, not a function",
                RECEIVED_HASH,
                { now: 1749990000000, releaseMarginMs: () => 600000n },
                new TypeError("timing.now must be a function"),
            ],
            ["no margin", RECEIVED_HASH, { now: () => 1749990000000 }, new TypeError("timing.releaseMarginMs must be a function")],
            [
                "a margin that is no function",
                RECEIVED_HASH,
                { now: () => 1749990000000, releaseMarginMs: 600000n },
                new TypeError("timing.releaseMarginMs must be a function"),
            ],
        ])("rejects %s before touching the storage", async (_, hash, timing, error) => {
            const { engine, storage } = await openedEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await holdReceived(engine);
            storage.ops.length = 0;
            await expect(engine.markHoldInvoiceReleased(hash as string, timing as HoldInvoiceReleaseTiming)).rejects.toThrow(error);
            expect(storage.ops).toEqual([]);
        });

        it.each([
            ["no reading", undefined, "undefined"],
            ["a fractional reading", 1749990000000.5, "1749990000000.5"],
            ["a negative reading", -1, "-1"],
            ["a reading past the safe integers", 2 ** 53, "9007199254740992"],
            ["a reading in a string", "1749990000000", "1749990000000"],
        ])("rejects a clock giving %s, writing nothing", async (_, reading, shown) => {
            const { engine, store, storage } = await openedEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await holdReceived(engine);
            storage.ops.length = 0;
            const timing = { now: () => reading, releaseMarginMs: () => 600000n } as unknown as HoldInvoiceReleaseTiming;
            await expect(engine.markHoldInvoiceReleased(RECEIVED_HASH, timing)).rejects.toThrow(
                new RangeError(`timing.now() must be an integer between 0 and 9007199254740991, got ${shown}`),
            );
            expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
            await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({ released: false });
        });

        it("rejects with what a throwing clock throws, writing nothing", async () => {
            const { engine, store, storage } = await openedEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await holdReceived(engine);
            storage.ops.length = 0;
            const failure = new Error("the host's clock failed");
            const now = (): number => {
                throw failure;
            };
            await expect(engine.markHoldInvoiceReleased(RECEIVED_HASH, { now, releaseMarginMs: () => 600000n })).rejects.toBe(failure);
            expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
            await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({ released: false });
        });

        it("reads the clock once, after the records it judges and before it writes", async () => {
            const { engine, storage } = await openedEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await holdReceived(engine);
            storage.ops.length = 0;
            const readAt: number[] = [];
            const now = jest.fn(() => {
                readAt.push(storage.ops.length);
                return 1749990000000;
            });
            await engine.markHoldInvoiceReleased(RECEIVED_HASH, { now, releaseMarginMs: () => 600000n });
            expect(now).toHaveBeenCalledTimes(1);
            const reads = storage.ops.slice(0, readAt[0]);
            expect(reads.length).toBeGreaterThan(1);
            expect(reads.every((operation) => operation.startsWith("get"))).toBe(true);
            // The update reads the record again before it writes it.
            expect(storage.ops.slice(readAt[0])).toEqual([
                `get fiber-lsp-sdk:invoice:${RECEIVED_HASH.slice(0, 40)}`,
                `set fiber-lsp-sdk:invoice:${RECEIVED_HASH.slice(0, 40)}`,
            ]);
        });

        it("reads each timing field once, so the function checked is the function called", async () => {
            const { engine, store } = await openedEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await holdReceived(engine);
            const reads = { now: 0, releaseMarginMs: 0 };
            const timing = {
                get now(): unknown {
                    reads.now += 1;
                    return reads.now === 1 ? (): number => 1749990000000 : 1749990000000;
                },
                get releaseMarginMs(): unknown {
                    reads.releaseMarginMs += 1;
                    return reads.releaseMarginMs === 1 ? (): bigint => 600000n : 600000n;
                },
            } as unknown as HoldInvoiceReleaseTiming;
            await engine.markHoldInvoiceReleased(RECEIVED_HASH, timing);
            expect(reads).toEqual({ now: 1, releaseMarginMs: 1 });
            await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({ released: true });
        });

        it("takes a clock at zero", async () => {
            const { engine, store } = await openedEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await holdReceived(engine);
            await engine.markHoldInvoiceReleased(RECEIVED_HASH, { now: () => 0, releaseMarginMs: () => 600000n });
            await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({ released: true });
        });
    });

    describe("readHoldInvoice", () => {
        it("reads the record by its full hash", async () => {
            const { engine } = await openedEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await holdReceived(engine);
            await engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING);
            await expect(engine.readHoldInvoice(RECEIVED_HASH)).resolves.toEqual<HoldInvoicePolicyRecord>({
                version: 1,
                paymentHash: RECEIVED_HASH,
                amountShannons: RECEIVED_AMOUNT,
                hashAlgorithm: "sha256",
                invoiceIndex: INVOICE_INDEX,
                released: true,
                channelIndexes: [CHANNEL_INDEX],
            });
        });

        it("refuses a hash no invoice was recorded under", async () => {
            const { engine } = newEngine();
            await expect(engine.readHoldInvoice(RECEIVED_HASH)).rejects.toThrow(
                new TypeError(`no hold invoice was recorded for ${RECEIVED_HASH}`),
            );
        });

        it.each([
            ["no hash", undefined],
            ["a hash of 31 bytes", RECEIVED_HASH.slice(2)],
            ["an uppercase hash", RECEIVED_HASH.toUpperCase()],
        ])("rejects %s before touching the storage", async (_, hash) => {
            const { engine, storage } = newEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            storage.ops.length = 0;
            await expect(engine.readHoldInvoice(hash as string)).rejects.toThrow(
                new TypeError("paymentHashHex must be 32 bytes of lowercase hex"),
            );
            expect(storage.ops).toEqual([]);
        });
    });

    describe("listsHoldInvoiceTlc", () => {
        it("answers no for an invoice no channel has shown", async () => {
            const { engine } = await openedEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await expect(engine.listsHoldInvoiceTlc(RECEIVED_HASH)).resolves.toBe(false);
        });

        it.each([true, false])("answers yes while one view lists a TLC of the invoice (for remote: %s)", async (forRemote) => {
            const { engine } = await openedEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({
                    forRemote,
                    commitmentNumber: 11,
                    settlementLocalShannons: OPENING_SETTLEMENT,
                    tlcIds: [RECEIVED_TLC_ID],
                }),
            );
            await expect(engine.listsHoldInvoiceTlc(RECEIVED_HASH)).resolves.toBe(true);
        });

        it("answers no once both views of every channel dropped the TLC, and yes while one still lists it", async () => {
            const { engine } = await openedEngine();
            await addOtherChannel(engine);
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await holdReceived(engine, OTHER_CHANNEL);
            await holdReceived(engine);
            await peerRevokes(engine, 11);
            // The peer's commitment drops the failed TLC first, on slot 13: the device's own took 12.
            const dropped = customCommitmentRequest({
                forRemote: true,
                commitmentNumber: 12,
                settlementLocalShannons: OPENING_SETTLEMENT,
                tlcIds: [],
            });
            await engine.checkAndClaim(KEYS, signedRequest(dropped.operation, 13));
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({
                    forRemote: false,
                    commitmentNumber: 14,
                    settlementLocalShannons: OPENING_SETTLEMENT,
                    tlcIds: [],
                }),
            );
            await expect(engine.listsHoldInvoiceTlc(RECEIVED_HASH)).resolves.toBe(true);
            await peerRevokes(engine, 11, OTHER_CHANNEL);
            const otherDropped = customCommitmentRequest(
                { forRemote: true, commitmentNumber: 12, settlementLocalShannons: OPENING_SETTLEMENT, tlcIds: [] },
                OTHER_CHANNEL,
            );
            await engine.checkAndClaim(OTHER_KEYS, signedRequest(otherDropped.operation, 13, OTHER_CHANNEL));
            await expect(engine.listsHoldInvoiceTlc(RECEIVED_HASH)).resolves.toBe(true);
            await engine.checkAndClaim(
                OTHER_KEYS,
                customCommitmentRequest(
                    { forRemote: false, commitmentNumber: 14, settlementLocalShannons: OPENING_SETTLEMENT, tlcIds: [] },
                    OTHER_CHANNEL,
                ),
            );
            await expect(engine.listsHoldInvoiceTlc(RECEIVED_HASH)).resolves.toBe(false);
        });

        it("answers yes while the second channel the invoice lists still holds its TLC, the first one dropped", async () => {
            const { engine, store } = await openedEngine();
            await addOtherChannel(engine);
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await holdReceived(engine);
            await holdReceived(engine, OTHER_CHANNEL);
            await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({
                channelIndexes: [CHANNEL_INDEX, OTHER_CHANNEL_INDEX],
            });
            await peerRevokes(engine, 11);
            const dropped = customCommitmentRequest({
                forRemote: true,
                commitmentNumber: 12,
                settlementLocalShannons: OPENING_SETTLEMENT,
                tlcIds: [],
            });
            await engine.checkAndClaim(KEYS, signedRequest(dropped.operation, 13));
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({
                    forRemote: false,
                    commitmentNumber: 14,
                    settlementLocalShannons: OPENING_SETTLEMENT,
                    tlcIds: [],
                }),
            );
            await expect(engine.listsHoldInvoiceTlc(RECEIVED_HASH)).resolves.toBe(true);
        });

        it("refuses a hash no invoice was recorded under", async () => {
            const { engine } = newEngine();
            await expect(engine.listsHoldInvoiceTlc(RECEIVED_HASH)).rejects.toThrow(
                new TypeError(`no hold invoice was recorded for ${RECEIVED_HASH}`),
            );
        });

        it("throws when the invoice lists a channel that holds no record", async () => {
            const { engine, store } = newEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await store.updateHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40), (current) => ({
                ...(current as HoldInvoicePolicyRecord),
                channelIndexes: [OTHER_CHANNEL_INDEX],
            }));
            await expect(engine.listsHoldInvoiceTlc(RECEIVED_HASH)).rejects.toThrow(
                new TypeError(`a payment record lists channel index ${OTHER_CHANNEL_INDEX}, which holds no record`),
            );
        });

        it.each([
            ["no hash", undefined],
            ["a hash of 31 bytes", RECEIVED_HASH.slice(2)],
            ["an uppercase hash", RECEIVED_HASH.toUpperCase()],
        ])("rejects %s before touching the storage", async (_, hash) => {
            const { engine, storage } = newEngine();
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            storage.ops.length = 0;
            await expect(engine.listsHoldInvoiceTlc(hash as string)).rejects.toThrow(
                new TypeError("paymentHashHex must be 32 bytes of lowercase hex"),
            );
            expect(storage.ops).toEqual([]);
        });
    });
});

describe("checkAndClaim", () => {
    async function registered(storage: Storage = new InMemorySignerStorage(), funded = FUNDED, terms = TERMS) {
        const context = newEngine(storage);
        await context.engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, funded, CLOSE_SCRIPT);
        await context.engine.pinChannelTerms(CHANNEL_ID, terms);
        return context;
    }

    async function opened(storage: Storage = new InMemorySignerStorage()) {
        const context = await registered(storage);
        await openChannel(context.engine);
        return context;
    }

    describe("the served path", () => {
        it("claims the commitment slot, records the session, and keeps the hash of the tx signed in its view", async () => {
            const { engine, store } = await registered();
            const kase = caseOf(digest.commitment_cases, "ckb, no tlcs, for remote");
            const request = commitmentRequest("ckb, no tlcs, for remote");

            await expect(engine.checkAndClaim(KEYS, request)).resolves.toEqual({
                status: "fresh",
                context: "COMMITMENT",
                commitmentNumber: 0,
            });
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toEqual<ChannelPolicyRecord>({
                version: 1,
                channelId: CHANNEL_ID,
                lastSignedCommitmentNumbers: { "COMMITMENT:local": 0 },
                signedSessions: { "COMMITMENT:0": buildSessionCommitment(request.session) },
                nonceReuse: {},
                commitmentHashes: {
                    remote: {
                        commitmentNumber: 0,
                        txHash: kase.digest,
                        source: { output: NO_TLC_REMOTE_OUTPUT, outputData: "" },
                        settlementWitness: NO_TLC_REMOTE_WITNESS,
                    },
                },
                revocations: [],
                pins: OPENED_PINS,
                views: { remote: OPENING_VIEW, local: OPENING_VIEW },
            });
        });

        // The digest is fiber's `compute_tx_message` of the tx it rebuilt, which is the tx the node sent once they match.
        it.each(["ckb, three tlcs, for local", "ckb, no tlcs, for remote, full payment hash"])(
            "keeps as the hash of the %s commitment the message of the tx fiber built",
            (name) => {
                const kase = caseOf(digest.commitment_cases, name);
                expect(bytesToHex(computeTxMessage(toTransaction(kase.transaction)))).toBe(kase.digest);
            },
        );

        it("keeps the cell and the settlement body of the device's own commitment in its view", async () => {
            const kase = caseOf(digest.commitment_cases, "ckb, three tlcs, for local");
            // Opened at the case's delay, which the "ckb" cases do not share.
            const delay = { commitmentDelayEpoch: BigInt(kase.delay_epoch) };
            const { engine, store } = await registered(new InMemorySignerStorage(), FUNDED, { ...TERMS, ...delay });
            await engine.checkAndClaim(
                KEYS,
                signedRequest({ kind: "commitment_tx", input: { ...ckbCommitment(), ...delay, commitmentNumber: 10 } }, 10),
            );
            await recordThreeTlcIntents(engine);
            const request = commitmentRequest("ckb, three tlcs, for local", { slot: { commitmentNumber: 11, counter: "local" } });

            await expect(engine.checkAndClaim(KEYS, request)).resolves.toMatchObject({ status: "fresh", commitmentNumber: 11 });
            expect((await store.getChannelRecord(CHANNEL_INDEX))?.commitmentHashes.local).toEqual({
                commitmentNumber: 12,
                txHash: kase.digest,
                source: { output: THREE_TLC_LOCAL_OUTPUT, outputData: "" },
                settlementWitness: kase.settlement_witness,
            });
        });

        it("claims the commitment slot for a cooperative close, and keeps no commitment hash", async () => {
            const { engine, store } = await registered();
            await expect(engine.checkAndClaim(KEYS, closingRequest("ckb"))).resolves.toEqual({
                status: "fresh",
                context: "COMMITMENT",
                commitmentNumber: SHUTDOWN_NONCE_NUMBER,
            });
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                lastSignedCommitmentNumbers: { "COMMITMENT:local": SHUTDOWN_NONCE_NUMBER },
                commitmentHashes: {},
            });
        });

        it("claims the revocation slot at the nonce number while the message commits to the previous one", async () => {
            const { engine, store } = await registered();
            const request = await holdingReplacement(store, revocationRequest("ckb, send side"));

            await expect(engine.checkAndClaim(KEYS, request)).resolves.toEqual({
                status: "fresh",
                context: "REVOKE",
                commitmentNumber: 5,
            });
            // The replacement stays the view's last: a revocation signs no commitment.
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                lastSignedCommitmentNumbers: { "REVOKE:remote": 5 },
                commitmentHashes: { local: { commitmentNumber: 5, txHash: REPLACEMENT_TX_HASH } },
            });
        });

        it("claims the fixed announcement slot", async () => {
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

        it("keeps counters per lane", async () => {
            const { engine, store } = await opened();
            await recordThreeTlcIntents(engine);
            await engine.checkAndClaim(KEYS, threeTlcRequest());
            await engine.checkAndClaim(KEYS, await holdingReplacement(store, revocationRequest("ckb, send side")));
            await engine.checkAndClaim(KEYS, await holdingReplacement(store, receivedRevocation(3)));

            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                lastSignedCommitmentNumbers: { "COMMITMENT:local": 11, "REVOKE:remote": 5, "REVOKE:local": 3 },
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

        // It leaves at the sign-once check, so the lane and the view's version it would trip never run.
        it("answers a repeat that its lane and its view's version would otherwise refuse", async () => {
            const { engine } = await opened();
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({ forRemote: true, commitmentNumber: 11, settlementLocalShannons: OPENING_SETTLEMENT, tlcIds: [] }),
            );
            const opening = customCommitmentRequest({
                forRemote: true,
                commitmentNumber: 10,
                settlementLocalShannons: OPENING_SETTLEMENT,
                tlcIds: [],
            });
            await expect(engine.checkAndClaim(KEYS, opening)).resolves.toMatchObject({ status: "already-signed" });
        });

        it("answers a repeat of a revocation, whatever the other lane signed since", async () => {
            const { engine, store } = await registered();
            await engine.checkAndClaim(KEYS, await holdingReplacement(store, revocationRequest("ckb, send side")));
            await engine.checkAndClaim(KEYS, await holdingReplacement(store, receivedRevocation(9)));
            await expect(
                engine.checkAndClaim(KEYS, await holdingReplacement(store, revocationRequest("ckb, send side"))),
            ).resolves.toMatchObject({
                status: "already-signed",
                commitmentNumber: 5,
            });
        });
    });

    describe("check 0: the shape of the request", () => {
        it.each([
            ["an empty channelId", commitmentRequest("ckb, no tlcs, for remote", { channelId: "" })],
            [
                "a commitment number above the chain",
                commitmentRequest("ckb, no tlcs, for remote", { slot: { commitmentNumber: 2 ** 48, counter: "local" } }),
            ],
            [
                "a fractional commitment number",
                commitmentRequest("ckb, no tlcs, for remote", { slot: { commitmentNumber: 0.5, counter: "local" } }),
            ],
            ["no slot", commitmentRequest("ckb, no tlcs, for remote", { slot: undefined as never })],
            [
                "a commitment read from the remote counter",
                commitmentRequest("ckb, no tlcs, for remote", { slot: { commitmentNumber: 0, counter: "remote" } }),
            ],
            ["a close read from no counter", closingRequest("ckb", { slot: { commitmentNumber: SHUTDOWN_NONCE_NUMBER, counter: null } })],
            [
                "a sent revocation read from the local counter",
                revocationRequest("ckb, send side", { slot: { commitmentNumber: 5, counter: "local" } }),
            ],
            [
                "a received revocation read from the remote counter",
                revocationRequest("udt, receive side", { slot: { commitmentNumber: 10, counter: "remote" } }),
            ],
            [
                "an announcement read from the local counter",
                announcementRequest("ckb", { slot: { commitmentNumber: 0, counter: "local" } }),
            ],
            ["an announcement at another slot than 0", announcementRequest("ckb", { slot: { commitmentNumber: 7, counter: null } })],
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
            const request = commitmentRequest("ckb, no tlcs, for remote", { slot: { commitmentNumber: 0, counter: "remote" } });
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
            await engine.pinChannelTerms(CHANNEL_ID, TERMS);
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

        it("refuses a close whose output holds more than a cell's capacity, writing nothing", async () => {
            const { engine, storage } = await registered();
            const request = closingRequest("ckb");
            const operation = request.operation;
            if (operation.kind !== "closing_tx") throw new Error("expected a close request");
            operation.input.localCapacityShannons = 1n << 64n;
            const stored = new Map(storage.map);
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, request));
            expect(refusal.code).toBe("malformed");
            expect(refusal.message).toContain("localCapacityShannons must be a bigint between 0 and 18446744073709551615");
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
            await engine.checkAndClaim(KEYS, threeTlcRequest());
            const other = commitmentRequest("udt, two tlcs, for remote");
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
            const close = closingRequest("ckb", { slot: { commitmentNumber: 11, counter: "local" } });
            expect((await refusalOf(engine.checkAndClaim(KEYS, close))).code).toBe("policy_refusal");
        });

        it("refuses a commitment on a slot a cooperative close already served", async () => {
            const { engine } = await registered();
            await engine.checkAndClaim(KEYS, closingRequest("ckb", { slot: { commitmentNumber: 11, counter: "local" } }));
            const commitment = threeTlcRequest();
            expect((await refusalOf(engine.checkAndClaim(KEYS, commitment))).code).toBe("policy_refusal");
        });

        // The reason the record is keyed by the channel index: two names must never mean two slot registries.
        it("refuses a slot the channel's other name already served", async () => {
            const { engine } = newEngine();
            await engine.registerChannel("temporary-id", CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
            await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
            await engine.pinChannelTerms(CHANNEL_ID, TERMS);
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
            await engine.pinChannelTerms(CHANNEL_ID, TERMS);
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

    describe("check 4: the lanes and the views' versions", () => {
        it("refuses a commitment number below the last signed in its lane", async () => {
            const { engine, storage } = await opened();
            await recordThreeTlcIntents(engine);
            await engine.checkAndClaim(KEYS, threeTlcRequest());
            const stored = new Map(storage.map);
            const older = customCommitmentRequest({
                forRemote: true,
                commitmentNumber: 9,
                settlementLocalShannons: OPENING_SETTLEMENT,
                tlcIds: [],
            });
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, older));
            expect(refusal.code).toBe("stale_state");
            expect(refusal.message).toBe("commitment number 9 is not above the last COMMITMENT:local signed, 11");
            expect(storage.map).toEqual(stored);
        });

        it("refuses a commitment number equal to the last signed when its slot is missing from the registry", async () => {
            const { engine, store } = await registered();
            const record = (await store.getChannelRecord(CHANNEL_INDEX)) as ChannelPolicyRecord;
            await store.setChannelRecord(CHANNEL_INDEX, { ...record, lastSignedCommitmentNumbers: { "COMMITMENT:local": 0 } });
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote")));
            expect(refusal.code).toBe("stale_state");
            expect(refusal.message).toBe("commitment number 0 is not above the last COMMITMENT:local signed, 0");
        });

        it("orders a close on the commitment lane", async () => {
            const { engine } = await opened();
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({ forRemote: true, commitmentNumber: 11, settlementLocalShannons: OPENING_SETTLEMENT, tlcIds: [] }),
            );
            const refusal = await refusalOf(
                engine.checkAndClaim(KEYS, closingRequest("ckb", { slot: { commitmentNumber: 9, counter: "local" } })),
            );
            expect(refusal.message).toBe("commitment number 9 is not above the last COMMITMENT:local signed, 11");
        });

        // The two lanes advance on different events: a SendRevokeAndAck and a CompleteReceivedRevokeAndAck.
        it("refuses a revocation below the last of its own lane", async () => {
            const { engine, store } = await registered();
            await engine.checkAndClaim(KEYS, await holdingReplacement(store, sentRevocation(5)));
            await engine.checkAndClaim(KEYS, await holdingReplacement(store, receivedRevocation(8)));
            expect((await refusalOf(engine.checkAndClaim(KEYS, sentRevocation(4)))).message).toBe(
                "commitment number 4 is not above the last REVOKE:remote signed, 5",
            );
            expect((await refusalOf(engine.checkAndClaim(KEYS, receivedRevocation(7)))).message).toBe(
                "commitment number 7 is not above the last REVOKE:local signed, 8",
            );
        });

        it("accepts a revocation below the last of the other lane", async () => {
            const { engine, store } = await registered();
            await engine.checkAndClaim(KEYS, await holdingReplacement(store, sentRevocation(9)));
            await expect(engine.checkAndClaim(KEYS, await holdingReplacement(store, receivedRevocation(3)))).resolves.toMatchObject({
                status: "fresh",
                commitmentNumber: 3,
            });
            await expect(engine.checkAndClaim(KEYS, await holdingReplacement(store, sentRevocation(10)))).resolves.toMatchObject({
                status: "fresh",
            });
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                lastSignedCommitmentNumbers: { "REVOKE:remote": 10, "REVOKE:local": 3 },
            });
        });

        // One nonce per slot whatever the lane: the second side of one revocation round is a second session.
        it("refuses the other lane's revocation on a slot one lane served", async () => {
            const { engine, store } = await registered();
            await engine.checkAndClaim(KEYS, await holdingReplacement(store, sentRevocation(5)));
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, receivedRevocation(5)));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe("slot REVOKE:5 has already served a different signing session");
        });

        // Fiber's device SDK refuses the same way (`fiber-lsp-sdk/src/commitment.rs:671-689`): a commitment is revoked only
        // once the one replacing it is signed, and before anything is signed after it.
        describe.each<[string, (slot: number) => PolicySignRequest, PolicyView, PolicyView]>([
            ["a sent revocation", sentRevocation, "local", "remote"],
            ["a received revocation", receivedRevocation, "remote", "local"],
        ])("the replacement of %s", (_, revocation, view, otherView) => {
            it("signs it once the view's last commitment is the replacement, at the slot's number", async () => {
                const { engine, store } = await registered();
                await holdLastCommitment(store, view, 5);
                await expect(engine.checkAndClaim(KEYS, revocation(5))).resolves.toEqual({
                    status: "fresh",
                    context: "REVOKE",
                    commitmentNumber: 5,
                });
            });

            it.each<[string, number | null, string]>([
                ["no commitment signed in the view", null, `no ${view} commitment has been signed`],
                ["the view's last commitment one below the replacement", 4, "the last one signed is version 4"],
                ["the view's last commitment one above the replacement", 6, "the last one signed is version 6"],
            ])("refuses it as stale with %s, writing nothing", async (_, last, tail) => {
                const { engine, store, storage } = await registered();
                if (last !== null) await holdLastCommitment(store, view, last);
                const stored = new Map(storage.map);
                const refusal = await refusalOf(engine.checkAndClaim(KEYS, revocation(5)));
                expect(refusal.code).toBe("stale_state");
                expect(refusal.message).toBe(
                    `the revocation at slot 5 must follow its replacement, the ${view} commitment at version 5, and ${tail}`,
                );
                expect(storage.map).toEqual(stored);
            });

            it("refuses it when only the other view's last commitment is at the slot's number", async () => {
                const { engine, store } = await registered();
                await holdLastCommitment(store, otherView, 5);
                const refusal = await refusalOf(engine.checkAndClaim(KEYS, revocation(5)));
                expect(refusal.message).toBe(
                    `the revocation at slot 5 must follow its replacement, the ${view} commitment at version 5, and no ${view} commitment has been signed`,
                );
            });

            // The repeat leaves at sign-once, ahead of the view it would trip.
            it("answers its repeat once the view has moved past the replacement", async () => {
                const { engine, store } = await registered();
                await holdLastCommitment(store, view, 5);
                await engine.checkAndClaim(KEYS, revocation(5));
                await holdLastCommitment(store, view, 6);
                await expect(engine.checkAndClaim(KEYS, revocation(5))).resolves.toMatchObject({ status: "already-signed" });
            });
        });

        it("keeps the announcement on a lane of its own", async () => {
            const { engine, store } = await opened();
            await engine.checkAndClaim(KEYS, announcementRequest("ckb"));
            await engine.checkAndClaim(KEYS, await holdingReplacement(store, sentRevocation(1)));
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                lastSignedCommitmentNumbers: { "COMMITMENT:local": 10, ANNOUNCEMENT: 0, "REVOKE:remote": 1 },
            });
        });

        it.each([
            ["equal to", 11],
            ["below", 10],
        ])("refuses a commitment whose version is %s the last its view signed, writing nothing", async (_, version) => {
            const { engine, storage } = await opened();
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({ forRemote: true, commitmentNumber: 11, settlementLocalShannons: OPENING_SETTLEMENT, tlcIds: [] }),
            );
            const stored = new Map(storage.map);
            const { input } = customCommitmentRequest({
                forRemote: true,
                commitmentNumber: version,
                settlementLocalShannons: OPENING_SETTLEMENT,
                tlcIds: [],
            }).operation as Extract<SignOperation, { kind: "commitment_tx" }>;
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, signedRequest({ kind: "commitment_tx", input }, 12)));
            expect(refusal.code).toBe("stale_state");
            expect(refusal.message).toBe(`the remote commitment's version ${version} is not one above the last one signed in its view, 11`);
            expect(storage.map).toEqual(stored);
        });

        // The device's own commitment carries the peer's number, which neither the lane nor the other view orders.
        it("holds each view to its own versions, apart from the slot and the other view", async () => {
            const { engine, store } = await opened();
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({ forRemote: true, commitmentNumber: 11, settlementLocalShannons: OPENING_SETTLEMENT, tlcIds: [] }),
            );
            const local = (version: number, slot: number): PolicySignRequest => {
                const { input } = customCommitmentRequest({
                    forRemote: false,
                    commitmentNumber: version,
                    settlementLocalShannons: OPENING_SETTLEMENT,
                    tlcIds: [],
                }).operation as Extract<SignOperation, { kind: "commitment_tx" }>;
                return signedRequest({ kind: "commitment_tx", input }, slot);
            };
            await expect(engine.checkAndClaim(KEYS, local(2, 12))).resolves.toMatchObject({ status: "fresh", commitmentNumber: 12 });
            expect((await refusalOf(engine.checkAndClaim(KEYS, local(2, 13)))).message).toBe(
                "the local commitment's version 2 is not above the last one signed in its view, 2",
            );
            await expect(engine.checkAndClaim(KEYS, local(3, 13))).resolves.toMatchObject({ status: "fresh" });
            const record = await store.getChannelRecord(CHANNEL_INDEX);
            expect(record?.commitmentHashes).toMatchObject({
                remote: {
                    commitmentNumber: 11,
                    txHash: bytesToHex(
                        customCommitmentRequest({
                            forRemote: true,
                            commitmentNumber: 11,
                            settlementLocalShannons: OPENING_SETTLEMENT,
                            tlcIds: [],
                        }).session.message,
                    ),
                },
                local: { commitmentNumber: 3, txHash: bytesToHex(local(3, 13).session.message) },
            });
        });

        // The peer holds at most two unrevoked commitments: with a third, the oldest's revocation is stale.
        describe("the remote view", () => {
            function remote(commitmentNumber: number): PolicySignRequest {
                return customCommitmentRequest({
                    forRemote: true,
                    commitmentNumber,
                    settlementLocalShannons: OPENING_SETTLEMENT,
                    tlcIds: [],
                });
            }

            it("signs the view's first commitment at any version", async () => {
                const { engine, store } = await registered();
                await expect(engine.checkAndClaim(KEYS, remote(7))).resolves.toEqual({
                    status: "fresh",
                    context: "COMMITMENT",
                    commitmentNumber: 7,
                });
                expect((await store.getChannelRecord(CHANNEL_INDEX))?.commitmentHashes).toMatchObject({
                    remote: { commitmentNumber: 7, txHash: bytesToHex(remote(7).session.message) },
                });
            });

            it("signs the one after the view's first with no revocation signed", async () => {
                const { engine, store } = await opened();
                await expect(engine.checkAndClaim(KEYS, remote(11))).resolves.toMatchObject({ status: "fresh", commitmentNumber: 11 });
                expect((await store.getChannelRecord(CHANNEL_INDEX))?.lastSignedCommitmentNumbers).toEqual({ "COMMITMENT:local": 11 });
            });

            it("refuses a version two above the view's last as stale, writing nothing", async () => {
                const { engine, storage } = await opened();
                const stored = new Map(storage.map);
                const refusal = await refusalOf(engine.checkAndClaim(KEYS, remote(12)));
                expect(refusal.code).toBe("stale_state");
                expect(refusal.message).toBe("the remote commitment's version 12 is not one above the last one signed in its view, 10");
                expect(storage.map).toEqual(stored);
            });

            it("refuses the one after the second as stale while the revocation of the first is not signed, writing nothing", async () => {
                const { engine, storage } = await opened();
                await engine.checkAndClaim(KEYS, remote(11));
                const stored = new Map(storage.map);
                const refusal = await refusalOf(engine.checkAndClaim(KEYS, remote(12)));
                expect(refusal.code).toBe("stale_state");
                expect(refusal.message).toBe(
                    "the remote commitment's version 12 must follow the revocation of version 10, at slot REVOKE:11, and nothing has been signed on REVOKE:local",
                );
                expect(storage.map).toEqual(stored);
            });

            // What a delivery failing after the claim leaves.
            it("refuses it as stale while the revocation of the first is claimed but its signature not recorded, writing nothing", async () => {
                const { engine, storage } = await opened();
                await engine.checkAndClaim(KEYS, remote(11));
                await engine.checkAndClaim(KEYS, receivedRevocation(11));
                const stored = new Map(storage.map);
                const refusal = await refusalOf(engine.checkAndClaim(KEYS, remote(12)));
                expect(refusal.code).toBe("stale_state");
                expect(refusal.message).toBe(
                    "the remote commitment's version 12 must follow the revocation of version 10, at slot REVOKE:11, and its complete signature has not been recorded",
                );
                expect(storage.map).toEqual(stored);
            });

            it("refuses the next one as stale while only an older revocation's signature is recorded, writing nothing", async () => {
                const { engine, storage } = await opened();
                await engine.checkAndClaim(KEYS, remote(11));
                await peerRevokes(engine, 11);
                await engine.checkAndClaim(KEYS, remote(12));
                await engine.checkAndClaim(KEYS, receivedRevocation(12));
                const stored = new Map(storage.map);
                const refusal = await refusalOf(engine.checkAndClaim(KEYS, remote(13)));
                expect(refusal.code).toBe("stale_state");
                expect(refusal.message).toBe(
                    "the remote commitment's version 13 must follow the revocation of version 11, at slot REVOKE:12, and its complete signature has not been recorded",
                );
                expect(storage.map).toEqual(stored);
            });

            it("signs it once the revocation of the first is claimed and its signature recorded", async () => {
                const { engine, store } = await opened();
                await engine.checkAndClaim(KEYS, remote(11));
                await engine.checkAndClaim(KEYS, receivedRevocation(11));
                await engine.recordRevocation(CHANNEL_ID, { version: 10, signature: SIGNATURE });
                await expect(engine.checkAndClaim(KEYS, remote(12))).resolves.toMatchObject({ status: "fresh", commitmentNumber: 12 });
                expect((await store.getChannelRecord(CHANNEL_INDEX))?.commitmentHashes.remote).toMatchObject({
                    commitmentNumber: 12,
                    txHash: bytesToHex(remote(12).session.message),
                });
            });

            it("keeps the cell and the settlement body of the last one as the previous one, signing the next", async () => {
                const { engine, store } = await opened();
                const opening = (await store.getChannelRecord(CHANNEL_INDEX))?.commitmentHashes.remote;
                expect((await store.getChannelRecord(CHANNEL_INDEX))?.previousRemoteCommitment).toBeUndefined();
                await engine.checkAndClaim(KEYS, remote(11));
                expect((await store.getChannelRecord(CHANNEL_INDEX))?.previousRemoteCommitment).toEqual({
                    commitmentNumber: 10,
                    source: opening?.source,
                    settlementWitness: opening?.settlementWitness,
                });
            });

            it("moves the previous one on with each remote commitment, and keeps it over a local one and a revocation", async () => {
                const { engine, store } = await opened();
                await engine.checkAndClaim(KEYS, remote(11));
                await peerRevokes(engine, 11);
                const eleventh = (await store.getChannelRecord(CHANNEL_INDEX))?.commitmentHashes.remote;
                await engine.checkAndClaim(KEYS, remote(12));
                const previous = { commitmentNumber: 11, source: eleventh?.source, settlementWitness: eleventh?.settlementWitness };
                expect((await store.getChannelRecord(CHANNEL_INDEX))?.previousRemoteCommitment).toEqual(previous);
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: false,
                        commitmentNumber: 13,
                        settlementLocalShannons: OPENING_SETTLEMENT,
                        tlcIds: [],
                    }),
                );
                expect((await store.getChannelRecord(CHANNEL_INDEX))?.previousRemoteCommitment).toEqual(previous);
                await peerRevokes(engine, 12);
                expect((await store.getChannelRecord(CHANNEL_INDEX))?.previousRemoteCommitment).toEqual(previous);
            });

            it("keeps no previous one after a last one signed before the record kept cells", async () => {
                const { engine, store } = await opened();
                await engine.checkAndClaim(KEYS, remote(11));
                await store.updateChannelRecord(CHANNEL_INDEX, (current) => {
                    if (current === null) throw new Error("the channel holds no record");
                    const cellless = { commitmentNumber: 11, txHash: REPLACEMENT_TX_HASH };
                    return { ...current, commitmentHashes: { ...current.commitmentHashes, remote: cellless } };
                });
                await peerRevokes(engine, 11);
                await engine.checkAndClaim(KEYS, remote(12));
                expect((await store.getChannelRecord(CHANNEL_INDEX))?.previousRemoteCommitment).toBeUndefined();
            });

            it("refuses the next one as stale while the last revocation signed is the one before, writing nothing", async () => {
                const { engine, storage } = await opened();
                await engine.checkAndClaim(KEYS, remote(11));
                await peerRevokes(engine, 11);
                await engine.checkAndClaim(KEYS, remote(12));
                const stored = new Map(storage.map);
                const refusal = await refusalOf(engine.checkAndClaim(KEYS, remote(13)));
                expect(refusal.code).toBe("stale_state");
                expect(refusal.message).toBe(
                    "the remote commitment's version 13 must follow the revocation of version 11, at slot REVOKE:12, and the last REVOKE:local signed is 11",
                );
                expect(storage.map).toEqual(stored);
            });

            // The device's own revocation gives up none of the peer's commitments, whatever signature the slot records.
            it("refuses it as stale when only the device's own revocation took that slot, writing nothing", async () => {
                const { engine, store, storage } = await opened();
                await engine.checkAndClaim(KEYS, remote(11));
                await engine.checkAndClaim(KEYS, await holdingReplacement(store, sentRevocation(11)));
                await engine.recordRevocation(CHANNEL_ID, { version: 10, signature: SIGNATURE });
                const stored = new Map(storage.map);
                const refusal = await refusalOf(engine.checkAndClaim(KEYS, remote(12)));
                expect(refusal.code).toBe("stale_state");
                expect(refusal.message).toBe(
                    "the remote commitment's version 12 must follow the revocation of version 10, at slot REVOKE:11, and nothing has been signed on REVOKE:local",
                );
                expect(storage.map).toEqual(stored);
            });

            // Fiber's receiving round: the device's revocation first, the peer's as the slot's second session.
            it("signs it once the peer's revocation took that slot as a second session", async () => {
                const { engine, store } = await openedEngine(new InMemorySignerStorage(), { nonceReuse: "allow" });
                await engine.checkAndClaim(KEYS, remote(11));
                await engine.checkAndClaim(KEYS, await holdingReplacement(store, sentRevocation(11)));
                await expect(engine.checkAndClaim(KEYS, receivedRevocation(11))).resolves.toMatchObject({ status: "reused" });
                await engine.recordRevocation(CHANNEL_ID, { version: 10, signature: SIGNATURE });
                await expect(engine.checkAndClaim(KEYS, remote(12))).resolves.toMatchObject({ status: "fresh", commitmentNumber: 12 });
            });

            it("holds a second session on the view to the revocation as a first one, writing nothing", async () => {
                const { engine, storage } = await openedEngine(new InMemorySignerStorage(), { nonceReuse: "allow" });
                await engine.checkAndClaim(KEYS, remote(11));
                // The device's own commitment takes the slot first, as in fiber's rounds.
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: false,
                        commitmentNumber: 12,
                        settlementLocalShannons: OPENING_SETTLEMENT,
                        tlcIds: [],
                    }),
                );
                const stored = new Map(storage.map);
                const refusal = await refusalOf(engine.checkAndClaim(KEYS, remote(12)));
                expect(refusal.code).toBe("stale_state");
                expect(refusal.message).toBe(
                    "the remote commitment's version 12 must follow the revocation of version 10, at slot REVOKE:11, and nothing has been signed on REVOKE:local",
                );
                expect(storage.map).toEqual(stored);
            });

            it("answers the repeat of a version the view has moved past as already signed, writing nothing", async () => {
                const { engine, storage } = await opened();
                await engine.checkAndClaim(KEYS, remote(11));
                await peerRevokes(engine, 11);
                await engine.checkAndClaim(KEYS, remote(12));
                storage.ops.length = 0;
                await expect(engine.checkAndClaim(KEYS, remote(11))).resolves.toEqual({
                    status: "already-signed",
                    context: "COMMITMENT",
                    commitmentNumber: 11,
                });
                expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
            });

            it("answers the repeat of a second session the view has moved past as reused, writing nothing", async () => {
                const { engine, storage } = await registeredEngine(new InMemorySignerStorage(), { nonceReuse: "allow" });
                // Fiber's open: the device's own commitment, then the peer's on its slot.
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: false,
                        commitmentNumber: 10,
                        settlementLocalShannons: OPENING_SETTLEMENT,
                        tlcIds: [],
                    }),
                );
                await engine.checkAndClaim(KEYS, remote(10));
                await engine.checkAndClaim(KEYS, remote(11));
                storage.ops.length = 0;
                await expect(engine.checkAndClaim(KEYS, remote(10))).resolves.toEqual({
                    status: "reused",
                    context: "COMMITMENT",
                    commitmentNumber: 10,
                });
                expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
            });

            // Fiber serves no slot below the view's first; one that is costs a revocation more, never one less.
            it("asks the one after the view's first for a revocation when a slot below the first was served", async () => {
                const { engine, storage } = await registered();
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: false,
                        commitmentNumber: 0,
                        settlementLocalShannons: OPENING_SETTLEMENT,
                        tlcIds: [],
                    }),
                );
                await engine.checkAndClaim(KEYS, remote(1));
                const stored = new Map(storage.map);
                const refusal = await refusalOf(engine.checkAndClaim(KEYS, remote(2)));
                expect(refusal.code).toBe("stale_state");
                expect(refusal.message).toBe(
                    "the remote commitment's version 2 must follow the revocation of version 0, at slot REVOKE:1, and nothing has been signed on REVOKE:local",
                );
                expect(storage.map).toEqual(stored);
            });

            it("leaves the device's own view free to skip versions", async () => {
                const { engine, store } = await opened();
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: false,
                        commitmentNumber: 11,
                        settlementLocalShannons: OPENING_SETTLEMENT,
                        tlcIds: [],
                    }),
                );
                const skipping = customCommitmentRequest({
                    forRemote: false,
                    commitmentNumber: 14,
                    settlementLocalShannons: OPENING_SETTLEMENT,
                    tlcIds: [],
                });
                await expect(engine.checkAndClaim(KEYS, skipping)).resolves.toMatchObject({ status: "fresh", commitmentNumber: 14 });
                expect((await store.getChannelRecord(CHANNEL_INDEX))?.commitmentHashes.local).toMatchObject({
                    commitmentNumber: 14,
                    txHash: bytesToHex(skipping.session.message),
                });
            });
        });
    });

    // Fiber's lifecycle signs more than one message per slot until it fixes its nonces; two sessions leave the key unsolvable.
    describe("nonce reuse under allow", () => {
        const ALLOW: PolicyEngineOptions = { nonceReuse: "allow" };

        // The opening on the peer's commitment, then fiber's second message on its slot: the device's own opening.
        function ownOpening(): PolicySignRequest {
            return customCommitmentRequest({
                forRemote: false,
                commitmentNumber: 0,
                settlementLocalShannons: OPENING_SETTLEMENT,
                tlcIds: [],
            });
        }

        function thirdSession(): PolicySignRequest {
            const kase = caseOf(digest.commitment_cases, "ckb, no tlcs, for remote");
            return commitmentRequest("ckb, no tlcs, for remote", {
                session: session(hexToBytes(kase.digest), { aggregatedNonce: OTHER_AGGREGATED_NONCE }),
            });
        }

        it("serves a second session on a served slot, logs it, and reports it as reused", async () => {
            const { engine, store } = await registeredEngine(new InMemorySignerStorage(), ALLOW);
            const first = commitmentRequest("ckb, no tlcs, for remote");
            await engine.checkAndClaim(KEYS, first);
            const second = ownOpening();

            await expect(engine.checkAndClaim(KEYS, second)).resolves.toEqual({
                status: "reused",
                context: "COMMITMENT",
                commitmentNumber: 0,
            });
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toEqual<ChannelPolicyRecord>({
                version: 1,
                channelId: CHANNEL_ID,
                lastSignedCommitmentNumbers: { "COMMITMENT:local": 0 },
                signedSessions: { "COMMITMENT:0": buildSessionCommitment(first.session) },
                nonceReuse: {
                    "COMMITMENT:0": {
                        sessionCommitment: buildSessionCommitment(second.session),
                        message: bytesToHex(second.session.message),
                    },
                },
                commitmentHashes: {
                    remote: expect.objectContaining({ commitmentNumber: 0, txHash: bytesToHex(first.session.message) }),
                    local: expect.objectContaining({ commitmentNumber: 0, txHash: bytesToHex(second.session.message) }),
                },
                revocations: [],
                pins: OPENED_PINS,
                views: { remote: OPENING_VIEW, local: OPENING_VIEW },
            });
        });

        it("refuses the same second session under the default mode, writing nothing", async () => {
            const { engine, storage } = await registeredEngine();
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote"));
            const stored = new Map(storage.map);
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, ownOpening()));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe("slot COMMITMENT:0 has already served a different signing session");
            expect(storage.map).toEqual(stored);
        });

        // Three partial signatures under one deterministic nonce are three equations that solve for the funding key.
        it("refuses a third session on the slot, whatever it signs, writing nothing", async () => {
            const { engine, storage } = await registeredEngine(new InMemorySignerStorage(), ALLOW);
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote"));
            await engine.checkAndClaim(KEYS, ownOpening());
            const stored = new Map(storage.map);
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, thirdSession()));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe("slot COMMITMENT:0 has already served two signing sessions, the most one nonce can");
            expect(storage.map).toEqual(stored);
        });

        it("answers a byte-identical repeat of the first session as already signed, and of the second as reused, writing nothing", async () => {
            const { engine, storage } = await registeredEngine(new InMemorySignerStorage(), ALLOW);
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote"));
            await engine.checkAndClaim(KEYS, ownOpening());
            storage.ops.length = 0;
            await expect(engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote"))).resolves.toMatchObject({
                status: "already-signed",
            });
            await expect(engine.checkAndClaim(KEYS, ownOpening())).resolves.toEqual({
                status: "reused",
                context: "COMMITMENT",
                commitmentNumber: 0,
            });
            expect(storage.ops.filter((operation) => operation.startsWith("set"))).toEqual([]);
        });

        // A host that turns the mode off keeps what was served: the repeat reveals nothing new, a third session would.
        it("keeps answering a logged session's repeat as reused once the mode is off, and refuses a third", async () => {
            const storage = new InMemorySignerStorage();
            const allowed = await registeredEngine(storage, ALLOW);
            await allowed.engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote"));
            await allowed.engine.checkAndClaim(KEYS, ownOpening());
            const { engine } = newEngine(storage);
            await expect(engine.checkAndClaim(KEYS, ownOpening())).resolves.toMatchObject({ status: "reused" });
            expect((await refusalOf(engine.checkAndClaim(KEYS, thirdSession()))).message).toBe(
                "slot COMMITMENT:0 has already served two signing sessions, the most one nonce can",
            );
        });

        // The lockstep round: both sides of one revocation use the nonce at one number, each on its own lane.
        it("serves the other lane's revocation on the slot one lane served, moving its own lane to the slot", async () => {
            const { engine, store } = await registeredEngine(new InMemorySignerStorage(), ALLOW);
            await engine.checkAndClaim(KEYS, await holdingReplacement(store, sentRevocation(5)));
            await expect(engine.checkAndClaim(KEYS, await holdingReplacement(store, receivedRevocation(5)))).resolves.toMatchObject({
                status: "reused",
                context: "REVOKE",
            });
            expect((await store.getChannelRecord(CHANNEL_INDEX))?.lastSignedCommitmentNumbers).toEqual({
                "REVOKE:remote": 5,
                "REVOKE:local": 5,
            });
            // The second session moved the local lane to 5, so 4 is a rollback.
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, await holdingReplacement(store, receivedRevocation(4))));
            expect(refusal.code).toBe("stale_state");
            expect(refusal.message).toBe("commitment number 4 is not above the last REVOKE:local signed, 5");
        });

        it("holds a second session on a revocation slot to its own replacement, logging nothing", async () => {
            const { engine, store, storage } = await registeredEngine(new InMemorySignerStorage(), ALLOW);
            await engine.checkAndClaim(KEYS, await holdingReplacement(store, sentRevocation(5)));
            const stored = new Map(storage.map);
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, receivedRevocation(5)));
            expect(refusal.code).toBe("stale_state");
            expect(refusal.message).toBe(
                "the revocation at slot 5 must follow its replacement, the remote commitment at version 5, and no remote commitment has been signed",
            );
            expect(storage.map).toEqual(stored);
        });

        it("serves a second session at its lane's last number", async () => {
            const { engine } = await openedEngine(new InMemorySignerStorage(), ALLOW);
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({ forRemote: true, commitmentNumber: 11, settlementLocalShannons: OPENING_SETTLEMENT, tlcIds: [] }),
            );
            const own = customCommitmentRequest({
                forRemote: false,
                commitmentNumber: 11,
                settlementLocalShannons: OPENING_SETTLEMENT,
                tlcIds: [],
            });
            await expect(engine.checkAndClaim(KEYS, own)).resolves.toMatchObject({ status: "reused", commitmentNumber: 11 });
        });

        // Reuse answers fiber's current lifecycle, never a rollback to a slot the lane has left.
        it("refuses a second session below its lane's last number as stale, writing nothing", async () => {
            const { engine, storage } = await openedEngine(new InMemorySignerStorage(), ALLOW);
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({ forRemote: true, commitmentNumber: 11, settlementLocalShannons: OPENING_SETTLEMENT, tlcIds: [] }),
            );
            const stored = new Map(storage.map);
            // The opening's slot, which the lane has left.
            const own = customCommitmentRequest({
                forRemote: false,
                commitmentNumber: 10,
                settlementLocalShannons: OPENING_SETTLEMENT,
                tlcIds: [],
            });
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, own));
            expect(refusal.code).toBe("stale_state");
            expect(refusal.message).toBe("commitment number 10 is below the last COMMITMENT:local signed, 11");
            expect(storage.map).toEqual(stored);
        });

        it.each([
            // The same message under another aggregated nonce: a second session over the view's last version.
            [
                "its view's version",
                thirdSession,
                "stale_state",
                "the remote commitment's version 0 is not one above the last one signed in its view, 0",
            ],
            [
                "the pins",
                () =>
                    signedRequest(
                        {
                            kind: "commitment_tx",
                            input: { ...ckbCommitment(), forRemote: false, commitmentNumber: 0, commitmentFeeRate: 1001n },
                        },
                        0,
                    ),
                "policy_refusal",
                "the request states commitmentFeeRate 1001, but the channel pinned 1000",
            ],
            [
                "the balance rule",
                () =>
                    customCommitmentRequest({ forRemote: false, commitmentNumber: 0, settlementLocalShannons: "61999999999", tlcIds: [] }),
                "policy_refusal",
                "the local commitment lowers the holdings by 1 shannons, which no offered TLC took",
            ],
            [
                "the close rule",
                () => signedRequest({ kind: "closing_tx", input: { ...ckbClose(), localCapacityShannons: 71_799_999_999n } }, 0),
                "policy_refusal",
                `the close pays the device 71799999999 shannons, below the ${FUNDED} of the remote commitment by more than the 100000000 its fee may take`,
            ],
        ])("holds a second session to %s, as a first one, writing nothing", async (_, request, code, message) => {
            const { engine, storage } = await registeredEngine(new InMemorySignerStorage(), ALLOW);
            await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote"));
            const stored = new Map(storage.map);
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, request()));
            expect(refusal.code).toBe(code);
            expect(refusal.message).toBe(message);
            expect(storage.map).toEqual(stored);
        });

        it("files the channel on the intents a reused commitment shows, as a fresh one does", async () => {
            const { engine, store } = await openedEngine(new InMemorySignerStorage(), ALLOW);
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({ forRemote: true, commitmentNumber: 11, settlementLocalShannons: OPENING_SETTLEMENT, tlcIds: [] }),
            );
            const own = customCommitmentRequest({
                forRemote: false,
                commitmentNumber: 11,
                settlementLocalShannons: "60500000000",
                tlcIds: [OFFERED_TLC_ID],
            });
            await expect(engine.checkAndClaim(KEYS, own)).resolves.toMatchObject({ status: "reused" });
            await expect(store.getDebitIntent(OFFERED_HASH.slice(0, 40))).resolves.toMatchObject({ channelIndexes: [CHANNEL_INDEX] });
            expect((await store.getChannelRecord(CHANNEL_INDEX))?.views.local.tlcs).toHaveLength(1);
        });

        it.each([
            ["an unknown mode", { nonceReuse: "warn" as never }, new TypeError("options.nonceReuse must be one of refuse, allow")],
            ["a null mode", { nonceReuse: null as never }, new TypeError("options.nonceReuse must be one of refuse, allow")],
            ["options that are no object", null as never, new TypeError("options must be an object")],
        ])("rejects %s", (_, options, error) => {
            expect(() => new PolicyEngine(new SignerStore(new InMemorySignerStorage()), options)).toThrow(error);
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
                () => signedRequest({ kind: "commitment_tx", input: { ...ckbCommitment(), liquidCapacityShannons: 80_500_000_001n } }, 11),
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
                            kind: "closing_tx",
                            input: { ...ckbClose(), fundingOutPoint: { txHash: hexToBytes(FUNDING_TX_HASH), index: 1 } },
                        },
                        11,
                    ),
                "fundingOutPoint",
                `${FUNDING_TX_HASH}:1`,
                `${FUNDING_TX_HASH}:0`,
            ],
            [
                "a close under another peer funding key",
                () => signedRequest({ kind: "closing_tx", input: { ...ckbClose(), remoteFundingPubkey: OTHER_FUNDING_PUBKEY } }, 11),
                "remoteFundingPubkey",
                bytesToHex(OTHER_FUNDING_PUBKEY),
                digest.remote.funding_pubkey,
            ],
            [
                "a close paying the device to another script",
                () =>
                    signedRequest(
                        {
                            kind: "closing_tx",
                            input: { ...ckbClose(), localCloseScript: { ...CLOSE_SCRIPT, args: new Uint8Array(20) } },
                        },
                        11,
                    ),
                "localCloseScript",
                "4900000010000000300000003100000074d3f63a22681bdb6ff6512866db95264338cfaee12f71e28b9f23c414990c9c0114000000" +
                    "00".repeat(20),
                REGISTERED_PINS.localCloseScript,
            ],
            // Fiber lets the peer's `Shutdown` replace the script of the open, and the device's own share still matches.
            [
                "a close paying the peer to another script",
                () =>
                    signedRequest(
                        {
                            kind: "closing_tx",
                            input: { ...ckbClose(), remoteCloseScript: { ...ckbClose().remoteCloseScript, args: new Uint8Array(32) } },
                        },
                        11,
                    ),
                "remoteCloseScript",
                "55000000100000003000000031000000014f879c667f549df6067c1797534f2b2de2312feff188d100669d4b8ad6f045" +
                    "0220000000" +
                    "00".repeat(32),
                REMOTE_CLOSE_SCRIPT_PIN,
            ],
            [
                "a close paying the peer to the device's own script",
                () => signedRequest({ kind: "closing_tx", input: { ...ckbClose(), remoteCloseScript: CLOSE_SCRIPT } }, 11),
                "remoteCloseScript",
                REGISTERED_PINS.localCloseScript,
                REMOTE_CLOSE_SCRIPT_PIN,
            ],
            // The funding output is read before the peer's close script, so it names the conflict.
            [
                "a close on another funding output, paying the peer to another script",
                () =>
                    signedRequest(
                        {
                            kind: "closing_tx",
                            input: {
                                ...ckbClose(),
                                fundingOutPoint: { txHash: hexToBytes(FUNDING_TX_HASH), index: 1 },
                                remoteCloseScript: CLOSE_SCRIPT,
                            },
                        },
                        11,
                    ),
                "fundingOutPoint",
                `${FUNDING_TX_HASH}:1`,
                `${FUNDING_TX_HASH}:0`,
            ],
            // Read by position, the swapped tx gives the device the peer's output, and its digest still matches.
            [
                "a close whose two outputs the node swapped",
                () => {
                    const tx = toTransaction(caseOf(digest.shutdown_cases, "ckb").transaction);
                    const swapped = { ...tx, outputs: [...tx.outputs].reverse(), outputsData: [...tx.outputsData].reverse() };
                    const input = readClosingTx(KEYS, REMOTE_FUNDING_PUBKEY, swapped);
                    const request = signedRequest({ kind: "closing_tx", input }, 11);
                    expect(request.session.message).toEqual(computeTxMessage(swapped));
                    return request;
                },
                "localCloseScript",
                REMOTE_CLOSE_SCRIPT_PIN,
                REGISTERED_PINS.localCloseScript,
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
                () => signedRequest({ kind: "revocation", input: { ...ckbRevocation(), liquidCapacityShannons: 80_500_000_001n } }, 5),
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
            const { engine, store, storage } = await opened();
            const held = await holdingReplacement(store, request());
            const stored = new Map(storage.map);
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, held));
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
            ["a revocation it receives, sweeping to its own script", () => receivedRevocation(5)],
            ["a close to its own script and the peer's pinned one", () => signedRequest({ kind: "closing_tx", input: ckbClose() }, 11)],
            ["an announcement", () => signedRequest({ kind: "channel_announcement", input: ckbAnnouncement() }, 0)],
        ])("signs %s that states every pinned value as pinned", async (_, request) => {
            const { engine, store } = await opened();
            await expect(engine.checkAndClaim(KEYS, await holdingReplacement(store, request()))).resolves.toMatchObject({
                status: "fresh",
            });
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ pins: OPENED_PINS });
        });

        it.each<[string, () => PolicySignRequest, Partial<ChannelPins>]>([
            [
                "a close",
                () => closingRequest("ckb"),
                {
                    fundingOutPoint: OPENED_PINS.fundingOutPoint,
                    remoteFundingPubkey: OPENED_PINS.remoteFundingPubkey,
                },
            ],
            [
                "a revocation",
                () => revocationRequest("ckb, send side"),
                {
                    fundingCapacityShannons: OPENED_PINS.fundingCapacityShannons,
                    remoteFundingPubkey: OPENED_PINS.remoteFundingPubkey,
                    commitmentDelayEpoch: OPENED_PINS.commitmentDelayEpoch,
                    lockLayout: "legacy",
                },
            ],
            [
                "an announcement",
                () => announcementRequest("ckb"),
                {
                    fundingOutPoint: OPENED_PINS.fundingOutPoint,
                    remoteFundingPubkey: OPENED_PINS.remoteFundingPubkey,
                },
            ],
        ])("pins what %s states, when it is the channel's first message", async (_, request, pinned) => {
            const { engine, store } = await registered();
            await engine.checkAndClaim(KEYS, await holdingReplacement(store, request()));
            const record = await store.getChannelRecord(CHANNEL_INDEX);
            expect(record?.pins).toEqual({ ...TERMS_PINNED_PINS, ...pinned });
        });

        it.each([
            ["a commitment", () => commitmentRequest("udt, two tlcs, for remote")],
            ["a revocation", () => revocationRequest("udt, receive side")],
            ["an announcement", () => announcementRequest("udt")],
        ])("refuses %s of a UDT channel, the asset being fixed at registration", async (_, request) => {
            const { engine, store, storage } = await registered();
            const held = await holdingReplacement(store, request());
            const stored = new Map(storage.map);
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, held));
            expect(refusal.message).toBe(`the request states udtTypeScript ${UDT_SCRIPT_PIN}, but the channel pinned null`);
            expect(storage.map).toEqual(stored);
        });

        it("signs a commitment fee of exactly half the reserve's margin", async () => {
            const { engine } = await registered(new InMemorySignerStorage(), FUNDED, { ...TERMS, commitmentFeeRate: 109_649_124n });
            const input = { ...ckbCommitment(), commitmentNumber: 0, commitmentFeeRate: 109_649_124n };
            await expect(engine.checkAndClaim(KEYS, signedRequest({ kind: "commitment_tx", input }, 0))).resolves.toMatchObject({
                status: "fresh",
            });
        });

        it("refuses a commitment fee one shannon past it, even at the rate the host pinned, writing nothing", async () => {
            const { engine, storage } = await registered(new InMemorySignerStorage(), FUNDED, {
                ...TERMS,
                commitmentFeeRate: 109_649_125n,
            });
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
            const { engine, store } = await registered(new InMemorySignerStorage(), FUNDED, { ...TERMS, commitmentFeeRate: 109_649_124n });
            const opening = { ...ckbCommitment(), commitmentNumber: 10, commitmentFeeRate: 109_649_124n };
            await engine.checkAndClaim(KEYS, signedRequest({ kind: "commitment_tx", input: opening }, 10));
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, await holdingReplacement(store, request())));
            expect(refusal.message).toBe("the commitment fee is 54057018 shannons, above the 50000000 the reserve keeps for it");
        });

        // The tx states no fee rate: the 1 CKB the reserve keeps for the close fee is read off what the close pays the device.
        it("signs a close paying the device its exposure less the 1 CKB its fee may take", async () => {
            const { engine } = await opened();
            const request = signedRequest({ kind: "closing_tx", input: { ...ckbClose(), localCapacityShannons: 71_800_000_000n } }, 11);
            await expect(engine.checkAndClaim(KEYS, request)).resolves.toMatchObject({ status: "fresh" });
        });

        it("refuses a close paying the device one shannon less, whatever the peer is paid, writing nothing", async () => {
            const { engine, storage } = await opened();
            const stored = new Map(storage.map);
            const request = signedRequest(
                { kind: "closing_tx", input: { ...ckbClose(), localCapacityShannons: 71_799_999_999n, remoteCapacityShannons: 0n } },
                11,
            );
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, request));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe(
                `the close pays the device 71799999999 shannons, below the ${FUNDED} of the remote commitment by more than the 100000000 its fee may take`,
            );
            expect(storage.map).toEqual(stored);
        });

        it("leaves the peer's output to the peer", async () => {
            const { engine } = await opened();
            const request = signedRequest({ kind: "closing_tx", input: { ...ckbClose(), remoteCapacityShannons: 0n } }, 11);
            await expect(engine.checkAndClaim(KEYS, request)).resolves.toMatchObject({ status: "fresh" });
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

        // Only the liquid capacity sizes the commitment cell; the balance rule never reads it.
        it("refuses a commitment whose liquid capacity no longer holds the channel's", async () => {
            const { engine } = await opened();
            const input = {
                ...ckbCommitment(),
                liquidCapacityShannons: 0n,
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
            const { engine, store } = await registered();
            await engine.checkAndClaim(KEYS, await holdingReplacement(store, first()));
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
            await engine.checkAndClaim(KEYS, closingRequest("ckb", { slot: { commitmentNumber: 10, counter: "local" } }));
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
                            fullPaymentHash: null,
                            amountShannons: OFFERED_AMOUNT,
                            expirySeconds: "1723257890",
                        },
                        {
                            direction: "offered",
                            hashAlgorithm: "sha256",
                            boundPaymentHash: OTHER_OFFERED_HASH.slice(0, 40),
                            fullPaymentHash: null,
                            amountShannons: OTHER_OFFERED_AMOUNT,
                            expirySeconds: "1699999999",
                        },
                        {
                            direction: "received",
                            hashAlgorithm: "sha256",
                            boundPaymentHash: RECEIVED_HASH.slice(0, 40),
                            fullPaymentHash: null,
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
            await peerRevokes(engine, 11);
            // Version 12 on slot 13: the device's own commitment took 12.
            const { operation } = customCommitmentRequest({
                forRemote: true,
                commitmentNumber: 12,
                settlementLocalShannons: THREE_TLC_SETTLEMENT,
                tlcIds: [OFFERED_TLC_ID, OTHER_OFFERED_TLC_ID, RECEIVED_TLC_ID],
            });
            await engine.checkAndClaim(KEYS, signedRequest(operation, 13));
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
            await peerRevokes(engine, 11);
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
            await addOtherChannel(engine);
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
            await addOtherChannel(engine);
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
                            revocation = engine.checkAndClaim(KEYS, revocationRequest("ckb, send side"));
                            await new Promise((resolve) => setTimeout(resolve, 0));
                        }
                        inner.set(key, value);
                    },
                }),
            );
            await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
            await engine.pinChannelTerms(CHANNEL_ID, TERMS);
            await openChannel(engine);
            await holdingReplacement(new SignerStore(inner), revocationRequest("ckb, send side"));
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            const part = { forRemote: true, commitmentNumber: 11, settlementLocalShannons: "60500000000", tlcIds: [OFFERED_TLC_ID] };
            armed = true;

            await expect(engine.checkAndClaim(KEYS, customCommitmentRequest(part))).resolves.toMatchObject({ status: "fresh" });
            expect(revocation).not.toBeNull();
            await expect(revocation).resolves.toMatchObject({ status: "fresh", context: "REVOKE" });
            await expect(new SignerStore(inner).getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                lastSignedCommitmentNumbers: { "COMMITMENT:local": 11, "REVOKE:remote": 5 },
            });
        });

        it("lets only one of two channels racing for one budget take it", async () => {
            const { engine } = await opened(new AsyncInMemorySignerStorage());
            await addOtherChannel(engine);
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
            await engine.pinChannelTerms(CHANNEL_ID, TERMS);
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
            await engine.pinChannelTerms(CHANNEL_ID, TERMS);
            const request = await holdingReplacement(new SignerStore(inner), revocationRequest("ckb, send side"));
            armed = true;
            await expect(engine.checkAndClaim(KEYS, request)).rejects.toThrow(
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
            // The received TLC alone in both views, the opening revoked: the next remote commitment, version 12, takes slot 13.
            async function holding() {
                const context = await opened();
                await recordThreeTlcIntents(context.engine);
                await context.engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
                await holdReceived(context.engine);
                await peerRevokes(context.engine, 11);
                await context.engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING);
                return context;
            }

            // A part that failed on a channel busy with outgoing payments must not hold the release back.
            it("releases while a channel the invoice was shown on no longer lists it, whatever else it lists", async () => {
                const { engine, store } = await opened();
                await addOtherChannel(engine);
                await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 11,
                        settlementLocalShannons: OPENING_SETTLEMENT,
                        tlcIds: [RECEIVED_TLC_ID],
                    }),
                );
                await peerRevokes(engine, 11);
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 12,
                        settlementLocalShannons: OPENING_SETTLEMENT,
                        tlcIds: [],
                    }),
                );
                await peerRevokes(engine, 12);
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 13,
                        settlementLocalShannons: "60500000000",
                        tlcIds: [OFFERED_TLC_ID],
                    }),
                );
                await holdReceived(engine, OTHER_CHANNEL);
                await engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING);
                await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({
                    released: true,
                    channelIndexes: [CHANNEL_INDEX, OTHER_CHANNEL_INDEX],
                });
                await peerRevokes(engine, 13);
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
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "ckb-hash", INVOICE_INDEX);
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: true,
                        commitmentNumber: 11,
                        settlementLocalShannons: OPENING_SETTLEMENT,
                        tlcIds: [RECEIVED_TLC_ID],
                    }),
                );
                const error = await engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING).catch((cause: unknown) => cause);
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
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
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
                await expect(engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING)).rejects.toMatchObject({
                    code: "offered_in_flight",
                });
            });

            it("refuses an offered TLC in one view while the other lists a released held TLC", async () => {
                const { engine } = await holding();
                // The device's own commitment is paid first; the peer's still lists the TLC.
                await engine.checkAndClaim(
                    KEYS,
                    customCommitmentRequest({
                        forRemote: false,
                        commitmentNumber: 13,
                        settlementLocalShannons: "64250000000",
                        tlcIds: [],
                    }),
                );
                const refusal = await refusalOf(
                    engine.checkAndClaim(
                        KEYS,
                        customCommitmentRequest({
                            forRemote: false,
                            commitmentNumber: 14,
                            settlementLocalShannons: "62750000000",
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
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
                await engine.checkAndClaim(KEYS, threeTlcRequest());
                const error = await engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING).catch((cause: unknown) => cause);
                expect(error).toBeInstanceOf(HoldInvoiceError);
                expect(error).toMatchObject({
                    code: "offered_in_flight",
                    message: `channel index ${CHANNEL_INDEX} lists an offered TLC, so the preimage of ${RECEIVED_HASH} is not released yet`,
                });
                await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({ released: false });
            });

            it("refuses an offered TLC on a channel holding a released TLC", async () => {
                const { engine } = await holding();
                const { operation } = customCommitmentRequest({
                    forRemote: true,
                    commitmentNumber: 12,
                    settlementLocalShannons: "60500000000",
                    tlcIds: [OFFERED_TLC_ID, RECEIVED_TLC_ID],
                });
                const refusal = await refusalOf(engine.checkAndClaim(KEYS, signedRequest(operation, 13)));
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
                await engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED, CLOSE_SCRIPT);
                await engine.pinChannelTerms(CHANNEL_ID, TERMS);
                await openChannel(engine);
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
                await holdReceived(engine);
                armed = true;
                await expect(engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING)).rejects.toThrow(
                    new TypeError("a payment record disappeared inside the balance lane"),
                );
                expect(invoiceReads).toBe(2);
            });

            it("throws when the invoice lists a channel that holds no record", async () => {
                const { engine, store } = await registered();
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
                await store.updateHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40), (current) => ({
                    ...(current as HoldInvoicePolicyRecord),
                    channelIndexes: [OTHER_CHANNEL_INDEX],
                }));
                await expect(engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING)).rejects.toThrow(
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
                const { operation } = customCommitmentRequest({
                    forRemote: true,
                    commitmentNumber: 12,
                    settlementLocalShannons: OPENING_SETTLEMENT,
                    tlcIds: [],
                });
                const refusal = await refusalOf(engine.checkAndClaim(KEYS, signedRequest(operation, 13)));
                expect(refusal.message).toBe(
                    `the remote commitment lowers the holdings by ${RECEIVED_AMOUNT} shannons, which no offered TLC took`,
                );
            });

            // Otherwise the node could broadcast the two commitments that did not pay.
            it("asks a channel for the invoice unless every commitment another channel holds has already paid it", async () => {
                const { engine } = await opened();
                await addOtherChannel(engine);
                await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
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
                await engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING);
                await peerRevokes(engine, 11);
                await peerRevokes(engine, 11, other);
                // The first channel's remote commitment pays the invoice; its local one does not yet. Slot 13: the device's own took 12.
                const paid = customCommitmentRequest({
                    forRemote: true,
                    commitmentNumber: 12,
                    settlementLocalShannons: "64250000000",
                    tlcIds: [],
                });
                await engine.checkAndClaim(KEYS, signedRequest(paid.operation, 13));

                const dropped = customCommitmentRequest(
                    { forRemote: true, commitmentNumber: 12, settlementLocalShannons: OPENING_SETTLEMENT, tlcIds: [] },
                    other,
                );
                const refusal = await refusalOf(engine.checkAndClaim(OTHER_KEYS, signedRequest(dropped.operation, 13, other)));
                expect(refusal.message).toBe(
                    `the remote commitment lowers the holdings by ${RECEIVED_AMOUNT} shannons, which no offered TLC took`,
                );
            });

            it("signs one that pays for it, and records the credit", async () => {
                const { engine, store } = await holding();
                const { operation } = customCommitmentRequest({
                    forRemote: true,
                    commitmentNumber: 12,
                    settlementLocalShannons: "64250000000",
                    tlcIds: [],
                });
                await engine.checkAndClaim(KEYS, signedRequest(operation, 13));
                const record = await store.getChannelRecord(CHANNEL_INDEX);
                expect(record?.views.remote.creditedShannons).toEqual({ [RECEIVED_HASH.slice(0, 40)]: RECEIVED_AMOUNT });
            });
        });

        it("reads the two views alone on a record that carries an unknown key beside them", async () => {
            const { engine, store } = await opened();
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await holdReceived(engine);
            const record = await store.getChannelRecord(CHANNEL_INDEX);
            const views = { ...(record as ChannelPolicyRecord).views, futureView: "x" } as unknown as ChannelPolicyRecord["views"];
            await store.setChannelRecord(CHANNEL_INDEX, { ...(record as ChannelPolicyRecord), views });

            await peerRevokes(engine, 11);
            await engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING);
            await engine.closeDebitIntent(OFFERED_HASH);
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            // Slot 13: the device's own commitment took 12.
            const { operation } = customCommitmentRequest({
                forRemote: true,
                commitmentNumber: 12,
                settlementLocalShannons: "64250000000",
                tlcIds: [],
            });
            await expect(engine.checkAndClaim(KEYS, signedRequest(operation, 13))).resolves.toMatchObject({ status: "fresh" });
        });

        it("refuses a cooperative close that pays the device less than a view showed, past its fee", async () => {
            const { engine } = await registered(new InMemorySignerStorage(), "75000000000");
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, closingRequest("ckb")));
            expect(refusal.message).toBe(
                `the close pays the device ${CLOSE_LOCAL_CAPACITY} shannons, below the 75000000000 of the remote commitment by more than the 100000000 its fee may take`,
            );
        });

        // A crossing removal can leave one view lower; the close must pay the higher.
        it("refuses a close that pays what the remote view showed but not the local one", async () => {
            const { engine } = await opened();
            await engine.checkAndClaim(
                KEYS,
                customCommitmentRequest({ forRemote: false, commitmentNumber: 11, settlementLocalShannons: "64250000000", tlcIds: [] }),
            );
            const refusal = await refusalOf(
                engine.checkAndClaim(KEYS, closingRequest("ckb", { slot: { commitmentNumber: 12, counter: "local" } })),
            );
            expect(refusal.message).toBe(
                `the close pays the device ${CLOSE_LOCAL_CAPACITY} shannons, below the 74150000000 of the local commitment by more than the 100000000 its fee may take`,
            );
        });

        it("refuses a cooperative close while a view still lists TLCs", async () => {
            const { engine } = await opened();
            await recordThreeTlcIntents(engine);
            await engine.checkAndClaim(KEYS, threeTlcRequest());
            const refusal = await refusalOf(
                engine.checkAndClaim(KEYS, closingRequest("ckb", { slot: { commitmentNumber: 12, counter: "local" } })),
            );
            expect(refusal.message).toBe("a cooperative close while the remote commitment still lists TLCs");
        });

        it("signs a cooperative close that pays what both views showed, and moves no snapshot", async () => {
            const { engine, store } = await registered();
            await engine.checkAndClaim(KEYS, closingRequest("ckb"));
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                views: { remote: OPENING_VIEW, local: OPENING_VIEW },
            });
        });

        it.each([
            ["a revocation", revocationRequest("ckb, send side")],
            ["an announcement", announcementRequest("ckb")],
        ])("leaves the views untouched for %s", async (_, request) => {
            const { engine, store } = await registered();
            await engine.checkAndClaim(KEYS, await holdingReplacement(store, request));
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                views: { remote: OPENING_VIEW, local: OPENING_VIEW },
            });
        });
    });

    describe("the lock layout", () => {
        const FULL_HASH_OPENING = caseOf(digest.commitment_cases, "ckb, no tlcs, for remote, full payment hash");
        // The full-hash opening's settlement plus its local reserve, 1 CKB above the legacy channel's.
        const FUNDED_FULL_HASH = fundedShannonsOf(FULL_HASH_OPENING);
        const OPENED_FULL_HASH_PINS: ChannelPins = {
            ...OPENED_PINS,
            fundedShannons: FUNDED_FULL_HASH,
            fundingCapacityShannons: "96800000000",
            lockLayout: "fullPaymentHash",
        };
        const OPENING_FULL_HASH_VIEW = { exposureShannons: FUNDED_FULL_HASH, tlcs: [], chargedShannons: {}, creditedShannons: {} };
        const TWIN_OFFERED_HASH = OFFERED_HASH.slice(0, 40) + "00".repeat(12);
        const TWIN_RECEIVED_HASH = RECEIVED_HASH.slice(0, 40) + "00".repeat(12);

        function fullHashCommitment(): Extract<SignOperation, { kind: "commitment_tx" }>["input"] {
            return { ...toCommitmentTxInput(FULL_HASH_OPENING, digest.remote), commitmentNumber: 11 };
        }

        // The full-hash opening's channel with TLCs of the three-TLC full-hash case, some with their unbound bytes moved.
        function fullHashRequest(
            commitmentNumber: number,
            settlementLocalShannons: string,
            hashes: Record<number, string>,
        ): PolicySignRequest {
            const base = toCommitmentTxInput(FULL_HASH_OPENING, digest.remote);
            const tlcs = caseOf(digest.commitment_cases, "ckb, three tlcs, for remote, full payment hash")
                .tlcs.filter((tlc) => tlc.id in hashes)
                .map((tlc) => ({ ...toTlc(tlc), paymentHash: hexToBytes(hashes[tlc.id] as string) }));
            const settlementLocal = BigInt(settlementLocalShannons);
            const input = {
                ...base,
                commitmentNumber,
                settlementLocalShannons: settlementLocal,
                settlementRemoteShannons:
                    base.liquidCapacityShannons - settlementLocal - tlcs.reduce((sum, tlc) => sum + tlc.amountShannons, 0n),
                tlcs,
            };
            return signedRequest({ kind: "commitment_tx", input }, commitmentNumber);
        }

        async function registeredFullHash() {
            const context = newEngine();
            await context.engine.registerChannel(CHANNEL_ID, CHANNEL_INDEX, FUNDED_FULL_HASH, CLOSE_SCRIPT);
            await context.engine.pinChannelTerms(CHANNEL_ID, TERMS);
            return context;
        }

        // At the legacy opening's version, the remote view's first.
        async function openedFullHash() {
            const context = await registeredFullHash();
            const input = { ...fullHashCommitment(), commitmentNumber: 10 };
            await context.engine.checkAndClaim(KEYS, signedRequest({ kind: "commitment_tx", input }, 10));
            return context;
        }

        it("pins the layout at first sight, from the opening commitment, beside the reserve it states under it", async () => {
            const { engine, store } = await registeredFullHash();
            await expect(
                engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote, full payment hash")),
            ).resolves.toMatchObject({ status: "fresh", commitmentNumber: 0 });
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
                pins: OPENED_FULL_HASH_PINS,
                views: { remote: OPENING_FULL_HASH_VIEW, local: OPENING_FULL_HASH_VIEW },
            });
        });

        it.each([
            ["a commitment", () => signedRequest({ kind: "commitment_tx", input: ckbCommitment() }, 11)],
            ["a revocation", () => revocationRequest("ckb, send side")],
        ])("refuses %s under the legacy layout once the full hash is pinned, and moves nothing", async (_, request) => {
            const { engine, store, storage } = await openedFullHash();
            const held = await holdingReplacement(store, request());
            const stored = new Map(storage.map);
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, held));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe("the request states lockLayout legacy, but the channel pinned fullPaymentHash");
            expect(storage.map).toEqual(stored);
        });

        it.each([
            ["a commitment", () => signedRequest({ kind: "commitment_tx", input: fullHashCommitment() }, 11)],
            ["a revocation", () => revocationRequest("ckb, send side, full payment hash")],
        ])("refuses %s under the full hash once the legacy layout is pinned", async (_, request) => {
            const { engine, store, storage } = await opened();
            const held = await holdingReplacement(store, request());
            const stored = new Map(storage.map);
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, held));
            expect(refusal.message).toBe("the request states lockLayout fullPaymentHash, but the channel pinned legacy");
            expect(storage.map).toEqual(stored);
        });

        it("signs the revocation sized under the pinned layout, pinning nothing new", async () => {
            const { engine, store } = await openedFullHash();
            await expect(
                engine.checkAndClaim(KEYS, await holdingReplacement(store, revocationRequest("ckb, send side, full payment hash"))),
            ).resolves.toMatchObject({
                status: "fresh",
                context: "REVOKE",
            });
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ pins: OPENED_FULL_HASH_PINS });
        });

        it("pins the layout from a revocation when it comes first", async () => {
            const { engine, store } = await registeredFullHash();
            await engine.checkAndClaim(KEYS, await holdingReplacement(store, revocationRequest("ckb, send side, full payment hash")));
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ pins: { lockLayout: "fullPaymentHash" } });
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote")));
            expect(refusal.message).toBe("the request states lockLayout legacy, but the channel pinned fullPaymentHash");
        });

        // The reserve the layout computes: 100 CKB under the full hash over this close script, 99 under legacy.
        it("refuses an opening under the full hash with the legacy reserve, 1 CKB short, writing nothing", async () => {
            const { engine, storage } = await registeredFullHash();
            const stored = new Map(storage.map);
            const input = { ...fullHashCommitment(), commitmentNumber: 0, localReservedCkbShannons: 9_900_000_000n };
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, signedRequest({ kind: "commitment_tx", input }, 0)));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe("the request states localReservedCkbShannons 9900000000, but the channel pinned 10000000000");
            expect(storage.map).toEqual(stored);
        });

        it("refuses an opening under legacy with the full-hash reserve, 1 CKB over, writing nothing", async () => {
            const { engine, storage } = await registered();
            const stored = new Map(storage.map);
            const input = { ...ckbCommitment(), commitmentNumber: 0, localReservedCkbShannons: 10_000_000_000n };
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, signedRequest({ kind: "commitment_tx", input }, 0)));
            expect(refusal.message).toBe("the request states localReservedCkbShannons 10000000000, but the channel pinned 9900000000");
            expect(storage.map).toEqual(stored);
        });

        // A close states no reserve and no layout, so either layout's channel takes it as it is.
        it("signs a close on a full-hash channel without reading its layout", async () => {
            const { engine, store } = await openedFullHash();
            const input = { ...ckbClose(), localCapacityShannons: 71_900_000_000n };
            await expect(engine.checkAndClaim(KEYS, signedRequest({ kind: "closing_tx", input }, 11))).resolves.toMatchObject({
                status: "fresh",
            });
            await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ pins: OPENED_FULL_HASH_PINS });
        });

        it("signs a commitment under the full hash and keeps the whole hashes in its view", async () => {
            const { engine, store } = await openedFullHash();
            await recordThreeTlcIntents(engine);
            const request = fullHashRequest(11, THREE_TLC_SETTLEMENT, {
                [OFFERED_TLC_ID]: OFFERED_HASH,
                [OTHER_OFFERED_TLC_ID]: OTHER_OFFERED_HASH,
                [RECEIVED_TLC_ID]: RECEIVED_HASH,
            });
            await expect(engine.checkAndClaim(KEYS, request)).resolves.toMatchObject({ status: "fresh" });
            const record = await store.getChannelRecord(CHANNEL_INDEX);
            expect(record?.views.remote).toEqual({
                exposureShannons: "69750000000",
                tlcs: [
                    {
                        direction: "offered",
                        hashAlgorithm: "ckb-hash",
                        boundPaymentHash: OFFERED_HASH.slice(0, 40),
                        fullPaymentHash: OFFERED_HASH,
                        amountShannons: OFFERED_AMOUNT,
                        expirySeconds: "1723257890",
                    },
                    {
                        direction: "offered",
                        hashAlgorithm: "sha256",
                        boundPaymentHash: OTHER_OFFERED_HASH.slice(0, 40),
                        fullPaymentHash: OTHER_OFFERED_HASH,
                        amountShannons: OTHER_OFFERED_AMOUNT,
                        expirySeconds: "1699999999",
                    },
                    {
                        direction: "received",
                        hashAlgorithm: "sha256",
                        boundPaymentHash: RECEIVED_HASH.slice(0, 40),
                        fullPaymentHash: RECEIVED_HASH,
                        amountShannons: RECEIVED_AMOUNT,
                        expirySeconds: "1750000000",
                    },
                ],
                chargedShannons: {},
                creditedShannons: {},
            });
        });

        it("refuses an offered TLC under a twin of its intent's hash, through a real request, writing nothing", async () => {
            const { engine, store, storage } = await openedFullHash();
            await recordThreeTlcIntents(engine);
            const stored = new Map(storage.map);
            const request = fullHashRequest(11, THREE_TLC_SETTLEMENT, {
                [OFFERED_TLC_ID]: TWIN_OFFERED_HASH,
                [OTHER_OFFERED_TLC_ID]: OTHER_OFFERED_HASH,
                [RECEIVED_TLC_ID]: RECEIVED_HASH,
            });
            const refusal = await refusalOf(engine.checkAndClaim(KEYS, request));
            expect(refusal.code).toBe("policy_refusal");
            expect(refusal.message).toBe(
                `the remote commitment offers a TLC under ${TWIN_OFFERED_HASH}, not the ${OFFERED_HASH} the debit intent under its bound hash names`,
            );
            expect(storage.map).toEqual(stored);
            await expect(store.getDebitIntent(OFFERED_HASH.slice(0, 40))).resolves.toMatchObject({ channelIndexes: [] });
        });

        // The twin is not the invoice's, so it holds nothing back; the invoice's own TLC would.
        it("releases a preimage while a channel lists a twin of the invoice beside an offered TLC", async () => {
            const { engine, store } = await openedFullHash();
            await addOtherChannel(engine);
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await engine.checkAndClaim(
                KEYS,
                fullHashRequest(11, "60500000000", { [OFFERED_TLC_ID]: OFFERED_HASH, [RECEIVED_TLC_ID]: TWIN_RECEIVED_HASH }),
            );
            await holdReceived(engine, OTHER_CHANNEL);
            await engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING);
            await expect(store.getHoldInvoiceRecord(RECEIVED_HASH.slice(0, 40))).resolves.toMatchObject({
                released: true,
                channelIndexes: [CHANNEL_INDEX, OTHER_CHANNEL_INDEX],
            });
        });

        it("holds a preimage back while a channel lists the invoice's own TLC, bound whole, beside an offered TLC", async () => {
            const { engine } = await openedFullHash();
            await engine.recordDebitIntent(OFFERED_HASH, OFFERED_AMOUNT);
            await engine.recordHoldInvoice(RECEIVED_HASH, RECEIVED_AMOUNT, "sha256", INVOICE_INDEX);
            await engine.checkAndClaim(
                KEYS,
                fullHashRequest(11, "60500000000", { [OFFERED_TLC_ID]: OFFERED_HASH, [RECEIVED_TLC_ID]: RECEIVED_HASH }),
            );
            await expect(engine.markHoldInvoiceReleased(RECEIVED_HASH, RELEASE_TIMING)).rejects.toMatchObject({
                code: "offered_in_flight",
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

const WATCHTOWER_APPROVAL: WatchtowerApproval = {
    destination: {
        codeHash: hexToBytes("9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"),
        hashType: "type",
        args: hexToBytes("b502c4a25f89b69ac44329eed55950843ab24495"),
    },
    maxFeeShannons: "100000",
};
// The funding lock's, which the commitment the peer broadcasts carries and no signature covers.
const BROADCAST_CELL_DEPS: CellDep[] = [
    { outPoint: { txHash: hexToBytes("202d47719dbcca8c60da1b133bbe23b5b4a1b350d985b0ff611a48a3b5de193c"), index: 6 }, depType: "code" },
    { outPoint: { txHash: hexToBytes("202d47719dbcca8c60da1b133bbe23b5b4a1b350d985b0ff611a48a3b5de193c"), index: 5 }, depType: "code" },
];

describe("the watchtower option", () => {
    const { destination } = WATCHTOWER_APPROVAL;

    it("takes an approval, and none", () => {
        expect(() => newEngine(undefined, { watchtower: WATCHTOWER_APPROVAL })).not.toThrow();
        expect(() => newEngine(undefined, { watchtower: undefined })).not.toThrow();
    });

    it("takes a fee of zero", () => {
        expect(() => newEngine(undefined, { watchtower: { ...WATCHTOWER_APPROVAL, maxFeeShannons: "0" } })).not.toThrow();
    });

    it("takes a fee at u64's maximum", () => {
        expect(() =>
            newEngine(undefined, { watchtower: { ...WATCHTOWER_APPROVAL, maxFeeShannons: "18446744073709551615" } }),
        ).not.toThrow();
    });

    it.each<[string, unknown, Error]>([
        ["a null approval", null, new TypeError("options.watchtower must be an object")],
        ["an approval that is an array", [], new TypeError("options.watchtower must be an object")],
        [
            "no destination",
            { ...WATCHTOWER_APPROVAL, destination: undefined },
            new TypeError("options.watchtower.destination must be an object"),
        ],
        [
            "a destination with a short code hash",
            { ...WATCHTOWER_APPROVAL, destination: { ...destination, codeHash: new Uint8Array(31) } },
            new TypeError("options.watchtower.destination.codeHash must be 32 bytes, got 31"),
        ],
        [
            "a destination of an unknown hash type",
            { ...WATCHTOWER_APPROVAL, destination: { ...destination, hashType: "data3" } },
            new TypeError("options.watchtower.destination.hashType must be one of data, type, data1, data2"),
        ],
        [
            "a destination without args",
            { ...WATCHTOWER_APPROVAL, destination: { ...destination, args: undefined } },
            new TypeError("options.watchtower.destination.args must be a Uint8Array"),
        ],
        [
            "no fee",
            { ...WATCHTOWER_APPROVAL, maxFeeShannons: undefined },
            new TypeError("options.watchtower.maxFeeShannons must be a string"),
        ],
        [
            "a numeric fee",
            { ...WATCHTOWER_APPROVAL, maxFeeShannons: 100000 },
            new TypeError("options.watchtower.maxFeeShannons must be a string"),
        ],
        [
            "a fee in hex",
            { ...WATCHTOWER_APPROVAL, maxFeeShannons: "0x1" },
            new TypeError("options.watchtower.maxFeeShannons must be an amount in decimal shannons"),
        ],
        [
            "a fee above u64",
            { ...WATCHTOWER_APPROVAL, maxFeeShannons: "18446744073709551616" },
            new RangeError("options.watchtower.maxFeeShannons must be at most 18446744073709551615, the most a CKB cell's capacity holds"),
        ],
    ])("refuses %s", (_, watchtower, error) => {
        expect(() => newEngine(undefined, { watchtower: watchtower as never })).toThrow(error);
    });

    it("keeps a copy, so the host changing its object later changes nothing", async () => {
        const watchtower = structuredClone(WATCHTOWER_APPROVAL);
        const { engine } = await registeredEngine(undefined, { watchtower });
        await engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote"));
        watchtower.destination.args.fill(0);
        watchtower.destination.codeHash.fill(0);
        await expect(engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, ownSettlementSpend())).resolves.toEqual({ status: "fresh" });
    });
});

const SPEND_REQUEST_ID = hexToBytes("cc".repeat(32));
const WATCHTOWER_SIGNATURE = Uint8Array.from({ length: 65 }, (_, index) => index);

// The device's balance in "ckb, no tlcs, for remote", settled from the cell the peer broadcast.
function ownSettlementSpend(): WatchtowerSpendRequest {
    const kase = caseOf(digest.commitment_cases, "ckb, no tlcs, for remote");
    const commitment = toTransaction(kase.transaction);
    const onchainHash = computeTxHash({ ...commitment, cellDeps: BROADCAST_CELL_DEPS });
    const [cell] = commitment.outputs;
    if (cell === undefined) throw new Error("the commitment has no output");
    const nextBody = hexToBytes(NO_TLC_REMOTE_WITNESS.slice(0, -72) + "00".repeat(36));
    return {
        requestId: SPEND_REQUEST_ID,
        purpose: { kind: "settlement" },
        transaction: {
            version: 0,
            cellDeps: [],
            headerDeps: [],
            inputs: [{ since: 0xa000010000000001n, previousOutput: { txHash: onchainHash, index: 0 } }],
            outputs: [
                {
                    capacityShannons: 24799999544n,
                    lock: { ...cell.lock, args: buildRemainderLockArgs(cell.lock.args, nextBody) },
                    type: null,
                },
                { capacityShannons: 71899900000n, lock: WATCHTOWER_APPROVAL.destination, type: null },
            ],
            outputsData: [new Uint8Array(0), new Uint8Array(0)],
            witnesses: [hexToBytes(`1000000010000000100000001000000001${NO_TLC_REMOTE_WITNESS}ff00${"00".repeat(65)}`)],
        },
    };
}

async function watchtowerEngine(options: PolicyEngineOptions = { watchtower: WATCHTOWER_APPROVAL }) {
    const context = await registeredEngine(undefined, options);
    await context.engine.checkAndClaim(KEYS, commitmentRequest("ckb, no tlcs, for remote"));
    return context;
}

describe("checkWatchtowerSpend", () => {
    it("claims the spend of the commitment cell the device signed, before anything is signed", async () => {
        const { engine, store } = await watchtowerEngine();
        const request = ownSettlementSpend();
        await expect(engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, request)).resolves.toEqual({ status: "fresh" });
        const [remainder] = request.transaction.outputs as [CellOutput];
        expect((await store.getChannelRecord(CHANNEL_INDEX))?.watchtowerSpends).toEqual([
            {
                requestId: "cc".repeat(32),
                purpose: { kind: "settlement" },
                view: "remote",
                commitmentNumber: 0,
                tlcEntry: null,
                txHash: bytesToHex(computeTxHash(request.transaction)),
                remainder: {
                    output: bytesToHex(moleculeCellOutput(remainder.capacityShannons, remainder.lock, remainder.type)),
                    outputData: "",
                },
                signature: null,
                applied: false,
            },
        ]);
    });

    it("serves a repeat, with no signature until the signer records one, and with it after", async () => {
        const { engine } = await watchtowerEngine();
        await engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, ownSettlementSpend());
        await expect(engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, ownSettlementSpend())).resolves.toEqual({
            status: "already-signed",
            signature: null,
        });
        await engine.recordWatchtowerSignature(CHANNEL_ID, SPEND_REQUEST_ID, WATCHTOWER_SIGNATURE);
        await expect(engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, ownSettlementSpend())).resolves.toEqual({
            status: "already-signed",
            signature: WATCHTOWER_SIGNATURE,
        });
    });

    it("refuses every spend when the host approved none, before reading the channel", async () => {
        const { engine } = newEngine();
        const refusal = await refusalOf(engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, ownSettlementSpend()));
        expect(refusal.code).toBe("policy_refusal");
        expect(refusal.message).toBe("watchtower option: the host approved no destination, so the device signs no watchtower spend");
    });

    it("refuses an empty channel id as malformed", async () => {
        const { engine } = await watchtowerEngine();
        const refusal = await refusalOf(engine.checkWatchtowerSpend(KEYS, "", ownSettlementSpend()));
        expect(refusal.code).toBe("malformed");
        expect(refusal.message).toBe("TypeError: channelId must be a non-empty string");
    });

    it("refuses a channel this device never registered", async () => {
        const { engine } = newEngine(undefined, { watchtower: WATCHTOWER_APPROVAL });
        expect((await refusalOf(engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, ownSettlementSpend()))).code).toBe("unknown_channel");
    });

    it("writes nothing on a refusal", async () => {
        const { engine, storage } = await watchtowerEngine();
        const stored = new Map(storage.map);
        const request = ownSettlementSpend();
        const paid = {
            ...request,
            transaction: { ...request.transaction, outputs: request.transaction.outputs.slice(0, 1), outputsData: [new Uint8Array(0)] },
        };
        expect((await refusalOf(engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, paid))).code).toBe("policy_refusal");
        expect(storage.map).toEqual(stored);
    });

    it("throws when the name resolves to an index that holds no record", async () => {
        const { engine, storage } = await watchtowerEngine();
        storage.map.delete(`fiber-lsp-sdk:channel:${CHANNEL_INDEX}`);
        await expect(engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, ownSettlementSpend())).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} resolves to channel index ${CHANNEL_INDEX}, which holds no record`),
        );
    });
});

describe("recordWatchtowerSignature", () => {
    it("records the signature on the claimed spend, once", async () => {
        const { engine, store, storage } = await watchtowerEngine();
        await engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, ownSettlementSpend());
        await engine.recordWatchtowerSignature(CHANNEL_ID, SPEND_REQUEST_ID, WATCHTOWER_SIGNATURE);
        expect((await store.getChannelRecord(CHANNEL_INDEX))?.watchtowerSpends?.[0]?.signature).toBe(bytesToHex(WATCHTOWER_SIGNATURE));

        const stored = new Map(storage.map);
        await engine.recordWatchtowerSignature(CHANNEL_ID, SPEND_REQUEST_ID, WATCHTOWER_SIGNATURE);
        expect(storage.map).toEqual(stored);
    });

    it("keeps the other spends as they are", async () => {
        const { engine, store } = await watchtowerEngine();
        // A TLC's spend of the same commitment.
        const tlcSpend: WatchtowerSpendRecord = {
            requestId: "dd".repeat(32),
            purpose: { kind: "tlc", commitmentNumber: 6 },
            view: "remote",
            commitmentNumber: 0,
            tlcEntry: "ab".repeat(85),
            txHash: "5f".repeat(32),
            remainder: null,
            signature: null,
            applied: false,
        };
        await store.updateChannelRecord(CHANNEL_INDEX, (current) => {
            if (current === null) throw new Error("the channel holds no record");
            return { ...current, watchtowerSpends: [tlcSpend] };
        });
        await engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, ownSettlementSpend());
        await engine.recordWatchtowerSignature(CHANNEL_ID, SPEND_REQUEST_ID, WATCHTOWER_SIGNATURE);
        expect((await store.getChannelRecord(CHANNEL_INDEX))?.watchtowerSpends?.map((spend) => spend.signature)).toEqual([
            null,
            bytesToHex(WATCHTOWER_SIGNATURE),
        ]);
    });

    // Fiber asks again under a new request each time the spend it rebuilds changes.
    it("throws on a request another one replaced, for the same commitment and unlock", async () => {
        const { engine } = await watchtowerEngine();
        await engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, ownSettlementSpend());
        await engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, { ...ownSettlementSpend(), requestId: hexToBytes("dd".repeat(32)) });
        await expect(engine.recordWatchtowerSignature(CHANNEL_ID, SPEND_REQUEST_ID, WATCHTOWER_SIGNATURE)).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} never claimed the watchtower request ${"cc".repeat(32)}`),
        );
    });

    it("throws on another signature for the same spend: the signature is deterministic", async () => {
        const { engine } = await watchtowerEngine();
        await engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, ownSettlementSpend());
        await engine.recordWatchtowerSignature(CHANNEL_ID, SPEND_REQUEST_ID, WATCHTOWER_SIGNATURE);
        await expect(engine.recordWatchtowerSignature(CHANNEL_ID, SPEND_REQUEST_ID, new Uint8Array(65))).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} already records another signature for the watchtower request ${"cc".repeat(32)}`),
        );
    });

    it("throws on a request the channel never claimed, with no spend or another one", async () => {
        const { engine } = await watchtowerEngine();
        const error = new TypeError(`channel ${CHANNEL_ID} never claimed the watchtower request ${"cc".repeat(32)}`);
        await expect(engine.recordWatchtowerSignature(CHANNEL_ID, SPEND_REQUEST_ID, WATCHTOWER_SIGNATURE)).rejects.toThrow(error);
        await engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, { ...ownSettlementSpend(), requestId: hexToBytes("dd".repeat(32)) });
        await expect(engine.recordWatchtowerSignature(CHANNEL_ID, SPEND_REQUEST_ID, WATCHTOWER_SIGNATURE)).rejects.toThrow(error);
    });

    it.each<[string, Uint8Array, Uint8Array, Error]>([
        ["a request id of 31 bytes", new Uint8Array(31), WATCHTOWER_SIGNATURE, new TypeError("requestId must be 32 bytes, got 31")],
        ["a compact signature", SPEND_REQUEST_ID, new Uint8Array(64), new TypeError("signature must be 65 bytes, got 64")],
    ])("throws on %s", async (_, requestId, signature, error) => {
        const { engine } = await watchtowerEngine();
        await expect(engine.recordWatchtowerSignature(CHANNEL_ID, requestId, signature)).rejects.toThrow(error);
    });

    it("throws when the name resolves to an index that holds no record", async () => {
        const { engine, storage } = await watchtowerEngine();
        storage.map.delete(`fiber-lsp-sdk:channel:${CHANNEL_INDEX}`);
        await expect(engine.recordWatchtowerSignature(CHANNEL_ID, SPEND_REQUEST_ID, WATCHTOWER_SIGNATURE)).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} resolves to channel index ${CHANNEL_INDEX}, which holds no record`),
        );
    });

    it("throws on a channel this device never registered", async () => {
        const { engine } = newEngine();
        await expect(engine.recordWatchtowerSignature(CHANNEL_ID, SPEND_REQUEST_ID, WATCHTOWER_SIGNATURE)).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} is not registered on this device`),
        );
    });
});

describe("markWatchtowerSpendApplied", () => {
    async function signedSpend() {
        const harness = await watchtowerEngine();
        await harness.engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, ownSettlementSpend());
        await harness.engine.recordWatchtowerSignature(CHANNEL_ID, SPEND_REQUEST_ID, WATCHTOWER_SIGNATURE);
        return harness;
    }

    it("marks the signed spend applied, once", async () => {
        const { engine, store, storage } = await signedSpend();
        await engine.markWatchtowerSpendApplied(CHANNEL_ID, SPEND_REQUEST_ID);
        const [spend] = (await store.getChannelRecord(CHANNEL_INDEX))?.watchtowerSpends ?? [];
        expect([spend?.applied, spend?.signature]).toEqual([true, bytesToHex(WATCHTOWER_SIGNATURE)]);

        const stored = new Map(storage.map);
        storage.ops.length = 0;
        await engine.markWatchtowerSpendApplied(CHANNEL_ID, SPEND_REQUEST_ID);
        expect(storage.map).toEqual(stored);
        expect(storage.ops.filter((op) => op.startsWith("set "))).toEqual([]);
    });

    it("keeps the other spends as they are", async () => {
        const { engine, store } = await signedSpend();
        const tlcSpend: WatchtowerSpendRecord = {
            requestId: "dd".repeat(32),
            purpose: { kind: "tlc", commitmentNumber: 6 },
            view: "remote",
            commitmentNumber: 0,
            tlcEntry: "ab".repeat(85),
            txHash: "5f".repeat(32),
            remainder: null,
            signature: "b4".repeat(65),
            applied: false,
        };
        await store.updateChannelRecord(CHANNEL_INDEX, (current) => {
            if (current === null) throw new Error("the channel holds no record");
            return { ...current, watchtowerSpends: [tlcSpend, ...(current.watchtowerSpends ?? [])] };
        });
        await engine.markWatchtowerSpendApplied(CHANNEL_ID, SPEND_REQUEST_ID);
        expect((await store.getChannelRecord(CHANNEL_INDEX))?.watchtowerSpends?.map((spend) => spend.applied)).toEqual([false, true]);
    });

    it("throws on a spend whose signature was never recorded", async () => {
        const { engine, storage } = await watchtowerEngine();
        await engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, ownSettlementSpend());
        const stored = new Map(storage.map);
        await expect(engine.markWatchtowerSpendApplied(CHANNEL_ID, SPEND_REQUEST_ID)).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} records no signature for the watchtower request ${"cc".repeat(32)}`),
        );
        expect(storage.map).toEqual(stored);
    });

    it("throws on a request the channel never claimed, with no spend or another one", async () => {
        const { engine } = await watchtowerEngine();
        const error = new TypeError(`channel ${CHANNEL_ID} never claimed the watchtower request ${"cc".repeat(32)}`);
        await expect(engine.markWatchtowerSpendApplied(CHANNEL_ID, SPEND_REQUEST_ID)).rejects.toThrow(error);
        await engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, { ...ownSettlementSpend(), requestId: hexToBytes("dd".repeat(32)) });
        await expect(engine.markWatchtowerSpendApplied(CHANNEL_ID, SPEND_REQUEST_ID)).rejects.toThrow(error);
    });

    // The signed spend stays the record's: a later request for its unlock goes unclaimed.
    it("throws on a request served after the spend of its unlock was signed", async () => {
        const { engine } = await signedSpend();
        const later = { ...ownSettlementSpend(), requestId: hexToBytes("dd".repeat(32)) };
        await expect(engine.checkWatchtowerSpend(KEYS, CHANNEL_ID, later)).resolves.toEqual({ status: "unclaimed" });
        await expect(engine.markWatchtowerSpendApplied(CHANNEL_ID, later.requestId)).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} never claimed the watchtower request ${"dd".repeat(32)}`),
        );
    });

    it("throws on a request id of 31 bytes", async () => {
        const { engine } = await signedSpend();
        await expect(engine.markWatchtowerSpendApplied(CHANNEL_ID, new Uint8Array(31))).rejects.toThrow(
            new TypeError("requestId must be 32 bytes, got 31"),
        );
    });

    it("throws when the name resolves to an index that holds no record", async () => {
        const { engine, storage } = await signedSpend();
        storage.map.delete(`fiber-lsp-sdk:channel:${CHANNEL_INDEX}`);
        await expect(engine.markWatchtowerSpendApplied(CHANNEL_ID, SPEND_REQUEST_ID)).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} resolves to channel index ${CHANNEL_INDEX}, which holds no record`),
        );
    });

    it("throws on a channel this device never registered", async () => {
        const { engine } = newEngine();
        await expect(engine.markWatchtowerSpendApplied(CHANNEL_ID, SPEND_REQUEST_ID)).rejects.toThrow(
            new TypeError(`channel ${CHANNEL_ID} is not registered on this device`),
        );
    });
});
