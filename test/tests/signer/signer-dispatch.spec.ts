import { schnorr } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { Session, keyAggExport, keyAggregate, nonceAggregate, nonceGen } from "@scure/btc-signer/musig2.js";
import type { NonceContext } from "../../../src/derivation";
import {
    deriveChannelKeys,
    deriveChannelSeed,
    deriveNonceSeed,
    deriveTlcKey,
    deriveWalletIdentityKey,
    pubkeyOf,
} from "../../../src/derivation";
import { COMMITMENT_LOCK_MAINNET, COMMITMENT_LOCK_TESTNET } from "../../../src/digest";
import type { ISignerStorage } from "../../../src/policy";
import {
    ANNOUNCEMENT_SLOT_NUMBER,
    CHANNEL_ALIAS_KEY_PREFIX,
    CHANNEL_RECORD_KEY_PREFIX,
    PolicyEngine,
    PolicyRefusalError,
    SignerStore,
} from "../../../src/policy";
import type { SignError, SignRequest, SignResult, SignatureMethod, SignerMethod } from "../../../src/protocol";
import { ProtocolError, SIGNER_METHODS, decodeSignParams } from "../../../src/protocol";
import type { DispatchOutcome, PendingChannelRegistration } from "../../../src/signer";
import { SignerDispatch, getBasePublicKeys, getChannelCommitmentPoint, getPublicNonce } from "../../../src/signer";
import { InMemorySignerStorage } from "../../mocks/policy";
import type { CommitmentCaseVector } from "../../utils/interop-vectors";
import { caseOf, loadInteropVectors } from "../../utils/interop-vectors";
import { SHUTDOWN_NONCE_NUMBER, revocationNonceNumber } from "../../utils/nonce-numbers";
import { standInAggregatedNonce } from "../../utils/stand-in-nonce";
import {
    toCommitmentNumberParamsWire,
    toPartialSignChannelAnnouncementParamsWire,
    toPartialSignClosingTxParamsWire,
    toPartialSignCommitmentTxParamsWire,
    toPartialSignRevocationParamsWire,
    toSignSessionWire,
} from "../../utils/wire-requests";
import { withField } from "../../utils/with-field";

const vectors = loadInteropVectors();
const digest = vectors.digest;
const REMOTE = digest.remote;
const MASTER_SEED = hexToBytes(vectors.sdk_scheme.master_seed);
const CHANNEL_INDEX = vectors.sdk_scheme.channel.channel_index;
const OTHER_CHANNEL_INDEX = CHANNEL_INDEX + 1;
const KEYS = deriveChannelKeys(hexToBytes(vectors.sdk_scheme.channel.seed));
const LOCAL_FUNDING_PUBKEY = pubkeyOf(KEYS.fundingKey);
const OTHER_KEYS = deriveChannelKeys(deriveChannelSeed(MASTER_SEED, OTHER_CHANNEL_INDEX));
const REMOTE_KEYS = deriveChannelKeys(hexToBytes(REMOTE.seed));
const REMOTE_FUNDING_PUBKEY = hexToBytes(REMOTE.funding_pubkey);
const PEER_NONCE_RAND = new Uint8Array(32).fill(0x07);

const CHANNEL_ID = `0x${"1f".repeat(32)}`;
const OTHER_CHANNEL_ID = `0x${"2e".repeat(32)}`;
const REQUEST_ID = "0x2a";
const STATE_VERSION = 7;

const NO_TLCS = caseOf(digest.commitment_cases, "ckb, no tlcs, for remote");
const THREE_TLCS = caseOf(digest.commitment_cases, "ckb, three tlcs, for remote");
const THREE_TLCS_FOR_LOCAL = caseOf(digest.commitment_cases, "ckb, three tlcs, for local");
const CKB_SHUTDOWN = caseOf(digest.shutdown_cases, "ckb");
const SEND_SIDE_REVOCATION = caseOf(digest.revocation_cases, "ckb, send side");
const CKB_ANNOUNCEMENT = caseOf(digest.announcement_cases, "ckb");

const REVOCATION_NONCE_NUMBER = revocationNonceNumber(SEND_SIDE_REVOCATION);

const OPENING_EXPOSURE = "62000000000";
const TLC_DECREASE = "2250000000";

// Fiber sorts the keys of a funding spend and the announcement (local first here), and a send-side revocation puts remote first.
const ORDERED_PUBLIC_KEYS: Record<SignatureMethod, [Uint8Array, Uint8Array]> = {
    partial_sign_commitment_tx: [LOCAL_FUNDING_PUBKEY, REMOTE_FUNDING_PUBKEY],
    partial_sign_closing_tx: [LOCAL_FUNDING_PUBKEY, REMOTE_FUNDING_PUBKEY],
    partial_sign_revocation: [REMOTE_FUNDING_PUBKEY, LOCAL_FUNDING_PUBKEY],
    partial_sign_channel_announcement: [LOCAL_FUNDING_PUBKEY, REMOTE_FUNDING_PUBKEY],
};

const AGGREGATED_NONCE = standInAggregatedNonce(0x01);
const OTHER_AGGREGATED_NONCE = standInAggregatedNonce(0x02);

type SigningCase = {
    method: SignatureMethod;
    published: SignerMethod;
    nonceNumber: number | undefined;
    context: NonceContext;
    digest: string;
};

const SIGNING_CASES: SigningCase[] = [
    {
        method: "partial_sign_commitment_tx",
        published: "get_commitment_pub_nonce",
        nonceNumber: THREE_TLCS.commitment_number,
        context: "COMMITMENT",
        digest: THREE_TLCS.digest,
    },
    {
        method: "partial_sign_closing_tx",
        published: "get_commitment_pub_nonce",
        nonceNumber: SHUTDOWN_NONCE_NUMBER,
        context: "COMMITMENT",
        digest: CKB_SHUTDOWN.digest,
    },
    {
        method: "partial_sign_revocation",
        published: "get_revocation_pub_nonce",
        nonceNumber: REVOCATION_NONCE_NUMBER,
        context: "REVOKE",
        digest: SEND_SIDE_REVOCATION.digest,
    },
    {
        method: "partial_sign_channel_announcement",
        published: "get_channel_announcement_pub_nonce",
        nonceNumber: undefined,
        context: "ANNOUNCEMENT",
        digest: CKB_ANNOUNCEMENT.digest,
    },
];

// Regenerated per use: scure zeroes a secret nonce buffer once it signs.
function peerNonces() {
    return nonceGen(REMOTE_FUNDING_PUBKEY, REMOTE_KEYS.fundingKey, undefined, undefined, undefined, PEER_NONCE_RAND);
}

function sessionWire(method: SignatureMethod, aggregatedNonce: Uint8Array, messageHex: string) {
    const [firstKey, secondKey] = ORDERED_PUBLIC_KEYS[method];
    return toSignSessionWire([bytesToHex(firstKey), bytesToHex(secondKey)], bytesToHex(aggregatedNonce), messageHex);
}

function commitmentParams(kase: CommitmentCaseVector, aggregatedNonce: Uint8Array): Record<string, unknown> {
    const session = sessionWire("partial_sign_commitment_tx", aggregatedNonce, kase.digest);
    return toPartialSignCommitmentTxParamsWire(kase, REMOTE, session, kase.commitment_number);
}

function signingParams(method: SignatureMethod, aggregatedNonce: Uint8Array): Record<string, unknown> {
    switch (method) {
        case "partial_sign_commitment_tx":
            return commitmentParams(THREE_TLCS, aggregatedNonce);
        case "partial_sign_closing_tx": {
            const session = sessionWire(method, aggregatedNonce, CKB_SHUTDOWN.digest);
            return toPartialSignClosingTxParamsWire(CKB_SHUTDOWN, REMOTE, session, SHUTDOWN_NONCE_NUMBER);
        }
        case "partial_sign_revocation": {
            const session = sessionWire(method, aggregatedNonce, SEND_SIDE_REVOCATION.digest);
            return toPartialSignRevocationParamsWire(SEND_SIDE_REVOCATION, REMOTE, session, REVOCATION_NONCE_NUMBER);
        }
        case "partial_sign_channel_announcement": {
            const session = sessionWire(method, aggregatedNonce, CKB_ANNOUNCEMENT.digest);
            return toPartialSignChannelAnnouncementParamsWire(CKB_ANNOUNCEMENT, REMOTE, session);
        }
    }
}

function paramsFor(method: SignerMethod): Record<string, unknown> {
    switch (method) {
        case "get_base_public_keys":
        case "get_channel_announcement_pub_nonce":
            return {};
        case "get_commitment_point":
        case "get_commitment_pub_nonce":
        case "get_revocation_pub_nonce":
        case "get_settlement_keys":
            return { commitment_number: "0x5" };
        default:
            return signingParams(method, AGGREGATED_NONCE);
    }
}

function request(method: SignerMethod, params: Record<string, unknown>, overrides: Partial<SignRequest> = {}): SignRequest {
    return { requestId: REQUEST_ID, channelId: CHANNEL_ID, method, params, stateVersion: STATE_VERSION, ...overrides };
}

type Harness = { dispatch: SignerDispatch; policy: PolicyEngine; store: SignerStore; storage: InMemorySignerStorage };

function newDispatch(commitmentLock = COMMITMENT_LOCK_TESTNET, storage = new InMemorySignerStorage()): Harness {
    const store = new SignerStore(storage);
    const policy = new PolicyEngine(store);
    return { dispatch: new SignerDispatch({ masterSeed: MASTER_SEED, commitmentLock, policy }), policy, store, storage };
}

async function registered(localExposureShannons = "0", commitmentLock = COMMITMENT_LOCK_TESTNET): Promise<Harness> {
    const harness = newDispatch(commitmentLock);
    await harness.dispatch.channelRegistered(CHANNEL_ID, harness.dispatch.prepareChannelRegistration(CHANNEL_INDEX, localExposureShannons));
    return harness;
}

function resultOf(outcome: DispatchOutcome): SignResult {
    if (outcome.kind !== "result") throw new Error(`expected a result, got ${JSON.stringify(outcome)}`);
    return outcome.result;
}

function refusalOf(outcome: DispatchOutcome): SignError {
    if (outcome.kind !== "refusal") throw new Error(`expected a refusal, got ${JSON.stringify(outcome)}`);
    return outcome.error;
}

function faultOf(outcome: DispatchOutcome): unknown {
    if (outcome.kind !== "fault") throw new Error(`expected a fault, got ${JSON.stringify(outcome)}`);
    return outcome.cause;
}

function pubNonceOf(outcome: DispatchOutcome): Uint8Array {
    const result = resultOf(outcome);
    if (result.kind !== "pub_nonce") throw new Error(`expected a public nonce, got ${result.kind}`);
    return result.pubNonce;
}

function partialSignatureOf(outcome: DispatchOutcome): Uint8Array {
    const result = resultOf(outcome);
    if (result.kind !== "partial_signature") throw new Error(`expected a partial signature, got ${result.kind}`);
    return result.partialSignature;
}

function writes(storage: InMemorySignerStorage): string[] {
    return storage.ops.filter((op) => op.startsWith("set "));
}

describe("constructor", () => {
    it.each([31, 33])("rejects a master seed of %i bytes", (length) => {
        const { policy } = newDispatch();
        expect(() => new SignerDispatch({ masterSeed: new Uint8Array(length), commitmentLock: COMMITMENT_LOCK_TESTNET, policy })).toThrow(
            TypeError,
        );
    });

    it("keeps its own copy of the seed, so the host may discard its buffer", () => {
        const { policy } = newDispatch();
        const seed = Uint8Array.from(MASTER_SEED);
        const dispatch = new SignerDispatch({ masterSeed: seed, commitmentLock: COMMITMENT_LOCK_TESTNET, policy });
        seed.fill(0);
        expect(dispatch.prepareChannelRegistration(CHANNEL_INDEX, "0").registration.fundingPubkey).toEqual(LOCAL_FUNDING_PUBKEY);
    });

    it("re-derives the same channel on a fresh instance over the same storage", async () => {
        const first = await registered();
        const second = new SignerDispatch({
            masterSeed: Uint8Array.from(MASTER_SEED),
            commitmentLock: COMMITMENT_LOCK_TESTNET,
            policy: first.policy,
        });
        const envelope = request("get_base_public_keys", {});
        await expect(second.handle(envelope)).resolves.toEqual(await first.dispatch.handle(envelope));
    });
});

describe("prepareChannelRegistration", () => {
    it("derives the base public keys and the delegated settlement key of the index", () => {
        const { dispatch } = newDispatch();
        expect(dispatch.prepareChannelRegistration(CHANNEL_INDEX, OPENING_EXPOSURE)).toEqual<PendingChannelRegistration>({
            channelIndex: CHANNEL_INDEX,
            localExposureShannons: OPENING_EXPOSURE,
            registration: {
                fundingPubkey: LOCAL_FUNDING_PUBKEY,
                tlcBasePubkey: pubkeyOf(KEYS.tlcBaseKey),
                localSettlementKey: KEYS.tlcBaseKey,
            },
        });
    });

    it("never hands out the funding key", () => {
        const { registration } = newDispatch().dispatch.prepareChannelRegistration(CHANNEL_INDEX, OPENING_EXPOSURE);
        for (const value of Object.values(registration)) expect(bytesToHex(value)).not.toBe(bytesToHex(KEYS.fundingKey));
    });

    it("derives the channel of any index, and keeps that index", () => {
        const { dispatch } = newDispatch();
        expect(dispatch.prepareChannelRegistration(OTHER_CHANNEL_INDEX, "0")).toEqual<PendingChannelRegistration>({
            channelIndex: OTHER_CHANNEL_INDEX,
            localExposureShannons: "0",
            registration: { ...getBasePublicKeys(OTHER_KEYS), localSettlementKey: OTHER_KEYS.tlcBaseKey },
        });
    });

    it.each(["", "01", "1.5", "-1", "1e3", "abc"])("rejects the exposure %p at preparation, ahead of any round trip", (exposure) => {
        expect(() => newDispatch().dispatch.prepareChannelRegistration(CHANNEL_INDEX, exposure)).toThrow(TypeError);
    });

    it.each([-1, 1.5, Number.MAX_SAFE_INTEGER + 1])("rejects the channel index %p", (channelIndex) => {
        expect(() => newDispatch().dispatch.prepareChannelRegistration(channelIndex, "0")).toThrow(RangeError);
    });
});

describe("channelRegistered", () => {
    it("files the channel under the node's name with the exposure prepared, after which its requests resolve", async () => {
        const { dispatch, store } = newDispatch();
        await expect(dispatch.handle(request("get_base_public_keys", {}))).resolves.toMatchObject({ kind: "refusal" });

        await dispatch.channelRegistered(CHANNEL_ID, dispatch.prepareChannelRegistration(CHANNEL_INDEX, OPENING_EXPOSURE));

        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
            channelId: CHANNEL_ID,
            localExposureShannons: OPENING_EXPOSURE,
            signedSessions: {},
        });
        await expect(dispatch.handle(request("get_base_public_keys", {}))).resolves.toEqual({
            kind: "result",
            result: { kind: "base_public_keys", ...getBasePublicKeys(KEYS) },
        });
    });

    it("propagates a host error, such as naming a record that has already served", async () => {
        const { dispatch } = await registered();
        partialSignatureOf(await dispatch.handle(request("partial_sign_commitment_tx", paramsFor("partial_sign_commitment_tx"))));

        await expect(dispatch.channelRegistered(OTHER_CHANNEL_ID, dispatch.prepareChannelRegistration(CHANNEL_INDEX, "0"))).rejects.toThrow(
            TypeError,
        );
    });
});

describe("two channels on one dispatch", () => {
    // The other channel goes first, so neither a fixed index nor keys kept from the first derivation can pass.
    async function twoChannels(): Promise<Harness> {
        const harness = newDispatch();
        await harness.dispatch.channelRegistered(OTHER_CHANNEL_ID, harness.dispatch.prepareChannelRegistration(OTHER_CHANNEL_INDEX, "0"));
        await harness.dispatch.channelRegistered(CHANNEL_ID, harness.dispatch.prepareChannelRegistration(CHANNEL_INDEX, "0"));
        return harness;
    }

    it("files each channel under its own index", async () => {
        const { store } = await twoChannels();
        await expect(store.resolveChannelIndex(OTHER_CHANNEL_ID)).resolves.toBe(OTHER_CHANNEL_INDEX);
        await expect(store.resolveChannelIndex(CHANNEL_ID)).resolves.toBe(CHANNEL_INDEX);
        await expect(store.getChannelRecord(OTHER_CHANNEL_INDEX)).resolves.toMatchObject({ channelId: OTHER_CHANNEL_ID });
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ channelId: CHANNEL_ID });
    });

    it("answers each channel from its own keys, so the two never share a nonce", async () => {
        const { dispatch } = await twoChannels();
        const params = { commitment_number: "0x5" };

        await expect(dispatch.handle(request("get_base_public_keys", {}, { channelId: OTHER_CHANNEL_ID }))).resolves.toEqual({
            kind: "result",
            result: { kind: "base_public_keys", ...getBasePublicKeys(OTHER_KEYS) },
        });
        const otherNonce = pubNonceOf(await dispatch.handle(request("get_commitment_pub_nonce", params, { channelId: OTHER_CHANNEL_ID })));
        const nonce = pubNonceOf(await dispatch.handle(request("get_commitment_pub_nonce", params)));

        expect(otherNonce).toEqual(getPublicNonce(OTHER_KEYS, 5, "COMMITMENT"));
        expect(nonce).toEqual(getPublicNonce(KEYS, 5, "COMMITMENT"));
        expect(bytesToHex(otherNonce)).not.toBe(bytesToHex(nonce));
    });
});

describe("the public data methods", () => {
    it("answers the base public keys", async () => {
        const { dispatch } = await registered();
        await expect(dispatch.handle(request("get_base_public_keys", {}))).resolves.toEqual({
            kind: "result",
            result: { kind: "base_public_keys", ...getBasePublicKeys(KEYS) },
        });
    });

    it("answers the commitment point of the number asked", async () => {
        const { dispatch } = await registered();
        await expect(dispatch.handle(request("get_commitment_point", { commitment_number: "0x5" }))).resolves.toEqual({
            kind: "result",
            result: { kind: "commitment_point", commitmentPoint: getChannelCommitmentPoint(KEYS, 5) },
        });
    });

    it("answers the commitment nonce of the number asked", async () => {
        const { dispatch } = await registered();
        await expect(dispatch.handle(request("get_commitment_pub_nonce", { commitment_number: "0x5" }))).resolves.toEqual({
            kind: "result",
            result: { kind: "pub_nonce", pubNonce: getPublicNonce(KEYS, 5, "COMMITMENT") },
        });
    });

    it("answers the revocation nonce of the number asked", async () => {
        const { dispatch } = await registered();
        await expect(dispatch.handle(request("get_revocation_pub_nonce", { commitment_number: "0x5" }))).resolves.toEqual({
            kind: "result",
            result: { kind: "pub_nonce", pubNonce: getPublicNonce(KEYS, 5, "REVOKE") },
        });
    });

    it("answers the announcement nonce at the fixed slot, whatever number the request carries", async () => {
        const { dispatch } = await registered();
        await expect(dispatch.handle(request("get_channel_announcement_pub_nonce", { commitment_number: "0x9" }))).resolves.toEqual({
            kind: "result",
            result: { kind: "pub_nonce", pubNonce: getPublicNonce(KEYS, ANNOUNCEMENT_SLOT_NUMBER, "ANNOUNCEMENT") },
        });
    });

    it("answers the settlement keys of the number asked: the TLC base key and the TLC key, never the funding key", async () => {
        const { dispatch } = await registered();
        const result = resultOf(await dispatch.handle(request("get_settlement_keys", { commitment_number: "0x5" })));
        expect(result).toEqual({ kind: "settlement_keys", localSettlementKey: KEYS.tlcBaseKey, tlcKey: deriveTlcKey(KEYS, 5) });
        for (const value of Object.values(result)) {
            if (value instanceof Uint8Array) expect(bytesToHex(value)).not.toBe(bytesToHex(KEYS.fundingKey));
        }
    });

    it("reads the commitment number up to the top of the chain", async () => {
        const { dispatch } = await registered();
        await expect(dispatch.handle(request("get_commitment_point", { commitment_number: "0xffffffffffff" }))).resolves.toEqual({
            kind: "result",
            result: { kind: "commitment_point", commitmentPoint: getChannelCommitmentPoint(KEYS, 2 ** 48 - 1) },
        });
    });

    it("answers whatever the state version, since nothing is claimed", async () => {
        const { dispatch, storage } = await registered();
        partialSignatureOf(await dispatch.handle(request("partial_sign_commitment_tx", paramsFor("partial_sign_commitment_tx"))));
        storage.ops.length = 0;

        const outcome = await dispatch.handle(request("get_commitment_point", { commitment_number: "0x5" }, { stateVersion: 1 }));

        expect(outcome.kind).toBe("result");
        expect(writes(storage)).toEqual([]);
    });
});

describe("the signing methods", () => {
    it.each(SIGNING_CASES)("signs $method under the nonce $published published, verifiable by the node", async (kase) => {
        const { dispatch } = await registered();
        const publishedParams = kase.nonceNumber === undefined ? {} : toCommitmentNumberParamsWire(kase.nonceNumber);
        const pubNonce = pubNonceOf(await dispatch.handle(request(kase.published, publishedParams)));
        const orderedPublicKeys = ORDERED_PUBLIC_KEYS[kase.method];
        const localIndex = orderedPublicKeys.indexOf(LOCAL_FUNDING_PUBKEY);
        const pubNonces = orderedPublicKeys.map((key) => (key === LOCAL_FUNDING_PUBKEY ? pubNonce : peerNonces().public));
        const aggregatedNonce = nonceAggregate(pubNonces);

        const partialSignature = partialSignatureOf(
            await dispatch.handle(request(kase.method, signingParams(kase.method, aggregatedNonce))),
        );

        const session = new Session(aggregatedNonce, orderedPublicKeys, hexToBytes(kase.digest));
        expect(session.partialSigVerify(partialSignature, pubNonces, localIndex)).toBe(true);
    });

    it.each(SIGNING_CASES)("claims the slot $context:$nonceNumber it signs $method with", async (kase) => {
        const { dispatch, store } = await registered();
        partialSignatureOf(await dispatch.handle(request(kase.method, signingParams(kase.method, AGGREGATED_NONCE))));
        const record = await store.getChannelRecord(CHANNEL_INDEX);
        expect(Object.keys(record?.signedSessions ?? {})).toEqual([`${kase.context}:${kase.nonceNumber ?? ANNOUNCEMENT_SLOT_NUMBER}`]);
    });

    it("aggregates with the peer's half into a valid schnorr signature under the 2-of-2 key", async () => {
        const { dispatch } = await registered();
        const pubNonce = pubNonceOf(
            await dispatch.handle(request("get_commitment_pub_nonce", toCommitmentNumberParamsWire(THREE_TLCS.commitment_number))),
        );
        const peer = peerNonces();
        const aggregatedNonce = nonceAggregate([pubNonce, peer.public]);
        const partialSignature = partialSignatureOf(
            await dispatch.handle(request("partial_sign_commitment_tx", signingParams("partial_sign_commitment_tx", aggregatedNonce))),
        );

        const message = hexToBytes(THREE_TLCS.digest);
        const orderedPublicKeys = ORDERED_PUBLIC_KEYS.partial_sign_commitment_tx;
        const session = new Session(aggregatedNonce, orderedPublicKeys, message);
        const peerPartialSignature = session.sign(peer.secret, REMOTE_KEYS.fundingKey);
        const signature = session.partialSigAgg([partialSignature, peerPartialSignature]);
        expect(schnorr.verify(signature, message, keyAggExport(keyAggregate(orderedPublicKeys)))).toBe(true);
    });

    it("consumes the debit intent that covers a decrease of the exposure", async () => {
        const { dispatch, policy, store } = await registered(OPENING_EXPOSURE);
        await policy.recordDebitIntent(CHANNEL_ID, TLC_DECREASE);

        partialSignatureOf(await dispatch.handle(request("partial_sign_commitment_tx", paramsFor("partial_sign_commitment_tx"))));

        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({
            localExposureShannons: THREE_TLCS.settlement_local,
            pendingDebitsShannons: [],
        });
    });
});

describe("re-delivery", () => {
    it("answers a re-delivered request with the identical partial signature, writing nothing and consuming no intent", async () => {
        const { dispatch, policy, store, storage } = await registered(OPENING_EXPOSURE);
        await policy.recordDebitIntent(CHANNEL_ID, TLC_DECREASE);
        const envelope = request("partial_sign_commitment_tx", paramsFor("partial_sign_commitment_tx"));
        const first = partialSignatureOf(await dispatch.handle(envelope));
        await policy.recordDebitIntent(CHANNEL_ID, TLC_DECREASE);
        storage.ops.length = 0;

        const second = partialSignatureOf(await dispatch.handle(envelope));

        expect(bytesToHex(second)).toBe(bytesToHex(first));
        expect(writes(storage)).toEqual([]);
        await expect(store.getChannelRecord(CHANNEL_INDEX)).resolves.toMatchObject({ pendingDebitsShannons: [TLC_DECREASE] });
    });
});

describe("refusals", () => {
    it.each(SIGNER_METHODS)("refuses %s for a channel this device never registered, claiming nothing", async (method) => {
        const { dispatch, storage } = newDispatch();
        await expect(dispatch.handle(request(method, paramsFor(method)))).resolves.toEqual({
            kind: "refusal",
            error: { code: "unknown_channel", message: expect.any(String) },
        });
        expect(writes(storage)).toEqual([]);
    });

    it("refuses a field the wire cannot read as malformed, naming the field and never the value", async () => {
        const { dispatch } = await registered();
        const params = withField(paramsFor("partial_sign_commitment_tx"), "commitment_tx.to_local", "0X1");

        const error = refusalOf(await dispatch.handle(request("partial_sign_commitment_tx", params)));

        expect(error.code).toBe("malformed");
        expect(error.message).toContain("sign_request.params.commitment_tx.to_local");
        expect(error.message).not.toContain("0X1");
    });

    it("refuses what the codecs refuse as malformed ahead of the channel lookup", async () => {
        const { dispatch } = newDispatch();
        const params = withField(paramsFor("partial_sign_commitment_tx"), "commitment_tx.to_local", "0X1");
        expect(refusalOf(await dispatch.handle(request("partial_sign_commitment_tx", params))).code).toBe("malformed");
    });

    it.each([
        ["an aggregated nonce off the curve", "session.aggregated_nonce", `0x${"03".repeat(66)}`],
        ["a message the attached state does not rebuild", "session.message", `0x${"00".repeat(32)}`],
    ])("refuses %s behind the channel lookup, as unknown_channel for a channel never registered", async (_, path, value) => {
        const { dispatch } = newDispatch();
        const params = withField(paramsFor("partial_sign_commitment_tx"), path, value);
        expect(refusalOf(await dispatch.handle(request("partial_sign_commitment_tx", params))).code).toBe("unknown_channel");
    });

    it("refuses a message the attached state does not rebuild as malformed", async () => {
        const { dispatch } = await registered();
        const params = withField(paramsFor("partial_sign_commitment_tx"), "session.message", `0x${"00".repeat(32)}`);
        const error = refusalOf(await dispatch.handle(request("partial_sign_commitment_tx", params)));
        expect(error.code).toBe("malformed");
        expect(error.message).toContain("does not match");
    });

    it("refuses a session that does not aggregate this channel's funding key as malformed", async () => {
        const { dispatch } = await registered();
        const foreign = [`0x${REMOTE.funding_pubkey}`, `0x${bytesToHex(pubkeyOf(REMOTE_KEYS.tlcBaseKey))}`];
        const params = withField(paramsFor("partial_sign_commitment_tx"), "session.ordered_pubkeys", foreign);
        expect(refusalOf(await dispatch.handle(request("partial_sign_commitment_tx", params))).code).toBe("malformed");
    });

    it.each([
        ["an aggregated nonce", "session.aggregated_nonce", `0x${"03".repeat(66)}`],
        ["a public key", "session.ordered_pubkeys", [`0x${bytesToHex(LOCAL_FUNDING_PUBKEY)}`, `0x${"03".repeat(33)}`]],
    ])("refuses %s off the curve as malformed before the claim, so the corrected request still signs", async (_, path, value) => {
        const { dispatch, storage } = await registered();
        storage.ops.length = 0;

        const outcome = await dispatch.handle(
            request("partial_sign_commitment_tx", withField(paramsFor("partial_sign_commitment_tx"), path, value)),
        );

        expect(refusalOf(outcome).code).toBe("malformed");
        expect(writes(storage)).toEqual([]);
        partialSignatureOf(await dispatch.handle(request("partial_sign_commitment_tx", paramsFor("partial_sign_commitment_tx"))));
    });

    it("refuses a second session on a served slot as policy_refusal", async () => {
        const { dispatch } = await registered();
        partialSignatureOf(await dispatch.handle(request("partial_sign_commitment_tx", paramsFor("partial_sign_commitment_tx"))));

        const outcome = await dispatch.handle(request("partial_sign_commitment_tx", commitmentParams(THREE_TLCS, OTHER_AGGREGATED_NONCE)));

        expect(refusalOf(outcome).code).toBe("policy_refusal");
    });

    it("refuses a decrease of the exposure with no debit intent as policy_refusal, claiming nothing", async () => {
        const { dispatch, storage } = await registered(OPENING_EXPOSURE);
        storage.ops.length = 0;

        const outcome = await dispatch.handle(request("partial_sign_commitment_tx", paramsFor("partial_sign_commitment_tx")));

        expect(refusalOf(outcome).code).toBe("policy_refusal");
        expect(writes(storage)).toEqual([]);
    });

    it("refuses a commitment number that does not advance its context as stale_state", async () => {
        const { dispatch } = await registered();
        partialSignatureOf(await dispatch.handle(request("partial_sign_commitment_tx", paramsFor("partial_sign_commitment_tx"))));

        const outcome = await dispatch.handle(request("partial_sign_commitment_tx", commitmentParams(NO_TLCS, AGGREGATED_NONCE)));

        expect(refusalOf(outcome).code).toBe("stale_state");
    });

    it("refuses a state version below the last one seen as stale_state", async () => {
        const { dispatch } = await registered();
        partialSignatureOf(await dispatch.handle(request("partial_sign_commitment_tx", paramsFor("partial_sign_commitment_tx"))));

        const outcome = await dispatch.handle(
            request("partial_sign_commitment_tx", commitmentParams(THREE_TLCS_FOR_LOCAL, AGGREGATED_NONCE), { stateVersion: 1 }),
        );

        expect(refusalOf(outcome).code).toBe("stale_state");
    });

    it("writes a codec refusal as exactly its code and the message the codec threw", async () => {
        const { dispatch } = await registered();
        const envelope = request(
            "partial_sign_commitment_tx",
            withField(paramsFor("partial_sign_commitment_tx"), "commitment_tx.to_local", "0X1"),
        );
        let thrown: unknown;
        try {
            decodeSignParams(envelope, COMMITMENT_LOCK_TESTNET);
        } catch (error) {
            thrown = error;
        }
        if (!(thrown instanceof ProtocolError)) throw new Error("expected a codec refusal");

        expect(refusalOf(await dispatch.handle(envelope))).toStrictEqual({ code: "malformed", message: thrown.message });
    });

    it("writes a gate refusal as exactly its code and the message the gate threw", async () => {
        const { dispatch, policy } = newDispatch();
        const thrown = await policy.requireChannelIndex(CHANNEL_ID).catch((error: unknown) => error);
        if (!(thrown instanceof PolicyRefusalError)) throw new Error("expected a gate refusal");

        expect(refusalOf(await dispatch.handle(request("get_base_public_keys", {})))).toStrictEqual({
            code: "unknown_channel",
            message: thrown.message,
        });
    });
});

describe("the commitment lock", () => {
    // Only the commitment tx tells the two locks apart: the revocation digest sizes a fee over the lock, not its bytes.
    it("rebuilds the commitment tx under the lock the dispatch holds, so the mainnet lock refuses the testnet vectors", async () => {
        const testnet = await registered("0", COMMITMENT_LOCK_TESTNET);
        const mainnet = await registered("0", COMMITMENT_LOCK_MAINNET);
        const params = paramsFor("partial_sign_commitment_tx");

        expect((await testnet.dispatch.handle(request("partial_sign_commitment_tx", params))).kind).toBe("result");
        expect(refusalOf(await mainnet.dispatch.handle(request("partial_sign_commitment_tx", params))).code).toBe("malformed");
    });
});

describe("faults", () => {
    it("leaves a request whose storage throws unanswered as a fault carrying the cause, even a cause with a code", async () => {
        const failure = Object.assign(new Error("no space left on device"), { code: "ENOSPC" });
        const storage: ISignerStorage = {
            get() {
                throw failure;
            },
            set() {
                throw failure;
            },
        };
        const policy = new PolicyEngine(new SignerStore(storage));
        const dispatch = new SignerDispatch({ masterSeed: MASTER_SEED, commitmentLock: COMMITMENT_LOCK_TESTNET, policy });

        await expect(dispatch.handle(request("partial_sign_commitment_tx", paramsFor("partial_sign_commitment_tx")))).resolves.toEqual({
            kind: "fault",
            cause: failure,
        });
    });

    it("reports a corrupt record as a fault that claims nothing, and answers once the record is back", async () => {
        const { dispatch, storage } = await registered();
        const key = `${CHANNEL_RECORD_KEY_PREFIX}${CHANNEL_INDEX}`;
        const record = storage.map.get(key) ?? "";
        storage.map.set(key, "garbage");
        storage.ops.length = 0;
        const envelope = request("partial_sign_commitment_tx", paramsFor("partial_sign_commitment_tx"));

        expect(faultOf(await dispatch.handle(envelope))).toBeInstanceOf(TypeError);
        expect(writes(storage)).toEqual([]);

        storage.map.set(key, record);
        partialSignatureOf(await dispatch.handle(envelope));
    });

    it("reports a name that resolves to an index holding no record as a fault that claims nothing, until it is registered", async () => {
        const { dispatch, storage } = newDispatch();
        storage.map.set(`${CHANNEL_ALIAS_KEY_PREFIX}${CHANNEL_ID}`, String(CHANNEL_INDEX));
        const envelope = request("partial_sign_commitment_tx", paramsFor("partial_sign_commitment_tx"));

        expect(faultOf(await dispatch.handle(envelope))).toBeInstanceOf(TypeError);
        expect(writes(storage)).toEqual([]);

        await dispatch.channelRegistered(CHANNEL_ID, dispatch.prepareChannelRegistration(CHANNEL_INDEX, "0"));
        partialSignatureOf(await dispatch.handle(envelope));
    });

    it("answers once the storage is back, since a fault claims nothing", async () => {
        const inner = await registered();
        inner.storage.ops.length = 0;
        let failures = 1;
        const storage: ISignerStorage = {
            get(key) {
                if (failures > 0) {
                    failures -= 1;
                    throw new Error("storage unavailable");
                }
                return inner.storage.get(key);
            },
            set(key, value) {
                inner.storage.set(key, value);
            },
        };
        const policy = new PolicyEngine(new SignerStore(storage));
        const dispatch = new SignerDispatch({ masterSeed: MASTER_SEED, commitmentLock: COMMITMENT_LOCK_TESTNET, policy });
        const envelope = request("partial_sign_commitment_tx", paramsFor("partial_sign_commitment_tx"));

        expect((await dispatch.handle(envelope)).kind).toBe("fault");
        expect(writes(inner.storage)).toHaveLength(0);
        expect((await dispatch.handle(envelope)).kind).toBe("result");
    });

    it("never throws, whatever the request", async () => {
        const { dispatch } = await registered();
        const outcome = await dispatch.handle(request("no_such_method" as SignerMethod, {}));
        expect(outcome.kind).toBe("fault");
    });
});

describe("secret hygiene", () => {
    it("names no key material in any refusal", async () => {
        const secrets = [
            MASTER_SEED,
            deriveWalletIdentityKey(MASTER_SEED),
            KEYS.fundingKey,
            KEYS.tlcBaseKey,
            KEYS.musig2BaseNonce,
            KEYS.commitmentSeed,
            deriveNonceSeed(KEYS, THREE_TLCS.commitment_number, "COMMITMENT"),
            deriveTlcKey(KEYS, THREE_TLCS.commitment_number),
        ].map(bytesToHex);
        const unregistered = newDispatch().dispatch;
        const served = await registered();
        partialSignatureOf(await served.dispatch.handle(request("partial_sign_commitment_tx", paramsFor("partial_sign_commitment_tx"))));
        const exposed = await registered(OPENING_EXPOSURE);
        const outcomes = await Promise.all([
            unregistered.handle(request("get_base_public_keys", {})),
            served.dispatch.handle(
                request("partial_sign_commitment_tx", withField(paramsFor("partial_sign_commitment_tx"), "commitment_tx.to_local", "0X1")),
            ),
            served.dispatch.handle(
                request(
                    "partial_sign_commitment_tx",
                    withField(paramsFor("partial_sign_commitment_tx"), "session.message", `0x${"00".repeat(32)}`),
                ),
            ),
            served.dispatch.handle(request("partial_sign_commitment_tx", commitmentParams(THREE_TLCS, OTHER_AGGREGATED_NONCE))),
            served.dispatch.handle(request("partial_sign_commitment_tx", commitmentParams(NO_TLCS, AGGREGATED_NONCE))),
            served.dispatch.handle(
                request("partial_sign_commitment_tx", commitmentParams(THREE_TLCS_FOR_LOCAL, AGGREGATED_NONCE), { stateVersion: 1 }),
            ),
            exposed.dispatch.handle(request("partial_sign_commitment_tx", paramsFor("partial_sign_commitment_tx"))),
        ]);

        const messages = outcomes.map((outcome) => refusalOf(outcome).message);

        expect(new Set(outcomes.map((outcome) => refusalOf(outcome).code))).toEqual(
            new Set(["unknown_channel", "malformed", "policy_refusal", "stale_state"]),
        );
        for (const message of messages) for (const secret of secrets) expect(message).not.toContain(secret);
    });
});
