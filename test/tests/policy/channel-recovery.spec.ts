import { hexToBytes } from "@noble/hashes/utils.js";
import { nonceAggregate } from "@scure/btc-signer/musig2.js";
import { deriveChannelKeys, deriveChannelSeed, pubkeyOf } from "../../../src/derivation";
import { COMMITMENT_LOCK_TESTNET } from "../../../src/digest";
import type { ChannelPolicyRecord, NodeChannelState, PolicySignRequest } from "../../../src/policy";
import { ChannelRecovery, PolicyEngine, PolicyRefusalError, SignerStore } from "../../../src/policy";
import { getPublicNonce, partialSign } from "../../../src/signer";
import { InMemorySignerStorage } from "../../mocks/policy";
import { toOutPoint } from "../../utils/digest-inputs";
import { loadInteropVectors } from "../../utils/interop-vectors";

const vectors = loadInteropVectors();

const MASTER_SEED = hexToBytes(vectors.sdk_scheme.master_seed);
const OTHER_MASTER_SEED = hexToBytes("11".repeat(32));
const CHANNEL_INDEX = vectors.sdk_scheme.channel.channel_index;
const KEYS = deriveChannelKeys(hexToBytes(vectors.sdk_scheme.channel.seed));
const LOCAL_FUNDING_PUBKEY = pubkeyOf(KEYS.fundingKey);
const REMOTE_FUNDING_PUBKEY = hexToBytes(vectors.digest.remote.funding_pubkey);
const REMOTE_TLC_BASE_PUBKEY = hexToBytes(vectors.digest.remote.tlc_base_pubkey);
const REMOTE_PUB_NONCE = hexToBytes(vectors.musig.remote_pubnonce);

const CHANNEL_ID = "0x1f".padEnd(66, "a");
const RENAMED_CHANNEL_ID = "0x2f".padEnd(66, "b");
const OTHER_CHANNEL_ID = "0x3f".padEnd(66, "c");
const NODE_EXPOSURE = "1000";

const commitmentCase = caseOf("ckb, no tlcs, for remote");
const SIGNED_EXPOSURE = commitmentCase.settlement_local;
const SIGNED_SLOT = 7;

// Real aggregates: policy never inspects them, but the engine that re-signs does.
const AGGREGATED_NONCE = nonceAggregate([getPublicNonce(KEYS, SIGNED_SLOT, "COMMITMENT"), REMOTE_PUB_NONCE]);
const OTHER_AGGREGATED_NONCE = nonceAggregate([getPublicNonce(KEYS, SIGNED_SLOT + 1, "COMMITMENT"), REMOTE_PUB_NONCE]);

function caseOf(name: string): (typeof vectors.digest.commitment_cases)[number] {
    const found = vectors.digest.commitment_cases.find((entry) => entry.name === name);
    if (found === undefined) throw new Error(`the vectors carry no case named "${name}"`);
    return found;
}

function fundingPubkeyOf(channelIndex: number, masterSeed = MASTER_SEED): Uint8Array {
    return pubkeyOf(deriveChannelKeys(deriveChannelSeed(masterSeed, channelIndex)).fundingKey);
}

function nodeChannel(channelId: string, channelIndex: number, masterSeed = MASTER_SEED): NodeChannelState {
    return { channelId, localFundingPubkey: fundingPubkeyOf(channelIndex, masterSeed), localExposureShannons: NODE_EXPOSURE };
}

function signRequest(nonceCommitmentNumber: number, aggregatedNonce = AGGREGATED_NONCE): PolicySignRequest {
    return {
        channelId: CHANNEL_ID,
        stateVersion: 1,
        nonceCommitmentNumber,
        session: {
            orderedPublicKeys: [LOCAL_FUNDING_PUBKEY, REMOTE_FUNDING_PUBKEY],
            aggregatedNonce,
            message: hexToBytes(commitmentCase.digest),
        },
        operation: {
            kind: "commitment_tx",
            input: {
                forRemote: commitmentCase.for_remote,
                fundingOutPoint: toOutPoint(commitmentCase.funding_out_point),
                remoteFundingPubkey: REMOTE_FUNDING_PUBKEY,
                remoteTlcBasePubkey: REMOTE_TLC_BASE_PUBKEY,
                commitmentNumber: commitmentCase.commitment_number,
                commitmentDelayEpoch: BigInt(commitmentCase.delay_epoch),
                commitmentFeeRate: BigInt(commitmentCase.fee_rate),
                cellDepsCount: commitmentCase.cell_deps_count,
                udtTypeScript: null,
                toLocalShannons: BigInt(commitmentCase.to_local),
                toRemoteShannons: BigInt(commitmentCase.to_remote),
                settlementLocalShannons: BigInt(commitmentCase.settlement_local),
                settlementRemoteShannons: BigInt(commitmentCase.settlement_remote),
                localReservedCkbShannons: BigInt(commitmentCase.local_reserved),
                remoteReservedCkbShannons: BigInt(commitmentCase.remote_reserved),
                tlcs: [],
                commitmentLock: COMMITMENT_LOCK_TESTNET,
            },
        },
    };
}

function signature(request: PolicySignRequest, commitmentNumber: number): Uint8Array {
    return partialSign(KEYS, {
        orderedPublicKeys: request.session.orderedPublicKeys,
        aggregatedNonce: request.session.aggregatedNonce,
        message: request.session.message,
        commitmentNumber,
        context: "COMMITMENT",
    });
}

async function signOnce(storage: InMemorySignerStorage, recoveryStorage: InMemorySignerStorage | null): Promise<Uint8Array> {
    const store = new SignerStore(storage, recoveryStorage);
    await new PolicyEngine(store).registerChannel(CHANNEL_ID, CHANNEL_INDEX, SIGNED_EXPOSURE);
    const verdict = await new PolicyEngine(store).checkAndClaim(KEYS, signRequest(SIGNED_SLOT));
    expect(verdict.status).toBe("fresh");
    return signature(signRequest(SIGNED_SLOT), verdict.commitmentNumber);
}

describe("matching the node's channels to their index", () => {
    it("maps a channel to the index its funding key derives from", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        const result = await new ChannelRecovery(store).reconcile(fundingPubkeyOf, [nodeChannel(CHANNEL_ID, 3)]);
        expect(result).toEqual({
            channels: [{ channelId: CHANNEL_ID, channelIndex: 3, status: "unguarded" }],
            unmatchedChannelIds: [],
            nextChannelIndex: 4,
        });
        await expect(store.resolveChannelIndex(CHANNEL_ID)).resolves.toBe(3);
    });

    it("rebuilds a lost record from the node's state when nothing survived", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await new ChannelRecovery(store).reconcile(fundingPubkeyOf, [nodeChannel(CHANNEL_ID, 3)]);
        await expect(store.getChannelRecord(3)).resolves.toEqual<ChannelPolicyRecord>({
            version: 1,
            channelId: CHANNEL_ID,
            lastSignedCommitmentNumbers: {},
            signedSessions: {},
            lastStateVersion: 0,
            localExposureShannons: NODE_EXPOSURE,
            pendingDebitsShannons: [],
        });
    });

    it("rebuilds it from the watermark when the recovery storage survived, ignoring the node's exposure", async () => {
        const storage = new InMemorySignerStorage();
        const recoveryStorage = new InMemorySignerStorage();
        await signOnce(storage, recoveryStorage);
        storage.map.clear();

        const store = new SignerStore(storage, recoveryStorage);
        const result = await new ChannelRecovery(store).reconcile(fundingPubkeyOf, [nodeChannel(CHANNEL_ID, CHANNEL_INDEX)]);
        expect(result.channels).toEqual([{ channelId: CHANNEL_ID, channelIndex: CHANNEL_INDEX, status: "restored" }]);
        const record = await store.getChannelRecord(CHANNEL_INDEX);
        expect(record?.lastSignedCommitmentNumbers).toEqual({ COMMITMENT: SIGNED_SLOT });
        expect(Object.keys(record?.signedSessions ?? {})).toEqual([`COMMITMENT:${SIGNED_SLOT}`]);
        expect(record?.lastStateVersion).toBe(1);
        expect(record?.localExposureShannons).toBe(SIGNED_EXPOSURE);
    });

    it("leaves a record it still finds exactly as it was", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        const registered = await new PolicyEngine(store).registerChannel(CHANNEL_ID, 3, SIGNED_EXPOSURE);
        const result = await new ChannelRecovery(store).reconcile(fundingPubkeyOf, [nodeChannel(CHANNEL_ID, 3)]);
        expect(result.channels).toEqual([{ channelId: CHANNEL_ID, channelIndex: 3, status: "known" }]);
        await expect(store.getChannelRecord(3)).resolves.toEqual(registered);
    });

    it("restores the record of a name that outlived it", async () => {
        const storage = new InMemorySignerStorage();
        storage.map.set(`fiber-lsp-sdk:alias:${CHANNEL_ID}`, "3");
        const store = new SignerStore(storage);
        await new ChannelRecovery(store).reconcile(fundingPubkeyOf, [nodeChannel(CHANNEL_ID, 3)]);
        await expect(store.getChannelRecord(3)).resolves.not.toBeNull();
        await expect(store.resolveChannelIndex(CHANNEL_ID)).resolves.toBe(3);
    });

    it("brings both names of a renamed channel to the one record", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        const result = await new ChannelRecovery(store).reconcile(fundingPubkeyOf, [
            nodeChannel(CHANNEL_ID, 3),
            nodeChannel(RENAMED_CHANNEL_ID, 3),
        ]);
        expect(result.channels.map((channel) => channel.channelIndex)).toEqual([3, 3]);
        expect(result.channels[1]?.status).toBe("known");
        await expect(store.resolveChannelIndex(RENAMED_CHANNEL_ID)).resolves.toBe(3);
    });

    it("reports a channel no index of this seed owns, and leaves it unregistered", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        const result = await new ChannelRecovery(store).reconcile(fundingPubkeyOf, [
            nodeChannel(CHANNEL_ID, 3),
            nodeChannel(OTHER_CHANNEL_ID, 0, OTHER_MASTER_SEED),
        ]);
        expect(result.channels.map((channel) => channel.channelId)).toEqual([CHANNEL_ID]);
        expect(result.unmatchedChannelIds).toEqual([OTHER_CHANNEL_ID]);
        await expect(store.resolveChannelIndex(OTHER_CHANNEL_ID)).resolves.toBeNull();
    });

    it("finds a channel the counter no longer knows about, within the gap", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        const result = await new ChannelRecovery(store).reconcile(fundingPubkeyOf, [nodeChannel(CHANNEL_ID, 15)]);
        expect(result.channels).toEqual([{ channelId: CHANNEL_ID, channelIndex: 15, status: "unguarded" }]);
    });

    it("keeps scanning past a match, so a run of channels is found beyond the first gap", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        const result = await new ChannelRecovery(store).reconcile(fundingPubkeyOf, [
            nodeChannel(CHANNEL_ID, 15),
            nodeChannel(RENAMED_CHANNEL_ID, 30),
        ]);
        expect(result.channels.map((channel) => channel.channelIndex)).toEqual([15, 30]);
    });

    it("does not find one past the gap, and refuses it rather than guessing", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        const result = await new ChannelRecovery(store).reconcile(fundingPubkeyOf, [nodeChannel(CHANNEL_ID, 40)]);
        expect(result.unmatchedChannelIds).toEqual([CHANNEL_ID]);
    });

    it("throws when a name already resolves to another index", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await new PolicyEngine(store).registerChannel(CHANNEL_ID, 1, SIGNED_EXPOSURE);
        await expect(new ChannelRecovery(store).reconcile(fundingPubkeyOf, [nodeChannel(CHANNEL_ID, 3)])).rejects.toThrow(TypeError);
    });

    it("changes nothing on a second run", async () => {
        const storage = new InMemorySignerStorage();
        const store = new SignerStore(storage);
        const recovery = new ChannelRecovery(store);
        const channels = [nodeChannel(CHANNEL_ID, 0), nodeChannel(OTHER_CHANNEL_ID, 2)];
        const first = await recovery.reconcile(fundingPubkeyOf, channels);
        const written = new Map(storage.map);
        const second = await recovery.reconcile(fundingPubkeyOf, channels);
        expect(second.channels).toEqual(first.channels.map((channel) => ({ ...channel, status: "known" })));
        expect(storage.map).toEqual(written);
    });

    it("raises the allocator's counter above the highest channel it matched", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await new ChannelRecovery(store).reconcile(fundingPubkeyOf, [nodeChannel(CHANNEL_ID, 4), nodeChannel(OTHER_CHANNEL_ID, 1)]);
        await expect(store.getNextChannelIndex()).resolves.toBe(5);
    });

    it.each([
        ["a channel with no name", { channelId: "" }],
        ["a public key of the wrong size", { localFundingPubkey: new Uint8Array(32) }],
        ["a public key that is not bytes", { localFundingPubkey: "02".repeat(33) as unknown as Uint8Array }],
        ["an exposure that is not decimal shannons", { localExposureShannons: "0x10" }],
        ["a negative exposure", { localExposureShannons: "-1" }],
    ])("refuses to reconcile %s", async (_case, overrides) => {
        const store = new SignerStore(new InMemorySignerStorage());
        const channel = { ...nodeChannel(CHANNEL_ID, 0), ...overrides };
        await expect(new ChannelRecovery(store).reconcile(fundingPubkeyOf, [channel])).rejects.toThrow(TypeError);
    });

    it("refuses a key provider that hands back something other than a public key", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await expect(new ChannelRecovery(store).reconcile(() => new Uint8Array(32), [nodeChannel(CHANNEL_ID, 0)])).rejects.toThrow(
            TypeError,
        );
    });
});

describe("allocating a channel index", () => {
    it("refuses before the node's channels have been reconciled", async () => {
        const recovery = new ChannelRecovery(new SignerStore(new InMemorySignerStorage()));
        await expect(recovery.allocateChannelIndex()).rejects.toThrow("reconcile the node's channels before allocating");
    });

    it("hands out an index no reconciled channel holds", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        const recovery = new ChannelRecovery(store);
        await recovery.reconcile(fundingPubkeyOf, [nodeChannel(CHANNEL_ID, 0), nodeChannel(OTHER_CHANNEL_ID, 1)]);
        await expect(recovery.allocateChannelIndex()).resolves.toBe(2);
    });

    it("allocates from zero on a device the node knows no channel of", async () => {
        const recovery = new ChannelRecovery(new SignerStore(new InMemorySignerStorage()));
        await recovery.reconcile(fundingPubkeyOf, []);
        await expect(recovery.allocateChannelIndex()).resolves.toBe(0);
    });

    it("asks every run of the app to reconcile again, since the counter alone cannot be trusted", async () => {
        const store = new SignerStore(new InMemorySignerStorage());
        await new ChannelRecovery(store).reconcile(fundingPubkeyOf, []);
        await expect(new ChannelRecovery(store).allocateChannelIndex()).rejects.toThrow("reconcile the node's channels before allocating");
    });
});

describe("what a restored device answers", () => {
    it("re-signs a re-delivered request to the same bytes it signed before losing the storage", async () => {
        const storage = new InMemorySignerStorage();
        const recoveryStorage = new InMemorySignerStorage();
        const first = await signOnce(storage, recoveryStorage);
        storage.map.clear();

        const store = new SignerStore(storage, recoveryStorage);
        await new ChannelRecovery(store).reconcile(fundingPubkeyOf, [nodeChannel(CHANNEL_ID, CHANNEL_INDEX)]);
        const verdict = await new PolicyEngine(store).checkAndClaim(KEYS, signRequest(SIGNED_SLOT));
        expect(verdict.status).toBe("already-signed");
        expect(signature(signRequest(SIGNED_SLOT), verdict.commitmentNumber)).toEqual(first);
    });

    it("refuses another session on the slot it served before the restore", async () => {
        const storage = new InMemorySignerStorage();
        const recoveryStorage = new InMemorySignerStorage();
        await signOnce(storage, recoveryStorage);
        storage.map.clear();

        const store = new SignerStore(storage, recoveryStorage);
        await new ChannelRecovery(store).reconcile(fundingPubkeyOf, [nodeChannel(CHANNEL_ID, CHANNEL_INDEX)]);
        await expect(new PolicyEngine(store).checkAndClaim(KEYS, signRequest(SIGNED_SLOT, OTHER_AGGREGATED_NONCE))).rejects.toThrow(
            new PolicyRefusalError("policy_refusal", `slot COMMITMENT:${SIGNED_SLOT} has already served a different signing session`),
        );
    });

    it("refuses a slot the counter covers although the pruned registry no longer names it", async () => {
        const storage = new InMemorySignerStorage();
        const recoveryStorage = new InMemorySignerStorage();
        await signOnce(storage, recoveryStorage);
        storage.map.clear();

        const store = new SignerStore(storage, recoveryStorage);
        await new ChannelRecovery(store).reconcile(fundingPubkeyOf, [nodeChannel(CHANNEL_ID, CHANNEL_INDEX)]);
        await expect(new PolicyEngine(store).checkAndClaim(KEYS, signRequest(SIGNED_SLOT - 4))).rejects.toThrow(
            new PolicyRefusalError("stale_state", `commitment number 3 is not above the last COMMITMENT signed, ${SIGNED_SLOT}`),
        );
    });

    it("serves a slot it already served when no recovery storage kept the watermark", async () => {
        const storage = new InMemorySignerStorage();
        await signOnce(storage, null);
        storage.map.clear();

        const store = new SignerStore(storage);
        const result = await new ChannelRecovery(store).reconcile(fundingPubkeyOf, [nodeChannel(CHANNEL_ID, CHANNEL_INDEX)]);
        expect(result.channels[0]?.status).toBe("unguarded");
        const verdict = await new PolicyEngine(store).checkAndClaim(KEYS, signRequest(SIGNED_SLOT, OTHER_AGGREGATED_NONCE));
        expect(verdict.status).toBe("fresh");
    });
});
