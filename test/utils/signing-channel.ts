import { hexToBytes } from "@noble/hashes/utils.js";
import type { ScriptTemplate } from "../../src/common";
import { SCRIPT_HASH_TYPES, TLC_DIRECTIONS, TLC_HASH_ALGORITHMS } from "../../src/common";
import type { FiberChannelKeys } from "../../src/derivation";
import { deriveChannelKeys, deriveChannelSeed } from "../../src/derivation";
import type { ChannelPolicyRecord, PolicyEngineOptions, PolicyView, PolicyViewTlc } from "../../src/policy";
import { PolicyEngine, SignerStore } from "../../src/policy";
import type { SdkEvent } from "../../src/sdk";
import { SignerDispatch } from "../../src/signer";
import type { WireField } from "../../src/wire";
import { InMemorySignerStorage } from "../mocks/policy";
import type { SentCall } from "../mocks/rpc";
import { toLockLayout, toScript } from "./digest-inputs";
import { asBoolean, asRecord, asString } from "./json-shape";
import { resignPeerHalf } from "./peer-musig";
import type { SigningCaseVector, SigningVectors } from "./signing-vectors";
import { signingCaseOf, signingStatusField, watchtowerSignedCommitmentOf } from "./signing-vectors";
import { withField } from "./with-field";

// The view a revocation's replacement belongs to: the device's own commitment when it sends one, the peer's when it receives.
const REPLACEMENT_VIEWS = { SendRevokeAndAck: "local", CompleteReceivedRevokeAndAck: "remote" } as const;

// The commitment case of each view, whose message stands for the replacement's hash.
const COMMITMENT_TRANSITIONS = { remote: "SendCommitmentSigned", local: "CompleteReceivedCommitment" } as const;

export type SigningChannel = {
    dispatch: SignerDispatch;
    policy: PolicyEngine;
    store: SignerStore;
    storage: InMemorySignerStorage;
    channelId: string;
    channelIndex: number;
    keys: FiberChannelKeys;
};

export function signingDeviceKeys(vectors: SigningVectors): FiberChannelKeys {
    return deriveChannelKeys(deriveChannelSeed(hexToBytes(vectors.device.master_seed), vectors.device.channel_index));
}

// A fiber `InMemorySigner` over the peer's seed.
export function signingPeerKeys(vectors: SigningVectors): FiberChannelKeys {
    return deriveChannelKeys(hexToBytes(vectors.peer.seed));
}

export function signingCommitmentLock(vectors: SigningVectors): ScriptTemplate {
    const lock = vectors.channel.commitment_lock;
    return {
        codeHash: hexToBytes(lock.code_hash),
        hashType: oneOf(lock.hash_type, "channel.commitment_lock.hash_type", SCRIPT_HASH_TYPES),
    };
}

export function signingViewTlcs(vectors: SigningVectors): PolicyViewTlc[] {
    const fullHash = toLockLayout(vectors.channel.lock_layout) === "fullPaymentHash";
    return vectors.channel.tlcs.map((tlc) => ({
        direction: oneOf(tlc.direction, "tlc.direction", TLC_DIRECTIONS),
        hashAlgorithm: oneOf(tlc.hash_algorithm, "tlc.hash_algorithm", TLC_HASH_ALGORITHMS),
        boundPaymentHash: tlc.payment_hash.slice(0, 40),
        fullPaymentHash: fullHash ? tlc.payment_hash : null,
        amountShannons: tlc.amount,
        expirySeconds: (BigInt(tlc.expiry_ms) / 1000n).toString(),
    }));
}

export async function openSigningChannel(
    vectors: SigningVectors,
    kase: SigningCaseVector,
    options: PolicyEngineOptions = {},
    storage: InMemorySignerStorage = new InMemorySignerStorage(),
): Promise<SigningChannel> {
    const { channel, device } = vectors;
    const store = new SignerStore(storage);
    const policy = new PolicyEngine(store, options);
    const dispatch = new SignerDispatch({
        masterSeed: hexToBytes(device.master_seed),
        commitmentLock: signingCommitmentLock(vectors),
        fundingLockCellDepsCount: channel.funding_lock_cell_deps_count,
        policy,
    });
    const channelId = kase.result.channel_id;
    const funded = (BigInt(channel.to_local) + BigInt(channel.local_reserved)).toString();
    await policy.registerChannel(channelId, device.channel_index, funded, toScript(channel.local_close_script));
    await policy.pinChannelTerms(channelId, {
        commitmentFeeRate: BigInt(channel.commitment_fee_rate),
        remoteReservedCkbShannons: channel.remote_reserved,
        liquidCapacityShannons: (BigInt(channel.to_local) + BigInt(channel.to_remote)).toString(),
    });
    // Every value from the vectors. Before a commitment: its lane one below the slot, its view already at the case's balance
    // and TLCs, so the balance rule judges no change. Before a revocation: its replacement as its view's last commitment.
    await store.updateChannelRecord(device.channel_index, (current) => withCaseState(vectors, kase, required(current)));
    return { dispatch, policy, store, storage, channelId, channelIndex: device.channel_index, keys: signingDeviceKeys(vectors) };
}

export function signingRequestIdOf(kase: SigningCaseVector): string {
    return asString(kase.result.status.request_id, "status.request_id");
}

export function signedEventOf(vectors: SigningVectors, kase: SigningCaseVector, outcome: "signed" | "warning" = "signed"): SdkEvent {
    return {
        type: "SIGNING",
        channelId: vectors.channel.channel_id,
        requestId: signingRequestIdOf(kase),
        transition: kase.transition,
        outcome,
    };
}

export function signatureSubmissionCall(vectors: SigningVectors, kase: SigningCaseVector): SentCall {
    const { partial_signature: partialSignature, next_material: material } = kase.expected;
    const params = {
        channel_id: vectors.channel.channel_id,
        request_id: signingRequestIdOf(kase),
        partial_signature: `0x${partialSignature}`,
        ...(material === null
            ? {}
            : {
                  next_material: {
                      next_commitment_point: material.next_commitment_point,
                      next_commitment_nonce: `0x${material.next_commitment_nonce}`,
                      next_revocation_nonce: `0x${material.next_revocation_nonce}`,
                  },
              }),
    };
    return { method: "submit_channel_signature", params };
}

// The vectors' channel with both views' commitments signed.
export async function openWatchtowerChannel(
    vectors: SigningVectors,
    options: PolicyEngineOptions,
    storage: InMemorySignerStorage = new InMemorySignerStorage(),
): Promise<SigningChannel> {
    const channel = await openSigningChannel(vectors, signingCaseOf(vectors, "SendClosingSigned"), options, storage);
    const commitmentHashes = { remote: watchtowerSignedCommitmentOf(vectors, true), local: watchtowerSignedCommitmentOf(vectors, false) };
    await channel.store.updateChannelRecord(channel.channelIndex, (current) => ({ ...required(current), commitmentHashes }));
    return channel;
}

// Fiber's open lands both commitment transitions on one slot: the received commitment, moved onto the sent one's slot.
export function secondSessionStatus(vectors: SigningVectors): WireField {
    const status = signingStatusField(signingCaseOf(vectors, "CompleteReceivedCommitment"));
    return resignPeerHalf(
        { ...status, value: withField(status.value, "content.slot.commitment_number", "0x4") },
        signingDeviceKeys(vectors),
        signingPeerKeys(vectors).fundingKey,
        0x71,
    );
}

// Moves the local view to the received commitment's balance and TLCs, so the second session's balance rule sees no change.
export async function stageSecondSession(vectors: SigningVectors, channel: SigningChannel): Promise<void> {
    const settlement = asRecord(signingCaseOf(vectors, "CompleteReceivedCommitment").result.status.settlement, "status.settlement");
    const localAmount = asString(settlement.local_amount, "settlement.local_amount");
    await channel.store.updateChannelRecord(channel.channelIndex, (current) => {
        const record = required(current);
        const local = {
            exposureShannons: BigInt(localAmount).toString(),
            tlcs: signingViewTlcs(vectors),
            chargedShannons: {},
            creditedShannons: {},
        };
        return { ...record, views: { ...record.views, local } };
    });
}

function withCaseState(vectors: SigningVectors, kase: SigningCaseVector, record: ChannelPolicyRecord): ChannelPolicyRecord {
    const pins = { ...record.pins, lockLayout: toLockLayout(vectors.channel.lock_layout) };
    const status = asRecord(kase.result.status, "status");
    const slot = asRecord(asRecord(status.content, "status.content").slot, "status.content.slot");
    const slotNumber = Number(asString(slot.commitment_number, "slot.commitment_number"));
    if (kase.transition === "SendRevokeAndAck" || kase.transition === "CompleteReceivedRevokeAndAck") {
        const view = REPLACEMENT_VIEWS[kase.transition];
        return { ...record, pins, commitmentHashes: { [view]: replacementOf(vectors, view, slotNumber) } };
    }
    if (kase.transition !== "SendCommitmentSigned" && kase.transition !== "CompleteReceivedCommitment") return { ...record, pins };
    const settlement = asRecord(status.settlement, "status.settlement");
    const view = asBoolean(settlement.for_remote, "settlement.for_remote") ? "remote" : "local";
    return {
        ...record,
        pins,
        lastSignedCommitmentNumbers: { "COMMITMENT:local": slotNumber - 1 },
        views: {
            ...record.views,
            [view]: {
                exposureShannons: BigInt(asString(settlement.local_amount, "settlement.local_amount")).toString(),
                tlcs: signingViewTlcs(vectors),
                chargedShannons: {},
                creditedShannons: {},
            },
        },
    };
}

function replacementOf(vectors: SigningVectors, view: PolicyView, slotNumber: number): { commitmentNumber: number; txHash: string } {
    // Hashed as the vectors' commitment of the view: the remote one is the replacement itself, the local one a version
    // below, a hash the revocation rule never reads.
    const commitment = vectors.cases.find((candidate) => candidate.transition === COMMITMENT_TRANSITIONS[view]);
    if (commitment === undefined) throw new Error(`the vectors carry no ${COMMITMENT_TRANSITIONS[view]} case`);
    return { commitmentNumber: slotNumber, txHash: commitment.expected.message };
}

function oneOf<Value extends string>(value: string, path: string, values: readonly Value[]): Value {
    const found = values.find((known) => known === value);
    if (found === undefined) throw new Error(`${path} is not one of ${values.join(", ")}: ${value}`);
    return found;
}

function required(record: ChannelPolicyRecord | null): ChannelPolicyRecord {
    if (record === null) throw new Error("the channel was registered and holds no record");
    return record;
}
