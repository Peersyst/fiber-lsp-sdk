import { hexToBytes } from "@noble/hashes/utils.js";
import { SCRIPT_HASH_TYPES, TLC_DIRECTIONS, TLC_HASH_ALGORITHMS } from "../../src/common";
import type { FiberChannelKeys } from "../../src/derivation";
import { deriveChannelKeys, deriveChannelSeed } from "../../src/derivation";
import type { ChannelPolicyRecord, PolicyEngineOptions, PolicyView, PolicyViewTlc } from "../../src/policy";
import { PolicyEngine, SignerStore } from "../../src/policy";
import { SignerDispatch } from "../../src/signer";
import { InMemorySignerStorage } from "../mocks/policy";
import { toLockLayout, toScript } from "./digest-inputs";
import { asBoolean, asRecord, asString } from "./json-shape";
import type { SigningCaseVector, SigningVectors } from "./signing-vectors";

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
): Promise<SigningChannel> {
    const { channel, device } = vectors;
    const storage = new InMemorySignerStorage();
    const store = new SignerStore(storage);
    const policy = new PolicyEngine(store, options);
    const dispatch = new SignerDispatch({
        masterSeed: hexToBytes(device.master_seed),
        commitmentLock: {
            codeHash: hexToBytes(channel.commitment_lock.code_hash),
            hashType: oneOf(channel.commitment_lock.hash_type, "channel.commitment_lock.hash_type", SCRIPT_HASH_TYPES),
        },
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
