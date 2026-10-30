import { hexToBytes } from "@noble/hashes/utils.js";
import { deriveChannelKeys, deriveChannelSeed } from "../../src/derivation";
import type { ChannelPolicyRecord, PolicyChannelTerms, PolicyEngineOptions } from "../../src/policy";
import { PolicyEngine, SignerStore } from "../../src/policy";
import type { FetchInit } from "../../src/rpc";
import { FiberRpcClient } from "../../src/rpc";
import type { PollStep, SdkEvent } from "../../src/sdk";
import {
    ActivityPoller,
    ActivityTracker,
    DeviceChannelList,
    PendingOpeningStore,
    buildChannelSigningStep,
    buildChannelStep,
    buildWatchtowerSigningStep,
} from "../../src/sdk";
import { SignerDispatch } from "../../src/signer";
import { TimerMock } from "../mocks/common";
import type { InMemorySignerStorage } from "../mocks/policy";
import { flush } from "./flush";
import { SIGNING_MILLISECONDS_PER_EPOCH, signingPeerKeys } from "./signing-channel";
import { loadSigningVectors } from "./signing-vectors";
import { InMemoryTenantNode, tenantNodeChannelOf } from "./tenant-node";

const vectors = loadSigningVectors();

const INTERVAL_MS = 5_000;

const STEP_TIMEOUT_MS = 60_000;

export const TENANT_NODE_URL = "http://127.0.0.1:8227";

export const CHANNEL = tenantNodeChannelOf(vectors);

export const CHANNEL_ID = CHANNEL.channelId;

export const CHANNEL_INDEX = vectors.device.channel_index;

export const OTHER_CHANNEL_ID = `0x${"2e".repeat(32)}`;

export const LSP_PUBKEY = hexToBytes("02c91d295563aa25d500374244b0428ed9d7978740d8dae8e466b8a16c15945b37");

// What the user pays in, reserve included.
export const FUNDED = (CHANNEL.localShannons + CHANNEL.localReservedCkbShannons).toString();

export const TERMS: PolicyChannelTerms = {
    commitmentFeeRate: CHANNEL.commitmentFeeRate,
    remoteReservedCkbShannons: CHANNEL.remoteReservedCkbShannons.toString(),
    liquidCapacityShannons: (CHANNEL.localShannons + CHANNEL.remoteShannons).toString(),
    remoteCloseScript: CHANNEL.remoteCloseScript,
    remoteFundingPubkey: hexToBytes(vectors.peer.funding_pubkey),
    remoteTlcBasePubkey: hexToBytes(vectors.peer.tlc_base_pubkey),
    commitmentDelayEpoch: CHANNEL.commitmentDelayEpoch,
};

export type TenantDevice = {
    storage: InMemorySignerStorage;
    store: SignerStore;
    policy: PolicyEngine;
    dispatch: SignerDispatch;
    activity: ActivityTracker;
    channels: DeviceChannelList;
    poller: ActivityPoller;
    timer: TimerMock;
    events: SdkEvent[];
};

export type TenantFlow = { node: InMemoryTenantNode; device: TenantDevice };

export type TenantDeviceOptions = {
    policy: PolicyEngineOptions;
    // The channel signing step polls alone, or the watchtower's after it, as the facade runs both.
    watchtower: boolean;
    // The channel step first, as the facade runs it: it forgets a channel it sees closed, which the two others then read.
    channelStep?: boolean;
    storage: InMemorySignerStorage;
};

// `now`: the flow's clock, shared with the device.
export function tenantNode(channelIndexes: readonly number[] = [CHANNEL_INDEX], now?: () => number): InMemoryTenantNode {
    const masterSeed = hexToBytes(vectors.device.master_seed);
    return new InMemoryTenantNode({
        channel: CHANNEL,
        lspPubkey: LSP_PUBKEY,
        deviceKeys: channelIndexes.map((index) => deriveChannelKeys(deriveChannelSeed(masterSeed, index))),
        peerKeys: signingPeerKeys(vectors),
        now,
    });
}

// As the facade wires it.
export function tenantDevice(node: InMemoryTenantNode, options: TenantDeviceOptions): TenantDevice {
    const { storage } = options;
    const store = new SignerStore(storage);
    const policy = new PolicyEngine(store, options.policy);
    const dispatch = new SignerDispatch({
        masterSeed: hexToBytes(vectors.device.master_seed),
        commitmentLock: CHANNEL.commitmentLock,
        fundingLockCellDepsCount: CHANNEL.fundingLockCellDepsCount,
        millisecondsPerEpoch: SIGNING_MILLISECONDS_PER_EPOCH,
        policy,
    });
    const events: SdkEvent[] = [];
    const emit = (event: SdkEvent): void => {
        events.push(event);
    };
    const timer = new TimerMock();
    const rpc = new FiberRpcClient({ url: TENANT_NODE_URL, fetch: node.fetch });
    const activity = new ActivityTracker(store);
    const channels = new DeviceChannelList(store);
    const steps: PollStep[] = [buildChannelSigningStep({ rpc, store, activity, dispatch, emit })];
    if (options.channelStep === true) steps.unshift(buildChannelStep({ rpc, activity, openings: new PendingOpeningStore(store), emit }));
    if (options.watchtower) steps.push(buildWatchtowerSigningStep({ rpc, store, policy, dispatch, activity, channels, emit }));
    const poller = new ActivityPoller({ timer, intervalMs: INTERVAL_MS, stepTimeoutMs: STEP_TIMEOUT_MS, steps, emit });
    return { storage, store, policy, dispatch, activity, channels, poller, timer, events };
}

export async function openChannel(h: TenantFlow, first: "CompleteReceivedCommitment" | "SendCommitmentSigned"): Promise<void> {
    const pending = h.device.dispatch.prepareChannelOpen(CHANNEL_INDEX, FUNDED, CHANNEL.localCloseScript);
    const channelId = h.node.openTenantChannel(pending.material, first);
    await h.device.policy.registerChannel(channelId, pending.channelIndex, pending.fundedShannons, pending.localCloseScript);
    await h.device.policy.pinChannelTerms(channelId, TERMS);
    await watchOpened(h.device, channelId);
}

// The device registers while the node still collaborates on the funding tx, before fiber watches the channel.
export async function negotiateChannel(h: TenantFlow): Promise<void> {
    const pending = h.device.dispatch.prepareChannelOpen(CHANNEL_INDEX, FUNDED, CHANNEL.localCloseScript);
    const channelId = h.node.negotiateTenantChannel(pending.material);
    await h.device.policy.registerChannel(channelId, pending.channelIndex, pending.fundedShannons, pending.localCloseScript);
    await h.device.policy.pinChannelTerms(channelId, TERMS);
    await watchOpened(h.device, channelId);
}

// As the opening's pins end: watched, then listed as the device's.
export async function watchOpened(device: Pick<TenantDevice, "activity" | "channels">, channelId: string): Promise<void> {
    await device.activity.watch("channel", channelId);
    await device.channels.add(channelId);
}

export async function start(device: TenantDevice): Promise<void> {
    device.poller.start();
    await flush();
}

export async function tick(device: Pick<TenantDevice, "timer">, count = 1): Promise<void> {
    for (let index = 0; index < count; index++) {
        device.timer.advance(INTERVAL_MS);
        await flush();
    }
}

export function methods(h: TenantFlow, from = 0): string[] {
    return h.node.calls.slice(from).map((call) => call.method);
}

export function ticks<Item>(shape: Item[], count: number): Item[] {
    return Array.from({ length: count }, () => shape).flat();
}

export async function recordOf(device: TenantDevice): Promise<ChannelPolicyRecord> {
    const record = await device.store.getChannelRecord(CHANNEL_INDEX);
    if (record === null) throw new Error("the channel holds no record");
    return record;
}

export async function post(node: InMemoryTenantNode, body: unknown): Promise<unknown> {
    const init: FetchInit = { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) };
    const response = await node.fetch(TENANT_NODE_URL, init);
    return JSON.parse(await response.text()) as unknown;
}
