import { advanceChainUntil, CHANNEL_CLOSED_STATE, CHANNEL_READY_STATE, fiberNodes } from "./fiber-node";
import type { FiberChannel, FiberGraphChannel, FiberNode } from "./fiber-node";
import type { ScenarioEnv } from "./scenario-env";
import { sleep, waitUntil } from "./wait";

const CONNECT_SETTLE_MS = 1000;

const GONE_STATES = new Set(["ShuttingDown", CHANNEL_CLOSED_STATE]);

type PublicChannelPair = { name: string; funder: FiberNode; funderPubkey: string; peerPubkey: string; peerAddr: string };

export type PublicChannels = {
    node1ToLsp: string;
    node3ToNode1: string;
};

function samePubkey(a: string, b: string): boolean {
    return a.toLowerCase() === b.toLowerCase();
}

function usable(channel: FiberChannel, peer: string): boolean {
    return (
        samePubkey(channel.peer, peer) &&
        channel.isPublic &&
        !GONE_STATES.has(channel.stateName) &&
        (channel.raw.failure_detail === undefined || channel.raw.failure_detail === null)
    );
}

function createdAt(channel: FiberChannel): number {
    const { created_at: value } = channel.raw;
    if (typeof value !== "string") throw new Error(`list_channels: ${channel.channelId}'s created_at must be a hex string`);
    return Number(BigInt(value));
}

// The time it opened one, null when one was usable.
async function findOrOpen(pair: PublicChannelPair, fundingShannons: bigint): Promise<number | null> {
    await pair.funder.connectPeer(pair.peerAddr);
    await sleep(CONNECT_SETTLE_MS);
    const channels = await pair.funder.listChannels({ peer: pair.peerPubkey });
    if (channels.some((channel) => usable(channel, pair.peerPubkey))) return null;
    const openedAt = Date.now();
    await pair.funder.openChannel(pair.peerPubkey, fundingShannons, true);
    return openedAt;
}

// Throws on its own opening aborting, which no wait turns ready. Fiber deletes an aborted opening's state, so only the pending
// listing shows it, with `is_public` always false (d8dd6d28 `fiber/network.rs:8576-8587`, `rpc/channel.rs:571-640`). Its
// `created_at` is the funder's clock and openedAt this process's: one clock, as the nodes run here.
async function readyChannel(pair: PublicChannelPair, openedAt: number | null): Promise<string | undefined> {
    if (openedAt !== null) {
        const pending = await pair.funder.listChannels({ peer: pair.peerPubkey, onlyPending: true });
        const aborted = pending.find(
            (channel) =>
                samePubkey(channel.peer, pair.peerPubkey) &&
                channel.stateName === CHANNEL_CLOSED_STATE &&
                channel.stateFlags.includes("FUNDING_ABORTED") &&
                createdAt(channel) >= openedAt,
        );
        if (aborted !== undefined)
            throw new Error(`the opening of ${pair.name} aborted: ${JSON.stringify(aborted.raw.failure_detail ?? null)}`);
    }
    const channels = await pair.funder.listChannels({ peer: pair.peerPubkey });
    return channels.find((channel) => usable(channel, pair.peerPubkey) && channel.stateName === CHANNEL_READY_STATE)?.channelId;
}

// One pair at a time: node 1 funds its own public channel and auto-accepts node 3's, which its pending funding could starve.
async function ensureReady(env: ScenarioEnv, pair: PublicChannelPair): Promise<string> {
    const openedAt = await findOrOpen(pair, BigInt(env.chain.publicChannelShannons));
    const ready = (): Promise<string | undefined> => readyChannel(pair, openedAt);
    return (await ready()) ?? (await advanceChainUntil(env, `${pair.name} to be ready`, ready, env.chain.openingTimeoutMs));
}

function announces(graph: FiberGraphChannel[], pair: PublicChannelPair): boolean {
    return graph.some(
        (channel) =>
            channel.updatedBothWays &&
            ((samePubkey(channel.node1, pair.funderPubkey) && samePubkey(channel.node2, pair.peerPubkey)) ||
                (samePubkey(channel.node1, pair.peerPubkey) && samePubkey(channel.node2, pair.funderPubkey))),
    );
}

// Both payers' graphs must announce the channels for trampoline routes to find them.
export async function ensurePublicChannels(env: ScenarioEnv): Promise<PublicChannels> {
    const { node1, node3 } = fiberNodes(env);
    const node1ToLsp: PublicChannelPair = {
        name: "node 1 to the LSP",
        funder: node1,
        funderPubkey: env.node1Pubkey,
        peerPubkey: env.node2Pubkey,
        peerAddr: env.node2Addr,
    };
    const node3ToNode1: PublicChannelPair = {
        name: "node 3 to node 1",
        funder: node3,
        funderPubkey: env.node3Pubkey,
        peerPubkey: env.node1Pubkey,
        peerAddr: env.node1Addr,
    };
    const pairs = [node1ToLsp, node3ToNode1];
    const ids: PublicChannels = { node1ToLsp: await ensureReady(env, node1ToLsp), node3ToNode1: await ensureReady(env, node3ToNode1) };
    for (const payer of [node1, node3]) {
        await waitUntil(
            `${payer.url}'s graph to announce ${pairs.map((pair) => pair.name).join(" and ")}`,
            async () => {
                const graph = await payer.graphChannels();
                return pairs.every((pair) => announces(graph, pair)) ? true : undefined;
            },
            { timeoutMs: env.chain.graphTimeoutMs },
        );
    }
    return ids;
}
