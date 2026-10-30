import type { DevnetEnv } from "./devnet-env";
import { fiberNodes, mineUntil } from "./fiber-node";
import type { FiberChannel, FiberGraphChannel, FiberNode } from "./fiber-node";
import { CHANNEL_FUNDING_SHANNONS } from "./scenario-device";
import { GRAPH_TIMEOUT_MS, OPENING_TIMEOUT_MS, sleep, waitUntil } from "./wait";

// A tenant channel's 500 CKB; node 2 auto-accepts with as much of its own, the outbound liquidity.
const PUBLIC_CHANNEL_FUNDING_SHANNONS = BigInt(CHANNEL_FUNDING_SHANNONS);

const CONNECT_SETTLE_MS = 1000;

const READY_STATE = "ChannelReady";

const GONE_STATES = new Set(["ShuttingDown", "Closed"]);

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

async function findOrOpen(pair: PublicChannelPair): Promise<void> {
    await pair.funder.connectPeer(pair.peerAddr);
    await sleep(CONNECT_SETTLE_MS);
    const channels = await pair.funder.listChannels({ peer: pair.peerPubkey });
    if (channels.some((channel) => usable(channel, pair.peerPubkey))) return;
    await pair.funder.openChannel(pair.peerPubkey, PUBLIC_CHANNEL_FUNDING_SHANNONS, true);
}

async function readyChannel(pair: PublicChannelPair): Promise<string | undefined> {
    const channels = await pair.funder.listChannels({ peer: pair.peerPubkey });
    return channels.find((channel) => usable(channel, pair.peerPubkey) && channel.stateName === READY_STATE)?.channelId;
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
export async function ensurePublicChannels(env: DevnetEnv, timeoutMs: number = OPENING_TIMEOUT_MS): Promise<PublicChannels> {
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
    for (const pair of pairs) await findOrOpen(pair);
    const readyIds = async (): Promise<PublicChannels | undefined> => {
        const lspChannel = await readyChannel(node1ToLsp);
        const node1Channel = await readyChannel(node3ToNode1);
        return lspChannel === undefined || node1Channel === undefined ? undefined : { node1ToLsp: lspChannel, node3ToNode1: node1Channel };
    };
    const ids = (await readyIds()) ?? (await mineUntil(env, "the public channels to be ready", readyIds, timeoutMs));
    for (const payer of [node1, node3]) {
        await waitUntil(
            `${payer.url}'s graph to announce ${pairs.map((pair) => pair.name).join(" and ")}`,
            async () => {
                const graph = await payer.graphChannels();
                return pairs.every((pair) => announces(graph, pair)) ? true : undefined;
            },
            { timeoutMs: GRAPH_TIMEOUT_MS },
        );
    }
    return ids;
}
